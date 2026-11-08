"""Local web dashboard for the synthetic BlindSpot network simulator."""
from __future__ import annotations

import argparse
import json
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import TypedDict
from urllib.parse import urlparse

SRC = Path(__file__).resolve().parents[1] / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from blindspot.core.config import GeneratorConfig, ObservationConfig  # noqa: E402
from blindspot.core.models import ActionType, PortState, ReconAction  # noqa: E402
from blindspot.discovery.discovery_engine import (  # noqa: E402
    BudgetExceededError,
    DiscoveryEngine,
    DiscoveryStrategy,
    FixedOrderStrategy,
    RandomDiscoveryStrategy,
)
from blindspot.simulator.network_generator import generate_network  # noqa: E402
from blindspot.simulator.observation_model import InvalidActionError, ObservationModel  # noqa: E402

STATIC_DIR = Path(__file__).resolve().parent / "static"
MAX_REQUEST_BYTES = 16_384
STRATEGIES = ("Fixed order", "Random")


class DashboardSession(TypedDict):
    engine: DiscoveryEngine
    strategy: DiscoveryStrategy
    strategy_name: str


_session: DashboardSession | None = None
_session_lock = threading.Lock()


def build_session(config: GeneratorConfig, budget: int, strategy_name: str) -> DashboardSession:
    """Create a fresh synthetic network and its observation-only discovery engine."""
    topology = generate_network(config)
    model = ObservationModel(topology, ObservationConfig(), seed=config.seed)
    if strategy_name == "Fixed order":
        strategy: DiscoveryStrategy = FixedOrderStrategy()
    elif strategy_name == "Random":
        strategy = RandomDiscoveryStrategy(config.seed)
    else:
        raise ValueError(f"unsupported strategy: {strategy_name}")
    return {
        "engine": DiscoveryEngine(model, budget),
        "strategy": strategy,
        "strategy_name": strategy_name,
    }


def session_state(session: DashboardSession | None) -> dict[str, object] | None:
    """Return JSON-ready agent-visible results without exposing simulator ground truth."""
    if session is None:
        return None

    engine = session["engine"]
    state = engine.state
    os_map = dict(state.os_estimates)
    open_ports: dict[str, list[int]] = {}
    for ip, port, port_state in state.observed_ports:
        if port_state is PortState.OPEN:
            open_ports.setdefault(ip, []).append(port)

    hosts = [
        {
            "ip": ip,
            "osEstimate": os_map.get(ip, ""),
            "openPorts": sorted(open_ports.get(ip, [])),
        }
        for ip in sorted(state.discovered_hosts)
    ]
    services = [
        {
            "ip": observation.ip,
            "port": observation.port,
            "service": observation.service_name,
            "version": observation.service_version or "(hidden)",
            "osHint": observation.os_hint or "",
        }
        for observation in state.services
    ]
    history = [
        {
            "sequence": record.sequence,
            "time": record.timestamp.strftime("%H:%M:%S"),
            "action": record.action.action_type.value,
            "target": record.action.target,
            "port": record.action.port,
            "observations": len(record.observations),
            "newHosts": len(record.newly_discovered_hosts),
            "newServices": len(record.newly_discovered_services),
            "budgetRemaining": record.budget_remaining,
        }
        for record in engine.history
    ]

    return {
        "strategy": session["strategy_name"],
        "scope": list(engine.scope),
        "budgetTotal": engine.budget_total,
        "budgetRemaining": engine.budget_remaining,
        "budgetUsed": engine.budget_used,
        "hosts": hosts,
        "services": services,
        "links": [
            {"source": source, "target": target, "relation": relation}
            for source, target, relation in sorted(state.confirmed_links)
        ],
        "history": history,
    }


def _integer(payload: dict[str, object], key: str, default: int) -> int:
    value = payload.get(key, default)
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"{key} must be an integer")
    return value


class DashboardHandler(BaseHTTPRequestHandler):
    """Serve the dashboard assets and a local API for synthetic recon sessions."""

    server_version = "BlindSpotDashboard/1.0"

    def do_GET(self) -> None:
        path = urlparse(self.path).path
        if path == "/":
            self._serve_asset("index.html", "text/html; charset=utf-8")
        elif path == "/styles.css":
            self._serve_asset("styles.css", "text/css; charset=utf-8")
        elif path == "/dashboard.js":
            self._serve_asset("dashboard.js", "text/javascript; charset=utf-8")
        elif path == "/api/state":
            with _session_lock:
                self._send_json(200, {"session": session_state(_session)})
        else:
            self._send_json(404, {"error": "not found"})

    def do_POST(self) -> None:
        path = urlparse(self.path).path
        origin = self.headers.get("Origin")
        if origin and urlparse(origin).netloc != self.headers.get("Host"):
            self._send_json(403, {"error": "cross-origin requests are not allowed"})
            return
        try:
            payload = self._read_json()
            if path == "/api/generate":
                self._generate(payload)
            elif path == "/api/run":
                self._run(payload)
            elif path == "/api/explore":
                self._explore(payload)
            else:
                self._send_json(404, {"error": "not found"})
        except (ValueError, InvalidActionError, BudgetExceededError) as exc:
            self._send_json(400, {"error": str(exc)})

    def _generate(self, payload: dict[str, object]) -> None:
        seed = _integer(payload, "seed", 42)
        num_hosts = _integer(payload, "hosts", 25)
        num_subnets = _integer(payload, "subnets", 4)
        budget = _integer(payload, "budget", 100)
        strategy = payload.get("strategy", "Fixed order")
        if not isinstance(strategy, str):
            raise ValueError("strategy must be a string")
        if budget < 1:
            raise ValueError("budget must be at least 1")
        config = GeneratorConfig(
            seed=seed,
            num_hosts=num_hosts,
            num_subnets=num_subnets,
        )
        global _session
        with _session_lock:
            _session = build_session(config, budget, strategy)
            response = {"session": session_state(_session)}
        self._send_json(200, response)

    def _run(self, payload: dict[str, object]) -> None:
        steps = payload.get("steps")
        if steps is not None and (
            isinstance(steps, bool) or not isinstance(steps, int) or steps < 0
        ):
            raise ValueError("steps must be a non-negative integer or null")
        with _session_lock:
            if _session is None:
                raise ValueError("generate a network before running reconnaissance")
            _session["engine"].run(_session["strategy"], max_actions=steps)
            response = {"session": session_state(_session)}
        self._send_json(200, response)

    def _explore(self, payload: dict[str, object]) -> None:
        subnet = payload.get("subnet")
        if not isinstance(subnet, str):
            raise ValueError("subnet must be a string")
        with _session_lock:
            if _session is None:
                raise ValueError("generate a network before exploring a subnet")
            _session["engine"].execute(ReconAction(ActionType.SUBNET_EXPLORE, subnet))
            response = {"session": session_state(_session)}
        self._send_json(200, response)

    def _read_json(self) -> dict[str, object]:
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError as exc:
            raise ValueError("invalid Content-Length header") from exc
        if length < 0 or length > MAX_REQUEST_BYTES:
            raise ValueError("request body is too large")
        try:
            payload = json.loads(self.rfile.read(length).decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError("request body must be valid JSON") from exc
        if not isinstance(payload, dict):
            raise ValueError("request body must be a JSON object")
        return payload

    def _serve_asset(self, name: str, content_type: str) -> None:
        content = (STATIC_DIR / name).read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(content)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(content)

    def _send_json(self, status: int, value: dict[str, object]) -> None:
        content = json.dumps(value).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(content)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(content)

    def log_message(self, format: str, *args: object) -> None:
        print(f"{self.address_string()} - {format % args}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the local BlindSpot simulator dashboard.")
    parser.add_argument("--port", type=int, default=8000)
    args = parser.parse_args()
    if not 1 <= args.port <= 65535:
        parser.error("--port must be between 1 and 65535")

    server = ThreadingHTTPServer(("127.0.0.1", args.port), DashboardHandler)
    print(f"BlindSpot simulator dashboard: http://127.0.0.1:{args.port}")
    print("Simulation only; this server does not scan real networks.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping dashboard.")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
