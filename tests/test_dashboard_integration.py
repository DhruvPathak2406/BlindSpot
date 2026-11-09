import json
import sys
import threading
from http.server import ThreadingHTTPServer
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import Request, urlopen

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from app import dashboard  # noqa: E402
from blindspot.core.config import GeneratorConfig  # noqa: E402


def post_json(base_url, path, body):
    request = Request(
        f"{base_url}{path}",
        data=json.dumps(body).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urlopen(request) as response:
        return json.load(response)


def test_session_run_populates_visible_state_and_respects_budget():
    session = dashboard.build_session(GeneratorConfig(seed=7), 5, "Fixed order")

    session["engine"].run(session["strategy"], max_actions=2)
    state = dashboard.session_state(session)

    assert state is not None
    assert state["budgetUsed"] == 2
    assert state["budgetRemaining"] == 3
    assert len(state["history"]) == 2
    assert state["scope"] == list(session["engine"].scope)
    assert "hosts" in state and "services" in state and "links" in state


def test_random_strategy_runs():
    session = dashboard.build_session(GeneratorConfig(seed=7), 5, "Random")
    session["engine"].run(session["strategy"], max_actions=2)

    assert session["engine"].budget_used == 2
    assert len(session["engine"].history) == 2


def test_http_dashboard_end_to_end():
    server = ThreadingHTTPServer(("127.0.0.1", 0), dashboard.DashboardHandler)
    thread = threading.Thread(target=server.serve_forever)
    thread.start()
    base_url = f"http://127.0.0.1:{server.server_port}"
    try:
        with urlopen(base_url) as response:
            page = response.read().decode("utf-8")
            assert response.status == 200
            assert "SIMULATION ONLY" in page
            assert "streamlit" not in page.lower()

        with urlopen(f"{base_url}/dashboard.js") as response:
            assert response.status == 200
            assert b"/api/generate" in response.read()

        initial = json.load(urlopen(f"{base_url}/api/state"))
        assert initial == {"session": None}

        cross_origin_request = Request(
            f"{base_url}/api/generate",
            data=b"{}",
            headers={
                "Content-Type": "application/json",
                "Origin": "https://example.com",
            },
            method="POST",
        )
        try:
            urlopen(cross_origin_request)
        except HTTPError as error:
            assert error.code == 403
        else:
            raise AssertionError("cross-origin API request should be rejected")

        generated = post_json(
            base_url,
            "/api/generate",
            {
                "seed": 7,
                "hosts": 25,
                "subnets": 4,
                "budget": 5,
                "strategy": "Fixed order",
            },
        )["session"]
        assert generated["budgetUsed"] == 0
        assert len(generated["scope"]) == 4

        stepped = post_json(base_url, "/api/run", {"steps": 2})["session"]
        assert stepped["budgetUsed"] == 2
        assert len(stepped["history"]) == 2

        explored = post_json(
            base_url, "/api/explore", {"subnet": stepped["scope"][0]}
        )["session"]
        assert explored["budgetUsed"] == 3
        assert explored["history"][-1]["action"] == "subnet_explore"

        completed = post_json(base_url, "/api/run", {"steps": None})["session"]
        assert completed["budgetUsed"] == 5
        assert completed["budgetRemaining"] == 0
    finally:
        server.shutdown()
        server.server_close()
        thread.join()
