"""The only bridge between simulator ground truth and the reconnaissance agent.

The agent submits a ``ReconAction`` and receives plain ``Observation`` objects.
No ``Host``, ``Topology`` or firewall object ever crosses this boundary.
Python cannot enforce true privacy, so the topology is name-mangled and the
public surface is limited to ``scope()`` and ``execute()``.
"""
from __future__ import annotations

import ipaddress
import random

from blindspot.core.config import ObservationConfig
from blindspot.core.models import (
    ActionType,
    Observation,
    ObservationKind,
    PortState,
    ReconAction,
)
from blindspot.simulator.host import OS_FAMILIES, Host, os_family
from blindspot.simulator.topology import Topology


class InvalidActionError(ValueError):
    """Raised for malformed actions or targets outside the authorised scope."""


class ObservationModel:
    """Turns reconnaissance actions into partial, noisy observations."""

    def __init__(self, topology: Topology, config: ObservationConfig | None = None, seed: int = 0) -> None:
        self.__topology = topology
        self.__config = config or ObservationConfig()
        self.__rng = random.Random(seed)
        self.__networks = {
            s.cidr: ipaddress.ip_network(s.cidr) for s in topology.subnets.values()
        }

    def __repr__(self) -> str:
        return f"ObservationModel(scope={self.scope()})"

    def scope(self) -> list[str]:
        """Authorised address ranges (CIDRs). This is all the agent knows up front."""
        return sorted(self.__networks)

    def execute(self, action: ReconAction) -> list[Observation]:
        """Run one action and return only what a scanner could see."""
        handlers = {
            ActionType.HOST_DISCOVERY: self.__host_discovery,
            ActionType.PORT_SCAN: self.__port_scan,
            ActionType.SERVICE_ID: self.__service_id,
            ActionType.SUBNET_EXPLORE: self.__subnet_explore,
        }
        handler = handlers.get(action.action_type)
        if handler is None:
            raise InvalidActionError(f"unsupported action {action.action_type}")
        if action.action_type is ActionType.SUBNET_EXPLORE:
            if action.target not in self.__networks:
                raise InvalidActionError(f"{action.target} is not an authorised subnet")
        else:
            self.__check_ip(action.target)
        return handler(action)

    # ---- validation -------------------------------------------------
    def __check_ip(self, ip: str) -> None:
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError as exc:
            raise InvalidActionError(f"invalid IP address {ip!r}") from exc
        if not any(addr in net for net in self.__networks.values()):
            raise InvalidActionError(f"{ip} is outside the authorised scope")

    # ---- network view from the scanner's vantage point -------------
    def __host_at(self, ip: str) -> Host | None:
        return self.__topology.hosts.get(ip)

    def __rule_to(self, ip: str):
        subnet = self.__topology.subnet_of_ip(ip)
        return self.__topology.rule_between(self.__topology.vantage_subnet, subnet.id)

    def __port_state(self, ip: str, port: int) -> PortState:
        """Externally visible state; unknown and unreachable targets look filtered."""
        host = self.__host_at(ip)
        rule = self.__rule_to(ip)
        if host is None or rule is None:
            return PortState.FILTERED
        if rule.allowed_ports is not None and port not in rule.allowed_ports:
            return PortState.FILTERED
        return host.state_of(port)

    def __pingable(self, ip: str) -> bool:
        host = self.__host_at(ip)
        rule = self.__rule_to(ip)
        return bool(host and rule and rule.allow_icmp and host.responds_to_icmp)

    # ---- action handlers --------------------------------------------
    def __host_discovery(self, action: ReconAction) -> list[Observation]:
        responded = self.__pingable(action.target) and self.__rng.random() >= self.__config.ping_miss_rate
        return [Observation(ObservationKind.HOST, action.action_type, action.target, responded=responded)]

    def __port_scan(self, action: ReconAction) -> list[Observation]:
        ports = [action.port] if action.port is not None else list(self.__config.top_ports)
        if any(not 1 <= p <= 65535 for p in ports):
            raise InvalidActionError("port out of range")
        return [
            Observation(
                ObservationKind.PORT, action.action_type, action.target,
                port=p, port_state=self.__port_state(action.target, p),
            )
            for p in ports
        ]

    def __service_id(self, action: ReconAction) -> list[Observation]:
        if action.port is None or not 1 <= action.port <= 65535:
            raise InvalidActionError("SERVICE_ID requires a valid port")
        state = self.__port_state(action.target, action.port)
        name = version = os_hint = None
        if state is PortState.OPEN:
            host = self.__host_at(action.target)
            service = host.services[action.port]
            name = service.name
            if self.__rng.random() >= self.__config.banner_hide_rate:
                version = service.version
            os_hint = self.__os_hint(host)
        return [
            Observation(
                ObservationKind.SERVICE, action.action_type, action.target,
                port=action.port, port_state=state,
                service_name=name, service_version=version, os_hint=os_hint,
            )
        ]

    def __os_hint(self, host: Host) -> str | None:
        if self.__rng.random() >= self.__config.os_hint_rate:
            return None
        truth = os_family(host.os_name)
        if self.__rng.random() < self.__config.os_hint_error_rate:
            return self.__rng.choice([f for f in OS_FAMILIES if f != truth])
        return truth

    def __subnet_explore(self, action: ReconAction) -> list[Observation]:
        """Ping-sweep a subnet, reporting live hosts and the links they reveal."""
        topo = self.__topology
        subnet = next(s for s in topo.subnets.values() if s.cidr == action.target)
        observations: list[Observation] = []
        live: set[str] = set()
        for addr in self.__networks[action.target].hosts():
            ip = str(addr)
            if self.__pingable(ip) and self.__rng.random() >= self.__config.ping_miss_rate:
                live.add(ip)
                observations.append(
                    Observation(ObservationKind.HOST, action.action_type, ip, responded=True)
                )
        gateway = subnet.gateway_ip
        for ip in sorted(live - {gateway}):
            if gateway in live:
                observations.append(
                    Observation(ObservationKind.LINK, action.action_type, ip, peer_ip=gateway, relation="l2")
                )
        vantage_gw = topo.subnets[topo.vantage_subnet].gateway_ip
        if subnet.id != topo.vantage_subnet and gateway in live:
            observations.append(
                Observation(ObservationKind.LINK, action.action_type, gateway, peer_ip=vantage_gw, relation="routed")
            )
        return observations
