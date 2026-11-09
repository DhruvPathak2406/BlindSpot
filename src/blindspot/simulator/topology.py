"""Private ground-truth topology and its consistency validation."""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field

from blindspot.core.models import PortState
from blindspot.simulator.host import Host, HostType


class TopologyValidationError(ValueError):
    """Raised when a generated topology is internally inconsistent."""


@dataclass(frozen=True)
class Subnet:
    id: str
    cidr: str
    zone: str
    gateway_ip: str


@dataclass(frozen=True)
class Link:
    """Undirected ground-truth connectivity. kind: l2, routed or flow."""

    a: str
    b: str
    kind: str


@dataclass(frozen=True)
class FirewallRule:
    """Traffic policy from one subnet to another.

    ``allowed_ports=None`` allows every port; an empty set allows none.
    """

    allow_icmp: bool
    allowed_ports: frozenset[int] | None = None


OPEN_RULE = FirewallRule(allow_icmp=True, allowed_ports=None)


@dataclass
class Topology:
    subnets: dict[str, Subnet]
    hosts: dict[str, Host]
    links: list[Link]
    firewall_rules: dict[tuple[str, str], FirewallRule]
    vantage_subnet: str
    seed: int | None = None
    _hosts_by_subnet: dict[str, list[Host]] = field(default_factory=dict, repr=False)

    def __post_init__(self) -> None:
        for host in self.hosts.values():
            self._hosts_by_subnet.setdefault(host.subnet_id, []).append(host)

    def hosts_in(self, subnet_id: str) -> list[Host]:
        return list(self._hosts_by_subnet.get(subnet_id, []))

    def rule_between(self, src: str, dst: str) -> FirewallRule | None:
        """Policy src -> dst; same-subnet traffic is unrestricted, no rule means deny."""
        if src == dst:
            return OPEN_RULE
        return self.firewall_rules.get((src, dst))

    def subnet_of_ip(self, ip: str) -> Subnet | None:
        addr = ipaddress.ip_address(ip)
        for subnet in self.subnets.values():
            if addr in ipaddress.ip_network(subnet.cidr):
                return subnet
        return None

    def validate(self) -> None:
        """Raise TopologyValidationError listing every inconsistency found."""
        errors: list[str] = []
        networks = {}
        for sid, subnet in self.subnets.items():
            if sid != subnet.id:
                errors.append(f"subnet key {sid} != id {subnet.id}")
            networks[sid] = ipaddress.ip_network(subnet.cidr)
        ids = list(networks)
        for i, a in enumerate(ids):
            for b in ids[i + 1:]:
                if networks[a].overlaps(networks[b]):
                    errors.append(f"subnets {a} and {b} overlap")
        if self.vantage_subnet not in self.subnets:
            errors.append("vantage subnet does not exist")
        for src, dst in self.firewall_rules:
            if src not in self.subnets or dst not in self.subnets:
                errors.append(f"firewall rule references unknown subnet {src}->{dst}")

        for key, host in self.hosts.items():
            if key != host.ip:
                errors.append(f"host key {key} != ip {host.ip}")
            if host.subnet_id not in self.subnets:
                errors.append(f"host {host.ip} in unknown subnet {host.subnet_id}")
                continue
            net = networks[host.subnet_id]
            addr = ipaddress.ip_address(host.ip)
            if addr not in net:
                errors.append(f"host {host.ip} outside {net}")
            elif addr in (net.network_address, net.broadcast_address):
                errors.append(f"host {host.ip} uses a reserved address")
            for port, service in host.services.items():
                if service.port != port:
                    errors.append(f"host {host.ip} service port mismatch at {port}")
                if port not in host.port_states:
                    errors.append(f"host {host.ip} service on {port} has no port state")
            for port, state in host.port_states.items():
                if not 1 <= port <= 65535:
                    errors.append(f"host {host.ip} invalid port {port}")
                if state is PortState.OPEN and port not in host.services:
                    errors.append(f"host {host.ip} open port {port} has no service")
                if state is PortState.CLOSED and port in host.services:
                    errors.append(f"host {host.ip} closed port {port} has a service")

        for sid, subnet in self.subnets.items():
            gw = self.hosts.get(subnet.gateway_ip)
            if gw is None or gw.subnet_id != sid or gw.host_type is not HostType.ROUTER:
                errors.append(f"subnet {sid} lacks a valid gateway router")
            if not self.hosts_in(sid):
                errors.append(f"subnet {sid} has no hosts")

        adjacency: dict[str, set[str]] = {ip: set() for ip in self.hosts}
        for link in self.links:
            if link.a not in self.hosts or link.b not in self.hosts or link.a == link.b:
                errors.append(f"invalid link {link.a}-{link.b}")
                continue
            adjacency[link.a].add(link.b)
            adjacency[link.b].add(link.a)
        if self.hosts and not errors:
            start = next(iter(self.hosts))
            seen, stack = {start}, [start]
            while stack:
                for nxt in adjacency[stack.pop()] - seen:
                    seen.add(nxt)
                    stack.append(nxt)
            if len(seen) != len(self.hosts):
                errors.append("ground-truth links do not form a connected network")

        if errors:
            raise TopologyValidationError("; ".join(errors))
