"""Seeded synthetic enterprise network generator."""
from __future__ import annotations

import ipaddress
import random

from blindspot.core.config import GeneratorConfig
from blindspot.core.models import PortState
from blindspot.simulator.host import HOST_PROFILES, Host, HostType
from blindspot.simulator.service import PORT_TO_SERVICE, SERVICE_CATALOG, Service
from blindspot.simulator.topology import (
    FirewallRule,
    Link,
    Subnet,
    Topology,
)

ZONE_ORDER = ("corp", "dmz", "servers", "iot")  # first zone hosts the scanner
ZONE_WEIGHTS = {"corp": 0.40, "dmz": 0.20, "servers": 0.25, "iot": 0.15}
ZONE_HOST_TYPES: dict[str, tuple[tuple[HostType, float], ...]] = {
    "corp": ((HostType.WORKSTATION, 0.75), (HostType.PRINTER, 0.15), (HostType.FILE_SERVER, 0.10)),
    "dmz": ((HostType.WEB_SERVER, 0.6), (HostType.MAIL_SERVER, 0.4)),
    "servers": ((HostType.DB_SERVER, 0.4), (HostType.FILE_SERVER, 0.3), (HostType.WEB_SERVER, 0.3)),
    "iot": ((HostType.IOT_DEVICE, 0.7), (HostType.PRINTER, 0.3)),
}
SERVER_TYPES = {HostType.WEB_SERVER, HostType.DB_SERVER, HostType.FILE_SERVER, HostType.MAIL_SERVER}
OPTIONAL_SERVICE_RATE = 0.4
FLOW_LINK_RATE = 0.5
ADDRESS_SPACE = "10.20.0.0/16"

# (src zone, dst zone) -> rule; anything missing is denied.
_ZONE_POLICY: dict[tuple[str, str], FirewallRule] = {
    ("corp", "dmz"): FirewallRule(True, frozenset({22, 25, 80, 443})),
    ("corp", "servers"): FirewallRule(True, frozenset({22, 443, 445, 3306, 5432})),
    ("corp", "iot"): FirewallRule(False, frozenset({80, 1883})),
    ("dmz", "servers"): FirewallRule(True, frozenset({3306, 5432})),
    ("servers", "corp"): FirewallRule(True, frozenset({445})),
    ("servers", "dmz"): FirewallRule(True, frozenset({443})),
}
_SAME_ZONE_POLICY = FirewallRule(True, frozenset({443, 445}))


def _weighted(rng: random.Random, options: tuple[tuple[object, float], ...]):
    return rng.choices([o for o, _ in options], weights=[w for _, w in options])[0]


def _pick_version(rng: random.Random, name: str, os_name: str) -> str | None:
    """Pick a plausible version for the OS, or None if the service cannot run there."""
    versions = SERVICE_CATALOG[name][1]
    windows = os_name.startswith("Windows")
    matching = [v for v in versions if ("Microsoft" in v) == windows]
    if name == "rdp":
        return rng.choice(versions) if windows else None
    return rng.choice(matching or list(versions))


def _build_services(rng: random.Random, host_type: HostType, os_name: str) -> list[Service]:
    profile = HOST_PROFILES[host_type]
    names = list(profile.core_services)
    names += [n for n in profile.optional_services if rng.random() < OPTIONAL_SERVICE_RATE]
    services = []
    for name in names:
        version = _pick_version(rng, name, os_name)
        if version is not None:
            services.append(Service(name, SERVICE_CATALOG[name][0], version))
    return services


def generate_network(config: GeneratorConfig | None = None) -> Topology:
    """Generate a validated topology; identical configs yield identical networks."""
    config = config or GeneratorConfig()
    rng = random.Random(config.seed)

    # Subnets
    blocks = ipaddress.ip_network(ADDRESS_SPACE).subnets(new_prefix=config.subnet_prefix)
    subnets: dict[str, Subnet] = {}
    networks: dict[str, ipaddress.IPv4Network] = {}
    for i in range(config.num_subnets):
        zone = ZONE_ORDER[i % len(ZONE_ORDER)]
        sid = zone if i < len(ZONE_ORDER) else f"{zone}-{i // len(ZONE_ORDER) + 1}"
        net = next(blocks)
        networks[sid] = net
        subnets[sid] = Subnet(sid, str(net), zone, str(net.network_address + 1))

    # Host counts per subnet: one gateway each, remainder spread by zone weight
    capacity = {sid: net.num_addresses - 2 for sid, net in networks.items()}
    counts = {sid: 1 for sid in subnets}
    for _ in range(config.num_hosts - len(subnets)):
        open_ids = [s for s in subnets if counts[s] < capacity[s]]
        if not open_ids:
            raise ValueError("subnets too small for requested num_hosts")
        weights = [ZONE_WEIGHTS[subnets[s].zone] for s in open_ids]
        counts[rng.choices(open_ids, weights=weights)[0]] += 1
    for sid in subnets:  # guarantee a non-gateway host per subnet
        if counts[sid] < 2:
            donor = max(counts, key=counts.get)
            counts[donor] -= 1
            counts[sid] += 1

    hosts: dict[str, Host] = {}
    for sid, subnet in subnets.items():
        net = networks[sid]
        gw_prefix = HOST_PROFILES[HostType.ROUTER].hostname_prefix
        gateway = Host(
            ip=subnet.gateway_ip,
            hostname=f"{gw_prefix}-{sid}",
            subnet_id=sid,
            host_type=HostType.ROUTER,
            os_name=HOST_PROFILES[HostType.ROUTER].os_choices[0],
        )
        _apply_services(rng, gateway, config, force_open=True)
        hosts[gateway.ip] = gateway

        free = [str(a) for a in net.hosts() if str(a) != subnet.gateway_ip]
        for n, ip in enumerate(rng.sample(free, counts[sid] - 1), start=1):
            host_type = _weighted(rng, ZONE_HOST_TYPES[subnet.zone])
            profile = HOST_PROFILES[host_type]
            host = Host(
                ip=ip,
                hostname=f"{profile.hostname_prefix}-{sid}-{n:02d}",
                subnet_id=sid,
                host_type=host_type,
                os_name=rng.choice(profile.os_choices),
                responds_to_icmp=rng.random() >= config.icmp_silent_rate,
                default_filtered=rng.random() < config.hardened_host_rate,
            )
            _apply_services(rng, host, config)
            hosts[ip] = host

    # Links: l2 to gateway, routed star around the vantage gateway, some app flows
    links = [Link(h.ip, subnets[h.subnet_id].gateway_ip, "l2") for h in hosts.values() if h.ip != subnets[h.subnet_id].gateway_ip]
    vantage = next(iter(subnets))
    vantage_gw = subnets[vantage].gateway_ip
    links += [Link(vantage_gw, s.gateway_ip, "routed") for sid, s in subnets.items() if sid != vantage]
    servers = [h.ip for h in hosts.values() if h.host_type in SERVER_TYPES]
    for host in hosts.values():
        if host.host_type is HostType.WORKSTATION and servers and rng.random() < FLOW_LINK_RATE:
            links.append(Link(host.ip, rng.choice(servers), "flow"))

    # Firewall rules between every ordered pair of subnets
    rules: dict[tuple[str, str], FirewallRule] = {}
    for src, s_sub in subnets.items():
        for dst, d_sub in subnets.items():
            if src == dst:
                continue
            rule = _SAME_ZONE_POLICY if s_sub.zone == d_sub.zone else _ZONE_POLICY.get((s_sub.zone, d_sub.zone))
            if rule is not None:
                rules[(src, dst)] = rule

    topology = Topology(subnets, hosts, links, rules, vantage, seed=config.seed)
    topology.validate()
    return topology


def _apply_services(rng: random.Random, host: Host, config: GeneratorConfig, force_open: bool = False) -> None:
    """Attach services plus open/filtered/closed port states to a host."""
    for service in _build_services(rng, host.host_type, host.os_name):
        host.services[service.port] = service
        hidden = not force_open and rng.random() < config.filtered_service_rate
        host.port_states[service.port] = PortState.FILTERED if hidden else PortState.OPEN
    spare = sorted(p for p in PORT_TO_SERVICE if p not in host.services)
    for port in rng.sample(spare, min(config.closed_ports_per_host, len(spare))):
        host.port_states[port] = PortState.CLOSED
