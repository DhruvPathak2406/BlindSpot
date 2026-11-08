import ipaddress

import pytest

from blindspot.core.config import GeneratorConfig
from blindspot.core.models import PortState
from blindspot.simulator.network_generator import generate_network
from blindspot.simulator.topology import TopologyValidationError


def snapshot(topo):
    return (
        {ip: (h.hostname, h.host_type, h.os_name, dict(h.services), dict(h.port_states),
              h.responds_to_icmp, h.default_filtered) for ip, h in topo.hosts.items()},
        sorted((l.a, l.b, l.kind) for l in topo.links),
        dict(topo.firewall_rules),
    )


@pytest.mark.parametrize("hosts,subnets", [(10, 2), (25, 4), (50, 6), (50, 8)])
def test_generates_valid_network_of_requested_size(hosts, subnets):
    topo = generate_network(GeneratorConfig(seed=1, num_hosts=hosts, num_subnets=subnets))
    assert len(topo.hosts) == hosts
    assert len(topo.subnets) == subnets
    topo.validate()


def test_same_seed_is_reproducible_and_different_seed_differs():
    a = snapshot(generate_network(GeneratorConfig(seed=7)))
    b = snapshot(generate_network(GeneratorConfig(seed=7)))
    c = snapshot(generate_network(GeneratorConfig(seed=8)))
    assert a == b
    assert a != c


def test_network_has_variety():
    topo = generate_network(GeneratorConfig(seed=3, num_hosts=40, num_subnets=4))
    assert len({h.host_type for h in topo.hosts.values()}) >= 4
    assert len({h.os_name for h in topo.hosts.values()}) >= 3
    states = {s for h in topo.hosts.values() for s in h.port_states.values()}
    assert states == {PortState.OPEN, PortState.CLOSED, PortState.FILTERED}
    assert {l.kind for l in topo.links} >= {"l2", "routed"}
    assert topo.firewall_rules  # segmentation exists
    assert ("corp", "iot") in topo.firewall_rules
    assert ("iot", "corp") not in topo.firewall_rules  # default deny


def test_hosts_live_inside_their_subnets():
    topo = generate_network(GeneratorConfig(seed=5))
    for host in topo.hosts.values():
        assert ipaddress.ip_address(host.ip) in ipaddress.ip_network(topo.subnets[host.subnet_id].cidr)


@pytest.mark.parametrize("kwargs", [
    {"num_hosts": 9}, {"num_hosts": 51}, {"num_subnets": 1}, {"num_hosts": 10, "num_subnets": 6},
    {"subnet_prefix": 30}, {"icmp_silent_rate": 1.5},
])
def test_invalid_config_rejected(kwargs):
    with pytest.raises(ValueError):
        GeneratorConfig(**kwargs)


def test_validation_catches_inconsistencies():
    topo = generate_network(GeneratorConfig(seed=2))
    host = next(h for h in topo.hosts.values() if h.services)
    port = next(iter(host.services))
    host.port_states[port] = PortState.CLOSED  # closed port that has a service
    with pytest.raises(TopologyValidationError):
        topo.validate()

    topo = generate_network(GeneratorConfig(seed=2))
    victim = next(h for h in topo.hosts.values() if h.ip != topo.subnets[h.subnet_id].gateway_ip)
    victim.ip = "192.168.0.5"  # outside any subnet; key mismatch too
    with pytest.raises(TopologyValidationError):
        topo.validate()
