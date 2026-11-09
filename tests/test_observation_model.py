import dataclasses

import pytest

from blindspot.core.config import GeneratorConfig, ObservationConfig
from blindspot.core.models import ActionType, Observation, ObservationKind, PortState, ReconAction
from blindspot.simulator.host import Host
from blindspot.simulator.network_generator import generate_network
from blindspot.simulator.observation_model import InvalidActionError, ObservationModel
from blindspot.simulator.topology import Topology

QUIET = ObservationConfig(ping_miss_rate=0.0, banner_hide_rate=0.0, os_hint_rate=1.0, os_hint_error_rate=0.0)


@pytest.fixture
def topo():
    return generate_network(GeneratorConfig(seed=11, num_hosts=30, num_subnets=4))


def act(kind, target, port=None):
    return ReconAction(kind, target, port)


def vantage_hosts(topo):
    return [h for h in topo.hosts.values() if h.subnet_id == topo.vantage_subnet]


def test_scope_lists_only_cidrs(topo):
    scope = ObservationModel(topo).scope()
    assert scope == sorted(s.cidr for s in topo.subnets.values())


def test_host_discovery_finds_pingable_host_and_misses_silent_ones(topo):
    model = ObservationModel(topo, QUIET)
    for host in vantage_hosts(topo):
        (obs,) = model.execute(act(ActionType.HOST_DISCOVERY, host.ip))
        assert obs.kind is ObservationKind.HOST
        assert obs.responded == host.responds_to_icmp


def test_unused_address_gives_no_response(topo):
    model = ObservationModel(topo, QUIET)
    cidr = topo.subnets[topo.vantage_subnet].cidr
    import ipaddress
    free = next(str(a) for a in ipaddress.ip_network(cidr).hosts() if str(a) not in topo.hosts)
    (obs,) = model.execute(act(ActionType.HOST_DISCOVERY, free))
    assert obs.responded is False


def test_port_scan_reports_open_closed_filtered_from_vantage(topo):
    model = ObservationModel(topo, QUIET)
    seen = set()
    for host in vantage_hosts(topo):  # same subnet: no network firewall
        for port, state in host.port_states.items():
            (obs,) = model.execute(act(ActionType.PORT_SCAN, host.ip, port))
            assert obs.port_state is state
            seen.add(state)
    assert {PortState.OPEN, PortState.CLOSED} <= seen


def test_default_port_scan_covers_top_ports_only(topo):
    model = ObservationModel(topo, QUIET)
    host = vantage_hosts(topo)[0]
    obs = model.execute(act(ActionType.PORT_SCAN, host.ip))
    assert [o.port for o in obs] == list(QUIET.top_ports)
    assert 1883 not in QUIET.top_ports


def test_firewall_filters_ports_across_subnets(topo):
    model = ObservationModel(topo, QUIET)
    rule = topo.rule_between(topo.vantage_subnet, "dmz")
    host = topo.hosts_in("dmz")[0]
    blocked = next(p for p in (21, 3389, 9999) if p not in rule.allowed_ports)
    (obs,) = model.execute(act(ActionType.PORT_SCAN, host.ip, blocked))
    assert obs.port_state is PortState.FILTERED


def test_service_identification(topo):
    model = ObservationModel(topo, QUIET)
    host = next(h for h in vantage_hosts(topo) if PortState.OPEN in h.port_states.values())
    port = next(p for p, s in host.port_states.items() if s is PortState.OPEN)
    (obs,) = model.execute(act(ActionType.SERVICE_ID, host.ip, port))
    assert obs.service_name == host.services[port].name
    assert obs.service_version == host.services[port].version
    assert obs.os_hint is not None

    closed = next((p for p, s in host.port_states.items() if s is PortState.CLOSED), None)
    if closed:
        (obs,) = model.execute(act(ActionType.SERVICE_ID, host.ip, closed))
        assert obs.service_name is None and obs.port_state is PortState.CLOSED


def test_service_id_requires_port(topo):
    with pytest.raises(InvalidActionError):
        ObservationModel(topo).execute(act(ActionType.SERVICE_ID, vantage_hosts(topo)[0].ip))


def test_subnet_explore_returns_hosts_and_links(topo):
    model = ObservationModel(topo, QUIET)
    cidr = topo.subnets["servers"].cidr
    obs = model.execute(act(ActionType.SUBNET_EXPLORE, cidr))
    hosts = {o.ip for o in obs if o.kind is ObservationKind.HOST}
    expected = {h.ip for h in topo.hosts_in("servers") if h.responds_to_icmp}
    assert hosts == expected
    assert any(o.kind is ObservationKind.LINK and o.relation == "routed" for o in obs)


def test_unreachable_segment_stays_hidden(topo):
    model = ObservationModel(topo, QUIET)
    assert topo.rule_between(topo.vantage_subnet, "iot").allow_icmp is False
    obs = model.execute(act(ActionType.SUBNET_EXPLORE, topo.subnets["iot"].cidr))
    assert obs == []


def test_out_of_scope_and_malformed_targets_rejected(topo):
    model = ObservationModel(topo)
    for bad in ("8.8.8.8", "not-an-ip"):
        with pytest.raises(InvalidActionError):
            model.execute(act(ActionType.HOST_DISCOVERY, bad))
    with pytest.raises(InvalidActionError):
        model.execute(act(ActionType.SUBNET_EXPLORE, "10.99.0.0/24"))
    with pytest.raises(InvalidActionError):
        model.execute(act(ActionType.PORT_SCAN, vantage_hosts(topo)[0].ip, 70000))


# ---- information-leakage guards --------------------------------------
def contains_ground_truth(value, depth=0) -> bool:
    if isinstance(value, (Host, Topology)):
        return True
    if depth > 3:
        return False
    if isinstance(value, dict):
        return any(contains_ground_truth(v, depth + 1) for v in value.values())
    if isinstance(value, (list, tuple, set)):
        return any(contains_ground_truth(v, depth + 1) for v in value)
    if dataclasses.is_dataclass(value):
        return any(contains_ground_truth(getattr(value, f.name), depth + 1) for f in dataclasses.fields(value))
    return False


def test_observations_are_plain_data_without_ground_truth(topo):
    model = ObservationModel(topo, QUIET)
    allowed = {f.name for f in dataclasses.fields(Observation)}
    for subnet in topo.subnets.values():
        for o in model.execute(act(ActionType.SUBNET_EXPLORE, subnet.cidr)):
            assert set(vars(o)) == allowed
            assert not contains_ground_truth(o)
    host = vantage_hosts(topo)[0]
    for o in model.execute(act(ActionType.PORT_SCAN, host.ip)):
        assert not contains_ground_truth(o)


def test_public_surface_exposes_no_ground_truth(topo):
    model = ObservationModel(topo)
    public = [n for n in dir(model) if not n.startswith("_")]
    assert sorted(public) == ["execute", "scope"]
    for name in public:
        attr = getattr(model, name)
        if not callable(attr):
            assert not contains_ground_truth(attr)
    assert not contains_ground_truth(model.scope())
    for hidden in ("topology", "hosts", "ground_truth"):
        assert not hasattr(model, hidden)
    text = repr(model)
    assert all(h.hostname not in text and h.os_name not in text for h in topo.hosts.values())


def test_nonexistent_and_firewalled_targets_are_indistinguishable(topo):
    """A blocked host and an empty address must look the same to the agent."""
    model = ObservationModel(topo, QUIET)
    import ipaddress
    iot = topo.subnets["iot"]
    real = topo.hosts_in("iot")[0].ip
    empty = next(str(a) for a in ipaddress.ip_network(iot.cidr).hosts() if str(a) not in topo.hosts)
    a = model.execute(act(ActionType.HOST_DISCOVERY, real))
    b = model.execute(act(ActionType.HOST_DISCOVERY, empty))
    assert [o.responded for o in a] == [o.responded for o in b] == [False]
    pa = model.execute(act(ActionType.PORT_SCAN, real, 22))[0].port_state
    pb = model.execute(act(ActionType.PORT_SCAN, empty, 22))[0].port_state
    assert pa == pb == PortState.FILTERED


def test_observations_reproducible_with_seed(topo):
    noisy = ObservationConfig(ping_miss_rate=0.4, banner_hide_rate=0.4, os_hint_rate=0.5, os_hint_error_rate=0.3)

    def run(seed):
        model = ObservationModel(topo, noisy, seed=seed)
        out = []
        for subnet in topo.subnets.values():
            out += model.execute(act(ActionType.SUBNET_EXPLORE, subnet.cidr))
        for host in vantage_hosts(topo):
            out += model.execute(act(ActionType.PORT_SCAN, host.ip))
        return out

    assert run(5) == run(5)
    assert run(5) != run(6)


def test_ping_noise_creates_false_negatives(topo):
    noisy = ObservationConfig(ping_miss_rate=1.0)
    model = ObservationModel(topo, noisy)
    host = next(h for h in vantage_hosts(topo) if h.responds_to_icmp)
    assert model.execute(act(ActionType.HOST_DISCOVERY, host.ip))[0].responded is False
