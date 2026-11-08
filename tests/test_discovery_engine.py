import pytest

from blindspot.core.config import GeneratorConfig, ObservationConfig
from blindspot.core.models import ActionType, PortState, ReconAction
from blindspot.discovery.discovery_engine import (
    BudgetExceededError,
    DiscoveryEngine,
    FixedOrderStrategy,
    RandomDiscoveryStrategy,
)
from blindspot.simulator.network_generator import generate_network
from blindspot.simulator.observation_model import InvalidActionError, ObservationModel

QUIET = ObservationConfig(
    ping_miss_rate=0.0,
    banner_hide_rate=0.0,
    os_hint_rate=1.0,
    os_hint_error_rate=0.0,
)


@pytest.fixture
def topo():
    return generate_network(GeneratorConfig(seed=31, num_hosts=24, num_subnets=4))


def engine_for(topo, budget=20, seed=2):
    return DiscoveryEngine(ObservationModel(topo, QUIET, seed=seed), budget=budget)


def test_host_discovery_updates_agent_state_and_history(topo):
    host = next(h for h in topo.hosts.values() if h.subnet_id == topo.vantage_subnet and h.responds_to_icmp)
    engine = engine_for(topo, budget=2)

    record = engine.execute(ReconAction(ActionType.HOST_DISCOVERY, host.ip))

    assert engine.budget_used == 1
    assert engine.budget_remaining == 1
    assert record.sequence == 1
    assert record.action.target == host.ip
    assert record.newly_discovered_hosts == (host.ip,)
    assert record.timestamp.tzinfo is not None
    assert host.ip in engine.state.checked_hosts
    assert host.ip in engine.state.discovered_hosts
    assert engine.history == (record,)


def test_no_response_is_checked_but_not_confirmed_absent(topo):
    engine = engine_for(topo, budget=2)
    unknown = "10.20.0.2"
    if unknown in topo.hosts:
        unknown = "10.20.0.3"
    engine.execute(ReconAction(ActionType.HOST_DISCOVERY, unknown))

    assert unknown in engine.state.checked_hosts
    assert unknown not in engine.state.discovered_hosts
    assert unknown not in engine.state.unprobed_addresses


def test_open_port_is_positive_host_evidence_without_ping_response(topo):
    host = next(
        h for h in topo.hosts.values()
        if h.subnet_id == topo.vantage_subnet
        and not h.responds_to_icmp
        and any(state is PortState.OPEN for state in h.port_states.values())
    )
    port = next(p for p, state in host.port_states.items() if state is PortState.OPEN)
    engine = engine_for(topo, budget=1)
    record = engine.execute(ReconAction(ActionType.PORT_SCAN, host.ip, port))

    assert host.ip in engine.state.discovered_hosts
    assert record.newly_discovered_hosts == (host.ip,)


def test_service_discovery_accumulates_only_observed_data(topo):
    host = next(
        h for h in topo.hosts.values()
        if h.subnet_id == topo.vantage_subnet and any(s is PortState.OPEN for s in h.port_states.values())
    )
    port = next(p for p, state in host.port_states.items() if state is PortState.OPEN)
    engine = engine_for(topo, budget=3)
    engine.execute(ReconAction(ActionType.HOST_DISCOVERY, host.ip))
    scan_record = engine.execute(ReconAction(ActionType.PORT_SCAN, host.ip, port))
    assert scan_record.newly_discovered_services == ()
    service_record = engine.execute(ReconAction(ActionType.SERVICE_ID, host.ip, port))

    assert service_record.newly_discovered_services[0].service_name == host.services[port].name
    assert (host.ip, port) in engine.state.service_probes
    assert engine.state.services[0].service_version == host.services[port].version
    assert (host.ip, port, PortState.OPEN) in engine.state.observed_ports


def test_budget_is_enforced_without_recording_or_charging_rejected_action(topo):
    engine = engine_for(topo, budget=1)
    action = ReconAction(ActionType.HOST_DISCOVERY, "8.8.8.8")
    with pytest.raises(InvalidActionError):
        engine.execute(action)
    assert engine.budget_remaining == 1
    assert engine.history == ()

    engine.execute(ReconAction(ActionType.HOST_DISCOVERY, "10.20.0.1"))
    with pytest.raises(BudgetExceededError):
        engine.execute(ReconAction(ActionType.HOST_DISCOVERY, "10.20.0.2"))
    assert engine.budget_used == 1
    assert len(engine.history) == 1


@pytest.mark.parametrize("budget", [-1, 1.5, True])
def test_invalid_budgets_are_rejected(topo, budget):
    with pytest.raises(ValueError):
        engine_for(topo, budget=budget)


def test_run_respects_action_limit_and_resumes_fixed_order(topo):
    engine = engine_for(topo, budget=5)
    strategy = FixedOrderStrategy()

    first = engine.run(strategy, max_actions=2)
    second = engine.run(strategy, max_actions=3)

    assert len(first) == 2
    assert len(second) == 3
    assert all(r.action.action_type is ActionType.HOST_DISCOVERY for r in first + second)
    assert [r.sequence for r in first + second] == [1, 2, 3, 4, 5]
    assert engine.budget_remaining == 0


def test_fixed_order_advances_to_port_and_service_identification(topo):
    # Use the agent's full authorized range, but cap the run when the first
    # confirmed host reaches the service-identification stage.
    engine = engine_for(topo, budget=1000)
    strategy = FixedOrderStrategy()
    records = engine.run(strategy, max_actions=1000)

    action_types = {record.action.action_type for record in records}
    assert ActionType.HOST_DISCOVERY in action_types
    assert ActionType.PORT_SCAN in action_types
    assert ActionType.SERVICE_ID in action_types
    assert all(
        record.action.target in engine.state.discovered_hosts
        for record in records
        if record.action.action_type in (ActionType.PORT_SCAN, ActionType.SERVICE_ID)
    )


def test_random_strategy_is_seed_reproducible(topo):
    def run(seed):
        engine = engine_for(topo, budget=30, seed=seed)
        records = engine.run(RandomDiscoveryStrategy(seed=seed))
        return [r.action for r in records]

    assert run(7) == run(7)
    assert run(7) != run(8)


def test_strategy_exhaustion_does_not_spend_remaining_budget(topo):
    engine = engine_for(topo, budget=1)
    records = engine.run(FixedOrderStrategy(), max_actions=0)

    assert records == ()
    assert engine.budget_remaining == 1


def test_engine_does_not_expose_ground_truth(topo):
    engine = engine_for(topo)
    public = [name for name in dir(engine) if not name.startswith("_")]

    assert public == [
        "budget_remaining",
        "budget_total",
        "budget_used",
        "execute",
        "history",
        "run",
        "scope",
        "state",
    ]
    assert not hasattr(engine, "topology")
    assert not hasattr(engine, "hosts")
