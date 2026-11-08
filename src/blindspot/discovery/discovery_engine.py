"""Budgeted orchestration that exposes only observation-model outputs."""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Protocol

from blindspot.core.models import (
    ActionType,
    Observation,
    ObservationKind,
    PortState,
    ReconAction,
)
from blindspot.simulator.observation_model import ObservationModel


class BudgetExceededError(RuntimeError):
    """Raised when an action is requested after the assessment budget is spent."""


@dataclass(frozen=True)
class DiscoveryState:
    """Immutable snapshot of evidence available to the reconnaissance agent."""

    unprobed_addresses: frozenset[str]
    checked_hosts: frozenset[str]
    discovered_hosts: frozenset[str]
    observed_ports: tuple[tuple[str, int, PortState], ...]
    service_probes: frozenset[tuple[str, int]]
    services: tuple[Observation, ...]
    os_estimates: tuple[tuple[str, str], ...]
    confirmed_links: frozenset[tuple[str, str, str]]
    completed_actions: frozenset[ReconAction]


@dataclass(frozen=True)
class ActionRecord:
    """Persistable history of one completed action and its discoveries."""

    sequence: int
    timestamp: datetime
    action: ReconAction
    observations: tuple[Observation, ...]
    newly_discovered_hosts: tuple[str, ...]
    newly_discovered_services: tuple[Observation, ...]
    budget_remaining: int


class DiscoveryStrategy(Protocol):
    """Action selector over authorised ranges and agent-visible state."""

    def next_action(self, scope: tuple[str, ...], state: DiscoveryState) -> ReconAction | None:
        """Return one next action, or ``None`` when the strategy is finished."""


class DiscoveryEngine:
    """Runs bounded actions and accumulates evidence without seeing ground truth.

    Budget is measured in completed ``ReconAction`` objects. In particular,
    one port-scan action probes the configured top-port set.
    """

    def __init__(self, observation_model: ObservationModel, budget: int) -> None:
        if isinstance(budget, bool) or not isinstance(budget, int) or budget < 0:
            raise ValueError("budget must be a non-negative integer")
        self.__observation_model = observation_model
        self.__scope = tuple(observation_model.scope())
        self.__unprobed_addresses = set(addresses_in_scope(self.__scope))
        self.__budget_total = budget
        self.__budget_remaining = budget
        self.__history: list[ActionRecord] = []
        self.__checked_hosts: set[str] = set()
        self.__discovered_hosts: set[str] = set()
        self.__observed_ports: dict[tuple[str, int], PortState] = {}
        self.__service_probes: set[tuple[str, int]] = set()
        self.__services: dict[tuple[str, int], Observation] = {}
        self.__os_estimates: dict[str, str] = {}
        self.__confirmed_links: set[tuple[str, str, str]] = set()
        self.__completed_actions: set[ReconAction] = set()

    @property
    def budget_total(self) -> int:
        return self.__budget_total

    @property
    def budget_remaining(self) -> int:
        return self.__budget_remaining

    @property
    def budget_used(self) -> int:
        return self.__budget_total - self.__budget_remaining

    @property
    def history(self) -> tuple[ActionRecord, ...]:
        return tuple(self.__history)

    @property
    def scope(self) -> tuple[str, ...]:
        return self.__scope

    @property
    def state(self) -> DiscoveryState:
        return DiscoveryState(
            unprobed_addresses=frozenset(self.__unprobed_addresses),
            checked_hosts=frozenset(self.__checked_hosts),
            discovered_hosts=frozenset(self.__discovered_hosts),
            observed_ports=tuple(
                (ip, port, state)
                for (ip, port), state in sorted(self.__observed_ports.items())
            ),
            service_probes=frozenset(self.__service_probes),
            services=tuple(self.__services[key] for key in sorted(self.__services)),
            os_estimates=tuple(sorted(self.__os_estimates.items())),
            confirmed_links=frozenset(self.__confirmed_links),
            completed_actions=frozenset(self.__completed_actions),
        )

    def execute(self, action: ReconAction) -> ActionRecord:
        """Execute one action and charge one budget unit after a valid response."""
        if self.__budget_remaining == 0:
            raise BudgetExceededError("reconnaissance budget is exhausted")

        # A failed/invalid action is not charged and is not recorded.
        observations = tuple(self.__observation_model.execute(action))
        old_hosts = set(self.__discovered_hosts)
        old_services = set(self.__services)
        self.__apply(observations)
        self.__budget_remaining -= 1
        self.__completed_actions.add(action)

        new_hosts = tuple(sorted(self.__discovered_hosts - old_hosts))
        new_services = tuple(
            self.__services[key]
            for key in sorted(set(self.__services) - old_services)
        )
        record = ActionRecord(
            sequence=len(self.__history) + 1,
            timestamp=datetime.now(timezone.utc),
            action=action,
            observations=observations,
            newly_discovered_hosts=new_hosts,
            newly_discovered_services=new_services,
            budget_remaining=self.__budget_remaining,
        )
        self.__history.append(record)
        return record

    def run(
        self,
        strategy: DiscoveryStrategy,
        max_actions: int | None = None,
    ) -> tuple[ActionRecord, ...]:
        """Run a baseline strategy until it finishes or reaches a bound."""
        if max_actions is not None and (
            isinstance(max_actions, bool) or not isinstance(max_actions, int) or max_actions < 0
        ):
            raise ValueError("max_actions must be a non-negative integer or None")
        start = len(self.__history)
        while self.__budget_remaining and (
            max_actions is None or len(self.__history) - start < max_actions
        ):
            action = strategy.next_action(self.__scope, self.state)
            if action is None:
                break
            self.execute(action)
        return tuple(self.__history[start:])

    def __apply(self, observations: tuple[Observation, ...]) -> None:
        for observation in observations:
            if observation.kind is ObservationKind.HOST:
                self.__checked_hosts.add(observation.ip)
                self.__unprobed_addresses.discard(observation.ip)
                if observation.responded is True:
                    self.__discovered_hosts.add(observation.ip)
            elif observation.kind in (ObservationKind.PORT, ObservationKind.SERVICE) and observation.port is not None:
                if observation.port_state is not None:
                    self.__observed_ports[(observation.ip, observation.port)] = observation.port_state
                    if observation.port_state in (PortState.OPEN, PortState.CLOSED):
                        self.__discovered_hosts.add(observation.ip)
                if observation.kind is ObservationKind.SERVICE:
                    self.__service_probes.add((observation.ip, observation.port))
                    if observation.service_name is not None:
                        self.__services[(observation.ip, observation.port)] = observation
                    if observation.os_hint is not None:
                        self.__os_estimates[observation.ip] = observation.os_hint
            elif observation.kind is ObservationKind.LINK and observation.peer_ip and observation.relation:
                self.__confirmed_links.add(
                    (observation.ip, observation.peer_ip, observation.relation)
                )


def addresses_in_scope(scope: tuple[str, ...]) -> tuple[str, ...]:
    """Enumerate usable addresses in the explicitly authorised CIDRs."""
    return tuple(
        sorted(
            str(address)
            for cidr in scope
            for address in ipaddress.ip_network(cidr, strict=True).hosts()
        )
    )


def _action_candidates(state: DiscoveryState) -> tuple[ReconAction, ...]:
    candidates: list[ReconAction] = []
    for ip in sorted(state.unprobed_addresses):
        candidates.append(ReconAction(ActionType.HOST_DISCOVERY, ip))
    for ip in sorted(state.discovered_hosts):
        scan = ReconAction(ActionType.PORT_SCAN, ip)
        if scan not in state.completed_actions:
            candidates.append(scan)
    for ip, port, port_state in state.observed_ports:
        action = ReconAction(ActionType.SERVICE_ID, ip, port)
        if port_state is PortState.OPEN and (ip, port) not in state.service_probes:
            candidates.append(action)
    return tuple(candidates)


class FixedOrderStrategy:
    """Discover addresses, then scan responsive hosts, then identify services."""

    def next_action(self, scope: tuple[str, ...], state: DiscoveryState) -> ReconAction | None:
        candidates = _action_candidates(state)
        return candidates[0] if candidates else None


class RandomDiscoveryStrategy:
    """Choose uniformly from currently eligible, non-repeated actions."""

    def __init__(self, seed: int = 0) -> None:
        import random

        self.__rng = random.Random(seed)

    def next_action(self, scope: tuple[str, ...], state: DiscoveryState) -> ReconAction | None:
        candidates = _action_candidates(state)
        return self.__rng.choice(candidates) if candidates else None
