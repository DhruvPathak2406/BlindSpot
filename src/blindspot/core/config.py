"""Configuration dataclasses with validation."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

MIN_HOSTS = 10
MAX_HOSTS = 50
MAX_SUBNETS = 8

# Ports probed by an unqualified PORT_SCAN. 631 and 1883 are deliberately left
# out so some services are only found by targeted probes.
DEFAULT_TOP_PORTS: tuple[int, ...] = (
    22, 23, 25, 53, 80, 389, 443, 445, 3306, 3389, 5432, 8080,
)


def _check_rate(name: str, value: float) -> None:
    if not 0.0 <= value <= 1.0:
        raise ValueError(f"{name} must be within [0, 1], got {value}")


@dataclass(frozen=True)
class GeneratorConfig:
    """Parameters for synthetic network generation."""

    seed: int = 42
    num_hosts: int = 25  # total, including one gateway per subnet
    num_subnets: int = 4
    subnet_prefix: int = 26
    hardened_host_rate: float = 0.2  # hosts that filter every unused port
    filtered_service_rate: float = 0.1  # listening services hidden by host firewall
    icmp_silent_rate: float = 0.1  # hosts that never answer ping
    closed_ports_per_host: int = 2

    def __post_init__(self) -> None:
        if not MIN_HOSTS <= self.num_hosts <= MAX_HOSTS:
            raise ValueError(f"num_hosts must be in [{MIN_HOSTS}, {MAX_HOSTS}]")
        if not 2 <= self.num_subnets <= MAX_SUBNETS:
            raise ValueError(f"num_subnets must be in [2, {MAX_SUBNETS}]")
        if self.num_hosts < 2 * self.num_subnets:
            raise ValueError("num_hosts must be at least 2 per subnet")
        if not 24 <= self.subnet_prefix <= 28:
            raise ValueError("subnet_prefix must be in [24, 28]")
        if self.closed_ports_per_host < 0:
            raise ValueError("closed_ports_per_host must be >= 0")
        for name in ("hardened_host_rate", "filtered_service_rate", "icmp_silent_rate"):
            _check_rate(name, getattr(self, name))

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "GeneratorConfig":
        return cls(**data)


@dataclass(frozen=True)
class ObservationConfig:
    """Noise and detail level of what the agent can observe."""

    ping_miss_rate: float = 0.05  # live, reachable host fails to answer
    banner_hide_rate: float = 0.1  # service name found, version withheld
    os_hint_rate: float = 0.7  # chance a service probe yields an OS hint
    os_hint_error_rate: float = 0.1  # chance the OS hint is wrong
    top_ports: tuple[int, ...] = DEFAULT_TOP_PORTS

    def __post_init__(self) -> None:
        for name in ("ping_miss_rate", "banner_hide_rate", "os_hint_rate", "os_hint_error_rate"):
            _check_rate(name, getattr(self, name))
        if not self.top_ports or any(not 1 <= p <= 65535 for p in self.top_ports):
            raise ValueError("top_ports must be non-empty valid port numbers")
