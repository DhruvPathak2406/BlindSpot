"""Agent-visible data types shared by the simulator and discovery layers.

Nothing here references simulator ground truth (hosts, topology, firewalls).
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
from enum import Enum
from typing import Any


class PortState(str, Enum):
    OPEN = "open"
    CLOSED = "closed"
    FILTERED = "filtered"


class ActionType(str, Enum):
    HOST_DISCOVERY = "host_discovery"  # target: IP
    PORT_SCAN = "port_scan"  # target: IP, port optional (default port list)
    SERVICE_ID = "service_id"  # target: IP, port required
    SUBNET_EXPLORE = "subnet_explore"  # target: CIDR


class ObservationKind(str, Enum):
    HOST = "host"
    PORT = "port"
    SERVICE = "service"
    LINK = "link"


@dataclass(frozen=True)
class ReconAction:
    """A single reconnaissance step requested by a strategy."""

    action_type: ActionType
    target: str
    port: int | None = None


@dataclass(frozen=True)
class Observation:
    """One piece of evidence returned to the agent.

    Unused fields stay ``None``. ``responded=False`` means *no response*,
    which is not proof that the host or link does not exist.
    """

    kind: ObservationKind
    action_type: ActionType
    ip: str
    responded: bool | None = None
    port: int | None = None
    port_state: PortState | None = None
    service_name: str | None = None
    service_version: str | None = None
    os_hint: str | None = None
    peer_ip: str | None = None
    relation: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
