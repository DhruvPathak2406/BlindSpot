"""Ground-truth host model and per-type generation profiles."""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

from blindspot.core.models import PortState
from blindspot.simulator.service import Service


class HostType(str, Enum):
    ROUTER = "router"
    WORKSTATION = "workstation"
    WEB_SERVER = "web_server"
    DB_SERVER = "db_server"
    FILE_SERVER = "file_server"
    MAIL_SERVER = "mail_server"
    PRINTER = "printer"
    IOT_DEVICE = "iot_device"


@dataclass
class Host:
    """A simulated host. Only the observation model may read this."""

    ip: str
    hostname: str
    subnet_id: str
    host_type: HostType
    os_name: str
    services: dict[int, Service] = field(default_factory=dict)
    port_states: dict[int, PortState] = field(default_factory=dict)
    responds_to_icmp: bool = True
    default_filtered: bool = False  # unlisted ports are filtered instead of closed

    def state_of(self, port: int) -> PortState:
        """Host-local port state, ignoring any network firewall in between."""
        if port in self.port_states:
            return self.port_states[port]
        return PortState.FILTERED if self.default_filtered else PortState.CLOSED


@dataclass(frozen=True)
class HostProfile:
    hostname_prefix: str
    os_choices: tuple[str, ...]
    core_services: tuple[str, ...]
    optional_services: tuple[str, ...] = ()


HOST_PROFILES: dict[HostType, HostProfile] = {
    HostType.ROUTER: HostProfile("gw", ("Cisco IOS",), ("ssh",), ("telnet", "http")),
    HostType.WORKSTATION: HostProfile(
        "ws", ("Windows 10", "Windows 11", "Ubuntu 22.04"), (), ("rdp", "smb", "ssh")
    ),
    HostType.WEB_SERVER: HostProfile(
        "web", ("Ubuntu 22.04", "Debian 12", "Windows Server 2019"), ("http", "https"), ("ssh", "http-alt")
    ),
    HostType.DB_SERVER: HostProfile(
        "db", ("Ubuntu 22.04", "CentOS 7", "Windows Server 2019"), ("ssh",), ("mysql", "postgresql")
    ),
    HostType.FILE_SERVER: HostProfile(
        "fs", ("Windows Server 2019", "Debian 12"), ("smb",), ("ssh", "ldap", "rdp")
    ),
    HostType.MAIL_SERVER: HostProfile(
        "mail", ("Debian 12", "CentOS 7"), ("smtp",), ("ssh", "https", "dns")
    ),
    HostType.PRINTER: HostProfile("prn", ("Embedded Linux",), ("ipp",), ("http",)),
    HostType.IOT_DEVICE: HostProfile("iot", ("Embedded Linux",), ("mqtt",), ("http", "telnet")),
}


def os_family(os_name: str) -> str:
    """Coarse OS family used for noisy OS hints."""
    if os_name.startswith("Windows"):
        return "Windows"
    if os_name.startswith("Cisco"):
        return "Cisco IOS"
    if os_name.startswith("Embedded"):
        return "Embedded Linux"
    return "Linux"


OS_FAMILIES: tuple[str, ...] = ("Windows", "Linux", "Cisco IOS", "Embedded Linux")
