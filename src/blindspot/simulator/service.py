"""Ground-truth service definitions and the catalogue used by the generator."""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Service:
    """A network service bound to a TCP port on a simulated host."""

    name: str
    port: int
    version: str


# name -> (port, candidate versions)
SERVICE_CATALOG: dict[str, tuple[int, tuple[str, ...]]] = {
    "ssh": (22, ("OpenSSH 8.9", "OpenSSH 7.4", "OpenSSH 9.2")),
    "telnet": (23, ("telnetd 0.17",)),
    "smtp": (25, ("Postfix 3.6", "Exim 4.96")),
    "dns": (53, ("BIND 9.18", "dnsmasq 2.89")),
    "http": (80, ("nginx 1.22", "Apache httpd 2.4.54", "Microsoft IIS 10.0")),
    "ldap": (389, ("OpenLDAP 2.5", "Microsoft AD LDAP")),
    "https": (443, ("nginx 1.22", "Apache httpd 2.4.54", "Microsoft IIS 10.0")),
    "smb": (445, ("Samba 4.15", "Microsoft SMB 3.1")),
    "ipp": (631, ("CUPS 2.4",)),
    "mysql": (3306, ("MySQL 8.0", "MariaDB 10.6")),
    "rdp": (3389, ("Microsoft RDP 10.0",)),
    "postgresql": (5432, ("PostgreSQL 14", "PostgreSQL 15")),
    "http-alt": (8080, ("Jetty 9.4", "Apache Tomcat 9.0")),
    "mqtt": (1883, ("Mosquitto 2.0",)),
}

PORT_TO_SERVICE: dict[int, str] = {port: name for name, (port, _) in SERVICE_CATALOG.items()}


def make_service(name: str, version: str) -> Service:
    """Build a catalogue service with its canonical port."""
    port, _ = SERVICE_CATALOG[name]
    return Service(name=name, port=port, version=version)
