"""SSRF guard and shared policy.

Every outbound connection goes through resolve_target(). The policy is:

* refuse targets that resolve to anything that is not a public unicast address
  (loopback, RFC 1918, link-local incl. the 169.254.169.254 cloud metadata
  endpoint, CGNAT, multicast, reserved, unspecified), unless the operator
  started the server with --allow-private;
* check EVERY address the name resolves to, and hand the checked address back
  so the caller connects to it directly (no second lookup an attacker could
  answer differently: DNS rebinding);
* the same check runs again on every redirect hop.
"""

from __future__ import annotations

import ipaddress
import socket
from dataclasses import dataclass


class NetcheckError(Exception):
    """An expected failure whose message is safe and useful to show the agent."""


class TargetRefused(NetcheckError):
    pass


@dataclass(frozen=True)
class Policy:
    allow_private: bool = False
    # Extra CA bundle to trust instead of the system store. Never exposed to
    # the agent or the command line: it exists so tests can use local CAs.
    cafile: str | None = None
    connect_timeout: float = 5.0
    total_timeout: float = 30.0
    max_redirects: int = 10
    max_body_bytes: int = 1_048_576
    max_ports: int = 20


_METADATA = {
    ipaddress.ip_address("169.254.169.254"),
    ipaddress.ip_address("fd00:ec2::254"),
    ipaddress.ip_address("100.100.100.200"),
}


def forbidden_reason(addr: str) -> str | None:
    """Why this address may not be contacted, or None if it is a public unicast address."""
    ip = ipaddress.ip_address(addr.split("%", 1)[0])
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    if ip in _METADATA:
        return "cloud metadata endpoint"
    if ip.is_loopback:
        return "loopback address"
    if ip.is_link_local:
        return "link-local address"
    if ip.is_multicast:
        return "multicast address"
    if ip.is_unspecified:
        return "unspecified address"
    if ip.is_private:
        return "private (RFC 1918 / ULA) address"
    if not ip.is_global:
        return "non-public address (CGNAT, reserved or documentation range)"
    return None


def check_ip(addr: str, policy: Policy, what: str = "target") -> None:
    reason = forbidden_reason(addr)
    if reason and not policy.allow_private:
        raise TargetRefused(
            f"Refusing to contact {what} {addr}: it is a {reason}. netcheck-mcp only "
            "talks to public internet hosts by default (SSRF protection). The operator "
            "can start the server with --allow-private to lift this."
        )


def resolve_target(host: str, port: int, policy: Policy) -> list[str]:
    """Resolve and vet a host. Returns the vetted addresses (IPv4 first)."""
    host = host.strip()
    if host.startswith("[") and host.endswith("]"):
        host = host[1:-1]
    if not host:
        raise NetcheckError("Empty host name.")
    if "/" in host:
        raise NetcheckError(
            f"{host!r} looks like a network range or a URL. Give a single host name or IP address."
        )
    addrs: list[str] = []
    try:
        socket.inet_pton(socket.AF_INET6, host.split("%", 1)[0])
        addrs.append(host)
    except OSError:
        pass
    if not addrs:
        try:
            infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
        except socket.gaierror as e:
            raise NetcheckError(f"Cannot resolve {host!r}: {e.strerror or e}") from e
        except UnicodeError as e:
            raise NetcheckError(f"Invalid host name {host!r}: {e}") from e
        for info in infos:
            a = str(info[4][0])
            if a not in addrs:
                addrs.append(a)
    for a in addrs:
        check_ip(a, policy, what=f"{host!r} ->")
    addrs.sort(key=lambda a: ":" in a)
    return addrs
