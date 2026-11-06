"""A DNS stub resolver written against RFC 1035, stdlib only.

Builds the query bytes, sends them over UDP (falling back to TCP when the
answer is truncated), and decodes the reply including name compression.
"""

from __future__ import annotations

import ipaddress
import os
import random
import socket
import struct
import sys
import time
from dataclasses import dataclass, field

from .guard import NetcheckError, Policy, check_ip

TYPES = {
    "A": 1, "NS": 2, "CNAME": 5, "SOA": 6, "PTR": 12, "MX": 15, "TXT": 16,
    "AAAA": 28, "SRV": 33, "OPT": 41, "CAA": 257,
}
TYPE_NAMES = {v: k for k, v in TYPES.items()}
RCODES = {0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN", 4: "NOTIMP", 5: "REFUSED"}
WELL_KNOWN = {
    "cloudflare": "1.1.1.1", "google": "8.8.8.8", "quad9": "9.9.9.9",
}


@dataclass
class Record:
    name: str
    rtype: str
    ttl: int
    data: str


@dataclass
class Message:
    id: int
    flags: int
    rcode: int
    question: tuple[str, int]
    answers: list[Record] = field(default_factory=list)
    authority: list[Record] = field(default_factory=list)
    additional: list[Record] = field(default_factory=list)

    @property
    def truncated(self) -> bool:
        return bool(self.flags & 0x0200)

    @property
    def authenticated(self) -> bool:
        return bool(self.flags & 0x0020)


def encode_name(name: str) -> bytes:
    name = name.rstrip(".")
    out = b""
    if name:
        for label in name.split("."):
            raw = label.encode("idna") if not label.isascii() else label.encode("ascii")
            if not 1 <= len(raw) <= 63:
                raise NetcheckError(f"Invalid DNS label {label!r} in {name!r} (1-63 bytes).")
            out += bytes([len(raw)]) + raw
    return out + b"\x00"


def build_query(name: str, qtype: int, qid: int) -> bytes:
    header = struct.pack(">HHHHHH", qid, 0x0100, 1, 0, 0, 1)  # RD set, one EDNS0 OPT record
    question = encode_name(name) + struct.pack(">HH", qtype, 1)
    opt = b"\x00" + struct.pack(">HHIH", TYPES["OPT"], 1232, 0, 0)
    return header + question + opt


def decode_name(msg: bytes, pos: int) -> tuple[str, int]:
    """Decode a possibly-compressed name at pos. Returns (name, position after it)."""
    labels: list[str] = []
    end = -1
    jumps = 0
    while True:
        if pos >= len(msg):
            raise NetcheckError("Malformed DNS reply (name runs past the end).")
        n = msg[pos]
        if n & 0xC0 == 0xC0:
            if pos + 1 >= len(msg):
                raise NetcheckError("Malformed DNS reply (truncated pointer).")
            ptr = ((n & 0x3F) << 8) | msg[pos + 1]
            if end < 0:
                end = pos + 2
            jumps += 1
            if jumps > 50 or ptr >= len(msg):
                raise NetcheckError("Malformed DNS reply (compression loop).")
            pos = ptr
        elif n == 0:
            if end < 0:
                end = pos + 1
            return ".".join(labels), end
        else:
            if n > 63 or pos + 1 + n > len(msg):
                raise NetcheckError("Malformed DNS reply (bad label).")
            labels.append(msg[pos + 1:pos + 1 + n].decode("ascii", "replace"))
            pos += 1 + n


def _rdata(msg: bytes, rtype: int, start: int, end: int) -> str:
    raw = msg[start:end]
    if rtype == TYPES["A"] and len(raw) == 4:
        return str(ipaddress.IPv4Address(raw))
    if rtype == TYPES["AAAA"] and len(raw) == 16:
        return str(ipaddress.IPv6Address(raw))
    if rtype in (TYPES["NS"], TYPES["CNAME"], TYPES["PTR"]):
        return decode_name(msg, start)[0]
    if rtype == TYPES["MX"]:
        pref = struct.unpack(">H", raw[:2])[0]
        return f"{pref} {decode_name(msg, start + 2)[0]}"
    if rtype == TYPES["TXT"]:
        parts = []
        i = 0
        while i < len(raw):
            ln = raw[i]
            parts.append(raw[i + 1:i + 1 + ln].decode("utf-8", "replace"))
            i += 1 + ln
        return "".join(parts)  # one TXT record = its strings concatenated (RFC 7208 3.3)
    if rtype == TYPES["SOA"]:
        mname, p = decode_name(msg, start)
        rname, p = decode_name(msg, p)
        serial, refresh, retry, expire, minimum = struct.unpack(">IIIII", msg[p:p + 20])
        return f"{mname} {rname} {serial} {refresh} {retry} {expire} {minimum}"
    if rtype == TYPES["SRV"]:
        prio, weight, port = struct.unpack(">HHH", raw[:6])
        return f"{prio} {weight} {port} {decode_name(msg, start + 6)[0]}"
    if rtype == TYPES["CAA"]:
        flags, tl = raw[0], raw[1]
        tag = raw[2:2 + tl].decode("ascii", "replace")
        return f"{flags} {tag} \"{raw[2 + tl:].decode('utf-8', 'replace')}\""
    return raw.hex()


def parse_message(msg: bytes) -> Message:
    if len(msg) < 12:
        raise NetcheckError("Malformed DNS reply (shorter than a header).")
    qid, flags, qd, an, ns, ar = struct.unpack(">HHHHHH", msg[:12])
    pos = 12
    question = ("", 0)
    try:
        for _ in range(qd):
            qname, pos = decode_name(msg, pos)
            qtype = struct.unpack(">H", msg[pos:pos + 2])[0]
            question = (qname, qtype)
            pos += 4
        out = Message(qid, flags, flags & 0xF, question)
        for count, bucket in ((an, out.answers), (ns, out.authority), (ar, out.additional)):
            for _ in range(count):
                name, pos = decode_name(msg, pos)
                rtype, _cls, ttl, rdlen = struct.unpack(">HHIH", msg[pos:pos + 10])
                pos += 10
                if pos + rdlen > len(msg):
                    raise NetcheckError("Malformed DNS reply (record overruns message).")
                if rtype != TYPES["OPT"]:
                    bucket.append(
                        Record(name, TYPE_NAMES.get(rtype, f"TYPE{rtype}"), ttl,
                               _rdata(msg, rtype, pos, pos + rdlen))
                    )
                pos += rdlen
    except struct.error as e:
        raise NetcheckError("Malformed DNS reply (truncated).") from e
    return out


# --- transport -------------------------------------------------------------

def _recv_exact(sock: socket.socket, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise NetcheckError("DNS server closed the TCP connection early.")
        buf += chunk
    return buf


def _udp_exchange(wire: bytes, qid: int, server: str, port: int, family: int, timeout: float) -> bytes:
    expected = ipaddress.ip_address(server)
    with socket.socket(family, socket.SOCK_DGRAM) as s:
        s.sendto(wire, (server, port))
        deadline = time.monotonic() + timeout
        while True:
            s.settimeout(max(0.05, deadline - time.monotonic()))
            data, addr = s.recvfrom(4096)
            if ipaddress.ip_address(addr[0].split("%", 1)[0]) != expected:
                continue  # not from the server we asked
            if len(data) >= 2 and struct.unpack(">H", data[:2])[0] == qid:
                return data


def query(name: str, rtype: str, server: str, port: int = 53, timeout: float = 4.0) -> Message:
    qtype = TYPES.get(rtype.upper())
    if qtype is None:
        raise NetcheckError(f"Unsupported record type {rtype!r}. Supported: {', '.join(sorted(TYPES))}.")
    qid = random.SystemRandom().randrange(65536)
    wire = build_query(name, qtype, qid)
    family = socket.AF_INET6 if ":" in server else socket.AF_INET
    where = f"{server}:{port}"
    try:
        data = b""
        for attempt in (1, 2):  # one retry: UDP datagrams get lost, and resolvers retry too
            try:
                data = _udp_exchange(wire, qid, server, port, family, timeout)
                break
            except (TimeoutError, socket.timeout):
                if attempt == 2:
                    raise
        reply = parse_message(data)
        if reply.truncated:
            with socket.socket(family, socket.SOCK_STREAM) as t:
                t.settimeout(timeout)
                t.connect((server, port))
                t.sendall(struct.pack(">H", len(wire)) + wire)
                ln = struct.unpack(">H", _recv_exact(t, 2))[0]
                reply = parse_message(_recv_exact(t, ln))
    except (TimeoutError, socket.timeout) as e:
        raise NetcheckError(f"DNS server {where} did not answer ({timeout:g}s, 2 attempts).") from e
    except OSError as e:
        raise NetcheckError(f"Cannot query DNS server {where}: {e}") from e
    if reply.id != qid:
        raise NetcheckError(f"DNS server {where} replied with a mismatched transaction id.")
    return reply


# --- resolver selection ----------------------------------------------------

def _split_hostport(spec: str) -> tuple[str, int]:
    if spec.startswith("["):
        host, _, rest = spec[1:].partition("]")
        return host, int(rest[1:]) if rest.startswith(":") else 53
    if spec.count(":") == 1:
        host, _, p = spec.partition(":")
        return host, int(p)
    return spec, 53


def system_nameservers() -> list[str]:
    found: list[str] = []
    if sys.platform == "win32":
        import winreg

        base = r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces"
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, base) as k:
                i = 0
                while True:
                    try:
                        sub = winreg.EnumKey(k, i)
                    except OSError:
                        break
                    i += 1
                    with winreg.OpenKey(k, sub) as sk:
                        for value in ("NameServer", "DhcpNameServer"):
                            try:
                                text = str(winreg.QueryValueEx(sk, value)[0])
                            except OSError:
                                continue
                            for tok in text.replace(",", " ").split():
                                if tok not in found:
                                    found.append(tok)
        except OSError as e:
            raise NetcheckError(f"Cannot read the system DNS settings: {e}") from e
    elif os.path.exists("/etc/resolv.conf"):
        with open("/etc/resolv.conf", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                parts = line.split()
                if len(parts) >= 2 and parts[0] == "nameserver" and parts[1] not in found:
                    found.append(parts[1])
    return found


@dataclass
class Resolver:
    """Where to send queries: one or more (ip, port) candidates tried in order."""
    label: str
    servers: list[tuple[str, int]]
    timeout: float = 4.0

    def ask(self, name: str, rtype: str) -> Message:
        last: NetcheckError | None = None
        for host, port in self.servers:
            try:
                return query(name, rtype, host, port, self.timeout)
            except NetcheckError as e:
                last = e
                if self.label != "system":
                    raise
        assert last is not None
        raise last


def make_resolver(spec: str | None, policy: Policy) -> Resolver:
    spec = (spec or "system").strip()
    if spec.lower() == "system":
        ns = system_nameservers()
        if not ns:
            raise NetcheckError(
                "Could not find a system DNS server. Pass resolver='1.1.1.1' (or 'google', '8.8.8.8')."
            )
        # The system resolver was configured by the machine's owner, not supplied by the agent.
        return Resolver("system", [(h, 53) for h in ns])
    spec = WELL_KNOWN.get(spec.lower(), spec)
    try:
        host, port = _split_hostport(spec)
        ipaddress.ip_address(host)
    except ValueError as e:
        raise NetcheckError(
            f"Invalid resolver {spec!r}. Use 'system', 'cloudflare', 'google', or an IP address "
            "(optionally ip:port)."
        ) from e
    check_ip(host, policy, what="DNS resolver")
    return Resolver(spec, [(host, port)])


# --- lookup ----------------------------------------------------------------

@dataclass
class LookupResult:
    name: str
    rtype: str
    status: str  # NOERROR | NXDOMAIN | NODATA | SERVFAIL | REFUSED | ...
    answers: list[Record]
    cname_chain: list[Record]
    negative_ttl: int | None = None
    authenticated: bool = False


def lookup(resolver: Resolver, name: str, rtype: str) -> LookupResult:
    reply = resolver.ask(name, rtype)
    rtype = rtype.upper()
    status = RCODES.get(reply.rcode, f"RCODE{reply.rcode}")
    # Follow the CNAME chain inside the answer section.
    chain: list[Record] = []
    cur = name.rstrip(".").lower()
    seen = {cur}
    while True:
        nxt = [r for r in reply.answers if r.rtype == "CNAME" and r.name.rstrip(".").lower() == cur]
        if not nxt or rtype == "CNAME":
            break
        chain.append(nxt[0])
        cur = nxt[0].data.rstrip(".").lower()
        if cur in seen:
            raise NetcheckError(f"CNAME loop while resolving {name}.")
        seen.add(cur)
    if rtype == "CNAME":
        final = [r for r in reply.answers if r.rtype == "CNAME"]
        chain = []
    else:
        final = [r for r in reply.answers if r.rtype == rtype and r.name.rstrip(".").lower() == cur]
    neg = None
    for r in reply.authority:
        if r.rtype == "SOA":
            neg = min(r.ttl, int(r.data.split()[-1]))
    if reply.rcode == 0 and not final:
        status = "NODATA"
    return LookupResult(name, rtype, status, final, chain, neg if not final else None,
                        reply.authenticated)
