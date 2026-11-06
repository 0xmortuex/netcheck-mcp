"""port_check: TCP reachability plus a passive banner grab, for a handful of ports."""

from __future__ import annotations

import socket
import time
from concurrent.futures import ThreadPoolExecutor

from .guard import NetcheckError, Policy, resolve_target
from .report import Report

SERVICES = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 80: "http", 110: "pop3",
    143: "imap", 443: "https", 465: "smtps", 587: "submission", 993: "imaps", 995: "pop3s",
    1433: "mssql", 3306: "mysql", 3389: "rdp", 5432: "postgres", 6379: "redis",
    8080: "http-alt", 8443: "https-alt", 27017: "mongodb",
}
# Ports that are risky to leave open to the whole internet.
_EXPOSED = {23: "telnet", 3389: "RDP", 5432: "PostgreSQL", 3306: "MySQL", 6379: "Redis",
            27017: "MongoDB", 1433: "SQL Server", 21: "FTP"}


def parse_ports(spec: list[int] | str | int, limit: int) -> list[int]:
    """Accept [22, 80], "22,80,8000-8005" or 443. At most `limit` distinct ports."""
    if isinstance(spec, int):
        items: list[str] = [str(spec)]
    elif isinstance(spec, str):
        items = [p for p in spec.replace(" ", ",").split(",") if p]
    else:
        items = [str(p) for p in spec]
    ports: list[int] = []
    for item in items:
        try:
            if "-" in item:
                lo_s, hi_s = item.split("-", 1)
                lo, hi = int(lo_s), int(hi_s)
                if hi < lo:
                    raise NetcheckError(f"Port range {item!r} is backwards.")
                if hi - lo + 1 > limit:
                    raise NetcheckError(
                        f"Port range {item!r} has {hi - lo + 1} ports; at most {limit} per call "
                        "(netcheck-mcp is not a port scanner)."
                    )
                rng = list(range(lo, hi + 1))
            else:
                rng = [int(item)]
        except ValueError as e:
            raise NetcheckError(f"Invalid port {item!r}: use numbers, e.g. '22,80,443' or '8000-8005'.") from e
        for p in rng:
            if not 1 <= p <= 65535:
                raise NetcheckError(f"Port {p} is out of range 1-65535.")
            if p not in ports:
                ports.append(p)
    if not ports:
        raise NetcheckError("No ports given.")
    if len(ports) > limit:
        raise NetcheckError(f"{len(ports)} ports requested; at most {limit} per call.")
    return ports


def _clean(raw: bytes) -> str:
    text = raw.decode("utf-8", "replace")
    return "".join(c if c.isprintable() or c in "\r\n\t" else "." for c in text).strip()[:200]


def _probe(ip: str, port: int, timeout: float, banner_wait: float) -> dict[str, object]:
    t0 = time.monotonic()
    try:
        s = socket.create_connection((ip, port), timeout=timeout)
    except (TimeoutError, socket.timeout):
        return {"port": port, "state": "filtered", "detail": f"no answer within {timeout:g}s (firewall drop?)"}
    except ConnectionRefusedError:
        return {"port": port, "state": "closed", "detail": "connection refused (nothing listening)"}
    except OSError as e:
        return {"port": port, "state": "error", "detail": str(e)}
    ms = (time.monotonic() - t0) * 1000
    banner = ""
    with s:
        s.settimeout(banner_wait)
        try:
            banner = _clean(s.recv(512))
        except (TimeoutError, socket.timeout):
            banner = ""
        except OSError:
            banner = ""
    return {"port": port, "state": "open", "ms": round(ms), "banner": banner}


def port_check(host: str, ports: list[int] | str | int, policy: Policy,
               timeout: float = 3.0, banner_wait: float = 1.5) -> Report:
    plist = parse_ports(ports, policy.max_ports)
    if not 0.2 <= timeout <= 10:
        raise NetcheckError("timeout must be between 0.2 and 10 seconds.")
    ip = resolve_target(host, plist[0], policy)[0]
    rep = Report(f"Port check: {host} ({ip})")
    with ThreadPoolExecutor(max_workers=5) as pool:
        results = list(pool.map(lambda p: _probe(ip, p, timeout, banner_wait), plist))
    lines = []
    for r in results:
        p = int(str(r["port"]))
        svc = SERVICES.get(p, "?")
        if r["state"] == "open":
            b = r["banner"]
            lines.append(f"{p}/tcp ({svc}) OPEN in {r['ms']}ms; banner: {b!r}" if b
                         else f"{p}/tcp ({svc}) OPEN in {r['ms']}ms; no banner (server speaks only after the client does)")
            if p in _EXPOSED:
                rep.add("WARN", f"port.exposed_{p}", f"{_EXPOSED[p]} port {p} is reachable from here.",
                        "Unless this is intended, restrict it with a firewall/security group to known addresses.")
            else:
                rep.add("PASS", f"port.open_{p}", f"Port {p} ({svc}) is open.")
        else:
            lines.append(f"{p}/tcp ({svc}) {str(r['state']).upper()}: {r['detail']}")
            rep.add("INFO", f"port.{r['state']}_{p}", f"Port {p} ({svc}) is {r['state']}: {r['detail']}.")
    rep.data["results"] = results
    rep.section("Results", lines)
    return rep
