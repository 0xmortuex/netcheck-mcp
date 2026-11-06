"""netcheck-mcp: TLS, DNS and HTTP health checks for AI agents."""

from __future__ import annotations

import argparse
import functools
import sys
from collections.abc import Callable, Sequence
from typing import Any, TypeVar

from mcp.server.mcpserver import MCPServer
from mcp.server.mcpserver.exceptions import ToolError

from . import __version__
from .dnswire import lookup, make_resolver
from .emaildns import email_dns_check as _email_dns_check
from .guard import NetcheckError, Policy
from .httpcheck import http_check as _http_check
from .ports import port_check as _port_check
from .report import Report
from .secheaders import security_headers as _security_headers
from .tlscheck import tls_check as _tls_check

mcp = MCPServer(
    "netcheck",
    instructions=(
        "Is my site/host healthy and configured right? Tools: tls_check (certificate, chain, "
        "expiry, protocols), dns_lookup (A/AAAA/CNAME/MX/TXT/NS/CAA/SOA with TTLs, NXDOMAIN vs "
        "NODATA), http_check (redirect chain, timings, compression, caching, HSTS), "
        "security_headers (graded, with the exact header to add), port_check (TCP reachability + "
        "banner, max 20 ports), email_dns_check (MX, SPF, DMARC, DKIM, MTA-STS). Results start "
        "with a VERDICT of PASS, WARN or FAIL and each finding includes a concrete fix. Only "
        "check hosts you own or are authorised to test. Private, loopback and cloud-metadata "
        "addresses are refused unless the operator started the server with --allow-private."
    ),
)

POLICY = Policy()

F = TypeVar("F", bound=Callable[..., Any])


def tool(fn: F) -> F:
    """Register fn as a tool; expected failures reach the agent as readable ToolErrors."""

    @functools.wraps(fn)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        try:
            return fn(*args, **kwargs)
        except (NetcheckError, ValueError) as e:
            raise ToolError(str(e)) from e

    mcp.tool()(wrapper)
    return fn


@tool
def tls_check(host: str, port: int = 443) -> str:
    """Check a host's TLS setup and judge it PASS/WARN/FAIL with fixes.

    Reports the leaf certificate (subject, SAN, issuer, validity, days left, key and
    signature algorithms), the chain actually served, whether the name matches, whether the
    chain validates against the system trust store (distinguishing expired, self-signed,
    incomplete chain and untrusted root), which of TLS 1.0/1.1/1.2/1.3 the server offers, and
    the negotiated cipher. Expiry under 30 days is a WARN, under 14 days a FAIL.
    `host` is a name or IP (no scheme); use port for non-443 TLS services (e.g. 465, 993).
    OCSP stapling cannot be observed from Python's ssl module, so only the responder URL is reported.
    """
    return _tls_check(host, port, POLICY).render()


@tool
def dns_lookup(name: str, types: str = "A,AAAA", resolver: str = "system") -> str:
    """Look up DNS records with TTLs, following the CNAME chain.

    `types` is a comma-separated list from A, AAAA, CNAME, MX, TXT, NS, CAA, SOA, SRV, PTR.
    `resolver` is 'system' (this machine's configured DNS), 'cloudflare' (1.1.1.1), 'google'
    (8.8.8.8), 'quad9', or an IP address (optionally ip:port) to ask a specific server, which
    is how you compare what different resolvers see. The result says NXDOMAIN (the name does
    not exist) separately from NODATA (the name exists but has no record of that type).
    """
    res = make_resolver(resolver, POLICY)
    wanted = [t.strip().upper() for t in types.replace(" ", ",").split(",") if t.strip()]
    if not wanted:
        raise ValueError("No record types given; try types='A,AAAA' or 'MX,TXT'.")
    if len(wanted) > 10:
        raise ValueError("At most 10 record types per call.")
    rep = Report(f"DNS lookup: {name} via {res.label}")
    lines: list[str] = []
    for t in wanted:
        r = lookup(res, name, t)
        for c in r.cname_chain:
            lines.append(f"{t}: {c.name} CNAME {c.data}  (ttl {c.ttl})")
        if r.status == "NXDOMAIN":
            lines.append(f"{t}: NXDOMAIN - the name {name} does not exist"
                         + (f" (negative-cache ttl {r.negative_ttl}s)" if r.negative_ttl is not None else ""))
            rep.add("FAIL", "dns.nxdomain", f"{name} does not exist (NXDOMAIN).")
        elif r.status == "NODATA":
            lines.append(f"{t}: NODATA - {name} exists but has no {t} record"
                         + (f" (negative-cache ttl {r.negative_ttl}s)" if r.negative_ttl is not None else ""))
            rep.add("INFO", f"dns.nodata_{t.lower()}", f"{name} exists but has no {t} record.")
        elif r.status != "NOERROR":
            lines.append(f"{t}: {r.status}")
            rep.add("FAIL", f"dns.{r.status.lower()}", f"Resolver returned {r.status} for {t} {name}.")
        else:
            for a in r.answers:
                lines.append(f"{t}: {a.name} {a.data}  (ttl {a.ttl})")
            rep.add("PASS", f"dns.ok_{t.lower()}", f"{len(r.answers)} {t} record(s).")
    rep.section("Records", lines)
    return rep.render()


@tool
def http_check(url: str) -> str:
    """Follow a URL through its redirects and time every hop.

    For each hop: status, DNS/connect/TLS/time-to-first-byte/total milliseconds. Then judges the
    final response: status, redirect problems (loops, >3 hops, HTTPS->HTTP downgrade, no HTTPS),
    compression, caching headers, and HSTS. Sends no cookies or credentials; reads at most 1 MiB of
    body; follows at most 10 redirects; gives up after 30 seconds. `url` may omit the scheme (https assumed).
    """
    return _http_check(url, POLICY).render()


@tool
def security_headers(url: str) -> str:
    """Grade a site's security headers (A+ to F) and give the exact header line to add for each gap.

    Covers Strict-Transport-Security, Content-Security-Policy (flags unsafe-inline, unsafe-eval,
    wildcards), clickjacking protection (X-Frame-Options / frame-ancestors), X-Content-Type-Options,
    Referrer-Policy, Permissions-Policy, cookie flags (Secure/HttpOnly/SameSite), version-disclosing
    headers, and cross-origin isolation headers. Follows redirects and grades the final page.
    """
    return _security_headers(url, POLICY).render()


@tool
def port_check(host: str, ports: str = "80,443", timeout_s: float = 3.0) -> str:
    """Check whether specific TCP ports on one host are reachable, and grab any banner.

    `ports` is e.g. '22,80,443' or '8000-8005' (max 20 ports per call; this is a health check, not a
    scanner, and CIDR ranges are refused). Each port is reported open, closed (refused) or filtered
    (no answer, usually a firewall). Open ports are listened to passively for a banner (SSH, SMTP,
    FTP announce themselves); nothing is sent. Warns when databases/RDP/telnet are open to the internet.
    """
    return _port_check(host, ports, POLICY, timeout=timeout_s).render()


@tool
def email_dns_check(domain: str, resolver: str = "system", selectors: str = "") -> str:
    """Audit a domain's email DNS: MX, SPF, DMARC, DKIM and MTA-STS.

    MX targets must resolve and not be CNAMEs. SPF is parsed and expanded through include:/redirect=
    and the 10-DNS-lookup limit and 2-void-lookup limit are counted (exceeding either makes receivers
    return permerror). DMARC reports its policy (none/quarantine/reject), pct and rua. DKIM probes
    common selectors; pass your own as a comma-separated `selectors` (e.g. 'mail2024,s1') since
    selectors are arbitrary. MTA-STS and TLS-RPT presence are reported.
    """
    res = make_resolver(resolver, POLICY)
    extra = [s.strip() for s in selectors.split(",") if s.strip()]
    return _email_dns_check(domain, res, extra).render()


def build_policy(argv: Sequence[str] | None) -> Policy:
    ap = argparse.ArgumentParser(
        prog="netcheck-mcp",
        description="MCP server: TLS, DNS and HTTP health checks. Talks to the network - only test hosts you are authorised to test.",
    )
    ap.add_argument("--allow-private", action="store_true",
                    help="allow loopback, private, link-local and metadata addresses "
                         "(for testing your own internal hosts; disables SSRF protection)")
    ap.add_argument("--version", action="version", version=f"netcheck-mcp {__version__}")
    args = ap.parse_args(argv)
    return Policy(allow_private=args.allow_private)


def main(argv: Sequence[str] | None = None) -> None:
    global POLICY
    POLICY = build_policy(sys.argv[1:] if argv is None else argv)
    mcp.run()


if __name__ == "__main__":
    main()
