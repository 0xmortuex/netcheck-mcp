"""http_check: follow a URL hop by hop and time every step."""

from __future__ import annotations

import http.client
import socket
import ssl
import time
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlsplit

from . import __version__
from .guard import NetcheckError, Policy, resolve_target
from .report import Report

_REDIRECTS = {301, 302, 303, 307, 308}
_TEXTUAL = ("text/", "application/json", "application/javascript", "application/xml",
            "image/svg+xml", "application/xhtml")


@dataclass
class Hop:
    url: str
    status: int
    reason: str
    headers: list[tuple[str, str]]
    ip: str
    dns_ms: float
    connect_ms: float
    tls_ms: float | None
    ttfb_ms: float
    total_ms: float
    body_bytes: int
    body_truncated: bool
    tls_version: str | None = None
    extra: dict[str, str] = field(default_factory=dict)

    def header(self, name: str) -> str | None:
        vals = self.header_all(name)
        return vals[0] if vals else None

    def header_all(self, name: str) -> list[str]:
        n = name.lower()
        return [v for k, v in self.headers if k.lower() == n]

    @property
    def location(self) -> str | None:
        return self.header("location")


def parse_url(url: str) -> tuple[str, str, int, str]:
    url = url.strip()
    if "://" not in url:
        url = "https://" + url
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https"):
        raise NetcheckError(f"Unsupported URL scheme {parts.scheme!r}: only http and https are allowed.")
    if parts.username or parts.password:
        raise NetcheckError("URLs with embedded credentials (user:pass@host) are refused.")
    if not parts.hostname:
        raise NetcheckError(f"No host in URL {url!r}.")
    try:
        port = parts.port or (443 if parts.scheme == "https" else 80)
    except ValueError as e:
        raise NetcheckError(f"Invalid port in URL {url!r}.") from e
    path = parts.path or "/"
    if parts.query:
        path += "?" + parts.query
    return parts.scheme, parts.hostname, port, path


def fetch_once(url: str, policy: Policy, deadline: float) -> Hop:
    """One request, no redirect following. The connection goes to the vetted IP."""
    scheme, host, port, path = parse_url(url)

    def remaining() -> float:
        left = deadline - time.monotonic()
        if left <= 0:
            raise NetcheckError(f"Gave up after {policy.total_timeout:g}s total (time budget exhausted).")
        return left

    t0 = time.monotonic()
    ip = resolve_target(host, port, policy)[0]
    dns_ms = (time.monotonic() - t0) * 1000

    t1 = time.monotonic()
    try:
        sock = socket.create_connection((ip, port), timeout=min(policy.connect_timeout, remaining()))
    except OSError as e:
        raise NetcheckError(f"Cannot connect to {host}:{port} ({ip}): {e}") from e
    connect_ms = (time.monotonic() - t1) * 1000
    tls_ms: float | None = None
    tls_version = None
    conn: http.client.HTTPConnection | None = None
    try:
        if scheme == "https":
            t2 = time.monotonic()
            ctx = ssl.create_default_context(cafile=policy.cafile)
            try:
                sock.settimeout(min(policy.connect_timeout, remaining()))
                sock = ctx.wrap_socket(sock, server_hostname=host)
            except ssl.SSLCertVerificationError as e:
                raise NetcheckError(
                    f"TLS certificate for {host} did not verify: {e.verify_message}. "
                    f"Run tls_check on {host} for the details."
                ) from e
            except ssl.SSLError as e:
                raise NetcheckError(f"TLS handshake with {host}:{port} failed: {e.reason or e}.") from e
            tls_ms = (time.monotonic() - t2) * 1000
            tls_version = sock.version()
        default_port = 443 if scheme == "https" else 80
        host_header = host if port == default_port else f"{host}:{port}"
        if ":" in host:
            host_header = f"[{host}]" + ("" if port == default_port else f":{port}")
        conn = http.client.HTTPConnection(ip, port)
        conn.sock = sock
        # One socket timeout for everything after connect: http.client closes the socket
        # as soon as a "Connection: close" response is complete, so it cannot be re-armed.
        sock.settimeout(remaining())
        t3 = time.monotonic()
        try:
            conn.putrequest("GET", path, skip_host=True, skip_accept_encoding=True)
            conn.putheader("Host", host_header)
            conn.putheader("User-Agent", f"netcheck-mcp/{__version__}")
            conn.putheader("Accept", "*/*")
            conn.putheader("Accept-Encoding", "gzip, deflate, br")
            conn.putheader("Connection", "close")
            conn.endheaders()
            resp = conn.getresponse()
        except (TimeoutError, socket.timeout) as e:
            raise NetcheckError(f"{host} did not answer the request in time.") from e
        except (OSError, http.client.HTTPException) as e:
            raise NetcheckError(f"HTTP request to {host}:{port} failed: {e}") from e
        ttfb_ms = (time.monotonic() - t3) * 1000
        headers = [(k, v) for k, v in resp.getheaders()]
        total = 0
        truncated = False
        try:
            while True:
                if time.monotonic() > deadline:
                    truncated = True
                    break
                chunk = resp.read(16384)
                if not chunk:
                    break
                total += len(chunk)
                if total >= policy.max_body_bytes:
                    truncated = True
                    break
        except (TimeoutError, socket.timeout):
            truncated = True
        except (OSError, http.client.HTTPException) as e:
            raise NetcheckError(f"Connection to {host} broke while reading the body: {e}") from e
        total_ms = (time.monotonic() - t1) * 1000 + dns_ms
        return Hop(url, resp.status, resp.reason, headers, ip, dns_ms, connect_ms, tls_ms,
                   ttfb_ms, total_ms, total, truncated, tls_version)
    finally:
        if conn is not None:
            conn.close()
        sock.close()


def follow(url: str, policy: Policy) -> tuple[list[Hop], str | None]:
    """Follow redirects. Returns (hops, problem) where problem is e.g. a loop or too many hops."""
    deadline = time.monotonic() + policy.total_timeout
    hops: list[Hop] = []
    seen: set[str] = set()
    current = url if "://" in url else "https://" + url.strip()
    while True:
        hop = fetch_once(current, policy, deadline)
        hops.append(hop)
        seen.add(current)
        if hop.status in _REDIRECTS and hop.location:
            nxt = urljoin(current, hop.location)
            if nxt in seen:
                return hops, f"redirect loop: {nxt} was already visited"
            if len(hops) > policy.max_redirects:
                return hops, f"more than {policy.max_redirects} redirects (stopped following)"
            current = nxt
            continue
        return hops, None


def _is_textual(ctype: str | None) -> bool:
    return bool(ctype) and any((ctype or "").lower().startswith(t) for t in _TEXTUAL)


def http_check(url: str, policy: Policy) -> Report:
    hops, problem = follow(url, policy)
    final = hops[-1]
    rep = Report(f"HTTP check: {url}")
    lines = []
    for i, h in enumerate(hops):
        tls = f" tls={h.tls_ms:.0f}ms({h.tls_version})" if h.tls_ms is not None else ""
        nxt = f" -> {urljoin(h.url, h.location)}" if h.status in _REDIRECTS and h.location else ""
        lines.append(
            f"{i + 1}. {h.status} {h.reason}  {h.url}{nxt}\n"
            f"       dns={h.dns_ms:.0f}ms connect={h.connect_ms:.0f}ms{tls} "
            f"ttfb={h.ttfb_ms:.0f}ms total={h.total_ms:.0f}ms ({h.ip})"
        )
    rep.section("Request chain", lines)
    rep.data.update(
        final_url=final.url, final_status=final.status, hops=len(hops),
        ttfb_ms=round(final.ttfb_ms), total_ms=round(final.total_ms),
    )

    if problem:
        rep.add("FAIL", "http.redirect_problem", f"Redirect problem: {problem}.",
                "Fix the redirect rules so the chain ends at a page that answers 200.")
    if final.status >= 500:
        rep.add("FAIL", "http.server_error", f"Final response is {final.status} {final.reason}.")
    elif final.status >= 400:
        rep.add("FAIL", "http.client_error", f"Final response is {final.status} {final.reason}.",
                "Check the URL and the server's routing/permissions.")
    elif final.status in _REDIRECTS and not problem:
        rep.add("WARN", "http.redirect_no_location", f"Status {final.status} but no Location header.")
    else:
        rep.add("PASS", "http.ok", f"Final response is {final.status} {final.reason} at {final.url}.")

    redirects = len(hops) - 1
    if redirects > 3:
        rep.add("WARN", "http.long_chain", f"{redirects} redirects before the final page; each adds a round trip.",
                "Redirect straight to the canonical URL in one hop.")
    for a, b in zip(hops, hops[1:], strict=False):
        if a.url.startswith("https://") and b.url.startswith("http://"):
            rep.add("FAIL", "http.downgrade", f"Redirect from {a.url} downgrades to plain HTTP ({b.url}).",
                    "Never redirect from HTTPS to HTTP.")
    if hops[0].url.startswith("http://") and final.url.startswith("https://"):
        rep.add("PASS", "http.https_upgrade", "Plain HTTP is redirected to HTTPS.")
    elif hops[0].url.startswith("http://") and final.url.startswith("http://") and not problem:
        rep.add("WARN", "http.no_https", "Site is served over plain HTTP only.",
                "Serve the site over HTTPS and redirect HTTP to it.")
    slow = [h for h in hops if h.ttfb_ms > 1000]
    if slow:
        rep.add("WARN", "http.slow_ttfb",
                f"Time to first byte was over 1s on {len(slow)} hop(s) (slowest {max(h.ttfb_ms for h in slow):.0f}ms).",
                "Check server load, backend latency, and caching.")

    # Compression
    ctype = final.header("content-type")
    enc = final.header("content-encoding")
    clen = final.header("content-length")
    if enc:
        rep.add("PASS", "http.compressed", f"Response is compressed ({enc}).")
    elif _is_textual(ctype) and final.status < 300:
        size = int(clen) if clen and clen.isdigit() else final.body_bytes
        if size > 1024:
            rep.add("WARN", "http.no_compression",
                    f"Text response ({ctype}, {size} bytes) is not compressed although the client offered gzip/br.",
                    "Enable gzip or brotli for text types (nginx: gzip on; gzip_types ...).")
        else:
            rep.add("INFO", "http.small_body", f"Response is small ({size} bytes); compression not needed.")

    # Caching
    cc = final.header("cache-control")
    cache_hdrs = {k: final.header(k) for k in ("cache-control", "etag", "last-modified", "expires", "age")}
    present = {k: v for k, v in cache_hdrs.items() if v}
    if not present:
        rep.add("WARN", "http.no_cache_headers", "No caching headers (Cache-Control, ETag, Last-Modified, Expires).",
                "Add Cache-Control (e.g. 'public, max-age=300') and an ETag or Last-Modified so clients can revalidate.")
    elif cc and "no-store" in cc.lower():
        rep.add("INFO", "http.no_store", "Cache-Control: no-store (responses are never cached).")
    else:
        rep.add("PASS", "http.cache_headers", "Caching headers: " + "; ".join(f"{k}={v}" for k, v in present.items()))

    # HSTS (only meaningful over HTTPS)
    if final.url.startswith("https://"):
        hsts = final.header("strict-transport-security")
        if hsts:
            rep.add("PASS", "http.hsts", f"HSTS present: {hsts}")
        else:
            rep.add("WARN", "http.no_hsts", "No Strict-Transport-Security header on the HTTPS response.",
                    "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains")

    size_note = f"{final.body_bytes} bytes read" + (" (truncated at the size cap)" if final.body_truncated else "")
    rep.section("Final response", [
        f"url: {final.url}",
        f"status: {final.status} {final.reason}",
        f"content-type: {ctype or '-'}; content-encoding: {enc or 'none'}; {size_note}",
        f"ttfb {final.ttfb_ms:.0f}ms, total {final.total_ms:.0f}ms",
    ])
    return rep
