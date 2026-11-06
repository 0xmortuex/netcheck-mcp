import gzip
import socket
import time
from dataclasses import replace

import lab
import pytest
from lab import Route
from netcheck_mcp.guard import NetcheckError, Policy, TargetRefused
from netcheck_mcp.httpcheck import follow, http_check


def test_redirect_chain_and_timings(web: lab.WebLab, policy: Policy) -> None:
    web.routes["/a"] = Route(301, [("Location", "/b")])
    web.routes["/b"] = Route(302, [("Location", web.url("/c"))])
    web.routes["/c"] = Route(200, [("Content-Type", "text/html"), ("Cache-Control", "max-age=60"), ("ETag", '"x"')],
                             b"<html>ok</html>")
    rep = http_check(web.url("/a"), policy)
    assert rep.data["hops"] == 3 and rep.data["final_status"] == 200
    assert rep.data["final_url"].endswith("/c")
    text = rep.render()
    assert "1. 301" in text and "2. 302" in text and "3. 200" in text
    assert "ttfb=" in text and "dns=" in text and "connect=" in text
    assert "http.ok" in rep.codes("PASS") and "http.cache_headers" in rep.codes("PASS")
    assert "http.no_https" in rep.codes("WARN")  # plain HTTP all the way


def test_slow_first_byte_is_measured(web: lab.WebLab, policy: Policy) -> None:
    web.routes["/slow"] = Route(200, [("Content-Type", "text/plain")], b"hi", delay=0.5)
    hops, _ = follow(web.url("/slow"), policy)
    assert 450 <= hops[0].ttfb_ms < 3000


def test_redirect_loop_detected(web: lab.WebLab, policy: Policy) -> None:
    web.routes["/x"] = Route(302, [("Location", "/y")])
    web.routes["/y"] = Route(302, [("Location", "/x")])
    rep = http_check(web.url("/x"), policy)
    assert "http.redirect_problem" in rep.codes("FAIL") and "loop" in rep.render()


def test_redirect_cap(web: lab.WebLab, policy: Policy) -> None:
    for i in range(10):
        web.routes[f"/r{i}"] = Route(302, [("Location", f"/r{i + 1}")])
    rep = http_check(web.url("/r0"), replace(policy, max_redirects=4))
    assert rep.data["hops"] == 5
    assert "more than 4 redirects" in rep.render()


def test_errors_and_missing_headers(web: lab.WebLab, policy: Policy) -> None:
    rep = http_check(web.url("/nothing"), policy)
    assert "http.client_error" in rep.codes("FAIL") and rep.verdict == "FAIL"
    assert "http.no_cache_headers" in rep.codes("WARN")


def test_compression_detected_and_missing(web: lab.WebLab, policy: Policy) -> None:
    big = b"<p>" + b"hello world " * 400 + b"</p>"
    web.routes["/plain"] = Route(200, [("Content-Type", "text/html")], big)
    web.routes["/gz"] = Route(200, [("Content-Type", "text/html"), ("Content-Encoding", "gzip")], gzip.compress(big))
    assert "http.no_compression" in http_check(web.url("/plain"), policy).codes("WARN")
    assert "http.compressed" in http_check(web.url("/gz"), policy).codes("PASS")


def test_body_size_cap(web: lab.WebLab, policy: Policy) -> None:
    web.routes["/huge"] = Route(200, [("Content-Type", "application/octet-stream")], b"z" * 500_000)
    hops, _ = follow(web.url("/huge"), replace(policy, max_body_bytes=100_000))
    assert hops[0].body_truncated and hops[0].body_bytes < 500_000


def test_total_time_budget(web: lab.WebLab, policy: Policy) -> None:
    web.routes["/hang"] = Route(200, [], b"x", delay=3.0)
    t0 = time.monotonic()
    with pytest.raises(NetcheckError, match="did not answer|time budget"):
        http_check(web.url("/hang"), replace(policy, total_timeout=0.6))
    assert time.monotonic() - t0 < 2.5


def test_no_credentials_or_cookies_forwarded(web: lab.WebLab, policy: Policy) -> None:
    web.routes["/"] = Route(200, [("Set-Cookie", "sid=1"), ("Content-Type", "text/plain")], b"hi")
    http_check(web.url("/"), policy)
    sent = {k.lower() for k in web.requests[0]["headers"]}
    assert sent <= {"host", "user-agent", "accept", "accept-encoding", "connection"}
    assert web.requests[0]["headers"]["User-Agent"].startswith("netcheck-mcp/")


def test_https_hsts_and_tls_details(tls_server, pki: lab.Pki, policy: Policy) -> None:  # type: ignore[no-untyped-def]
    srv = tls_server(pki.leaf())
    srv.routes["/"] = Route(200, [("Strict-Transport-Security", "max-age=31536000"), ("Content-Type", "text/plain")], b"ok")
    rep = http_check(srv.url("/", host="localhost"), policy)
    assert "http.hsts" in rep.codes("PASS")
    assert "tls=" in rep.render()
    srv.routes["/n"] = Route(200, [("Content-Type", "text/plain")], b"ok")
    assert "http.no_hsts" in http_check(srv.url("/n", host="localhost"), policy).codes("WARN")


def test_https_with_untrusted_certificate_is_an_actionable_error(tls_server, pki: lab.Pki, policy: Policy) -> None:  # type: ignore[no-untyped-def]
    srv = tls_server(pki.leaf())
    (pki.dir / "o").mkdir()
    other = lab.Pki(pki.dir / "o", label="Other")  # this client trusts a different CA
    with pytest.raises(NetcheckError, match="tls_check"):
        http_check(srv.url("/", host="localhost"), replace(policy, cafile=other.root_file))


def test_https_wrong_host_is_an_error(tls_server, pki: lab.Pki, policy: Policy) -> None:  # type: ignore[no-untyped-def]
    srv = tls_server(pki.leaf("other", ["other.example.test"]))
    with pytest.raises(NetcheckError, match="does not match|did not verify"):
        http_check(srv.url("/", host="localhost"), policy)


def test_https_to_http_downgrade_flagged(tls_server, pki: lab.Pki, web: lab.WebLab, policy: Policy) -> None:  # type: ignore[no-untyped-def]
    srv = tls_server(pki.leaf())
    web.routes["/"] = Route(200, [("Content-Type", "text/plain")], b"plain")
    srv.routes["/"] = Route(302, [("Location", web.url("/"))])
    rep = http_check(srv.url("/", host="localhost"), policy)
    assert "http.downgrade" in rep.codes("FAIL")


def test_http_to_https_upgrade_passes(tls_server, pki: lab.Pki, web: lab.WebLab, policy: Policy) -> None:  # type: ignore[no-untyped-def]
    srv = tls_server(pki.leaf())
    srv.routes["/"] = Route(200, [("Content-Type", "text/plain")], b"secure")
    web.routes["/"] = Route(301, [("Location", srv.url("/", host="localhost"))])
    assert "http.https_upgrade" in http_check(web.url("/"), policy).codes("PASS")


def test_closed_port_error(policy: Policy) -> None:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    with pytest.raises(NetcheckError, match="Cannot connect"):
        http_check(f"http://127.0.0.1:{port}/", policy)


def test_refuses_loopback_by_default(web: lab.WebLab, strict: Policy) -> None:
    with pytest.raises(TargetRefused):
        http_check(web.url("/"), strict)
    assert web.requests == []


def test_non_tls_port_gives_tls_error(web: lab.WebLab, policy: Policy) -> None:
    with pytest.raises(NetcheckError, match="handshake"):
        http_check(f"https://127.0.0.1:{web.port}/", policy)
