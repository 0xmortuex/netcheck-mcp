import lab
from lab import Route
from netcheck_mcp.guard import Policy
from netcheck_mcp.secheaders import security_headers

GOOD = [
    ("Content-Type", "text/html"),
    ("Strict-Transport-Security", "max-age=63072000; includeSubDomains; preload"),
    ("Content-Security-Policy", "default-src 'self'; script-src 'self' 'nonce-abc'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'"),
    ("X-Content-Type-Options", "nosniff"),
    ("Referrer-Policy", "strict-origin-when-cross-origin"),
    ("Permissions-Policy", "camera=(), microphone=()"),
    ("Cross-Origin-Opener-Policy", "same-origin"),
]


def test_well_configured_site_gets_top_grade(tls_server, pki: lab.Pki, policy: Policy) -> None:  # type: ignore[no-untyped-def]
    srv = tls_server(pki.leaf())
    srv.routes["/"] = Route(200, GOOD, b"ok")
    rep = security_headers(srv.url("/", host="localhost"), policy)
    assert rep.data["grade"] == "A+", rep.render()
    assert rep.verdict == "PASS"


def test_bare_http_site_fails_with_concrete_fixes(web: lab.WebLab, policy: Policy) -> None:
    web.routes["/"] = Route(200, [("Content-Type", "text/html"), ("Server", "nginx/1.18.0"), ("X-Powered-By", "PHP/7.4")], b"x")
    rep = security_headers(web.url("/"), policy)
    assert rep.data["grade"] == "F"
    assert {"sec.no_https", "sec.csp_missing", "sec.frame_missing", "sec.xcto_missing"} <= rep.codes("FAIL")
    assert {"sec.referrer_missing", "sec.perms_missing", "sec.info_leak"} <= rep.codes("WARN")
    text = rep.render()
    assert "X-Content-Type-Options: nosniff" in text  # the exact line to add
    assert "nginx/1.18.0" in text


def test_weak_csp_and_hsts_are_called_out(tls_server, pki: lab.Pki, policy: Policy) -> None:  # type: ignore[no-untyped-def]
    srv = tls_server(pki.leaf())
    srv.routes["/"] = Route(200, [
        ("Content-Type", "text/html"),
        ("Strict-Transport-Security", "max-age=300"),
        ("Content-Security-Policy", "default-src *; script-src 'self' 'unsafe-inline' 'unsafe-eval' https:"),
        ("X-Frame-Options", "ALLOW-FROM https://x.test"),
        ("Referrer-Policy", "unsafe-url"),
        ("X-XSS-Protection", "1; mode=block"),
    ], b"x")
    rep = security_headers(srv.url("/", host="localhost"), policy)
    assert {"sec.hsts_short", "sec.csp_weak", "sec.frame_weak", "sec.referrer_weak"} <= rep.codes("WARN")
    msg = " ".join(f.message for f in rep.findings if f.code == "sec.csp_weak")
    assert "unsafe-inline" in msg and "unsafe-eval" in msg
    assert "sec.xxp_legacy" in rep.codes("INFO")
    assert rep.data["grade"] in ("C", "D", "F")


def test_cookie_flags(tls_server, pki: lab.Pki, policy: Policy) -> None:  # type: ignore[no-untyped-def]
    srv = tls_server(pki.leaf())
    srv.routes["/bad"] = Route(200, GOOD + [("Set-Cookie", "sid=1"), ("Set-Cookie", "ok=1; Secure; HttpOnly; SameSite=Lax")], b"x")
    srv.routes["/good"] = Route(200, GOOD + [("Set-Cookie", "ok=1; Secure; HttpOnly; SameSite=Lax")], b"x")
    bad = security_headers(srv.url("/bad", host="localhost"), policy)
    assert "sec.cookie_flags" in bad.codes("WARN") and "sid (no Secure/HttpOnly/SameSite)" in bad.render()
    assert "sec.cookie_ok" in security_headers(srv.url("/good", host="localhost"), policy).codes("PASS")


def test_follows_redirect_and_grades_final_page(web: lab.WebLab, tls_server, pki: lab.Pki, policy: Policy) -> None:  # type: ignore[no-untyped-def]
    srv = tls_server(pki.leaf())
    srv.routes["/"] = Route(200, GOOD, b"ok")
    web.routes["/"] = Route(301, [("Location", srv.url("/", host="localhost"))])
    rep = security_headers(web.url("/"), policy)
    assert rep.data["final_url"].startswith("https://") and rep.data["grade"] == "A+"
