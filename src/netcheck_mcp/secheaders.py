"""security_headers: grade a site's response headers and say exactly what to add."""

from __future__ import annotations

import re

from .guard import Policy
from .httpcheck import Hop, follow
from .report import Report

# (points available per check)
_W_HSTS, _W_CSP, _W_XCTO, _W_FRAME, _W_REFERRER, _W_PERMS, _W_COOKIE, _W_LEAK, _W_ISO = (
    20, 25, 10, 10, 10, 8, 10, 4, 3
)


def _directives(csp: str) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    for part in csp.split(";"):
        toks = part.split()
        if toks:
            out.setdefault(toks[0].lower(), toks[1:])
    return out


def _check_hsts(hop: Hop, rep: Report) -> tuple[int, int]:
    v = hop.header("strict-transport-security")
    if not hop.url.startswith("https://"):
        rep.add("FAIL", "sec.no_https", "Final page is not served over HTTPS, so HSTS cannot apply.",
                "Serve over HTTPS and redirect HTTP to it.")
        return 0, _W_HSTS
    if not v:
        rep.add("FAIL", "sec.hsts_missing", "Strict-Transport-Security is missing.",
                "Strict-Transport-Security: max-age=31536000; includeSubDomains")
        return 0, _W_HSTS
    m = re.search(r"max-age\s*=\s*(\d+)", v, re.I)
    age = int(m.group(1)) if m else 0
    if age < 15552000:
        rep.add("WARN", "sec.hsts_short", f"HSTS max-age is {age}s (under 180 days): {v}",
                "Raise it: Strict-Transport-Security: max-age=31536000; includeSubDomains")
        return _W_HSTS // 2, _W_HSTS
    if "includesubdomains" not in v.lower():
        rep.add("WARN", "sec.hsts_no_subdomains", f"HSTS lacks includeSubDomains: {v}",
                "Strict-Transport-Security: max-age=31536000; includeSubDomains (once all subdomains support HTTPS)")
        return _W_HSTS - 4, _W_HSTS
    rep.add("PASS", "sec.hsts_ok", f"HSTS is strong: {v}")
    return _W_HSTS, _W_HSTS


def _check_csp(hop: Hop, rep: Report) -> tuple[int, int]:
    v = hop.header("content-security-policy")
    if not v:
        rep.add("FAIL", "sec.csp_missing", "Content-Security-Policy is missing.",
                "Start with: Content-Security-Policy: default-src 'self'; object-src 'none'; "
                "base-uri 'self'; frame-ancestors 'self'")
        return 0, _W_CSP
    d = _directives(v)
    score = _W_CSP
    script = d.get("script-src") or d.get("default-src") or []
    problems = []
    if "'unsafe-inline'" in script and not any(t.startswith(("'nonce-", "'sha")) for t in script):
        problems.append("script-src allows 'unsafe-inline' (defeats XSS protection)")
        score -= 10
    if "'unsafe-eval'" in script:
        problems.append("script-src allows 'unsafe-eval'")
        score -= 5
    if "*" in script or "https:" in script or "http:" in script:
        problems.append("script sources include a wildcard or whole scheme (*, https:, http:)")
        score -= 8
    if "object-src" not in d and "default-src" not in d:
        problems.append("no object-src or default-src (plugins unrestricted)")
        score -= 3
    if "base-uri" not in d:
        problems.append("no base-uri (injected <base> can hijack relative URLs)")
        score -= 2
    if problems:
        rep.add("WARN", "sec.csp_weak", "Content-Security-Policy is weak: " + "; ".join(problems) + ".",
                "Remove 'unsafe-inline'/'unsafe-eval' (use nonces or hashes), list exact origins, "
                "add object-src 'none'; base-uri 'self'")
    else:
        rep.add("PASS", "sec.csp_ok", "Content-Security-Policy is present with no obvious weaknesses.")
    return max(score, 0), _W_CSP


def _check_frame(hop: Hop, rep: Report) -> tuple[int, int]:
    xfo = hop.header("x-frame-options")
    csp = hop.header("content-security-policy") or ""
    if "frame-ancestors" in csp.lower():
        rep.add("PASS", "sec.frame_ok", "Clickjacking protection via CSP frame-ancestors.")
        return _W_FRAME, _W_FRAME
    if xfo and xfo.strip().upper() in ("DENY", "SAMEORIGIN"):
        rep.add("PASS", "sec.frame_ok", f"X-Frame-Options: {xfo}")
        return _W_FRAME, _W_FRAME
    if xfo:
        rep.add("WARN", "sec.frame_weak", f"X-Frame-Options has a weak or unsupported value: {xfo}",
                "X-Frame-Options: DENY (or SAMEORIGIN), or CSP frame-ancestors 'self'")
        return _W_FRAME // 2, _W_FRAME
    rep.add("FAIL", "sec.frame_missing", "No clickjacking protection (X-Frame-Options / frame-ancestors).",
            "X-Frame-Options: DENY   (or Content-Security-Policy: frame-ancestors 'self')")
    return 0, _W_FRAME


def _check_xcto(hop: Hop, rep: Report) -> tuple[int, int]:
    v = hop.header("x-content-type-options")
    if v and v.strip().lower() == "nosniff":
        rep.add("PASS", "sec.xcto_ok", "X-Content-Type-Options: nosniff")
        return _W_XCTO, _W_XCTO
    rep.add("FAIL" if not v else "WARN", "sec.xcto_missing" if not v else "sec.xcto_bad",
            "X-Content-Type-Options is " + ("missing." if not v else f"wrong: {v}"),
            "X-Content-Type-Options: nosniff")
    return 0, _W_XCTO


def _check_referrer(hop: Hop, rep: Report) -> tuple[int, int]:
    v = hop.header("referrer-policy")
    if not v:
        rep.add("WARN", "sec.referrer_missing", "Referrer-Policy is missing (browsers default to a middle ground).",
                "Referrer-Policy: strict-origin-when-cross-origin")
        return _W_REFERRER // 2, _W_REFERRER
    last = v.split(",")[-1].strip().lower()
    if last in ("unsafe-url", "no-referrer-when-downgrade", "origin-when-cross-origin"):
        rep.add("WARN", "sec.referrer_weak", f"Referrer-Policy leaks full URLs cross-origin: {v}",
                "Referrer-Policy: strict-origin-when-cross-origin (or no-referrer)")
        return _W_REFERRER // 2, _W_REFERRER
    rep.add("PASS", "sec.referrer_ok", f"Referrer-Policy: {v}")
    return _W_REFERRER, _W_REFERRER


def _check_perms(hop: Hop, rep: Report) -> tuple[int, int]:
    v = hop.header("permissions-policy") or hop.header("feature-policy")
    if v:
        rep.add("PASS", "sec.perms_ok", f"Permissions-Policy present: {v[:120]}")
        return _W_PERMS, _W_PERMS
    rep.add("WARN", "sec.perms_missing", "Permissions-Policy is missing (powerful browser features not restricted).",
            "Permissions-Policy: camera=(), microphone=(), geolocation=()")
    return 0, _W_PERMS


def _check_cookies(hop: Hop, rep: Report) -> tuple[int, int]:
    cookies = hop.header_all("set-cookie")
    if not cookies:
        return 0, 0
    bad = []
    for c in cookies:
        low = c.lower()
        name = c.split("=", 1)[0].strip()
        missing = []
        if "secure" not in low and hop.url.startswith("https://"):
            missing.append("Secure")
        if "httponly" not in low:
            missing.append("HttpOnly")
        if "samesite" not in low:
            missing.append("SameSite")
        if missing:
            bad.append(f"{name} (no {'/'.join(missing)})")
    if bad:
        rep.add("WARN", "sec.cookie_flags", "Cookies missing flags: " + ", ".join(bad) + ".",
                "Set-Cookie: <name>=<value>; Secure; HttpOnly; SameSite=Lax")
        return _W_COOKIE // 2, _W_COOKIE
    rep.add("PASS", "sec.cookie_ok", f"All {len(cookies)} cookie(s) set Secure/HttpOnly/SameSite.")
    return _W_COOKIE, _W_COOKIE


def _check_leaks(hop: Hop, rep: Report) -> tuple[int, int]:
    leaks = []
    server = hop.header("server")
    if server and re.search(r"\d+\.\d+", server):
        leaks.append(f"Server: {server}")
    for h in ("x-powered-by", "x-aspnet-version", "x-aspnetmvc-version"):
        v = hop.header(h)
        if v:
            leaks.append(f"{h}: {v}")
    if leaks:
        rep.add("WARN", "sec.info_leak", "Response reveals software details: " + "; ".join(leaks) + ".",
                "Remove version info (nginx: server_tokens off; Express: app.disable('x-powered-by')).")
        return 0, _W_LEAK
    rep.add("PASS", "sec.no_leak", "No obvious version disclosure headers.")
    return _W_LEAK, _W_LEAK


def _check_isolation(hop: Hop, rep: Report) -> tuple[int, int]:
    got = [h for h in ("cross-origin-opener-policy", "cross-origin-resource-policy",
                       "cross-origin-embedder-policy") if hop.header(h)]
    xxp = hop.header("x-xss-protection")
    if xxp and xxp.strip().startswith("1"):
        rep.add("INFO", "sec.xxp_legacy", f"X-XSS-Protection: {xxp} is obsolete and can introduce bugs.",
                "Send X-XSS-Protection: 0 or drop it; rely on CSP.")
    if got:
        rep.add("PASS", "sec.isolation_ok", "Cross-origin isolation headers present: " + ", ".join(got))
        return _W_ISO, _W_ISO
    rep.add("INFO", "sec.isolation_missing", "No Cross-Origin-Opener/Resource/Embedder-Policy headers (optional hardening).",
            "Cross-Origin-Opener-Policy: same-origin")
    return 0, _W_ISO


def _grade(pct: float) -> str:
    for cut, g in ((95, "A+"), (85, "A"), (70, "B"), (55, "C"), (40, "D")):
        if pct >= cut:
            return g
    return "F"


def security_headers(url: str, policy: Policy) -> Report:
    hops, problem = follow(url, policy)
    hop = hops[-1]
    rep = Report(f"Security headers: {hop.url}")
    if problem:
        rep.add("WARN", "sec.redirect_problem", f"Redirect problem while fetching: {problem}.")
    earned = possible = 0
    for chk in (_check_hsts, _check_csp, _check_frame, _check_xcto, _check_referrer,
                _check_perms, _check_cookies, _check_leaks, _check_isolation):
        e, p = chk(hop, rep)
        earned += e
        possible += p
    pct = 100.0 * earned / possible if possible else 0.0
    grade = _grade(pct)
    rep.data.update(grade=grade, score=round(pct), status=hop.status, final_url=hop.url)
    rep.section("Grade", [f"{grade} ({pct:.0f}/100) for {hop.url} (HTTP {hop.status})"])
    return rep
