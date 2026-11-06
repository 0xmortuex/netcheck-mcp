"""Real-internet checks. Excluded from the default run (`-m "not network"` in pyproject);
run them with:  pytest -m network

They assert the behaviour badssl.com was built to exercise, using the system trust store.
"""

import pytest
from netcheck_mcp.dnswire import lookup, make_resolver
from netcheck_mcp.emaildns import email_dns_check
from netcheck_mcp.guard import Policy
from netcheck_mcp.httpcheck import http_check
from netcheck_mcp.secheaders import security_headers
from netcheck_mcp.tlscheck import tls_check

pytestmark = pytest.mark.network
P = Policy()


def test_example_com_tls_is_healthy() -> None:
    rep = tls_check("example.com", 443, P)
    assert "tls.hostname_ok" in rep.codes("PASS") and "tls.trusted" in rep.codes("PASS")
    assert "FAIL" != rep.verdict


@pytest.mark.parametrize(
    "host,code",
    [
        ("expired.badssl.com", "tls.expired"),
        ("self-signed.badssl.com", "tls.self_signed"),
        ("wrong.host.badssl.com", "tls.hostname_mismatch"),
        ("untrusted-root.badssl.com", "tls.untrusted_root"),
        ("incomplete-chain.badssl.com", "tls.incomplete_chain"),
    ],
)
def test_badssl_failures_are_detected(host: str, code: str) -> None:
    rep = tls_check(host, 443, P)
    assert code in rep.codes("FAIL"), rep.render()


def test_example_com_http_and_headers() -> None:
    rep = http_check("http://example.com/", P)
    assert rep.data["final_status"] == 200
    assert security_headers("https://example.com/", P).data["grade"] in "ABCDF"


def test_example_com_dns_over_each_resolver() -> None:
    for spec in ("cloudflare", "google"):
        r = lookup(make_resolver(spec, P), "example.com", "A")
        assert r.status == "NOERROR" and r.answers
    nx = lookup(make_resolver("cloudflare", P), "no-such-name-netcheck.invalid", "A")
    assert nx.status == "NXDOMAIN"
    nd = lookup(make_resolver("cloudflare", P), "example.com", "CAA")
    assert nd.status in ("NODATA", "NOERROR")


def test_system_resolver_works() -> None:
    assert lookup(make_resolver("system", P), "example.com", "A").answers


def test_email_dns_on_a_real_domain() -> None:
    rep = email_dns_check("google.com", make_resolver("cloudflare", P))
    assert rep.data["spf"]["lookups"] >= 1 and "dmarc" in rep.data
