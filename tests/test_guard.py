import ipaddress
from dataclasses import replace

import pytest
from lab import Route
from netcheck_mcp import guard, httpcheck
from netcheck_mcp.guard import NetcheckError, Policy, TargetRefused, forbidden_reason, resolve_target

DEFAULT = Policy()


@pytest.mark.parametrize(
    "addr,why",
    [
        ("127.0.0.1", "loopback"),
        ("::1", "loopback"),
        ("10.0.0.5", "private"),
        ("192.168.1.1", "private"),
        ("172.16.0.1", "private"),
        ("169.254.169.254", "metadata"),
        ("169.254.1.1", "link-local"),
        ("fe80::1", "link-local"),
        ("fd00:ec2::254", "metadata"),
        ("100.64.0.1", "non-public"),
        ("0.0.0.0", "unspecified"),
        ("224.0.0.1", "multicast"),
        ("::ffff:127.0.0.1", "loopback"),
        ("::ffff:169.254.169.254", "metadata"),
    ],
)
def test_forbidden_ranges(addr: str, why: str) -> None:
    reason = forbidden_reason(addr)
    assert reason is not None and why in reason


@pytest.mark.parametrize("addr", ["1.1.1.1", "8.8.8.8", "93.184.215.14", "2606:4700:4700::1111"])
def test_public_addresses_allowed(addr: str) -> None:
    assert forbidden_reason(addr) is None


@pytest.mark.parametrize(
    "host",
    ["127.0.0.1", "localhost", "169.254.169.254", "10.1.2.3", "[::1]"],
)
def test_resolve_refuses_internal_targets_by_default(host: str) -> None:
    with pytest.raises(TargetRefused) as ei:
        resolve_target(host, 80, DEFAULT)
    assert "--allow-private" in str(ei.value)


def test_allow_private_lifts_the_block() -> None:
    assert resolve_target("127.0.0.1", 80, replace(DEFAULT, allow_private=True)) == ["127.0.0.1"]


def test_cidr_and_url_forms_refused() -> None:
    with pytest.raises(NetcheckError, match="range or a URL"):
        resolve_target("10.0.0.0/8", 80, DEFAULT)


def test_unresolvable_name_is_a_clear_error() -> None:
    with pytest.raises(NetcheckError, match="Cannot resolve"):
        resolve_target("no-such-host.invalid", 80, DEFAULT)


def test_url_schemes_and_credentials_refused() -> None:
    for bad in ("file:///etc/passwd", "gopher://x/", "ftp://example.com/"):
        with pytest.raises(NetcheckError, match="scheme"):
            httpcheck.parse_url(bad)
    with pytest.raises(NetcheckError, match="credentials"):
        httpcheck.parse_url("https://user:pw@example.com/")


def test_fetch_to_metadata_endpoint_refused_before_any_connection() -> None:
    with pytest.raises(TargetRefused):
        httpcheck.http_check("http://169.254.169.254/latest/meta-data/", DEFAULT)


def test_redirect_into_metadata_endpoint_is_refused(web, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    """The local server is loopback, so for this one test only the loopback block is lifted;
    the metadata block stays, and the redirect hop must hit it."""
    real = guard.forbidden_reason

    def only_metadata(addr: str) -> str | None:
        r = real(addr)
        return r if r and "metadata" in r else None

    monkeypatch.setattr(guard, "forbidden_reason", only_metadata)
    web.routes["/go"] = Route(302, [("Location", "http://169.254.169.254/latest/meta-data/")])
    with pytest.raises(TargetRefused, match="metadata"):
        httpcheck.http_check(web.url("/go"), DEFAULT)
    assert [r["path"] for r in web.requests] == ["/go"]  # we never left for the metadata host


@pytest.mark.parametrize("host", ["2130706433", "0x7f.1", "0177.0.0.1", "127.1"])
def test_obfuscated_loopback_spellings_never_get_through(host: str) -> None:
    """Platforms disagree about these spellings: some expand them to 127.0.0.1 (refused), some
    reject them as unresolvable (refused), and some (macOS) read a leading 0 as decimal, so
    '0177.0.0.1' becomes the PUBLIC address 177.0.0.1, which is allowed. What must never happen is
    a successful resolution to a loopback/private/internal address."""
    try:
        addrs = resolve_target(host, 80, DEFAULT)
    except NetcheckError:
        return
    for a in addrs:
        assert ipaddress.ip_address(a).is_global, f"{host!r} resolved to non-public {a}"
