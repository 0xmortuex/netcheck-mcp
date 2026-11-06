import datetime as dt
import ssl

import lab
import pytest
from netcheck_mcp.guard import NetcheckError, Policy, TargetRefused
from netcheck_mcp.tlscheck import tls_check

UTC = dt.timezone.utc


def run(srv: lab.WebLab, policy: Policy, host: str = "localhost"):  # type: ignore[no-untyped-def]
    return tls_check(host, srv.port, policy)


def test_healthy_server_passes(tls_server, pki, policy) -> None:  # type: ignore[no-untyped-def]
    rep = run(tls_server(pki.leaf()), policy)
    assert rep.verdict == "PASS", rep.render()
    assert {"tls.valid", "tls.hostname_ok", "tls.trusted"} <= rep.codes("PASS")
    assert rep.data["version"] == "TLSv1.3"
    assert len(rep.data["chain"]) == 2  # leaf + intermediate
    assert rep.data["protocols"]["TLSv1.3"] == "offered"
    assert rep.data["protocols"]["TLSv1.2"] == "offered"
    text = rep.render()
    assert "VERDICT: PASS" in text and "Chain served (2 certificate(s))" in text


def test_ip_literal_target_matches_ip_san(tls_server, pki, policy) -> None:  # type: ignore[no-untyped-def]
    rep = run(tls_server(pki.leaf()), policy, host="127.0.0.1")
    assert "tls.hostname_ok" in rep.codes("PASS"), rep.render()


def test_expired_certificate_fails(tls_server, pki, policy) -> None:  # type: ignore[no-untyped-def]
    now = dt.datetime.now(UTC)
    leaf = pki.leaf(not_before=now - dt.timedelta(days=400), not_after=now - dt.timedelta(days=5))
    rep = run(tls_server(leaf), policy)
    assert rep.verdict == "FAIL"
    assert "tls.expired" in rep.codes("FAIL")
    assert "EXPIRED 5 day(s) ago" in rep.render()


def test_not_yet_valid_fails(tls_server, pki, policy) -> None:  # type: ignore[no-untyped-def]
    now = dt.datetime.now(UTC)
    leaf = pki.leaf(not_before=now + dt.timedelta(days=3), not_after=now + dt.timedelta(days=90))
    assert "tls.not_yet_valid" in run(tls_server(leaf), policy).codes("FAIL")


@pytest.mark.parametrize("days,level,code", [(10, "FAIL", "tls.expiring_soon"), (20, "WARN", "tls.expiring")])
def test_expiry_thresholds(tls_server, pki, policy, days, level, code) -> None:  # type: ignore[no-untyped-def]
    now = dt.datetime.now(UTC)
    leaf = pki.leaf(not_before=now - dt.timedelta(days=5), not_after=now + dt.timedelta(days=days, hours=1))
    rep = run(tls_server(leaf), policy)
    assert code in rep.codes(level), rep.render()
    assert rep.verdict == level


def test_self_signed_detected(tls_server, policy) -> None:  # type: ignore[no-untyped-def]
    ss = lab.make_cert("localhost", sans=["localhost", "127.0.0.1"])
    assert ss.cert.issuer == ss.cert.subject
    pki_dir = policy.cafile  # root file is irrelevant: ss is not signed by it
    assert pki_dir
    import pathlib
    d = pathlib.Path(pki_dir).parent
    (d / "ss.pem").write_bytes(ss.pem)
    (d / "ss.key").write_bytes(ss.key_pem)
    srv = lab.WebLab(lab.server_ctx(str(d / "ss.pem"), str(d / "ss.key")))
    try:
        rep = run(srv, policy)
    finally:
        srv.close()
    assert "tls.self_signed" in rep.codes("FAIL"), rep.render()
    assert "self-signed" in rep.render()


def test_wrong_host_detected(tls_server, pki, policy) -> None:  # type: ignore[no-untyped-def]
    leaf = pki.leaf("other", ["other.example.test"])
    rep = run(tls_server(leaf), policy)
    assert "tls.hostname_mismatch" in rep.codes("FAIL")
    assert "other.example.test" in rep.render()
    assert "tls.trusted" in rep.codes("PASS")  # the chain itself is fine


def test_incomplete_chain_detected_and_distinguished(tls_server, pki, policy) -> None:  # type: ignore[no-untyped-def]
    rep = run(tls_server(pki.leaf(), with_intermediate=False), policy)
    assert "tls.incomplete_chain" in rep.codes("FAIL"), rep.render()
    assert "tls.self_signed" not in rep.codes()
    assert "fullchain" in rep.render()
    assert len(rep.data["chain"]) == 1


def test_untrusted_root_when_ca_unknown(tls_server, pki, policy) -> None:  # type: ignore[no-untyped-def]
    (pki.dir / "x").mkdir()
    other = lab.Pki(pki.dir / "x", label="Stranger")
    leaf = other.leaf()
    chain, key = other.files(leaf, with_intermediate=True, extra=[other.root])
    srv = lab.WebLab(lab.server_ctx(chain, key))
    try:
        rep = run(srv, policy)
    finally:
        srv.close()
    assert "tls.untrusted_root" in rep.codes("FAIL"), rep.render()


def test_weak_key_flagged(tls_server, pki, policy) -> None:  # type: ignore[no-untyped-def]
    leaf = pki.leaf(rsa_bits=1024)
    try:
        srv = tls_server(leaf, legacy=True)
        rep = run(srv, policy)
    except (ssl.SSLError, NetcheckError):
        pytest.skip("this OpenSSL refuses to serve/handshake 1024-bit 1024-bit RSA certificates")
    assert "tls.weak_key" in rep.codes("FAIL"), rep.render()


def test_tls12_only_server_reports_protocols(tls_server, pki, policy) -> None:  # type: ignore[no-untyped-def]
    srv = tls_server(pki.leaf(), max_v=ssl.TLSVersion.TLSv1_2)
    rep = run(srv, policy)
    assert rep.data["version"] == "TLSv1.2"
    assert rep.data["protocols"]["TLSv1.3"] == "not offered"
    assert rep.data["protocols"]["TLSv1.2"] == "offered"
    assert "tls.no_tls13" in rep.codes("INFO")


def test_legacy_tls10_server_is_warned_about(tls_server, pki, policy) -> None:  # type: ignore[no-untyped-def]
    try:
        srv = tls_server(pki.leaf(), min_v=ssl.TLSVersion.TLSv1, legacy=True)
    except (ssl.SSLError, ValueError):
        pytest.skip("this OpenSSL cannot be configured as a TLS 1.0 server")
    rep = run(srv, policy)
    if rep.data["protocols"]["TLSv1.0"] != "offered":
        pytest.skip(f"TLS 1.0 not testable on this OpenSSL: {rep.data['protocols']}")
    assert "tls.weak_protocol_10" in rep.codes("WARN")
    assert rep.verdict == "WARN"


def test_plain_http_port_is_an_actionable_error(web, policy) -> None:  # type: ignore[no-untyped-def]
    with pytest.raises(NetcheckError, match="TLS"):
        tls_check("127.0.0.1", web.port, policy)


def test_closed_port_is_an_actionable_error(policy) -> None:  # type: ignore[no-untyped-def]
    import socket
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    with pytest.raises(NetcheckError, match="Cannot connect"):
        tls_check("127.0.0.1", port, policy)


def test_loopback_refused_without_allow_private(tls_server, pki, strict) -> None:  # type: ignore[no-untyped-def]
    srv = tls_server(pki.leaf())
    with pytest.raises(TargetRefused):
        tls_check("localhost", srv.port, strict)
