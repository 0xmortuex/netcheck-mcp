from datetime import timezone

import lab
import pytest
from cryptography import x509 as cx
from cryptography.hazmat.primitives import serialization
from netcheck_mcp.guard import NetcheckError
from netcheck_mcp.x509 import hostname_matches, parse_certificate


def der(i: lab.Ident) -> bytes:
    return i.cert.public_bytes(serialization.Encoding.DER)


def test_parser_agrees_with_cryptography_on_a_leaf(pki: lab.Pki) -> None:
    leaf = pki.leaf("shop.example.test", ["shop.example.test", "*.cdn.example.test", "10.1.2.3"], rsa_bits=2048)
    c = parse_certificate(der(leaf))
    assert c.subject == "CN=shop.example.test"
    assert c.issuer == "CN=Lab Intermediate CA"
    assert c.dns_names == ["shop.example.test", "*.cdn.example.test"]
    assert c.ip_addrs == ["10.1.2.3"]
    assert c.key_desc == "RSA 2048 bit" and c.key_bits == 2048
    assert c.sig_alg == "ecdsa-with-SHA256" or c.sig_alg == "sha256WithRSAEncryption"
    assert c.not_after == leaf.cert.not_valid_after_utc.astimezone(timezone.utc)
    assert c.not_before == leaf.cert.not_valid_before_utc
    assert c.serial == f"{leaf.cert.serial_number:x}".rjust(len(c.serial), "0")
    assert c.is_ca is False
    assert not c.self_signed


def test_parser_reads_ca_flag_and_ec_keys_and_self_signed(pki: lab.Pki) -> None:
    c = parse_certificate(der(pki.root))
    assert c.is_ca is True and c.self_signed
    assert c.key_desc == "EC P-256"
    assert c.sig_alg == "ecdsa-with-SHA256"
    inter = parse_certificate(der(pki.inter))
    assert not inter.self_signed and inter.issuer == c.subject


def test_rsa_signature_and_key_sizes(pki: lab.Pki) -> None:
    root = lab.make_cert("R", ca=True, rsa_bits=3072)
    c = parse_certificate(der(root))
    assert c.key_bits == 3072 and c.sig_alg == "sha256WithRSAEncryption"


def test_aia_urls_are_extracted(pki: lab.Pki) -> None:
    from cryptography.x509.oid import AuthorityInformationAccessOID as A

    leaf = pki.leaf()
    builder = cx.CertificateBuilder(
        subject_name=leaf.cert.subject, issuer_name=leaf.cert.issuer, public_key=leaf.key.public_key(),
        serial_number=5, not_valid_before=leaf.cert.not_valid_before_utc,
        not_valid_after=leaf.cert.not_valid_after_utc,
    ).add_extension(cx.AuthorityInformationAccess([
        cx.AccessDescription(A.OCSP, cx.UniformResourceIdentifier("http://ocsp.example.test")),
        cx.AccessDescription(A.CA_ISSUERS, cx.UniformResourceIdentifier("http://ca.example.test/i.crt")),
    ]), critical=False)
    from cryptography.hazmat.primitives import hashes
    cert = builder.sign(pki.inter.key, hashes.SHA256())
    c = parse_certificate(cert.public_bytes(serialization.Encoding.DER))
    assert c.ocsp_urls == ["http://ocsp.example.test"]
    assert c.ca_issuer_urls == ["http://ca.example.test/i.crt"]


def test_garbage_is_a_clean_error() -> None:
    with pytest.raises(NetcheckError):
        parse_certificate(b"\x30\x03\x01\x02")
    with pytest.raises(NetcheckError):
        parse_certificate(b"not a certificate")


@pytest.mark.parametrize(
    "host,ok",
    [
        ("shop.example.test", True),
        ("SHOP.example.test.", True),
        ("img.cdn.example.test", True),
        ("a.b.cdn.example.test", False),  # wildcard covers exactly one label
        ("cdn.example.test", False),
        ("10.1.2.3", True),
        ("10.1.2.4", False),
        ("evil.test", False),
    ],
)
def test_hostname_matching(pki: lab.Pki, host: str, ok: bool) -> None:
    leaf = pki.leaf("x", ["shop.example.test", "*.cdn.example.test", "10.1.2.3"])
    assert hostname_matches(host, parse_certificate(der(leaf))) is ok
