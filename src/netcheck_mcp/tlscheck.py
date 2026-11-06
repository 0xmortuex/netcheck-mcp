"""tls_check: handshake with a host and judge the certificate, chain and protocols."""

from __future__ import annotations

import ipaddress
import socket
import ssl
import warnings
from dataclasses import dataclass
from datetime import datetime, timezone

from .guard import NetcheckError, Policy, resolve_target
from .report import Report
from .x509 import Certificate, hostname_matches, parse_certificate

_PROTOCOLS = [
    ("TLSv1.0", ssl.TLSVersion.TLSv1),
    ("TLSv1.1", ssl.TLSVersion.TLSv1_1),
    ("TLSv1.2", ssl.TLSVersion.TLSv1_2),
    ("TLSv1.3", ssl.TLSVersion.TLSv1_3),
]
_WEAK_CIPHER_WORDS = ("RC4", "3DES", "DES-CBC", "NULL", "EXPORT", "MD5", "anon")

# X509_V_ERR_* codes we classify
_V_EXPIRED = 10
_V_NOT_YET = 9
_V_SELF_SIGNED = 18
_V_SELF_SIGNED_CHAIN = 19
_V_NO_LOCAL_ISSUER = 20
_V_UNABLE_VERIFY_LEAF = 21


@dataclass
class _Handshake:
    version: str
    cipher: str
    chain: list[Certificate]
    chain_available: bool


def _open(host: str, ip: str, port: int, policy: Policy, ctx: ssl.SSLContext) -> ssl.SSLSocket:
    try:
        raw = socket.create_connection((ip, port), timeout=policy.connect_timeout)
    except OSError as e:
        raise NetcheckError(f"Cannot connect to {host}:{port} ({ip}): {e}") from e
    try:
        try:
            ipaddress.ip_address(host.strip("[]"))
            sni = None
        except ValueError:
            sni = host
        return ctx.wrap_socket(raw, server_hostname=sni)
    except BaseException:
        raw.close()
        raise


def _unverified_ctx() -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    # We are here to inspect weak servers, not to refuse them: allow small keys / old digests.
    ctx.set_ciphers("DEFAULT:@SECLEVEL=0")
    return ctx


def _verified_ctx(policy: Policy) -> ssl.SSLContext:
    ctx = ssl.create_default_context(cafile=policy.cafile)
    ctx.check_hostname = False  # hostname is judged separately, from the SAN list
    return ctx


def _get_chain(sock: ssl.SSLSocket) -> tuple[list[Certificate], bool]:
    getter = getattr(sock, "get_unverified_chain", None)
    if getter is None:
        sslobj = getattr(sock, "_sslobj", None)
        getter = getattr(sslobj, "get_unverified_chain", None)
    if getter is None:
        # Very old CPython: at least the leaf is available.
        leaf = sock.getpeercert(binary_form=True)
        return ([parse_certificate(leaf)] if leaf else []), False
    out = []
    for item in getter() or []:
        der = item if isinstance(item, bytes) else ssl.PEM_cert_to_DER_cert(item.public_bytes())
        out.append(parse_certificate(der))
    return out, True


def _handshake(host: str, ip: str, port: int, policy: Policy) -> _Handshake:
    try:
        with _open(host, ip, port, policy, _unverified_ctx()) as s:
            chain, avail = _get_chain(s)
            cipher = s.cipher()
            return _Handshake(s.version() or "?", cipher[0] if cipher else "?", chain, avail)
    except ssl.SSLError as e:
        raise NetcheckError(
            f"{host}:{port} did not complete a TLS handshake ({e.reason or e}). "
            "Is this really a TLS port? (For plain HTTP use http_check; port 443 is the usual TLS port.)"
        ) from e
    except TimeoutError as e:
        raise NetcheckError(f"Timed out during the TLS handshake with {host}:{port}.") from e
    except ConnectionError as e:
        raise NetcheckError(f"Connection to {host}:{port} was reset during the handshake: {e}") from e


def _verify(host: str, ip: str, port: int, policy: Policy) -> tuple[int, str] | None:
    """Verify the chain against the trust store. None if OK, else (openssl code, message)."""
    try:
        with _open(host, ip, port, policy, _verified_ctx(policy)):
            return None
    except ssl.SSLCertVerificationError as e:
        return int(e.verify_code), str(e.verify_message)
    except ssl.SSLError as e:
        return -1, str(e.reason or e)
    except (TimeoutError, ConnectionError) as e:
        raise NetcheckError(f"Connection to {host}:{port} failed during verification: {e}") from e


def _probe(host: str, ip: str, port: int, policy: Policy, version: ssl.TLSVersion, name: str) -> str:
    """'offered', 'not offered' or 'untestable' for one protocol version."""
    ctx = _unverified_ctx()
    try:
        if version in (ssl.TLSVersion.TLSv1, ssl.TLSVersion.TLSv1_1):
            ctx.set_ciphers("ALL:@SECLEVEL=0")
        with warnings.catch_warnings():  # probing the deprecated versions is the point
            warnings.simplefilter("ignore", DeprecationWarning)
            ctx.minimum_version = version
            ctx.maximum_version = version
    except (ssl.SSLError, ValueError):
        return "untestable"
    try:
        with _open(host, ip, port, policy, ctx):
            return "offered"
    except ssl.SSLError as e:
        # The client library itself (not the server) may have no such protocol
        # compiled or enabled: say "untestable" instead of claiming "not offered".
        if e.reason in ("NO_PROTOCOLS_AVAILABLE", "UNSUPPORTED_PROTOCOL") and version in (
            ssl.TLSVersion.TLSv1, ssl.TLSVersion.TLSv1_1
        ):
            return "untestable"
        return "not offered"
    except NetcheckError:
        return "not offered"
    except (TimeoutError, ConnectionError):
        return "not offered"


def tls_check(host: str, port: int, policy: Policy, warn_days: int = 30, fail_days: int = 14) -> Report:
    if not 1 <= port <= 65535:
        raise NetcheckError(f"Port {port} is out of range 1-65535.")
    ips = resolve_target(host, port, policy)
    ip = ips[0]
    rep = Report(f"TLS check: {host}:{port} ({ip})")
    hs = _handshake(host, ip, port, policy)
    if not hs.chain:
        raise NetcheckError(f"{host}:{port} completed a handshake but sent no certificate.")
    leaf = hs.chain[0]
    rep.data.update(
        host=host, port=port, ip=ip, version=hs.version, cipher=hs.cipher,
        chain=[c.subject for c in hs.chain], days_left=round(leaf.days_left(), 1),
    )

    # Validity
    days = leaf.days_left()
    if days < 0:
        rep.add("FAIL", "tls.expired",
                f"Certificate EXPIRED {-days:.0f} day(s) ago (notAfter {leaf.not_after:%Y-%m-%d}).",
                "Renew/re-issue the certificate and reload the server.")
    elif leaf.not_before > datetime.now(timezone.utc):
        rep.add("FAIL", "tls.not_yet_valid",
                f"Certificate is not valid until {leaf.not_before:%Y-%m-%d %H:%M} UTC.",
                "Check the server's clock and the certificate's notBefore.")
    elif days < fail_days:
        rep.add("FAIL", "tls.expiring_soon",
                f"Certificate expires in {days:.0f} day(s) ({leaf.not_after:%Y-%m-%d}).",
                "Renewal is overdue: check why automatic renewal (certbot/ACME) is not working.")
    elif days < warn_days:
        rep.add("WARN", "tls.expiring",
                f"Certificate expires in {days:.0f} day(s) ({leaf.not_after:%Y-%m-%d}).",
                "Confirm automatic renewal is configured and will run before expiry.")
    else:
        rep.add("PASS", "tls.valid", f"Certificate is valid for another {days:.0f} day(s).")

    # Hostname
    if hostname_matches(host, leaf):
        rep.add("PASS", "tls.hostname_ok", f"Certificate covers {host}.")
    else:
        names = ", ".join(leaf.dns_names + leaf.ip_addrs) or "(no SAN entries)"
        rep.add("FAIL", "tls.hostname_mismatch",
                f"Certificate does not cover {host}. It is issued for: {names}.",
                f"Re-issue the certificate with {host} in its Subject Alternative Names, "
                "or point the name at the right server.")

    # Trust and chain
    verdict = _verify(host, ip, port, policy)
    last = hs.chain[-1]
    if verdict is None:
        rep.add("PASS", "tls.trusted", "Chain validates against the trust store.")
    else:
        code, msg = verdict
        if code == _V_SELF_SIGNED and len(hs.chain) == 1:
            rep.add("FAIL", "tls.self_signed",
                    "Certificate is self-signed: clients will not trust it.",
                    "Use a certificate from a public CA (e.g. Let's Encrypt), or install your own CA in the clients.")
        elif code in (_V_SELF_SIGNED, _V_SELF_SIGNED_CHAIN, _V_NO_LOCAL_ISSUER, _V_UNABLE_VERIFY_LEAF)                 and last.self_signed:
            rep.add("FAIL", "tls.untrusted_root",
                    f"Chain ends in a root ('{last.subject}') that clients do not trust ({msg}).",
                    "Use a CA that is in public trust stores, or install this root on the clients.")
        elif code in (_V_NO_LOCAL_ISSUER, _V_UNABLE_VERIFY_LEAF):
            rep.add("FAIL", "tls.incomplete_chain",
                    f"Server sends an incomplete chain: it ends at a certificate issued by "
                    f"'{last.issuer}', which is not in the trust store ({msg}).",
                    "Serve the intermediate certificate(s) too: use the 'fullchain' file "
                    "(leaf + intermediates), not just the leaf certificate.")
        elif code == _V_EXPIRED:
            if "tls.expired" not in rep.codes():
                rep.add("FAIL", "tls.chain_expired", f"A certificate in the chain has expired ({msg}).",
                        "Replace the expired intermediate in the served chain.")
        elif code == _V_NOT_YET:
            pass  # already reported above
        else:
            rep.add("FAIL", "tls.untrusted", f"Chain does not validate: {msg}.")

    # Chain structure
    ordered = all(
        hs.chain[i].issuer_der == hs.chain[i + 1].subject_der for i in range(len(hs.chain) - 1)
    )
    if len(hs.chain) > 1 and not ordered:
        rep.add("WARN", "tls.chain_order",
                "Served certificates are not in leaf-to-root order; some clients reject that.",
                "Order the chain file leaf first, then each issuer in turn.")
    if not hs.chain_available:
        rep.add("INFO", "tls.chain_unavailable",
                "This Python cannot list the full served chain; only the leaf is shown.")

    # Crypto strength
    if leaf.sig_alg in ("sha1WithRSAEncryption", "md5WithRSAEncryption", "ecdsa-with-SHA1"):
        rep.add("FAIL", "tls.weak_signature", f"Certificate is signed with {leaf.sig_alg}, which is broken.",
                "Re-issue with SHA-256 or better.")
    if leaf.key_type == "RSA" and leaf.key_bits is not None and leaf.key_bits < 2048:
        rep.add("FAIL", "tls.weak_key", f"RSA key is only {leaf.key_bits} bits.",
                "Re-issue with an RSA 2048+ or ECDSA P-256 key.")

    # Protocols
    support: dict[str, str] = {}
    for name, ver in _PROTOCOLS:
        support[name] = _probe(host, ip, port, policy, ver, name)
    rep.data["protocols"] = support
    for old in ("TLSv1.0", "TLSv1.1"):
        if support[old] == "offered":
            rep.add("WARN", f"tls.weak_protocol_{old[-3:].replace('.', '')}",
                    f"Server still offers {old}, which is deprecated (RFC 8996).",
                    f"Disable {old}: allow TLS 1.2 and 1.3 only (e.g. nginx: ssl_protocols TLSv1.2 TLSv1.3;).")
    if support["TLSv1.2"] == "not offered" and support["TLSv1.3"] == "not offered":
        rep.add("FAIL", "tls.no_modern_protocol", "Server offers neither TLS 1.2 nor TLS 1.3.",
                "Enable TLS 1.2 and 1.3.")
    elif support["TLSv1.3"] == "not offered":
        rep.add("INFO", "tls.no_tls13", "TLS 1.3 is not offered (TLS 1.2 works).",
                "Enable TLS 1.3 if your server software supports it.")
    if any(w in hs.cipher for w in _WEAK_CIPHER_WORDS):
        rep.add("WARN", "tls.weak_cipher", f"Negotiated cipher {hs.cipher} is weak.",
                "Restrict the cipher list to AEAD suites (AES-GCM / ChaCha20-Poly1305).")

    # OCSP
    if leaf.ocsp_urls:
        rep.add("INFO", "tls.ocsp_url", f"Certificate advertises OCSP responder {leaf.ocsp_urls[0]}. "
                "Stapling presence is not checked: Python's ssl module cannot see stapled responses.")
    else:
        rep.add("INFO", "tls.no_ocsp", "Certificate has no OCSP responder URL (common for short-lived certificates).")

    rep.section("Handshake", [
        f"protocol {hs.version}, cipher {hs.cipher}",
        "supported: " + ", ".join(f"{k}={v}" for k, v in support.items()),
    ])
    rep.section("Leaf certificate", [
        f"subject: {leaf.subject}",
        f"issuer:  {leaf.issuer}",
        f"valid:   {leaf.not_before:%Y-%m-%d} to {leaf.not_after:%Y-%m-%d} ({days:.0f} days left)",
        f"SAN:     {', '.join(leaf.dns_names + leaf.ip_addrs) or '(none)'}",
        f"key:     {leaf.key_desc}; signature {leaf.sig_alg}",
        f"sha256:  {leaf.fingerprint_sha256}",
    ])
    rep.section(f"Chain served ({len(hs.chain)} certificate(s))", [
        f"[{i}] {c.subject}  (issuer: {c.issuer}; expires {c.not_after:%Y-%m-%d})"
        for i, c in enumerate(hs.chain)
    ])
    return rep
