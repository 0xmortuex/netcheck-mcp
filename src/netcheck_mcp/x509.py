"""A small X.509 reader (DER), enough for health checks.

Python's ssl module only decodes a certificate it has already verified, and
we want to inspect certificates that FAIL verification. So we parse the DER
ourselves: subject, issuer, validity, SAN, basic constraints, AIA, key and
signature algorithms.
"""

from __future__ import annotations

import hashlib
import ipaddress
from dataclasses import dataclass, field
from datetime import datetime, timezone

from .guard import NetcheckError

_OIDS = {
    "2.5.4.3": "CN", "2.5.4.6": "C", "2.5.4.7": "L", "2.5.4.8": "ST", "2.5.4.10": "O",
    "2.5.4.11": "OU", "1.2.840.113549.1.9.1": "emailAddress", "2.5.4.5": "serialNumber",
}
_SIG = {
    "1.2.840.113549.1.1.5": "sha1WithRSAEncryption",
    "1.2.840.113549.1.1.4": "md5WithRSAEncryption",
    "1.2.840.113549.1.1.11": "sha256WithRSAEncryption",
    "1.2.840.113549.1.1.12": "sha384WithRSAEncryption",
    "1.2.840.113549.1.1.13": "sha512WithRSAEncryption",
    "1.2.840.113549.1.1.10": "rsassa-pss",
    "1.2.840.10045.4.1": "ecdsa-with-SHA1",
    "1.2.840.10045.4.3.2": "ecdsa-with-SHA256",
    "1.2.840.10045.4.3.3": "ecdsa-with-SHA384",
    "1.2.840.10045.4.3.4": "ecdsa-with-SHA512",
    "1.3.101.112": "Ed25519",
}
_CURVES = {
    "1.2.840.10045.3.1.7": ("P-256", 256),
    "1.3.132.0.34": ("P-384", 384),
    "1.3.132.0.35": ("P-521", 521),
}
_OID_RSA = "1.2.840.113549.1.1.1"
_OID_EC = "1.2.840.10045.2.1"
_OID_ED25519 = "1.3.101.112"
_OID_SAN = "2.5.29.17"
_OID_BC = "2.5.29.19"
_OID_AIA = "1.3.6.1.5.5.7.1.1"
_OID_OCSP = "1.3.6.1.5.5.7.48.1"
_OID_CAISSUERS = "1.3.6.1.5.5.7.48.2"


@dataclass
class Certificate:
    der: bytes
    subject: str
    issuer: str
    subject_der: bytes
    issuer_der: bytes
    serial: str
    not_before: datetime
    not_after: datetime
    sig_alg: str
    key_desc: str
    key_bits: int | None
    key_type: str
    dns_names: list[str] = field(default_factory=list)
    ip_addrs: list[str] = field(default_factory=list)
    is_ca: bool | None = None
    ocsp_urls: list[str] = field(default_factory=list)
    ca_issuer_urls: list[str] = field(default_factory=list)

    @property
    def fingerprint_sha256(self) -> str:
        return hashlib.sha256(self.der).hexdigest()

    @property
    def self_signed(self) -> bool:
        return self.subject_der == self.issuer_der

    def days_left(self, now: datetime | None = None) -> float:
        now = now or datetime.now(timezone.utc)
        return (self.not_after - now).total_seconds() / 86400.0


def _tlv(data: bytes, pos: int) -> tuple[int, int, int]:
    """Return (tag, value_start, value_end) of the element at pos."""
    if pos + 2 > len(data):
        raise NetcheckError("Malformed certificate (truncated).")
    tag = data[pos]
    first = data[pos + 1]
    pos += 2
    if first < 0x80:
        length = first
    else:
        n = first & 0x7F
        if n == 0 or n > 4 or pos + n > len(data):
            raise NetcheckError("Malformed certificate (bad length).")
        length = int.from_bytes(data[pos:pos + n], "big")
        pos += n
    end = pos + length
    if end > len(data):
        raise NetcheckError("Malformed certificate (length overruns).")
    return tag, pos, end


def _children(data: bytes, start: int, end: int) -> list[tuple[int, int, int, int]]:
    """Children of a constructed element: (tag, value_start, value_end, element_start)."""
    out = []
    pos = start
    while pos < end:
        tag, vs, ve = _tlv(data, pos)
        out.append((tag, vs, ve, pos))
        pos = ve
    return out


def _oid(data: bytes, vs: int, ve: int) -> str:
    raw = data[vs:ve]
    if not raw:
        raise NetcheckError("Malformed certificate (empty OID).")
    parts = [str(raw[0] // 40), str(raw[0] % 40)]
    val = 0
    for b in raw[1:]:
        val = (val << 7) | (b & 0x7F)
        if not b & 0x80:
            parts.append(str(val))
            val = 0
    return ".".join(parts)


def _string(tag: int, raw: bytes) -> str:
    if tag == 30:
        return raw.decode("utf-16-be", "replace")
    if tag == 20:
        return raw.decode("latin-1")
    return raw.decode("utf-8", "replace")


def _name(data: bytes, vs: int, ve: int) -> str:
    parts = []
    for _t, svs, sve, _e in _children(data, vs, ve):  # each RDN is a SET
        for _t2, avs, ave, _e2 in _children(data, svs, sve):  # AttributeTypeAndValue
            kids = _children(data, avs, ave)
            oid = _oid(data, kids[0][1], kids[0][2])
            val = _string(kids[1][0], data[kids[1][1]:kids[1][2]])
            parts.append(f"{_OIDS.get(oid, oid)}={val}")
    return ", ".join(parts)


def _time(tag: int, raw: bytes) -> datetime:
    s = raw.decode("ascii", "replace")
    try:
        if tag == 23:  # UTCTime YYMMDDHHMMSSZ
            yy = int(s[:2])
            year = 2000 + yy if yy < 50 else 1900 + yy
            return datetime(year, int(s[2:4]), int(s[4:6]), int(s[6:8]), int(s[8:10]),
                            int(s[10:12]), tzinfo=timezone.utc)
        return datetime(int(s[:4]), int(s[4:6]), int(s[6:8]), int(s[8:10]), int(s[10:12]),
                        int(s[12:14]), tzinfo=timezone.utc)
    except ValueError as e:
        raise NetcheckError(f"Malformed certificate time {s!r}.") from e


def _key_info(data: bytes, vs: int, ve: int) -> tuple[str, str, int | None]:
    kids = _children(data, vs, ve)
    alg = _children(data, kids[0][1], kids[0][2])
    oid = _oid(data, alg[0][1], alg[0][2])
    if oid == _OID_RSA:
        # BIT STRING (leading unused-bits byte) -> SEQUENCE { modulus, exponent }
        _tag, svs, sve = _tlv(data, kids[1][1] + 1)
        mod = _children(data, svs, sve)[0]
        raw = data[mod[1]:mod[2]].lstrip(b"\x00")
        bits = (len(raw) - 1) * 8 + raw[0].bit_length() if raw else 0
        return "RSA", f"RSA {bits} bit", bits
    if oid == _OID_EC:
        curve = _oid(data, alg[1][1], alg[1][2]) if len(alg) > 1 else ""
        name, bits = _CURVES.get(curve, (curve or "unknown curve", 0))
        return "EC", f"EC {name}", bits or None
    if oid == _OID_ED25519:
        return "Ed25519", "Ed25519", 256
    return oid, f"key algorithm {oid}", None


def parse_certificate(der: bytes) -> Certificate:
    try:
        return _parse(der)
    except IndexError as e:
        raise NetcheckError("Malformed certificate (unexpected structure).") from e


def _parse(der: bytes) -> Certificate:
    tag, vs, ve = _tlv(der, 0)
    if tag != 0x30:
        raise NetcheckError("Not a DER certificate.")
    top = _children(der, vs, ve)
    tbs = _children(der, top[0][1], top[0][2])
    i = 0
    if tbs[0][0] == 0xA0:  # explicit version
        i = 1
    serial = der[tbs[i][1]:tbs[i][2]].hex()
    sigalg = _children(der, tbs[i + 1][1], tbs[i + 1][2])
    sig_oid = _oid(der, sigalg[0][1], sigalg[0][2])
    issuer = tbs[i + 2]
    validity = _children(der, tbs[i + 3][1], tbs[i + 3][2])
    nb = _time(validity[0][0], der[validity[0][1]:validity[0][2]])
    na = _time(validity[1][0], der[validity[1][1]:validity[1][2]])
    subject = tbs[i + 4]
    key_type, key_desc, key_bits = _key_info(der, tbs[i + 5][1], tbs[i + 5][2])
    cert = Certificate(
        der=der,
        subject=_name(der, subject[1], subject[2]),
        issuer=_name(der, issuer[1], issuer[2]),
        subject_der=der[subject[3]:subject[2]],
        issuer_der=der[issuer[3]:issuer[2]],
        serial=serial,
        not_before=nb,
        not_after=na,
        sig_alg=_SIG.get(sig_oid, sig_oid),
        key_desc=key_desc,
        key_bits=key_bits,
        key_type=key_type,
    )
    for tg, evs, eve, _e in tbs[i + 6:]:
        if tg != 0xA3:
            continue
        ext_seq = _children(der, evs, eve)[0]
        for _t, xvs, xve, _e2 in _children(der, ext_seq[1], ext_seq[2]):
            parts = _children(der, xvs, xve)
            oid = _oid(der, parts[0][1], parts[0][2])
            val = parts[-1]  # OCTET STRING wrapping the extension's own DER
            _itag, ivs, ive = _tlv(der, val[1])
            if oid == _OID_SAN:
                for gt, gvs, gve, _e3 in _children(der, ivs, ive):
                    raw = der[gvs:gve]
                    if gt == 0x82:
                        cert.dns_names.append(raw.decode("ascii", "replace"))
                    elif gt == 0x87 and len(raw) in (4, 16):
                        cert.ip_addrs.append(str(ipaddress.ip_address(raw)))
            elif oid == _OID_BC:
                kids = _children(der, ivs, ive)
                cert.is_ca = bool(kids and kids[0][0] == 0x01 and der[kids[0][1]] != 0)
            elif oid == _OID_AIA:
                for _t3, avs, ave, _e4 in _children(der, ivs, ive):
                    ad = _children(der, avs, ave)
                    method = _oid(der, ad[0][1], ad[0][2])
                    if ad[1][0] == 0x86:
                        url = der[ad[1][1]:ad[1][2]].decode("ascii", "replace")
                        if method == _OID_OCSP:
                            cert.ocsp_urls.append(url)
                        elif method == _OID_CAISSUERS:
                            cert.ca_issuer_urls.append(url)
    return cert


def hostname_matches(host: str, cert: Certificate) -> bool:
    """RFC 6125 style: SAN only (no CN fallback), wildcard only as the whole leftmost label."""
    host = host.strip("[]").rstrip(".").lower()
    try:
        ip: str | None = str(ipaddress.ip_address(host))
    except ValueError:
        ip = None
    if ip is not None:
        return ip in cert.ip_addrs
    labels = host.split(".")
    for pattern in cert.dns_names:
        p = pattern.rstrip(".").lower()
        pl = p.split(".")
        if len(pl) != len(labels):
            continue
        if pl[0] == "*" and len(pl) >= 3:
            if pl[1:] == labels[1:]:
                return True
        elif p == host:
            return True
    return False
