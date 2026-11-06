"""Hermetic test lab: throwaway CAs and certificates, a TLS/HTTP server, a DNS server.

Nothing here touches the internet. Certificates are minted at test time with the
`cryptography` package (a TEST-only dependency: writing an X.509 *signer* in the
stdlib is out of scope, and shelling out to an openssl CLI is not portable to
every CI runner).
"""

from __future__ import annotations

import datetime as dt
import ipaddress
import socket
import ssl
import struct
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID

UTC = dt.timezone.utc


def _name(cn: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


class Ident:
    """A certificate plus its private key."""

    def __init__(self, cert: x509.Certificate, key: Any) -> None:
        self.cert = cert
        self.key = key

    @property
    def pem(self) -> bytes:
        return self.cert.public_bytes(serialization.Encoding.PEM)

    @property
    def key_pem(self) -> bytes:
        return self.key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )


def make_cert(
    cn: str,
    *,
    issuer: Ident | None = None,
    ca: bool = False,
    sans: list[str] | None = None,
    days: int = 90,
    not_before: dt.datetime | None = None,
    not_after: dt.datetime | None = None,
    rsa_bits: int | None = None,
    sign_hash: hashes.HashAlgorithm | None = None,
) -> Ident:
    key: Any = rsa.generate_private_key(65537, rsa_bits) if rsa_bits else ec.generate_private_key(ec.SECP256R1())
    now = dt.datetime.now(UTC)
    nb = not_before or now - dt.timedelta(days=1)
    na = not_after or nb + dt.timedelta(days=days)
    builder = (
        x509.CertificateBuilder()
        .subject_name(_name(cn))
        .issuer_name(issuer.cert.subject if issuer else _name(cn))
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(nb)
        .not_valid_after(na)
        .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
    )
    # Python 3.13 verifies with VERIFY_X509_STRICT, which wants SKI/AKI and keyUsage on CAs.
    builder = builder.add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
    if issuer is not None:
        builder = builder.add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer.key.public_key()), critical=False)
    else:
        builder = builder.add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(key.public_key()), critical=False)
    if ca:
        builder = builder.add_extension(x509.KeyUsage(
            digital_signature=True, content_commitment=False, key_encipherment=False, data_encipherment=False,
            key_agreement=False, key_cert_sign=True, crl_sign=True, encipher_only=False, decipher_only=False),
            critical=True)
    if sans:
        names: list[x509.GeneralName] = []
        for s in sans:
            try:
                names.append(x509.IPAddress(ipaddress.ip_address(s)))
            except ValueError:
                names.append(x509.DNSName(s))
        builder = builder.add_extension(x509.SubjectAlternativeName(names), critical=False)
    if issuer is None:
        signer: Any = key
    else:
        signer = issuer.key
    cert = builder.sign(signer, sign_hash or hashes.SHA256())
    return Ident(cert, key)


class Pki:
    """root CA -> intermediate CA -> helper to issue leaves."""

    def __init__(self, tmp_path: Any, label: str = "Lab") -> None:
        self.root = make_cert(f"{label} Root CA", ca=True, days=3650)
        self.inter = make_cert(f"{label} Intermediate CA", issuer=self.root, ca=True, days=3650)
        self.dir = tmp_path
        self.root_file = str(tmp_path / "root.pem")
        (tmp_path / "root.pem").write_bytes(self.root.pem)
        self._n = 0

    def leaf(self, cn: str = "localhost", sans: list[str] | None = None, **kw: Any) -> Ident:
        return make_cert(cn, issuer=self.inter, sans=sans if sans is not None else ["localhost", "127.0.0.1"], **kw)

    def files(self, leaf: Ident, *, with_intermediate: bool, extra: list[Ident] | None = None) -> tuple[str, str]:
        """Write chain + key files. Returns (chain_file, key_file)."""
        self._n += 1
        chain = leaf.pem + (self.inter.pem if with_intermediate else b"") + b"".join(e.pem for e in extra or [])
        cf = self.dir / f"chain{self._n}.pem"
        kf = self.dir / f"key{self._n}.pem"
        cf.write_bytes(chain)
        kf.write_bytes(leaf.key_pem)
        return str(cf), str(kf)


def server_ctx(chain: str, key: str, min_v: ssl.TLSVersion | None = None, max_v: ssl.TLSVersion | None = None,
               legacy: bool = False) -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    if legacy:
        ctx.set_ciphers("ALL:@SECLEVEL=0")
    ctx.load_cert_chain(chain, key)
    if min_v is not None:
        ctx.minimum_version = min_v
    if max_v is not None:
        ctx.maximum_version = max_v
    return ctx


class Route:
    def __init__(self, status: int = 200, headers: list[tuple[str, str]] | None = None, body: bytes = b"",
                 delay: float = 0.0) -> None:
        self.status = status
        self.headers = headers or []
        self.body = body
        self.delay = delay


class WebLab:
    """HTTP or HTTPS server on 127.0.0.1 with a mutable route table. Responses are written raw."""

    def __init__(self, ctx: ssl.SSLContext | None = None) -> None:
        self.routes: dict[str, Route] = {}
        self.requests: list[dict[str, Any]] = []
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def handle_one_request(self) -> None:  # noqa: D102
                try:
                    super().handle_one_request()
                except (ssl.SSLError, OSError):
                    self.close_connection = True

            def do_GET(self) -> None:  # noqa: N802
                outer.requests.append({"path": self.path, "headers": dict(self.headers.items())})
                route = outer.routes.get(self.path.split("?")[0]) or outer.routes.get(self.path)
                if route is None:
                    route = Route(404, [("Content-Type", "text/plain")], b"not found")
                if route.delay:
                    threading.Event().wait(route.delay)
                reason = {200: "OK", 301: "Moved Permanently", 302: "Found", 404: "Not Found"}.get(route.status, "X")
                head = f"HTTP/1.1 {route.status} {reason}\r\n"
                hdrs = list(route.headers)
                if not any(k.lower() == "content-length" for k, _ in hdrs):
                    hdrs.append(("Content-Length", str(len(route.body))))
                hdrs.append(("Connection", "close"))
                head += "".join(f"{k}: {v}\r\n" for k, v in hdrs) + "\r\n"
                try:
                    self.wfile.write(head.encode("latin-1") + route.body)
                except OSError:
                    pass
                self.close_connection = True

            def log_message(self, *a: Any) -> None:  # silence
                pass

        class Server(ThreadingHTTPServer):
            daemon_threads = True

            def get_request(self) -> tuple[Any, Any]:
                sock, addr = super().get_request()
                if ctx is not None:
                    sock = ctx.wrap_socket(sock, server_side=True, do_handshake_on_connect=False)
                return sock, addr

            def handle_error(self, request: Any, client_address: Any) -> None:
                pass

        self.httpd = Server(("127.0.0.1", 0), Handler)
        self.port: int = self.httpd.server_address[1]
        self.scheme = "https" if ctx is not None else "http"
        self._t = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self._t.start()

    def url(self, path: str = "/", host: str = "127.0.0.1") -> str:
        return f"{self.scheme}://{host}:{self.port}{path}"

    def close(self) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()


# --- DNS -------------------------------------------------------------------

def _enc_name(name: str) -> bytes:
    name = name.rstrip(".")
    out = b""
    for label in name.split(".") if name else []:
        out += bytes([len(label)]) + label.encode()
    return out + b"\x00"


def _rdata(rtype: str, text: str) -> bytes:
    if rtype == "A":
        return socket.inet_aton(text)
    if rtype == "AAAA":
        return socket.inet_pton(socket.AF_INET6, text)
    if rtype in ("NS", "CNAME", "PTR"):
        return _enc_name(text)
    if rtype == "MX":
        pref, host = text.split()
        return struct.pack(">H", int(pref)) + _enc_name(host)
    if rtype == "TXT":
        raw = text.encode()
        chunks = [raw[i:i + 255] for i in range(0, max(len(raw), 1), 255)]
        return b"".join(bytes([len(c)]) + c for c in chunks)
    if rtype == "SOA":
        m, r, *nums = text.split()
        return _enc_name(m) + _enc_name(r) + struct.pack(">IIIII", *map(int, nums))
    if rtype == "CAA":
        flags, tag, val = text.split(" ", 2)
        t = tag.encode()
        return bytes([int(flags), len(t)]) + t + val.strip('"').encode()
    raise ValueError(rtype)


CODES = {"A": 1, "NS": 2, "CNAME": 5, "SOA": 6, "PTR": 12, "MX": 15, "TXT": 16, "AAAA": 28, "CAA": 257}


class DnsLab:
    """Authoritative-style UDP+TCP DNS server on 127.0.0.1 driven by a tiny zone table."""

    def __init__(self, *, truncate_udp: bool = False, swallow: bool = False) -> None:
        self.zone: dict[tuple[str, str], list[tuple[int, str]]] = {}
        self.queries: list[tuple[str, str, str]] = []
        self.truncate_udp = truncate_udp
        self.swallow = swallow
        # DNS needs the SAME port number for UDP and TCP. The OS picks the UDP port, but that
        # number can be reserved or in use for TCP (Windows excluded ranges give WinError 10013,
        # other OSes EADDRINUSE), so retry with a fresh port until both protocols bind.
        last: OSError | None = None
        for _ in range(50):
            udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            try:
                udp.bind(("127.0.0.1", 0))
                tcp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                tcp.bind(("127.0.0.1", udp.getsockname()[1]))
                tcp.listen(5)
            except OSError as e:
                last = e
                udp.close()
                tcp.close()
                continue
            self.udp, self.tcp = udp, tcp
            break
        else:
            raise RuntimeError(f"no port free for both UDP and TCP after 50 tries: {last}")
        self.port: int = self.udp.getsockname()[1]
        self._stop = False
        self._threads = [threading.Thread(target=self._udp_loop, daemon=True),
                         threading.Thread(target=self._tcp_loop, daemon=True)]
        for t in self._threads:
            t.start()

    @property
    def spec(self) -> str:
        return f"127.0.0.1:{self.port}"

    def add(self, name: str, rtype: str, rdata: str, ttl: int = 300) -> None:
        self.zone.setdefault((name.lower().rstrip("."), rtype), []).append((ttl, rdata))

    def _answer(self, wire: bytes, via: str) -> bytes | None:
        qid, _flags, _qd = struct.unpack(">HHH", wire[:6])
        pos = 12
        labels = []
        while wire[pos]:
            n = wire[pos]
            labels.append(wire[pos + 1:pos + 1 + n].decode())
            pos += 1 + n
        qtype = struct.unpack(">H", wire[pos + 1:pos + 3])[0]
        question = wire[12:pos + 5]
        qname = ".".join(labels).lower()
        tname = {v: k for k, v in CODES.items()}.get(qtype, "?")
        self.queries.append((qname, tname, via))
        if self.swallow:
            return None
        if via == "udp" and self.truncate_udp:
            return struct.pack(">HHHHHH", qid, 0x8380 | 0x0200 & 0xFFFF, 1, 0, 0, 0) + question
        answers: list[tuple[str, str, int, str]] = []
        cur = qname
        for _ in range(8):
            cn = self.zone.get((cur, "CNAME"))
            if cn and tname != "CNAME":
                answers.append((cur, "CNAME", cn[0][0], cn[0][1]))
                cur = cn[0][1].lower().rstrip(".")
                continue
            break
        for ttl, data in self.zone.get((cur, tname), []):
            answers.append((cur, tname, ttl, data))
        exists = any(k[0] == qname or k[0] == cur for k in self.zone)
        rcode = 0 if (answers or exists) else 3
        authority = b""
        nscount = 0
        if not [a for a in answers if a[1] == tname]:
            apex = ".".join(qname.split(".")[-2:])
            for ttl, data in self.zone.get((apex, "SOA"), []):
                rd = _rdata("SOA", data)
                authority += _enc_name(apex) + struct.pack(">HHIH", 6, 1, ttl, len(rd)) + rd
                nscount += 1
        body = b""
        for owner, rt, ttl, data in answers:
            rd = _rdata(rt, data)
            if owner == qname:
                nm = b"\xc0\x0c"  # compression pointer to the question name
            else:
                nm = _enc_name(owner)
            body += nm + struct.pack(">HHIH", CODES[rt], 1, ttl, len(rd)) + rd
        header = struct.pack(">HHHHHH", qid, 0x8180 | rcode, 1, len(answers), nscount, 0)
        return header + question + body + authority

    def _udp_loop(self) -> None:
        self.udp.settimeout(0.2)
        while not self._stop:
            try:
                data, addr = self.udp.recvfrom(2048)
            except (TimeoutError, socket.timeout):
                continue
            except OSError:
                return
            out = self._answer(data, "udp")
            if out is not None:
                self.udp.sendto(out, addr)

    def _tcp_loop(self) -> None:
        self.tcp.settimeout(0.2)
        while not self._stop:
            try:
                conn, _ = self.tcp.accept()
            except (TimeoutError, socket.timeout):
                continue
            except OSError:
                return
            with conn:
                conn.settimeout(2)
                try:
                    ln = struct.unpack(">H", conn.recv(2))[0]
                    data = b""
                    while len(data) < ln:
                        data += conn.recv(ln - len(data))
                    out = self._answer(data, "tcp")
                    if out is not None:
                        conn.sendall(struct.pack(">H", len(out)) + out)
                except OSError:
                    pass

    def close(self) -> None:
        self._stop = True
        self.udp.close()
        self.tcp.close()
