import socket
import threading

import pytest
from netcheck_mcp.guard import NetcheckError, Policy, TargetRefused
from netcheck_mcp.ports import parse_ports, port_check


def free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = int(s.getsockname()[1])
    s.close()
    return p


class BannerServer:
    """TCP listener that greets with a banner (SSH-style) or stays silent (HTTP-style)."""

    def __init__(self, banner: bytes | None) -> None:
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(5)
        self.port: int = self.sock.getsockname()[1]
        self.banner = banner
        self.received: list[bytes] = []
        threading.Thread(target=self._run, daemon=True).start()

    def _run(self) -> None:
        while True:
            try:
                c, _ = self.sock.accept()
            except OSError:
                return
            with c:
                if self.banner:
                    c.sendall(self.banner)
                c.settimeout(0.5)
                try:
                    self.received.append(c.recv(100))
                except OSError:
                    pass

    def close(self) -> None:
        self.sock.close()


def test_open_closed_and_banner(policy: Policy) -> None:
    ssh = BannerServer(b"SSH-2.0-OpenSSH_9.6\r\n")
    quiet = BannerServer(None)
    dead = free_port()
    try:
        rep = port_check("127.0.0.1", [ssh.port, quiet.port, dead], policy, timeout=6.0, banner_wait=0.5)
    finally:
        ssh.close()
        quiet.close()
    by_port = {r["port"]: r for r in rep.data["results"]}
    assert by_port[ssh.port]["state"] == "open" and by_port[ssh.port]["banner"] == "SSH-2.0-OpenSSH_9.6"
    assert by_port[quiet.port]["state"] == "open" and by_port[quiet.port]["banner"] == ""
    assert by_port[dead]["state"] == "closed"
    assert "SSH-2.0-OpenSSH_9.6" in rep.render() and "refused" in rep.render()
    assert quiet.received == [b""] or all(r == b"" for r in quiet.received)  # nothing was sent to it


def test_open_port_passes_and_exposed_database_port_warns(policy: Policy, monkeypatch: pytest.MonkeyPatch) -> None:
    from netcheck_mcp import ports

    srv = BannerServer(b"+PONG\r\n")
    try:
        rep = port_check("127.0.0.1", srv.port, policy, timeout=2.0, banner_wait=0.3)
        assert f"port.open_{srv.port}" in rep.codes("PASS")
        monkeypatch.setitem(ports._EXPOSED, srv.port, "Redis")  # pretend this is a database port
        rep = port_check("127.0.0.1", srv.port, policy, timeout=2.0, banner_wait=0.3)
        assert f"port.exposed_{srv.port}" in rep.codes("WARN") and rep.verdict == "WARN"
    finally:
        srv.close()


def test_timeout_means_filtered(monkeypatch: pytest.MonkeyPatch) -> None:
    from netcheck_mcp import ports

    def hang(*a: object, **k: object) -> socket.socket:
        raise TimeoutError("timed out")

    monkeypatch.setattr(ports.socket, "create_connection", hang)
    r = ports._probe("192.0.2.1", 81, 0.5, 0.1)
    assert r["state"] == "filtered" and "firewall" in str(r["detail"])


@pytest.mark.parametrize(
    "spec,expected",
    [
        ("22,80,443", [22, 80, 443]),
        ("22 80", [22, 80]),
        ("8000-8003", [8000, 8001, 8002, 8003]),
        ([80, 80, 443], [80, 443]),
        (443, [443]),
    ],
)
def test_parse_ports(spec: object, expected: list[int]) -> None:
    assert parse_ports(spec, 20) == expected  # type: ignore[arg-type]


@pytest.mark.parametrize("spec", ["", "0", "65536", "abc", "10-5", "1-1000", ",".join(str(p) for p in range(1, 22))])
def test_parse_ports_rejects(spec: str) -> None:
    with pytest.raises(NetcheckError):
        parse_ports(spec, 20)


def test_twenty_ports_is_the_cap(policy: Policy) -> None:
    ok = parse_ports(",".join(str(p) for p in range(100, 120)), 20)
    assert len(ok) == 20
    with pytest.raises(NetcheckError, match="at most 20"):
        port_check("127.0.0.1", ",".join(str(p) for p in range(100, 121)), policy)


def test_cidr_ranges_are_refused(policy: Policy) -> None:
    with pytest.raises(NetcheckError, match="range or a URL"):
        port_check("192.168.0.0/24", "80", policy)


def test_loopback_refused_by_default() -> None:
    with pytest.raises(TargetRefused):
        port_check("127.0.0.1", "80", Policy())
