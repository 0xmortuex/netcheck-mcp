"""MCP stdio smoke test: spawns the real server over stdio, checks the tool list, runs checks
against local lab servers, and checks that instructive errors survive the trip to the agent
(MCPServer hides any exception that isn't a ToolError)."""

import sys

import lab
import pytest

pytest.importorskip("mcp")

from mcp import ClientSession  # noqa: E402
from mcp.client.stdio import StdioServerParameters, stdio_client  # noqa: E402

EXPECTED_TOOLS = {
    "tls_check",
    "dns_lookup",
    "http_check",
    "security_headers",
    "port_check",
    "email_dns_check",
}


def params(*extra: str) -> StdioServerParameters:
    return StdioServerParameters(command=sys.executable, args=["-m", "netcheck_mcp", *extra])


@pytest.mark.anyio
async def test_tools_and_checks_over_stdio(web: lab.WebLab, dns: lab.DnsLab, tmp_path) -> None:  # type: ignore[no-untyped-def]
    web.routes["/"] = lab.Route(200, [("Content-Type", "text/plain")], b"hello")
    dns.add("ex.test", "A", "192.0.2.5", 77)
    dns.add("ex.test", "SOA", "ns.ex.test h.ex.test 1 3600 600 86400 60")
    ss = lab.make_cert("localhost", sans=["localhost", "127.0.0.1"])
    (tmp_path / "c.pem").write_bytes(ss.pem)
    (tmp_path / "k.pem").write_bytes(ss.key_pem)
    tls = lab.WebLab(lab.server_ctx(str(tmp_path / "c.pem"), str(tmp_path / "k.pem")))
    try:
        async with stdio_client(params("--allow-private")) as (read, write), ClientSession(read, write) as session:
            init = await session.initialize()
            assert init.server_info.name == "netcheck"
            tools = (await session.list_tools()).tools
            assert {t.name for t in tools} == EXPECTED_TOOLS
            assert all(t.description and len(t.description) > 80 for t in tools)

            res = await session.call_tool("http_check", {"url": web.url("/")})
            assert not res.is_error and "VERDICT" in res.content[0].text and "200 OK" in res.content[0].text  # type: ignore[union-attr]

            res = await session.call_tool("dns_lookup", {"name": "ex.test", "types": "A,MX", "resolver": dns.spec})
            text = res.content[0].text  # type: ignore[union-attr]
            assert "192.0.2.5" in text and "ttl 77" in text and "NODATA" in text

            res = await session.call_tool("tls_check", {"host": "127.0.0.1", "port": tls.port})
            assert not res.is_error and "self-signed" in res.content[0].text  # type: ignore[union-attr]

            res = await session.call_tool("port_check", {"host": "127.0.0.1", "ports": str(web.port)})
            assert "OPEN" in res.content[0].text  # type: ignore[union-attr]
    finally:
        tls.close()


@pytest.mark.anyio
async def test_instructive_errors_reach_the_agent(web: lab.WebLab) -> None:
    async with stdio_client(params()) as (read, write), ClientSession(read, write) as session:
        await session.initialize()
        res = await session.call_tool("http_check", {"url": web.url("/")})
        assert res.is_error and "SSRF" in res.content[0].text and "--allow-private" in res.content[0].text  # type: ignore[union-attr]
        res = await session.call_tool("http_check", {"url": "http://169.254.169.254/latest/meta-data/"})
        assert res.is_error and "metadata" in res.content[0].text  # type: ignore[union-attr]
        res = await session.call_tool("port_check", {"host": "example.com", "ports": "1-100"})
        assert res.is_error and "at most 20" in res.content[0].text  # type: ignore[union-attr]
        res = await session.call_tool("dns_lookup", {"name": "example.com", "resolver": "10.0.0.1"})
        assert res.is_error and "DNS resolver" in res.content[0].text  # type: ignore[union-attr]
        res = await session.call_tool("http_check", {"url": "file:///etc/passwd"})
        assert res.is_error and "scheme" in res.content[0].text  # type: ignore[union-attr]
