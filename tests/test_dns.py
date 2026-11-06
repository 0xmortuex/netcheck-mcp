import socket
import struct

import lab
import pytest
from netcheck_mcp import dnswire
from netcheck_mcp.dnswire import lookup, make_resolver, parse_message
from netcheck_mcp.guard import NetcheckError, Policy, TargetRefused


def zone(d: lab.DnsLab) -> None:
    d.add("example.test", "SOA", "ns1.example.test hostmaster.example.test 7 3600 600 86400 120", 3600)
    d.add("example.test", "A", "192.0.2.10", 300)
    d.add("example.test", "A", "192.0.2.11", 300)
    d.add("example.test", "AAAA", "2001:db8::1", 120)
    d.add("example.test", "MX", "10 mail.example.test", 600)
    d.add("example.test", "MX", "20 mail2.example.test", 600)
    d.add("example.test", "NS", "ns1.example.test", 86400)
    d.add("example.test", "TXT", "v=spf1 -all", 60)
    d.add("example.test", "CAA", '0 issue "letsencrypt.org"', 3600)
    d.add("www.example.test", "CNAME", "cdn.example.test", 30)
    d.add("cdn.example.test", "CNAME", "edge.example.test", 45)
    d.add("edge.example.test", "A", "198.51.100.7", 20)


def resolver(d: lab.DnsLab, policy: Policy) -> dnswire.Resolver:
    return make_resolver(d.spec, policy)


def test_a_record_with_ttl(dns: lab.DnsLab, policy: Policy) -> None:
    zone(dns)
    r = lookup(resolver(dns, policy), "example.test", "A")
    assert r.status == "NOERROR"
    assert sorted((a.data, a.ttl) for a in r.answers) == [("192.0.2.10", 300), ("192.0.2.11", 300)]


@pytest.mark.parametrize(
    "rtype,expected",
    [
        ("AAAA", "2001:db8::1"),
        ("MX", "10 mail.example.test"),
        ("NS", "ns1.example.test"),
        ("TXT", "v=spf1 -all"),
        ("CAA", '0 issue "letsencrypt.org"'),
        ("SOA", "ns1.example.test hostmaster.example.test 7 3600 600 86400 120"),
    ],
)
def test_record_types_decode(dns: lab.DnsLab, policy: Policy, rtype: str, expected: str) -> None:
    zone(dns)
    r = lookup(resolver(dns, policy), "example.test", rtype)
    assert expected in [a.data for a in r.answers]


def test_cname_chain_is_followed_and_reported(dns: lab.DnsLab, policy: Policy) -> None:
    zone(dns)
    r = lookup(resolver(dns, policy), "www.example.test", "A")
    assert [(c.name, c.data, c.ttl) for c in r.cname_chain] == [
        ("www.example.test", "cdn.example.test", 30),
        ("cdn.example.test", "edge.example.test", 45),
    ]
    assert [a.data for a in r.answers] == ["198.51.100.7"]
    assert r.status == "NOERROR"


def test_nxdomain_is_distinguished_from_nodata(dns: lab.DnsLab, policy: Policy) -> None:
    zone(dns)
    res = resolver(dns, policy)
    nx = lookup(res, "nope.example.test", "A")
    assert nx.status == "NXDOMAIN" and not nx.answers
    nd = lookup(res, "edge.example.test", "MX")  # name exists, no MX
    assert nd.status == "NODATA" and not nd.answers
    assert nx.negative_ttl == 120 and nd.negative_ttl == 120  # min(SOA ttl 3600, minimum 120)


def test_truncated_udp_reply_falls_back_to_tcp(policy: Policy) -> None:
    d = lab.DnsLab(truncate_udp=True)
    try:
        zone(d)
        r = lookup(resolver(d, policy), "example.test", "A")
        assert len(r.answers) == 2
        assert [q[2] for q in d.queries] == ["udp", "tcp"]
    finally:
        d.close()


def test_timeout_is_a_clear_error(policy: Policy) -> None:
    d = lab.DnsLab(swallow=True)
    try:
        res = resolver(d, policy)
        res.timeout = 0.4
        with pytest.raises(NetcheckError, match="did not answer"):
            lookup(res, "example.test", "A")
    finally:
        d.close()


def test_long_txt_is_reassembled(dns: lab.DnsLab, policy: Policy) -> None:
    text = "v=DKIM1; k=rsa; p=" + "A" * 600
    dns.add("sel._domainkey.example.test", "TXT", text)
    r = lookup(resolver(dns, policy), "sel._domainkey.example.test", "TXT")
    assert r.answers[0].data == text


def test_resolver_names_and_validation(policy: Policy) -> None:
    assert make_resolver("cloudflare", policy).servers == [("1.1.1.1", 53)]
    assert make_resolver("google", policy).servers == [("8.8.8.8", 53)]
    assert make_resolver("9.9.9.9", policy).servers == [("9.9.9.9", 53)]
    assert make_resolver("[2606:4700:4700::1111]:5353", policy).servers == [("2606:4700:4700::1111", 5353)]
    with pytest.raises(NetcheckError, match="Invalid resolver"):
        make_resolver("not an ip", policy)


def test_private_resolver_refused_by_default() -> None:
    with pytest.raises(TargetRefused, match="DNS resolver"):
        make_resolver("10.0.0.53", Policy())
    with pytest.raises(TargetRefused):
        make_resolver("169.254.169.254", Policy())


def test_unsupported_type_lists_supported_ones(dns: lab.DnsLab, policy: Policy) -> None:
    with pytest.raises(NetcheckError, match="Supported"):
        lookup(resolver(dns, policy), "example.test", "BOGUS")


def test_name_compression_pointers_and_loops() -> None:
    # Hand-built reply: question www.a.test A, answer owner is a pointer to the question name,
    # CNAME rdata is "x" followed by a pointer to "a.test" inside the question (offset 16).
    q = b"\x03www\x01a\x04test\x00" + struct.pack(">HH", 1, 1)
    cname_rdata = b"\x01x\xc0\x10"
    ans = b"\xc0\x0c" + struct.pack(">HHIH", 5, 1, 99, len(cname_rdata)) + cname_rdata
    msg = struct.pack(">HHHHHH", 1, 0x8180, 1, 1, 0, 0) + q + ans
    m = parse_message(msg)
    assert m.question == ("www.a.test", 1)
    assert m.answers[0].name == "www.a.test" and m.answers[0].data == "x.a.test" and m.answers[0].ttl == 99
    loop = struct.pack(">HHHHHH", 1, 0x8180, 1, 0, 0, 0) + b"\xc0\x0c" + struct.pack(">HH", 1, 1)
    with pytest.raises(NetcheckError, match="loop"):
        parse_message(loop)
    with pytest.raises(NetcheckError, match="Malformed"):
        parse_message(b"\x00\x01")


def test_build_query_wire_format() -> None:
    wire = dnswire.build_query("a.test", 1, 0x1234)
    assert wire[:2] == b"\x12\x34"
    assert wire[2:4] == b"\x01\x00"  # RD
    assert wire[4:12] == struct.pack(">HHHH", 1, 0, 0, 1)  # one question, one EDNS0 OPT
    assert wire[12:20] == b"\x01a\x04test\x00"
    assert struct.unpack(">HH", wire[20:24]) == (1, 1)
    with pytest.raises(NetcheckError):
        dnswire.build_query("a" * 64 + ".test", 1, 1)


def test_system_resolver_candidates_are_readable() -> None:
    for n in dnswire.system_nameservers():
        socket.inet_pton(socket.AF_INET6 if ":" in n else socket.AF_INET, n)
