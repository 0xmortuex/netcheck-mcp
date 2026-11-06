import lab
import pytest
from netcheck_mcp.dnswire import make_resolver
from netcheck_mcp.emaildns import email_dns_check, parse_spf
from netcheck_mcp.guard import NetcheckError, Policy
from netcheck_mcp.report import Report


def base(d: lab.DnsLab, domain: str = "ex.test") -> None:
    d.add(domain, "SOA", f"ns.{domain} h.{domain} 1 3600 600 86400 60", 3600)
    d.add(domain, "MX", f"10 mail.{domain}")
    d.add(f"mail.{domain}", "A", "192.0.2.25")


def run(d: lab.DnsLab, policy: Policy, domain: str = "ex.test", **kw: object) -> Report:
    return email_dns_check(domain, make_resolver(d.spec, policy), **kw)  # type: ignore[arg-type]


def test_perfectly_configured_domain(dns: lab.DnsLab, policy: Policy) -> None:
    base(dns)
    dns.add("ex.test", "TXT", "v=spf1 mx include:_spf.mailer.test ip4:192.0.2.0/24 -all")
    dns.add("_spf.mailer.test", "TXT", "v=spf1 ip4:203.0.113.0/24 -all")
    dns.add("_dmarc.ex.test", "TXT", "v=DMARC1; p=reject; rua=mailto:d@ex.test")
    dns.add("google._domainkey.ex.test", "TXT", "v=DKIM1; k=rsa; p=MIIBIjANBgkq")
    dns.add("_mta-sts.ex.test", "TXT", "v=STSv1; id=2026")
    rep = run(dns, policy)
    assert rep.verdict == "PASS", rep.render()
    assert rep.data["spf"]["lookups"] == 2  # mx + include
    assert rep.data["dmarc"]["p"] == "reject"
    assert rep.data["dkim_selectors"] == ["google"]
    assert {"mx.ok", "spf.hardfail", "dmarc.reject", "dkim.found", "mtasts.present"} <= rep.codes("PASS")


def test_nothing_published_fails_everywhere(dns: lab.DnsLab, policy: Policy) -> None:
    dns.add("bare.test", "SOA", "ns.bare.test h.bare.test 1 3600 600 86400 60")
    dns.add("bare.test", "A", "192.0.2.1")
    rep = run(dns, policy, "bare.test")
    assert {"mx.missing", "spf.missing", "dmarc.missing"} <= rep.codes("FAIL")
    assert "dkim.none_found" in rep.codes("INFO") and "does NOT prove" in rep.render()
    assert "mtasts.missing" in rep.codes("INFO")


def test_spf_lookup_limit_counted_across_includes(dns: lab.DnsLab, policy: Policy) -> None:
    base(dns)
    # top: 4 includes + a + mx = 6 terms; each include has 2 more -> 6 + 8 = 14
    inc = [f"s{i}.vendor.test" for i in range(4)]
    dns.add("ex.test", "TXT", "v=spf1 " + " ".join(f"include:{h}" for h in inc) + " a mx -all")
    dns.add("ex.test", "A", "192.0.2.1")
    for h in inc:
        dns.add(h, "TXT", "v=spf1 a mx -all")
        dns.add(h, "A", "192.0.2.2")
        dns.add(h, "MX", "10 mx.vendor.test")
    rep = run(dns, policy)
    assert rep.data["spf"]["lookups"] == 14
    assert "spf.too_many_lookups" in rep.codes("FAIL")
    assert "14 DNS-lookup terms; the limit is 10" in rep.render()


def test_spf_exactly_ten_is_ok_but_warned_near_limit(dns: lab.DnsLab, policy: Policy) -> None:
    base(dns)
    dns.add("ex.test", "TXT", "v=spf1 " + " ".join(f"include:i{i}.v.test" for i in range(10)) + " -all")
    for i in range(10):
        dns.add(f"i{i}.v.test", "TXT", "v=spf1 ip4:203.0.113.0/24 -all")
    rep = run(dns, policy)
    assert rep.data["spf"]["lookups"] == 10
    assert "spf.too_many_lookups" not in rep.codes()
    assert "spf.near_lookup_limit" in rep.codes("WARN")


def test_spf_redirect_counts_and_loops_are_caught(dns: lab.DnsLab, policy: Policy) -> None:
    base(dns)
    dns.add("ex.test", "TXT", "v=spf1 redirect=a.test")
    dns.add("a.test", "TXT", "v=spf1 include:b.test -all")
    dns.add("b.test", "TXT", "v=spf1 include:a.test -all")
    rep = run(dns, policy)
    assert rep.data["spf"]["lookups"] >= 3
    assert any("loop" in e for e in rep.data["spf"]["errors"])
    assert "spf.syntax" in rep.codes("FAIL")


def test_spf_void_lookups(dns: lab.DnsLab, policy: Policy) -> None:
    base(dns)
    dns.add("ex.test", "TXT", "v=spf1 include:gone1.test include:gone2.test include:gone3.test -all")
    rep = run(dns, policy)
    assert "spf.too_many_void" in rep.codes("FAIL")


def test_spf_qualifiers(dns: lab.DnsLab, policy: Policy) -> None:
    base(dns)
    dns.add("ex.test", "TXT", "v=spf1 mx ~all")
    assert "spf.softfail" in run(dns, policy).codes("WARN")
    dns.zone[("ex.test", "TXT")] = [(300, "v=spf1 mx +all")]
    assert "spf.permissive" in run(dns, policy).codes("FAIL")
    dns.zone[("ex.test", "TXT")] = [(300, "v=spf1 mx")]
    assert "spf.no_all" in run(dns, policy).codes("WARN")


def test_two_spf_records_fail(dns: lab.DnsLab, policy: Policy) -> None:
    base(dns)
    dns.add("ex.test", "TXT", "v=spf1 mx -all")
    dns.add("ex.test", "TXT", "v=spf1 a -all")
    assert "spf.multiple" in run(dns, policy).codes("FAIL")


@pytest.mark.parametrize(
    "record,problem",
    [
        ("v=spf1 ip4:300.1.1.1 -all", "invalid ip4"),
        ("v=spf1 ip6:192.0.2.1 -all", "invalid ip6"),
        ("v=spf1 bogus:foo -all", "unknown mechanism"),
        ("v=spf1 include -all", "needs a domain"),
    ],
)
def test_spf_syntax_errors(record: str, problem: str) -> None:
    assert any(problem in e for e in parse_spf(record).errors)


def test_spf_parse_ok_forms() -> None:
    r = parse_spf("v=spf1 +a/24 mx:mail.x.test/28 ip6:2001:db8::/32 exists:%{i}.x.test ?all exp=why.x.test")
    assert not r.errors
    assert [t.mech for t in r.terms] == ["a", "mx", "ip6", "exists", "all"]


def test_dmarc_policies(dns: lab.DnsLab, policy: Policy) -> None:
    base(dns)
    dns.add("_dmarc.ex.test", "TXT", "v=DMARC1; p=none")
    rep = run(dns, policy)
    assert {"dmarc.monitor_only", "dmarc.no_rua"} <= rep.codes("WARN")
    dns.zone[("_dmarc.ex.test", "TXT")] = [(300, "v=DMARC1; p=quarantine; pct=50; rua=mailto:a@ex.test")]
    rep = run(dns, policy)
    assert "dmarc.quarantine" in rep.codes("PASS") and "dmarc.pct" in rep.codes("WARN")
    dns.zone[("_dmarc.ex.test", "TXT")] = [(300, "v=DMARC1; p=oops")]
    assert "dmarc.bad_policy" in run(dns, policy).codes("FAIL")


def test_dkim_custom_selector_and_revoked_key(dns: lab.DnsLab, policy: Policy) -> None:
    base(dns)
    dns.add("mail2026._domainkey.ex.test", "TXT", "v=DKIM1; k=rsa; p=MIIB")
    dns.add("old._domainkey.ex.test", "TXT", "v=DKIM1; p=")
    rep = run(dns, policy, selectors=["mail2026", "old"])
    assert rep.data["dkim_selectors"] == ["mail2026", "old"]
    assert "revoked" in rep.render()


def test_mx_pointing_at_cname_is_flagged(dns: lab.DnsLab, policy: Policy) -> None:
    dns.add("ex.test", "SOA", "ns.ex.test h.ex.test 1 3600 600 86400 60")
    dns.add("ex.test", "MX", "10 mail.ex.test")
    dns.add("mail.ex.test", "CNAME", "real.host.test")
    dns.add("real.host.test", "A", "192.0.2.9")
    rep = run(dns, policy)
    assert "mx.bad_target" in rep.codes("FAIL") and "CNAME" in rep.render()


def test_nonexistent_domain_and_bad_input(dns: lab.DnsLab, policy: Policy) -> None:
    dns.add("other.test", "SOA", "ns.other.test h.other.test 1 3600 600 86400 60")
    dns.add("other.test", "A", "192.0.2.1")
    assert "mx.nxdomain" in run(dns, policy, "ghost.other.test").codes("FAIL")
    for bad in ("user@ex.test", "https://ex.test", "ex test", ""):
        with pytest.raises(NetcheckError, match="not a domain"):
            run(dns, policy, bad)
