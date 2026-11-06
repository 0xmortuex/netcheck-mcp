"""email_dns_check: MX, SPF (with the 10-lookup limit), DMARC, DKIM probes, MTA-STS."""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field

from .dnswire import LookupResult, Resolver, lookup
from .guard import NetcheckError
from .report import Report

DKIM_SELECTORS = [
    "default", "google", "selector1", "selector2", "k1", "k2", "s1", "s2", "mail", "dkim",
    "smtp", "mandrill", "mxvault", "everlytickey1", "cm", "zendesk1", "sendgrid", "amazonses",
]
_MECHS = {"all", "include", "a", "mx", "ptr", "ip4", "ip6", "exists"}
MAX_LOOKUPS = 10
MAX_VOID = 2
_QUERY_BUDGET = 60


@dataclass
class SpfTerm:
    qualifier: str
    mech: str
    arg: str


@dataclass
class SpfRecord:
    terms: list[SpfTerm] = field(default_factory=list)
    redirect: str | None = None
    errors: list[str] = field(default_factory=list)


def parse_spf(text: str) -> SpfRecord:
    rec = SpfRecord()
    toks = text.split()
    for tok in toks[1:]:
        low = tok.lower()
        if "=" in tok and tok[0] not in "+-~?" and ":" not in tok.split("=")[0]:
            name, _, val = tok.partition("=")
            if name.lower() == "redirect":
                if rec.redirect:
                    rec.errors.append("more than one redirect= modifier")
                rec.redirect = val
            elif name.lower() == "exp":
                pass
            elif not name.replace("-", "").replace("_", "").replace(".", "").isalnum():
                rec.errors.append(f"malformed modifier {tok!r}")
            continue
        q = "+"
        if low[0] in "+-~?":
            q, low = low[0], low[1:]
        mech, sep, arg = low.partition(":")
        if "/" in mech and not sep:  # a/24 or mx/24 forms
            mech, _, cidr = mech.partition("/")
            arg = "/" + cidr
        if mech not in _MECHS:
            rec.errors.append(f"unknown mechanism {tok!r}")
            continue
        if mech in ("include", "exists") and not arg:
            rec.errors.append(f"{mech} needs a domain (e.g. {mech}:example.com)")
            continue
        if mech in ("ip4", "ip6"):
            try:
                ipaddress.ip_network(arg, strict=False)
                if (mech == "ip4") != (":" not in arg):
                    raise ValueError("address family mismatch")
            except ValueError:
                rec.errors.append(f"invalid {mech} value {arg!r}")
                continue
        rec.terms.append(SpfTerm(q, mech, arg))
    return rec


class _Counter:
    def __init__(self, resolver: Resolver) -> None:
        self.resolver = resolver
        self.queries = 0
        self.lookups = 0
        self.void = 0
        self.notes: list[str] = []
        self.errors: list[str] = []
        self.tree: list[str] = []

    def q(self, name: str, rtype: str) -> LookupResult:
        self.queries += 1
        if self.queries > _QUERY_BUDGET:
            raise NetcheckError("SPF expansion needed too many DNS queries; stopped (that alone is a red flag).")
        return lookup(self.resolver, name, rtype)

    def void_check(self, res: LookupResult, what: str) -> None:
        if res.status in ("NXDOMAIN", "NODATA"):
            self.void += 1
            self.notes.append(f"void lookup: {what} returned {res.status}")


def _spf_records(res: LookupResult) -> list[str]:
    return [r.data for r in res.answers if r.data.lower().startswith("v=spf1")]


def _walk(c: _Counter, domain: str, text: str, depth: int, stack: tuple[str, ...]) -> None:
    pad = "  " * depth
    rec = parse_spf(text)
    for e in rec.errors:
        c.errors.append(f"{domain}: {e}")
    c.tree.append(f"{pad}{domain}: {text}")
    for t in rec.terms:
        if t.mech in ("a", "mx", "ptr", "exists", "include"):
            c.lookups += 1
        if t.mech == "ptr":
            c.notes.append(f"{domain}: 'ptr' is deprecated (RFC 7208) and slow")
        if t.mech == "include":
            target = t.arg.lower()
            if target in stack:
                c.errors.append(f"include loop: {' -> '.join(stack + (target,))}")
                continue
            _expand(c, target, depth + 1, stack + (target,), via="include")
        elif t.mech == "a":
            dom = t.arg.split("/")[0].lstrip(":") or domain
            r4 = c.q(dom, "A")
            if r4.status in ("NXDOMAIN", "NODATA"):
                r6 = c.q(dom, "AAAA")
                if r6.status in ("NXDOMAIN", "NODATA"):
                    c.void_check(r4, f"a:{dom}")
        elif t.mech == "mx":
            dom = t.arg.split("/")[0].lstrip(":") or domain
            c.void_check(c.q(dom, "MX"), f"mx:{dom}")
        elif t.mech == "exists" and "%" not in t.arg:
            c.void_check(c.q(t.arg, "A"), f"exists:{t.arg}")
    if rec.redirect:
        c.lookups += 1
        target = rec.redirect.lower()
        if target in stack:
            c.errors.append(f"redirect loop: {' -> '.join(stack + (target,))}")
        else:
            _expand(c, target, depth + 1, stack + (target,), via="redirect")


def _expand(c: _Counter, domain: str, depth: int, stack: tuple[str, ...], via: str) -> None:
    res = c.q(domain, "TXT")
    recs = _spf_records(res)
    if not recs:
        if res.status == "NXDOMAIN" or res.status == "NODATA":
            c.void += 1
        c.errors.append(f"{via}:{domain} has no SPF record ({res.status}); evaluation gives permerror")
        return
    if len(recs) > 1:
        c.errors.append(f"{domain} publishes {len(recs)} SPF records; must be exactly one")
    _walk(c, domain, recs[0], depth, stack)


def check_spf(resolver: Resolver, domain: str, rep: Report) -> None:
    res = lookup(resolver, domain, "TXT")
    recs = _spf_records(res)
    if not recs:
        rep.add("FAIL", "spf.missing", f"No SPF record at {domain}.",
                'Publish a TXT record, e.g. "v=spf1 include:_spf.your-mail-provider.com -all"')
        return
    if len(recs) > 1:
        rep.add("FAIL", "spf.multiple", f"{len(recs)} SPF records published; receivers return permerror.",
                "Merge them into a single v=spf1 TXT record.")
    c = _Counter(resolver)
    _walk(c, domain, recs[0], 0, (domain.lower(),))
    top = parse_spf(recs[0])
    for e in c.errors:
        rep.add("FAIL", "spf.syntax", f"SPF problem: {e}.")
    if c.lookups > MAX_LOOKUPS:
        rep.add("FAIL", "spf.too_many_lookups",
                f"SPF needs {c.lookups} DNS-lookup terms; the limit is {MAX_LOOKUPS} (RFC 7208), so receivers return permerror.",
                "Flatten includes, remove unused services, or replace include: with ip4:/ip6: ranges.")
    elif c.lookups >= 8:
        rep.add("WARN", "spf.near_lookup_limit", f"SPF uses {c.lookups} of {MAX_LOOKUPS} allowed DNS lookups.",
                "Little headroom: adding another sender may break SPF.")
    else:
        rep.add("PASS", "spf.lookups_ok", f"SPF uses {c.lookups} of {MAX_LOOKUPS} allowed DNS lookups.")
    if c.void > MAX_VOID:
        rep.add("FAIL", "spf.too_many_void", f"{c.void} void lookups (limit {MAX_VOID}); receivers return permerror.",
                "Remove mechanisms that point at names with no records.")
    for n in c.notes:
        rep.add("WARN" if "deprecated" in n else "INFO", "spf.note", n + ".")
    alls = [t for t in top.terms if t.mech == "all"]
    if alls:
        q = alls[0].qualifier
        if top.terms[-1].mech != "all":
            rep.add("WARN", "spf.terms_after_all", "Terms after 'all' are never evaluated.",
                    "Move 'all' to the end.")
        if q == "-":
            rep.add("PASS", "spf.hardfail", "SPF ends in -all (hard fail).")
        elif q == "~":
            rep.add("WARN", "spf.softfail", "SPF ends in ~all (soft fail): spoofed mail is only marked, not rejected.",
                    "Once your senders are listed, switch to -all and enforce with DMARC.")
        else:
            rep.add("FAIL", "spf.permissive", f"SPF ends in {q}all: it authorises (or ignores) any sender.",
                    "Use -all (or ~all while testing).")
    elif not top.redirect:
        rep.add("WARN", "spf.no_all", "SPF has no 'all' term or redirect=: the default result is neutral.",
                "End the record with -all.")
    rep.data["spf"] = {"record": recs[0], "lookups": c.lookups, "void": c.void, "errors": c.errors}
    rep.section("SPF expansion", c.tree)


def _parse_tags(text: str) -> dict[str, str]:
    tags = {}
    for part in text.split(";"):
        k, sep, v = part.strip().partition("=")
        if sep:
            tags[k.strip().lower()] = v.strip()
    return tags


def check_dmarc(resolver: Resolver, domain: str, rep: Report) -> None:
    name = f"_dmarc.{domain}"
    res = lookup(resolver, name, "TXT")
    recs = [r.data for r in res.answers if r.data.lower().replace(" ", "").startswith("v=dmarc1")]
    if not recs:
        rep.add("FAIL", "dmarc.missing", f"No DMARC record at {name}.",
                f'Publish TXT {name}: "v=DMARC1; p=none; rua=mailto:dmarc@{domain}" then tighten to quarantine/reject.')
        return
    if len(recs) > 1:
        rep.add("FAIL", "dmarc.multiple", "More than one DMARC record; receivers ignore all of them.",
                "Keep exactly one.")
    tags = _parse_tags(recs[0])
    policy = tags.get("p", "").lower()
    rep.data["dmarc"] = {"record": recs[0], "p": policy}
    if policy == "reject":
        rep.add("PASS", "dmarc.reject", "DMARC policy is p=reject.")
    elif policy == "quarantine":
        rep.add("PASS", "dmarc.quarantine", "DMARC policy is p=quarantine.")
    elif policy == "none":
        rep.add("WARN", "dmarc.monitor_only", "DMARC policy is p=none: monitoring only, spoofed mail is still delivered.",
                "After reviewing reports, move to p=quarantine then p=reject.")
    else:
        rep.add("FAIL", "dmarc.bad_policy", f"DMARC p= tag is missing or invalid ({tags.get('p')!r}).",
                "Set p=none, p=quarantine or p=reject.")
    pct = tags.get("pct")
    if pct and pct.isdigit() and int(pct) < 100:
        rep.add("WARN", "dmarc.pct", f"DMARC applies to only pct={pct}% of mail.", "Raise to pct=100 when ready.")
    if "rua" not in tags:
        rep.add("WARN", "dmarc.no_rua", "No rua= address: you will not receive aggregate reports.",
                f"Add rua=mailto:dmarc@{domain}")
    sp = tags.get("sp")
    if sp and sp.lower() == "none" and policy in ("quarantine", "reject"):
        rep.add("WARN", "dmarc.sp_none", "Subdomains are exempt (sp=none).", "Remove sp= or set it to reject.")


def check_dkim(resolver: Resolver, domain: str, extra: list[str], rep: Report) -> None:
    selectors = list(dict.fromkeys(extra + DKIM_SELECTORS))
    found = []
    for sel in selectors:
        res = lookup(resolver, f"{sel}._domainkey.{domain}", "TXT")
        txt = [r.data for r in res.answers if "p=" in r.data.replace(" ", "") or r.data.lower().startswith("v=dkim1")]
        cnames = res.cname_chain
        if txt or (cnames and res.answers):
            tags = _parse_tags(txt[0]) if txt else {}
            revoked = txt and tags.get("p", "x") == ""
            found.append((sel, "revoked (empty p=)" if revoked else "key published"))
    rep.data["dkim_selectors"] = [s for s, _ in found]
    if found:
        rep.add("PASS", "dkim.found", "DKIM keys found for selector(s): " + ", ".join(f"{s} ({st})" for s, st in found) + ".")
    else:
        rep.add("INFO", "dkim.none_found",
                f"None of the {len(selectors)} common DKIM selectors has a key. This does NOT prove DKIM is absent: "
                "selectors are arbitrary (look at the DKIM-Signature: s= tag of a real message and pass it as selectors=).")


def check_mx(resolver: Resolver, domain: str, rep: Report) -> None:
    res = lookup(resolver, domain, "MX")
    if res.status == "NXDOMAIN":
        rep.add("FAIL", "mx.nxdomain", f"{domain} does not exist (NXDOMAIN).")
        return
    if not res.answers:
        rep.add("FAIL", "mx.missing", f"{domain} has no MX records, so it cannot receive mail (RFC 5321 falls back to A, which is fragile).",
                "Publish MX records, or a null MX ('0 .') if the domain never receives mail.")
        return
    mxs = sorted((int(r.data.split()[0]), r.data.split()[1].rstrip(".")) for r in res.answers)
    rep.data["mx"] = [f"{p} {h}" for p, h in mxs]
    if len(mxs) == 1 and mxs[0][1] == "":
        rep.add("INFO", "mx.null", "Null MX: the domain declares it does not receive mail.")
        return
    bad = []
    for _p, host in mxs[:6]:
        a = lookup(resolver, host, "A")
        if a.cname_chain:
            bad.append(f"{host} is a CNAME")
        if not a.answers:
            a6 = lookup(resolver, host, "AAAA")
            if not a6.answers:
                bad.append(f"{host} has no A/AAAA")
    if bad:
        rep.add("FAIL", "mx.bad_target", "MX target problem: " + "; ".join(bad) + ".",
                "MX must point at hostnames with A/AAAA records, never at CNAMEs.")
    else:
        rep.add("PASS", "mx.ok", f"{len(mxs)} MX record(s), all targets resolve.")
    if len(mxs) == 1:
        rep.add("INFO", "mx.single", "Only one MX host; there is no backup mail server.")


def check_mta_sts(resolver: Resolver, domain: str, rep: Report) -> None:
    res = lookup(resolver, f"_mta-sts.{domain}", "TXT")
    sts = [r.data for r in res.answers if r.data.lower().startswith("v=stsv1")]
    if sts:
        rep.add("PASS", "mtasts.present", f"MTA-STS record present: {sts[0]}")
    else:
        rep.add("INFO", "mtasts.missing", f"No MTA-STS record at _mta-sts.{domain} (optional; protects inbound mail from TLS downgrade).",
                f'TXT _mta-sts.{domain}: "v=STSv1; id=<timestamp>" plus a policy file at https://mta-sts.{domain}/.well-known/mta-sts.txt')
    rpt = lookup(resolver, f"_smtp._tls.{domain}", "TXT")
    if any(r.data.lower().startswith("v=tlsrptv1") for r in rpt.answers):
        rep.add("INFO", "tlsrpt.present", "TLS-RPT record present.")


def email_dns_check(domain: str, resolver: Resolver, selectors: list[str] | None = None) -> Report:
    domain = domain.strip().rstrip(".").lower()
    if not domain or "/" in domain or " " in domain or "@" in domain:
        raise NetcheckError(f"{domain!r} is not a domain name (give e.g. 'example.com', not an address or URL).")
    rep = Report(f"Email DNS check: {domain} (resolver {resolver.label})")
    check_mx(resolver, domain, rep)
    check_spf(resolver, domain, rep)
    check_dmarc(resolver, domain, rep)
    check_dkim(resolver, domain, selectors or [], rep)
    check_mta_sts(resolver, domain, rep)
    return rep
