# netcheck-mcp

**Ask your AI "is my site healthy and configured right?" and get a verdict with the exact fix.**

<!-- mcp-name: io.github.0xmortuex/netcheck-mcp -->

netcheck-mcp is an [MCP](https://modelcontextprotocol.io) server with six focused checks for TLS,
DNS, HTTP, security headers, ports and email DNS. Every result starts with a `VERDICT: PASS | WARN | FAIL`,
and every problem comes with a concrete fix (the header line to add, the record to publish, the file to serve).

**What is different from other site-audit MCP servers.** The closest I found are all-in-one "audit this site"
servers such as [security-mcp](https://github.com/pratham-jain33/security-mcp) (one graded `audit_site` call that bundles
headers, certificate and email-auth DNS) and certificate *management* servers such as
[CERT-MCP-SERVER](https://github.com/wouter-bon/CERT-MCP-SERVER). I only read their READMEs, not their code. netcheck-mcp is a
diagnosis toolkit instead: separate tools the agent can combine, and checks that tell *why* something is wrong:

- **TLS failures are told apart**: expired vs not-yet-valid vs self-signed vs *incomplete chain* (server forgot the
  intermediate) vs untrusted root vs wrong hostname, each with its own fix. It parses the X.509 itself, so it can describe
  certificates that fail verification, which Python's `ssl` module refuses to decode.
- **A hand-written DNS resolver** (RFC 1035 over UDP with TCP fallback, name compression, TTLs, CNAME chains) with no
  `dnspython`, that separates **NXDOMAIN from NODATA** and can ask any resolver (system, 1.1.1.1, 8.8.8.8, or a specific IP).
- **SPF is actually expanded**: includes and redirects are followed and the 10-lookup and 2-void-lookup limits are counted
  the way receivers count them.
- **SSRF protection by design** (see Security), and tests that are hermetic: local CAs, local TLS/HTTP servers and a local
  DNS server, with the real-internet checks (example.com, badssl.com) in a separate opt-in suite.
- One runtime dependency: `mcp`.

## What it looks like

Real output (`tls_check incomplete-chain.badssl.com`, abridged):

```
TLS check: incomplete-chain.badssl.com:443 (104.154.89.105)
VERDICT: FAIL

[FAIL] Server sends an incomplete chain: it ends at a certificate issued by 'C=US, O=Let's Encrypt, CN=YR1', which is not in the trust store (unable to get local issuer certificate).
       fix: Serve the intermediate certificate(s) too: use the 'fullchain' file (leaf + intermediates), not just the leaf certificate.
[WARN] Server still offers TLSv1.0, which is deprecated (RFC 8996).
       fix: Disable TLSv1.0: allow TLS 1.2 and 1.3 only (e.g. nginx: ssl_protocols TLSv1.2 TLSv1.3;).
[INFO] TLS 1.3 is not offered (TLS 1.2 works).
[PASS] Certificate is valid for another 52 day(s).
[PASS] Certificate covers incomplete-chain.badssl.com.

Handshake:
  protocol TLSv1.2, cipher ECDHE-RSA-AES128-GCM-SHA256
  supported: TLSv1.0=offered, TLSv1.1=offered, TLSv1.2=offered, TLSv1.3=not offered
Chain served (1 certificate(s)):
  [0] CN=*.badssl.com  (issuer: C=US, O=Let's Encrypt, CN=YR1; expires 2026-12-28)
```

And from `email_dns_check` (against the test DNS server, an SPF record with too many includes):

```
[FAIL] SPF needs 14 DNS-lookup terms; the limit is 10 (RFC 7208), so receivers return permerror.
       fix: Flatten includes, remove unused services, or replace include: with ip4:/ip6: ranges.
```

## Tools

| Tool | What it answers |
|---|---|
| `tls_check(host, port=443)` | Certificate subject/SAN/issuer/validity/days left, chain served, hostname match, trust, TLS 1.0-1.3 offered, cipher. Expiry under 30 days WARN, under 14 FAIL. |
| `dns_lookup(name, types="A,AAAA", resolver="system")` | A AAAA CNAME MX TXT NS CAA SOA SRV PTR with TTLs, the CNAME chain, NXDOMAIN vs NODATA (with negative-cache TTL). |
| `http_check(url)` | Redirect chain with each hop's status and DNS/connect/TLS/TTFB/total ms, final URL, compression, caching headers, HSTS, downgrade and loop detection. |
| `security_headers(url)` | Grade A+ to F for HSTS, CSP (unsafe-inline/eval, wildcards), clickjacking, nosniff, Referrer-Policy, Permissions-Policy, cookie flags, version leaks, with the exact header to add. |
| `port_check(host, ports)` | TCP open/closed/filtered for up to 20 ports plus a passive banner grab; warns on exposed databases, RDP, telnet. |
| `email_dns_check(domain, resolver, selectors)` | MX health, SPF syntax + lookup/void limits, DMARC policy, DKIM selector probe, MTA-STS / TLS-RPT presence. |

Try asking:

- "Is the certificate on example.com okay? When does it expire, and is the chain complete?"
- "Why does https://shop.example.com redirect so many times? Show me each hop and how long it took."
- "Grade the security headers on my site and give me the nginx lines to fix them."
- "My domain's mail is going to spam. Check SPF, DKIM and DMARC for example.org."
- "Does www.example.com resolve the same on Cloudflare and Google DNS? What are the TTLs?"
- "Is port 5432 on my server reachable from the internet?"
- "Is `staging.example.com` returning NXDOMAIN or just no A record?"

## Install

Requires Python 3.10+. Nothing else.

**Claude Code**

```bash
claude mcp add netcheck -- uvx netcheck-mcp
```

**Claude Desktop** (`claude_desktop_config.json`)

```json
{
  "mcpServers": {
    "netcheck": {
      "command": "uvx",
      "args": ["netcheck-mcp"]
    }
  }
}
```

Or `pip install netcheck-mcp` and run `netcheck-mcp`.

To check hosts on your own network (a NAS, a staging box at 10.x, `localhost`), start it with the explicit opt-in flag:
`"args": ["netcheck-mcp", "--allow-private"]`.

## Security and responsible use

This server makes network connections on behalf of an AI agent, so it is deliberately cautious:

- **SSRF guard.** By default every target is resolved and **refused** if any address is loopback, private (RFC 1918/ULA),
  link-local, CGNAT, multicast, reserved or a cloud metadata endpoint (`169.254.169.254` and friends). This blocks the
  classic "make the server fetch its own internal services" attack, including numeric-IP spellings, IPv4-mapped IPv6 and
  hostnames that resolve to internal addresses.
- **No DNS rebinding.** The address that passed the check is the address that gets connected to; the name is not looked up a second time.
- **Every redirect hop is re-checked**, so a public site cannot bounce you into the internal network. Redirects to non-http(s) schemes and URLs with embedded credentials are refused.
- **`--allow-private`** lifts the block for the whole process. Only the person who configures the server can set it; the agent cannot.
- **Hard caps**: 10 redirects, 1 MiB of body, 30 s total per HTTP check, 5 s connect timeout, **at most 20 ports per call**,
  one host per call. CIDR ranges are rejected. This is a health checker, not a scanner.
- **No secrets sent**: no cookies, no `Authorization`, no custom headers; the only request header beyond `Host` is a `netcheck-mcp/<version>` User-Agent.
- **A custom DNS resolver** you pass is held to the same private-address rule. The `system` resolver is whatever the machine already uses (it was configured by the machine's owner, not by the agent).

**Only test hosts you own or are authorised to test.** Port probing and repeated requests against third parties can be
unwelcome or against their terms of service. You are responsible for what you point this at.

## Limits you should know

- **OCSP stapling is not reported.** Python's `ssl` module cannot see a stapled response. `tls_check` reports the certificate's OCSP responder URL instead.
- Probing TLS 1.0/1.1 needs a client OpenSSL that still allows them. When it does not, the result says `untestable` rather than guessing "not offered".
- Some DNS providers (Cloudflare among them) answer a nonexistent name with NOERROR/NODATA instead of NXDOMAIN ("compact denial of existence"). netcheck-mcp reports what the resolver said, so such names show as NODATA.
- DKIM selectors are arbitrary, so the probe of common selectors can find keys but can never prove there is none. Pass your own via `selectors`.
- DMARC is looked up at exactly `_dmarc.<domain>`; the organisational-domain fallback for subdomains needs the Public Suffix List and is not done.
- The `system` DNS resolver on Windows is read from the registry (adapter settings), on Linux/macOS from `/etc/resolv.conf`.

## Development

```bash
uv sync --extra test
uv run pytest                 # hermetic: local CA, TLS/HTTP servers and DNS server
uv run pytest -m network      # optional: real example.com / badssl.com
uv run ruff check src tests && uv run mypy --strict src
```

`cryptography` is a **test-only** dependency: the tests mint throwaway CAs and certificates (expired, self-signed, wrong
host, missing intermediate) at run time. The server itself parses certificates with its own DER reader.

There is a from-scratch tutorial that builds a small version of this server step by step:
[netcheck-mcp-the-hard-way](https://github.com/0xmortuex/netcheck-mcp-the-hard-way).

## License

MIT
