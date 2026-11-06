# Changelog

## 0.1.0 - 2026-11-06

First release.

- `tls_check`: leaf certificate details (own DER parser), chain served, hostname match, trust
  verification classified into expired / not yet valid / self-signed / incomplete chain / untrusted
  root, TLS 1.0-1.3 probing, cipher, key and signature strength, PASS/WARN/FAIL with fixes.
- `dns_lookup`: stdlib DNS wire-format resolver (UDP, TCP fallback, name compression, EDNS0) for
  A, AAAA, CNAME, MX, TXT, NS, CAA, SOA, SRV, PTR; system/Cloudflare/Google/Quad9/custom resolver;
  CNAME chains, TTLs, NXDOMAIN vs NODATA.
- `http_check`: manual redirect following with per-hop DNS/connect/TLS/TTFB/total timings,
  compression, caching and HSTS checks, loop and downgrade detection.
- `security_headers`: graded A+ to F with the exact header to add.
- `port_check`: TCP reachability and passive banner grab, max 20 ports per call.
- `email_dns_check`: MX, SPF (expansion, 10-lookup and void-lookup limits), DMARC, DKIM selector
  probe, MTA-STS and TLS-RPT presence.
- SSRF guard (private/loopback/link-local/metadata refused unless `--allow-private`), connection
  pinning to the vetted address, per-hop redirect checks, size/time/redirect/port caps.
