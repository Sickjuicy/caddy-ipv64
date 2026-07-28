# Release Notes

## v1.0.4 (2026-07-28)

### Bug Fixes
- **DynIP updater auth fixed**: adjusted the DynIP update flow for ipv64.net so record updates use the expected authenticated API path.
- **Regression tests added**: covered DNS add/delete record requests and DynIP update behavior to prevent regressions.

Install via xcaddy:

```
xcaddy build --with github.com/Sickjuicy/caddy-ipv64@v1.0.4
```

Built against Caddy v2.11.4, libdns v1.1.1, Go 1.25.

---

## v1.0.2 (2026-07-11)

### Improvements
- **DynIP uses `nic/update` endpoint**: replaced delete+add approach with ipv64.net's DynDNS2 `nic/update` endpoint for true in-place record updates. Single GET request per subdomain instead of 2 API calls. IPv4 and IPv6 combined in one call for dual-stack.
- Regression tests updated to verify single-call behavior and correct query params (`domain`, `praefix`, `ip`, `ip6`).

Install via xcaddy:

```
xcaddy build --with github.com/Sickjuicy/caddy-ipv64@v1.0.2
```

Built against Caddy v2.11.4, libdns v1.1.1, Go 1.25.

---

## v1.0.1 (2026-07-11)

### Bug Fixes
- **DynIP duplicate-record fix**: IP changes no longer create duplicate DNS records. Old record is now deleted before adding the new one.
- DynIP API requests now use properly encoded form payloads.
- Regression tests added for delete-before-add sequence.

Install via xcaddy:

```
xcaddy build --with github.com/Sickjuicy/caddy-ipv64@v1.0.1
```

Built against Caddy v2.11.4, libdns v1.1.1, Go 1.25.

---

## v1.0.0 (2026-07-09)

First stable release. Production-tested with wildcard and single-domain certificates, DynIP, and automatic renewal on ipv64.net.

### Breaking Changes
- `propagation_delay_seconds` replaced by `propagation_timeout_seconds` + `propagation_poll_interval`
- Active DNS propagation polling replaces blind fixed delay

### New Features
- **Active DNS Propagation Checking**: Polls DNS resolvers until TXT record is visible instead of blind waiting. Best case ~10s, returns early when ready.
- **DynDNS IP Updates** (`dynip` block): Optional automatic A/AAAA record creation for one or more subdomains.
- **DS-Lite Support**: Auto-detects IPv6-only networks. Explicit `dslite` mode skips IPv4 detection entirely.
- **Auto-Detection**: Automatically detects dual-stack, IPv4-only, or DS-Lite mode on first run.
- **Multi-Subdomain DynIP**: Update multiple subdomains in one config block.
- **IP Change Detection**: DynIP only sends API requests when the IP actually changes — no unnecessary calls.

### Improvements
- Code refactored: removed dead code (`normalizeZone`), unified `apiCall` for add/delete, `slices.Contains` instead of manual loops, `strconv.Atoi` instead of `fmt.Sscanf`
- `isIpv64Domain` bug fix: now requires **both** service AND TLD to match (previously matched if either matched)
- `AppendRecords` skips non-ipv64 domains instead of returning error (prevents ACME solver stall)
- `deriveManagedZone` simplified to single parameter (zone parameter was unused)
- Response body closed immediately after each retry attempt (no `defer` in loop)
- `caddy.ModuleInfo` uses named fields (`ID:`, `New:`)

### Testing
- Internal unit tests: `isIpv64Domain`, `deriveManagedZone`, `computePrefix`, `Validate`
- External integration tests with mock HTTP server: success, retry, rate-limit, 4xx, context-cancel, form-data verification
- Full lifecycle test script: build → cert obtain → renewal → DynIP
- Renewal test verified with 2-minute emergency certificate

### Performance
| Scenario | Time | Retries |
|----------|------|---------|
| Cert obtain (fast propagation) | ~25s | 0 |
| Cert obtain (slow propagation) | ~45s | 0 |
| Cert renewal (emergency) | ~5s | 0 |
| DynIP (IP unchanged) | 0 API calls | 0 |

Install via xcaddy:

```
xcaddy build --with github.com/Sickjuicy/caddy-ipv64@v1.0.0
```

Built against Caddy v2.10.2, libdns v1.1.1, Go 1.25.

---

## v0.2.0

- New issuer module tls.issuance.acme_defaults: wrapper around Caddy's ACME issuer that sets safer DNS-01 defaults when unset
	- propagation_delay: 30s
	- propagation_timeout: 4m
- Documentation: examples for using acme_defaults in Caddyfile and JSON
- Repo cleanup: moved standalone main.go to .gitignore

Install via xcaddy:

```
xcaddy build v2.8.0 --with github.com/Sickjuicy/caddy-ipv64@v0.2.0
```

---

## v0.1.0

- Initial release of the ipv64 DNS-01 provider for Caddy v2
- Supports Caddyfile and JSON configuration
- Configurable resolvers and timing (timeout, retries, backoff, delete delay)
- Built against Caddy v2.8.0

Install via xcaddy:

```
xcaddy build v2.8.0 --with github.com/Sickjuicy/caddy-ipv64@v0.1.0
```