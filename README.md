# caddy-ipv64

Caddy v2 DNS provider module for [ipv64.net](https://ipv64.net) — DNS-01 ACME challenges for wildcard SSL certificates and optional DynDNS IP updates.

## Features

- **DNS-01 ACME Challenges** — individual domains, wildcards, sub-subdomains
- **Active DNS Propagation Checking** — polls resolvers instead of blind waiting (~25s vs 85s)
- **DynDNS IP Updates** — automatic A/AAAA record creation with auto-detection
- **DS-Lite Support** — auto-detects IPv6-only networks, or explicit `dslite` mode
- **Automatic Renewal** — Caddy auto-renews expiring certificates using the same DNS-01 flow
- **Multi-Subdomain DynIP** — update multiple subdomains in one config block
- **Retry with Exponential Backoff** — resilient against API rate-limits and server errors
- **Periodic Force-Update** — corrects external IP changes every ~6h even if local IP is unchanged

## Installation

```bash
xcaddy build --with github.com/Sickjuicy/caddy-ipv64@dev
```

## Quick Start

### Minimal Config
```caddyfile
example.ipv64.de {
    tls {
        dns ipv64 {
            api_token {env.IPV64_API_TOKEN}
        }
    }
    respond "Hello"
}
```

### Full Config (DNS-01 + DynIP)
```caddyfile
example.ipv64.de {
    tls {
        dns ipv64 {
            api_token {env.IPV64_API_TOKEN}
            resolvers ns1.ipv64.net ns2.ipv64.net 1.1.1.1 8.8.8.8

            # Optional: propagation tuning
            propagation_timeout_seconds 60
            propagation_poll_interval 5

            # Optional: HTTP client tuning
            timeout_seconds 30
            max_retries 5
            initial_backoff_ms 500

            # Optional: DynDNS IP updates
            dynip {
                subdomain example.ipv64.de
                subdomain vpn.example.ipv64.de
                interval 30m
                # ipv4_only     # only A records
                # ipv6_only     # only AAAA records
                # dslite        # DS-Lite: IPv6 only, skip IPv4 detection
            }
        }
    }
    respond "Hello"
}
```

## Configuration Reference

### DNS Provider Options

| Option | Default | Description |
|--------|---------|-------------|
| `api_token` | (env `IPV64_API_TOKEN`) | Required API token |
| `resolvers` | `ns1.ipv64.net:53, ns2.ipv64.net:53` | DNS resolvers for propagation checking |
| `propagation_timeout_seconds` | 60 | Max time to wait for DNS propagation (0 = disable) |
| `propagation_poll_interval` | 5 | Seconds between propagation polls |
| `timeout_seconds` | 30 | HTTP client timeout |
| `max_retries` | 5 | Max API retry attempts |
| `initial_backoff_ms` | 500 | Initial backoff (exponential) |

### DynIP Options

| Option | Default | Description |
|--------|---------|-------------|
| `subdomain` | (required) | One or more subdomains to update (repeatable) |
| `interval` | 30m | Time between IP update checks (accepts `30m`, `1h`, `6h`, `24h`) |
| `ipv4_only` | false | Only create A records |
| `ipv6_only` | false | Only create AAAA records |
| `dslite` | false | DS-Lite mode: skip IPv4 detection entirely |

### DynIP Auto-Detection

If no explicit mode (`ipv4_only`, `ipv6_only`, `dslite`) is set, the provider auto-detects on first run:

- IPv4 + IPv6 available → **dual-stack** (A + AAAA)
- IPv4 only → **IPv4-only** (A only)
- IPv6 only → **DS-Lite** (AAAA only, skip IPv4)
- No public IP → **warning** logged

## How It Works

### DNS-01 Challenge Flow
1. CertMagic requests DNS-01 challenge for a domain
2. Plugin creates TXT record via ipv64.net API (`add_record`)
3. **Active propagation check**: polls DNS resolvers every 5s until TXT record visible on ≥2
4. CertMagic triggers Let's Encrypt validation → `valid`
5. Plugin deletes TXT record (`del_record`) — automatic cleanup
6. Certificate obtained

### Automatic Renewal
Caddy's `tls.cache.maintenance` monitors certificates and auto-renews at 1/3 remaining lifetime. The renewal uses the same DNS-01 flow — no manual intervention needed.

### DynIP Flow
1. Detect public IPv4/IPv6 via ipv64.net and ipify.org
2. Auto-detect network mode (dual-stack / IPv4-only / DS-Lite)
3. **Skip if IP unchanged** — no unnecessary API calls
4. If changed: create A and/or AAAA records for each configured subdomain
5. **Periodic force-update** every ~6h (12 cycles) — corrects external modifications even if local IP is unchanged
6. Repeat at configured interval (default: 30 minutes)

## Testing

### Unit Tests (no API needed)
```bash
go test -v -count=1 -timeout 60s ./...
```

### Full Lifecycle Test (needs API token)
```powershell
$env:IPV64_API_TOKEN = "your_token"
.\tests\run-lifecycle-test.ps1 -Domain "example.ipv64.de"
```

This tests: build → cert obtain → automatic renewal → DynIP record creation.

## Performance

| Scenario | Time | API Calls |
|----------|------|-----------|
| Cert obtain (fast propagation) | ~25s | 2 (create + delete TXT) |
| Cert renewal (emergency) | ~5s | 2 (create + delete TXT) |
| DynIP (IP unchanged) | 0s | 0 (skipped) |
| DynIP (IP changed) | <1s | 1 per subdomain |
| DynIP (periodic force-update) | <1s | 1 per subdomain |

## Supported ipv64.net Services

`ipv64`, `any64`, `api64`, `dns64`, `dyndns64`, `dynipv6`, `eth64`, `home64`, `iot64`, `lan64`, `nas64`, `root64`, `route64`, `srv64`, `tcp64`, `udp64`, `vpn64`, `wan64`

Supported TLDs: `.de`, `.net`

## License

See [LICENSE](LICENSE).