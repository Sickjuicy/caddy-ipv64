# caddy-ipv64

Caddy v2 DNS provider module for [ipv64.net](https://ipv64.net) — DNS-01 ACME challenges for wildcard SSL certificates and optional DynDNS IP updates.

> **Note:** If you use internal DNS servers (e.g. Technitium), see [Troubleshooting — `no such host`](#no-such-host-for-nameservers) for required DNS configuration.

## Features

- **DNS-01 ACME Challenges** — individual domains, wildcards, sub-subdomains
- **Active DNS Propagation Checking** — polls resolvers instead of blind waiting (~25s vs 85s)
- **DynDNS IP Updates** — automatic A/AAAA record updates via `nic/update` (in-place, no delete needed)
- **DS-Lite Support** — auto-detects IPv6-only networks, or explicit `dslite` mode
- **Automatic Renewal** — Caddy auto-renews expiring certificates using the same DNS-01 flow
- **Multi-Subdomain DynIP** — update multiple subdomains in one config block
- **Retry with Exponential Backoff** — resilient against API rate-limits and server errors
- **Periodic Force-Update** — corrects external IP changes every ~6h even if local IP is unchanged

## Installation

**Production (stable release):**
```bash
xcaddy build --with github.com/Sickjuicy/caddy-ipv64@latest
```

**Development branch:**
```bash
xcaddy build --with github.com/Sickjuicy/caddy-ipv64@dev
```

## Environment Variables

The plugin reads the API token from the `IPV64_API_TOKEN` environment variable if not set in the Caddyfile.

**systemd (recommended):**
```bash
sudo systemctl edit caddy
```
```ini
[Service]
Environment=IPV64_API_TOKEN=your_token_here
```

**Or with a .env file:**
```ini
[Service]
EnvironmentFile=/etc/caddy/.env
```
```bash
# /etc/caddy/.env (no quotes, no spaces around =):
IPV64_API_TOKEN=your_token_here
```

> **Note:** On some systemd versions, `EnvironmentFile=` may not work with `ProtectSystem=full`.
> If the variable is empty, use `Environment=` instead (see above).

**Caddyfile usage:**
```caddyfile
api_token {env.IPV64_API_TOKEN}
```
The plugin substitutes `{env.VAR_NAME}` patterns automatically.

## Quick Start

### Minimal Config
```caddyfile
example.ipv64.de {
    tls {
        dns ipv64 {
            api_token {env.IPV64_API_TOKEN}
        }
        resolvers 1.1.1.1 8.8.8.8
        propagation_delay 30s
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
        resolvers 1.1.1.1 8.8.8.8
        propagation_delay 30s
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
4. If changed: send a single `nic/update` request per subdomain — updates A and/or AAAA in-place (no delete/re-add)
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
| DynIP (IP changed) | <1s | 1 per subdomain (nic/update) |
| DynIP (periodic force-update) | <1s | 1 per subdomain (nic/update) |

## Supported ipv64.net Services

`ipv64`, `any64`, `api64`, `dns64`, `dyndns64`, `dynipv6`, `eth64`, `home64`, `iot64`, `lan64`, `nas64`, `root64`, `route64`, `srv64`, `tcp64`, `udp64`, `vpn64`, `wan64`

Supported TLDs: `.de`, `.net`

## Troubleshooting

### 401 Unauthorized
The API token is wrong or expired. Test it directly:
```bash
curl -s -H "Authorization: Bearer YOUR_TOKEN" \
  -d "add_record=example.ipv64.de&praefix=test&type=TXT&content=hello" \
  https://ipv64.net/api
```
If this returns `401`, the token is invalid. Generate a new one at ipv64.net.

### `{env.IPV64_API_TOKEN}` not substituted
The plugin substitutes `{env.VAR}` patterns in the `api_token` field. Ensure the variable is set in the environment (see [Environment Variables](#environment-variables)).

### `no such host` for nameservers
Caddy's CertMagic does its own DNS propagation check **after** the plugin creates the TXT record.
If the SOA/NS records of your ipv64.net subdomain point to non-resolvable nameservers (e.g. `technitiumdns.`),
Caddy's check will fail even though the plugin already confirmed propagation.

**Fix 1 — Caddyfile:** Add `resolvers 1.1.1.1 8.8.8.8` in the `tls` block, **outside** the `dns ipv64` block:
```caddyfile
tls {
    dns ipv64 {
        api_token {env.IPV64_API_TOKEN}
    }
    resolvers 1.1.1.1 8.8.8.8  # <-- fixes Caddy's DNS check
}
```

**Fix 2 — DNS SOA/NS records:** Ensure the SOA and NS records for your ipv64.net subdomain
point to `ns1.ipv64.net` / `ns2.ipv64.net` (publicly resolvable), not to internal nameservers.
If you use a local DNS server like Technitium, change the SOA primary NS to `ns1.ipv64.net`
and add `ns1.ipv64.net` / `ns2.ipv64.net` as NS records.

**Fix 3 — System resolvers:** If Caddy still fails, set your system resolvers to public DNS:
```bash
echo -e "nameserver 1.1.1.1\nnameserver 8.8.8.8" > /etc/resolv.conf
```

### `No TXT record found` / `During secondary validation`
Let's Encrypt performs multi-perspective validation from multiple locations. If the TXT record
hasn't propagated to all LE validation servers yet, validation fails.

**Fix:** Add `propagation_delay 30s` in the `tls` block, **outside** the `dns ipv64` block:
```caddyfile
tls {
    dns ipv64 {
        api_token {env.IPV64_API_TOKEN}
    }
    resolvers 1.1.1.1 8.8.8.8
    propagation_delay 30s  # <-- gives LE time to reach all perspectives
}
```

The plugin's active propagation check confirms the TXT record is visible on ≥2 resolvers before
returning, but LE's secondary validators may need additional time. `propagation_delay 30s` adds
a fixed delay after the plugin returns, ensuring global propagation.

### 429 Rate Limited
Too many failed authorization attempts. Let's Encrypt limits 5 failures per identifier per hour. Wait ~1 hour or use the staging CA for testing:
```caddyfile
{
    acme_ca https://acme-staging-v02.api.letsencrypt.org/directory
}
```

### Certificate not obtained but no errors
Caddy may be in a backoff state from previous failures. Reset ACME state:
example:
```bash
sudo systemctl stop caddy
rm -rf /var/lib/caddy/.local/share/caddy/locks/issue_cert_*
sudo systemctl start caddy
```

## License

See [LICENSE](LICENSE).