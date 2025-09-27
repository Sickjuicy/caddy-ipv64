# caddy-ipv64

An ACME DNS-01 provider for Caddy v2 integrated with ipv64.net. Includes:

- dns.providers.ipv64 – DNS-01 provider (creates/deletes TXT via API)
- tls.issuance.acme_defaults – issuer wrapper with safer DNS propagation defaults
- http.handlers.acme_ipv64 – optional DynDNS update handler (use only if needed)

## Installation / Build

Build with xcaddy (recommended: Caddy v2.10.x):

```
xcaddy build v2.10.2 --with github.com/Sickjuicy/caddy-ipv64@latest
```

Verify modules are present:

```
caddy list-modules | grep -E "ipv64|acme_defaults"
```

Expected to include at least:

- dns.providers.ipv64
- tls.issuance.acme_defaults
- http.handlers.acme_ipv64 (if you use it)

## Quick Start

1) Set your token as an environment variable:

```bash
export IPV64_API_TOKEN='YOUR_TOKEN'
```

2) Choose one of the configurations below (A or B).

Notes:
- When testing, prefer Let’s Encrypt staging first.
- Domain auto-detection: in many cases you can omit `domain`. For base zones with two labels (e.g., `ipv64.de`, `ipv64.net`, `any64.de`), the managed subzone is inferred from the ACME record name.

## Examples

<details>
  <summary><strong>Option A: Global provider (set once)</strong></summary>

Put the provider in the global options block using `acme_dns`. Applies to all sites unless overridden.

```caddyfile
{
  # acme_ca https://acme-staging-v02.api.letsencrypt.org/directory

  acme_dns ipv64 {
    api_token {env.IPV64_API_TOKEN}
    # optional:
    # resolver ns1.ipv64.net ns2.ipv64.net
    # timeout_seconds 15
    # max_retries 5
    # initial_backoff_ms 400
    # delete_delay_seconds 20
  }
}

example.com {
  # uses global ipv64 provider
  respond "OK"
}
```

</details>

<details>
  <summary><strong>Option B: Per-site provider</strong></summary>

```caddyfile
example.com {
  tls {
    dns ipv64 {
      api_token {env.IPV64_API_TOKEN}
    }
  }
  respond "OK"
}
```

</details>

<details>
  <summary><strong>Optional: Wildcard and SAN</strong></summary>

```caddyfile
# Wildcard + apex in one site (DNS-01 required for wildcard)
*.example.ipv64.de, example.ipv64.de {
  tls {
    dns ipv64 {
      api_token {env.IPV64_API_TOKEN}
    }
  }
  respond "OK"
}
```

</details>

<details>
  <summary><strong>Recommended: use acme_defaults issuer (safer DNS-01 defaults)</strong></summary>

The `acme_defaults` wrapper issuer sets better defaults for DNS propagation with DNS-01:

- propagation_delay: 30s
- propagation_timeout: 4m

You can still override these explicitly; the wrapper only sets them when not provided.

```caddyfile
example.com {
  tls {
    issuer acme_defaults
    dns ipv64 {
      api_token {env.IPV64_API_TOKEN}
    }
  }
  respond "OK"
}
```

JSON equivalent (note the issuer module name):

```json
{
  "apps": {
    "tls": {
      "certificates": { "automate": ["example.com"] },
      "automation": {
        "policies": [
          {
            "issuers": [
              {
                "module": "acme_defaults",
                "challenges": {
                  "dns": {
                    "provider": {
                      "name": "ipv64",
                      "api_token": "{env.IPV64_API_TOKEN}"
                    }
                  }
                }
              }
            ]
          }
        ]
      }
    }
  }
}
```

</details>

<details>
  <summary><strong>JSON example</strong></summary>

```json
{
  "apps": {
    "tls": {
      "certificates": { "automate": ["example.com"] },
      "automation": {
        "policies": [
          {
            "issuers": [
              {
                "module": "acme",
                "challenges": {
                  "dns": {
                    "provider": {
                      "name": "ipv64",
                      "api_token": "{env.IPV64_API_TOKEN}",
                      "resolver": ["ns1.ipv64.net", "ns2.ipv64.net"],
                      "timeout_seconds": 15,
                      "max_retries": 5,
                      "initial_backoff_ms": 400,
                      "delete_delay_seconds": 20
                    }
                  }
                }
              }
            ]
          }
        ]
      }
    }
  }
}
```

</details>

## Environment variables

- IPV64_API_TOKEN (required): token for the ipv64 API.

Set the variable before starting Caddy. Example (bash/zsh):

```bash
export IPV64_API_TOKEN='YOUR_TOKEN'
```

With systemd, you can use an EnvironmentFile.

## Options

All options map 1:1 between Caddyfile and JSON:

- api_token: your ipv64 API token. Prefer using an environment variable.
- domain: the base domain managed at ipv64 that contains your ACME TXT records. Optional; often auto-detected for ipv64-managed subzones.
- resolver: one or more DNS resolvers to use for propagation checks. If omitted, the provider uses sensible defaults that prioritize ipv64 nameservers.
- timeout_seconds: HTTP timeout per API call.
- max_retries: retry attempts on transient API errors.
- initial_backoff_ms: starting backoff when retrying.
- delete_delay_seconds: keep TXT records for a short time to accommodate ACME secondary validation before deleting them.

## Tips

- If you see “No TXT record found during secondary validation”, increase `delete_delay_seconds` and/or prioritize authoritative ipv64 resolvers.
- For testing, use Let’s Encrypt staging to avoid rate limits.

## Troubleshooting

- ipv64 API 400 "domain not found":
  - Ensure the subzone exists in your ipv64 account.
  - With auto-detection, the provider infers the subzone from your hostname; check logs for `cfg_domain`.
  - You can always override by explicitly setting `domain` in the Caddyfile.
- "api_token must be set":
  - Set `IPV64_API_TOKEN` in the environment or specify `api_token` in the Caddyfile/JSON config.

## References & internals

- ipv64.net: https://ipv64.net — DNS hosting service used by this provider.
- ipv64 API: this module uses https://ipv64.net/api.php with a bearer token to create/delete TXT records for ACME DNS-01.
- Caddy/CertMagic: issuance via CertMagic (https://github.com/caddyserver/certmagic) using the DNS challenge.
- libdns: the provider implements the libdns interfaces (AppendRecords/DeleteRecords) expected by Caddy’s DNS plugin bridge.
- Resolvers: by default, authoritative ipv64 nameservers (e.g., ns1.ipv64.net, ns2.ipv64.net) are prioritized, then public resolvers.
