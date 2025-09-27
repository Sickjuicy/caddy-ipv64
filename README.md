# caddy-ipv64

An ACME DNS-01 provider for Caddy v2 that integrates with ipv64.net.

Provides Caddyfile and JSON configuration support and lets you customize DNS resolvers and timing behavior.

## Installation

Build a Caddy binary with this module using xcaddy:

```
xcaddy build v2.8.0 --with github.com/Sickjuicy/caddy-ipv64@latest
```

This produces a Caddy binary that includes the `dns.providers.ipv64` module.

## Quick start

1) Build a Caddy with this module:
```
xcaddy build v2.8.0 --with github.com/Sickjuicy/caddy-ipv64@latest
```
2) Provide your ipv64 API token (e.g., via environment):
```bash
export IPV64_API_TOKEN='YOUR_TOKEN'
```
3) Choose one configuration style below (A or B).

Note:
- Start with Let’s Encrypt staging while testing.
- Domain autodetection: You can usually omit `domain`. If the base zone has two labels (e.g., `ipv64.de`, `ipv64.net`, `any64.de`, ...), the provider infers your managed subzone from the ACME record name.

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
    # resolver ns1.ipv64.de ns2.ipv64.de
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
  <summary><strong>Optional: wildcard and SAN</strong></summary>

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

The wrapper issuer `acme_defaults` sets better defaults for DNS propagation when using DNS-01:

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
                      "resolver": ["ns1.ipv64.de", "ns2.ipv64.de"],
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

- IPV64_API_TOKEN (required): Bearer token for the ipv64 API.

Set it in your environment before starting Caddy. For example (bash/zsh):

```bash
export IPV64_API_TOKEN='YOUR_TOKEN'
```

You can also use a .env file if your process manager or container loads it into the environment.

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

- If you see “No TXT record found during secondary validation”, increase `delete_delay_seconds` or use authoritative ipv64 resolvers first.
- Use Let’s Encrypt staging while testing to avoid rate limits.

## Troubleshooting

- ipv64 API 400 "domain not found":
	- Ensure the subzone actually exists in your ipv64 account.
	- With autodetection, the provider infers the subzone from your hostname; double-check logs for `cfg_domain`.
	- You can always override by explicitly setting `domain` in the Caddyfile.
- "api_token must be set":
	- Set `IPV64_API_TOKEN` in the environment or specify `api_token` in the Caddyfile/JSON config.

## References & internals

- ipv64.net: https://ipv64.net — DNS hosting service used by this provider.
- ipv64 API: this module talks to https://ipv64.net/api.php using a Bearer token to create and delete TXT records for ACME DNS-01.
- Caddy/CertMagic: issuance is handled by Caddy via CertMagic (https://github.com/caddyserver/certmagic) using the DNS challenge.
- libdns: the provider implements the libdns-style interfaces (AppendRecords/DeleteRecords) expected by Caddy’s DNS plugin system.
- Resolvers: by default, ipv64 nameservers (e.g., ns1.ipv64.de, ns2.ipv64.de) are preferred for propagation checks, with public resolvers as fallbacks.
