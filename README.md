# caddy-ipv64

An ACME DNS-01 provider for Caddy v2 that integrates with ipv64.net.

Provides Caddyfile and JSON configuration support and lets you customize DNS resolvers and timing behavior.

## Installation

Build a Caddy binary with this module using xcaddy:

```
xcaddy build v2.8.0 --with github.com/Sickjuicy/caddy-ipv64@latest
```

This produces a Caddy binary that includes the `dns.providers.ipv64` module.

## Caddyfile usage

```caddyfile
{
	# Optional: use staging first to avoid rate limits
	# acme_ca https://acme-staging-v02.api.letsencrypt.org/directory
}

example.com {
	tls {
		dns ipv64 {
			api_token {env.IPV64_API_TOKEN}
			domain example.ipv64.de

			# optional settings
			resolver ns1.ipv64.de ns2.ipv64.de
			timeout_seconds 15
			max_retries 5
			initial_backoff_ms 400
			delete_delay_seconds 20
		}
	}

	respond "Hello from Caddy + ipv64 DNS!"
}
```

Notes:
- Put the provider inside the site’s `tls { dns ... }` block.
- Set your ipv64 API token via environment variable (see below).
- Start with Let’s Encrypt staging, then switch to production when ready.

## JSON usage

Minimal example of an ACME issuer using the ipv64 DNS provider:

```json
{
	"apps": {
		"tls": {
			"certificates": {
				"automate": ["example.com"]
			},
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
											"domain": "example.ipv64.de",
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

## Environment variables

- IPV64_API_TOKEN (required): Bearer token for the ipv64 API.

## Options

All options map 1:1 between Caddyfile and JSON:

- api_token: your ipv64 API token. Prefer using an environment variable.
- domain: the base domain managed at ipv64 that contains your ACME TXT records.
- resolver: one or more DNS resolvers to use for propagation checks. If omitted, the provider uses sensible defaults that prioritize ipv64 nameservers.
- timeout_seconds: HTTP timeout per API call.
- max_retries: retry attempts on transient API errors.
- initial_backoff_ms: starting backoff when retrying.
- delete_delay_seconds: keep TXT records for a short time to accommodate ACME secondary validation before deleting them.

## Tips

- If you see “No TXT record found during secondary validation”, increase `delete_delay_seconds` or use authoritative ipv64 resolvers first.
- Use Let’s Encrypt staging while testing to avoid rate limits.

## References & internals

- ipv64.net: https://ipv64.net — DNS hosting service used by this provider.
- ipv64 API: this module talks to https://ipv64.net/api.php using a Bearer token to create and delete TXT records for ACME DNS-01.
- Caddy/CertMagic: issuance is handled by Caddy via CertMagic (https://github.com/caddyserver/certmagic) using the DNS challenge.
- libdns: the provider implements the libdns-style interfaces (AppendRecords/DeleteRecords) expected by Caddy’s DNS plugin system.
- Resolvers: by default, ipv64 nameservers (e.g., ns1.ipv64.de, ns2.ipv64.de) are preferred for propagation checks, with public resolvers as fallbacks.
