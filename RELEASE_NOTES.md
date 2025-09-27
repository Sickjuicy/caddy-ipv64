# Release Notes

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

## v0.1.0

- Initial release of the ipv64 DNS-01 provider for Caddy v2
- Supports Caddyfile and JSON configuration
- Configurable resolvers and timing (timeout, retries, backoff, delete delay)
- Built against Caddy v2.8.0

Install via xcaddy:

```
xcaddy build v2.8.0 --with github.com/Sickjuicy/caddy-ipv64@v0.1.0
```
