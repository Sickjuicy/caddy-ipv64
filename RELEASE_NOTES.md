# Release Notes

## v0.1.0

- Initial release of the ipv64 DNS-01 provider for Caddy v2
- Supports Caddyfile and JSON configuration
- Configurable resolvers and timing (timeout, retries, backoff, delete delay)
- Built against Caddy v2.8.0

Install via xcaddy:

```
xcaddy build v2.8.0 --with github.com/Sickjuicy/caddy-ipv64@v0.1.0
```
