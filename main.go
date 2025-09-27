package main

import (
	_ "github.com/Sickjuicy/caddy-ipv64/caddy-ipv64"
	_ "github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"     // config adapter: caddyfile
	_ "github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile" // HTTP Caddyfile support
	caddycmd "github.com/caddyserver/caddy/v2/cmd"
)

func main() {
	caddycmd.Main()
}
