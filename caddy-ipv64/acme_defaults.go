package caddyipv64

import (
	"time"

	caddy "github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddytls"
)

// AcmeDefaultsIssuer is a thin wrapper around Caddy's built-in ACME issuer.
// It applies safer defaults for DNS-01 reliability and then delegates entirely
// to the upstream issuer. Specifically, if not explicitly configured by the user:
//   - propagation_delay   => 30s
//   - propagation_timeout => 4m
//
// These defaults help when authoritative resolvers or CAs observe changes with delay.
// Users can still override these values in config; non-zero values are respected.
type AcmeDefaultsIssuer struct {
	caddytls.ACMEIssuer
}

// CaddyModule implements caddy.Module.
func (AcmeDefaultsIssuer) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "tls.issuance.acme_defaults",
		New: func() caddy.Module { return new(AcmeDefaultsIssuer) },
	}
}

// Provision sets default propagation values (if unset) and then provisions the embedded issuer.
func (iss *AcmeDefaultsIssuer) Provision(ctx caddy.Context) error {
	// Ensure nested structs exist
	if iss.Challenges == nil {
		iss.Challenges = new(caddytls.ChallengesConfig)
	}
	if iss.Challenges.DNS == nil {
		iss.Challenges.DNS = new(caddytls.DNSChallengeConfig)
	}

	// Apply safer defaults only when user hasn't set them (zero value)
	if iss.Challenges.DNS.PropagationDelay == 0 {
		iss.Challenges.DNS.PropagationDelay = caddy.Duration(30 * time.Second)
	}
	if iss.Challenges.DNS.PropagationTimeout == 0 {
		iss.Challenges.DNS.PropagationTimeout = caddy.Duration(4 * time.Minute)
	}

	return iss.ACMEIssuer.Provision(ctx)
}

// UnmarshalCaddyfile delegates to the embedded ACME issuer, so syntax is identical.
func (iss *AcmeDefaultsIssuer) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	return iss.ACMEIssuer.UnmarshalCaddyfile(d)
}

func init() {
	caddy.RegisterModule(AcmeDefaultsIssuer{})
}

// Interface assertions
var (
	_ caddy.Provisioner     = (*AcmeDefaultsIssuer)(nil)
	_ caddyfile.Unmarshaler = (*AcmeDefaultsIssuer)(nil)
)
