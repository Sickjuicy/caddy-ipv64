package caddyipv64

import "testing"

// ---------------------------------------------------------------------------
// isIpv64Domain
// ---------------------------------------------------------------------------

func TestIsIpv64Domain(t *testing.T) {
	tests := []struct {
		domain string
		want   bool
	}{
		// Valid ipv64 domains (service + TLD both match)
		{"user.ipv64.de.", true},
		{"sub.user.ipv64.de.", true},
		{"user.vpn64.net.", true},
		{"a.b.c.home64.de.", true},

		// Invalid: TLD matches but service doesn't
		{"example.de.", false},
		{"foo.bar.de.", false},
		{"something.net.", false},

		// Invalid: service matches but TLD doesn't
		{"user.ipv64.com.", false},
		{"user.vpn64.org.", false},

		// Invalid: neither matches
		{"example.com.", false},
		{"foo.bar.org.", false},

		// Too short
		{"ipv64.de.", false}, // only 2 parts
		{"de.", false},
		{"", false},
	}

	for _, tt := range tests {
		t.Run(tt.domain, func(t *testing.T) {
			got := isIpv64Domain(tt.domain)
			if got != tt.want {
				t.Errorf("isIpv64Domain(%q) = %v, want %v", tt.domain, got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// deriveManagedZone
// ---------------------------------------------------------------------------

func TestDeriveManagedZone(t *testing.T) {
	p := &Provider{}

	tests := []struct {
		name string
		fqdn string
		zone string
		want string
	}{
		{
			name: "simple subdomain",
			fqdn: "_acme-challenge.test.user.ipv64.de.",
			zone: "ipv64.de.",
			want: "user.ipv64.de",
		},
		{
			name: "wildcard with multiple subdomains",
			fqdn: "_acme-challenge.app.sub.user.ipv64.de.",
			zone: "ipv64.de.",
			want: "user.ipv64.de",
		},
		{
			name: "apex record",
			fqdn: "_acme-challenge.user.ipv64.de.",
			zone: "user.ipv64.de.",
			want: "user.ipv64.de",
		},
		{
			name: "vpn64 service",
			fqdn: "_acme-challenge.test.user.vpn64.net.",
			zone: "vpn64.net.",
			want: "user.vpn64.net",
		},
		{
			name: "non-ipv64 domain returns empty",
			fqdn: "_acme-challenge.test.example.com.",
			zone: "example.com.",
			want: "",
		},
		{
			name: "zone passed by CertMagic is generic",
			fqdn: "_acme-challenge.*.user.ipv64.de.",
			zone: "ipv64.de.",
			want: "user.ipv64.de",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := p.deriveManagedZone(tt.fqdn)
			if got != tt.want {
				t.Errorf("deriveManagedZone(%q) = %q, want %q", tt.fqdn, got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// computePrefix
// ---------------------------------------------------------------------------

func TestComputePrefix(t *testing.T) {
	p := &Provider{}

	tests := []struct {
		name    string
		fqdn    string
		managed string
		want    string
	}{
		{
			name:    "apex record returns @",
			fqdn:    "user.ipv64.de.",
			managed: "user.ipv64.de",
			want:    "@",
		},
		{
			name:    "single label prefix",
			fqdn:    "_acme-challenge.test.user.ipv64.de.",
			managed: "user.ipv64.de",
			want:    "_acme-challenge.test",
		},
		{
			name:    "multi label prefix",
			fqdn:    "_acme-challenge.app.sub.user.ipv64.de.",
			managed: "user.ipv64.de",
			want:    "_acme-challenge.app.sub",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := p.computePrefix(tt.fqdn, tt.managed)
			if got != tt.want {
				t.Errorf("computePrefix(%q, %q) = %q, want %q", tt.fqdn, tt.managed, got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Validate
// ---------------------------------------------------------------------------

func TestValidate_MissingToken(t *testing.T) {
	p := &Provider{}
	if err := p.Validate(); err == nil {
		t.Fatal("expected error for missing token")
	}
}

func TestValidate_WithToken(t *testing.T) {
	p := &Provider{Token: "some-token"}
	if err := p.Validate(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}