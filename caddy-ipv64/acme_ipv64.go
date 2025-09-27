package caddyipv64

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.uber.org/zap"
)

// ModuleName is the module name for Caddy.
// It must be under http.handlers.* to be used as a HTTP middleware/handler.
const ModuleName = "http.handlers.acme_ipv64"

// AcmeIPv64Module implements the Caddy HTTP handler for ACME HTTP-01 challenges via ipv64.net.
// (Stub: DNS-01 is handled by the dedicated DNS provider module.)
type AcmeIPv64Module struct {
	// Token is the ipv64 DynDNS key (Bearer-like token) used for the update endpoint.
	Token string `json:"token,omitempty"`

	// Domain is the hostname managed at ipv64 that should resolve to this server (A/AAAA via DynDNS API).
	Domain string `json:"domain,omitempty"`

	// UpdateOnStart triggers a DynDNS update during provisioning/startup.
	UpdateOnStart bool `json:"update_on_start,omitempty"`

	// IntervalSeconds triggers periodic updates (set to 0 to disable).
	IntervalSeconds int `json:"interval_seconds,omitempty"`

	// UpdateOnChallenge updates right before serving an ACME HTTP-01 request path.
	// Note: DNS propagation is not instantaneous; prefer UpdateOnStart and/or intervals.
	UpdateOnChallenge bool `json:"update_on_challenge,omitempty"`

	// internal ticker control
	stopPeriodic chan struct{}
}

// CaddyModule returns the Caddy module information.
func (AcmeIPv64Module) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  ModuleName,
		New: func() caddy.Module { return new(AcmeIPv64Module) },
	}
}

// Provision sets up the module.
func (m *AcmeIPv64Module) Provision(ctx caddy.Context) error {
	// Validate early to avoid silent misconfigurations
	if err := m.Validate(); err != nil {
		return err
	}

	lg := ctx.Logger(m)

	if m.UpdateOnStart {
		if err := m.ipv64Update(""); err != nil {
			lg.Warn("ipv64 dynDNS update on start failed", zap.Error(err))
		} else {
			lg.Debug("ipv64 dynDNS update on start succeeded")
		}
	}

	if m.IntervalSeconds > 0 {
		m.stopPeriodic = make(chan struct{})
		interval := time.Duration(m.IntervalSeconds) * time.Second
		go func() {
			ticker := time.NewTicker(interval)
			defer ticker.Stop()
			for {
				select {
				case <-ticker.C:
					if err := m.ipv64Update(""); err != nil {
						lg.Warn("ipv64 dynDNS periodic update failed", zap.Error(err))
					} else {
						lg.Debug("ipv64 dynDNS periodic update succeeded")
					}
				case <-m.stopPeriodic:
					return
				}
			}
		}()
	}

	return nil
}

// Validate validates the module config.
func (m *AcmeIPv64Module) Validate() error {
	if m.Token == "" || m.Domain == "" {
		return fmt.Errorf("token and domain must be set")
	}
	return nil
}

// ServeHTTP handles HTTP-01 ACME challenges by updating ipv64.net.
func (m *AcmeIPv64Module) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	// Optionally trigger a DynDNS update when we detect an ACME HTTP-01 request.
	if m.UpdateOnChallenge && strings.HasPrefix(r.URL.Path, "/.well-known/acme-challenge/") {
		// Fire-and-forget; do not block the response path.
		go m.ipv64Update("")
	}
	return next.ServeHTTP(w, r)
}

// Interface guards
var _ caddyhttp.MiddlewareHandler = (*AcmeIPv64Module)(nil)
var _ caddy.CleanerUpper = (*AcmeIPv64Module)(nil)

// Cleanup stops background routines.
func (m *AcmeIPv64Module) Cleanup() error {
	if m.stopPeriodic != nil {
		close(m.stopPeriodic)
	}
	return nil
}

// UnmarshalCaddyfile configures the module from Caddyfile.
func (m *AcmeIPv64Module) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	for d.Next() {
		for d.NextBlock(0) {
			switch d.Val() {
			case "token":
				if !d.NextArg() {
					return d.ArgErr()
				}
				m.Token = d.Val()
			case "domain":
				if !d.NextArg() {
					return d.ArgErr()
				}
				m.Domain = d.Val()
			case "update_on_start":
				m.UpdateOnStart = true
			case "interval_seconds":
				if !d.NextArg() {
					return d.ArgErr()
				}
				var v int
				if _, err := fmt.Sscanf(d.Val(), "%d", &v); err != nil || v < 0 {
					return d.Errf("invalid interval_seconds: %s", d.Val())
				}
				m.IntervalSeconds = v
			case "update_on_challenge":
				m.UpdateOnChallenge = true
			}
		}
	}
	return nil
}

// ipv64Update calls the ipv64.net DynDNS2 API to update the challenge record.
func (m *AcmeIPv64Module) ipv64Update(ip string) error {
	apiURL := "https://ipv64.net/nic/update"
	params := url.Values{}
	params.Set("key", m.Token)
	params.Set("domain", m.Domain)
	if ip != "" {
		params.Set("ip", ip)
	}
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(apiURL + "?" + params.Encode())
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("ipv64.net API error: %s", resp.Status)
	}
	body, _ := io.ReadAll(resp.Body)
	var result map[string]interface{}
	_ = json.Unmarshal(body, &result)
	return nil
}

// Register the module
func init() {
	caddy.RegisterModule(AcmeIPv64Module{})
	httpcaddyfile.RegisterHandlerDirective("acme_ipv64", parseAcmeIPv64Caddyfile)
}

// parseAcmeIPv64Caddyfile parses the Caddyfile directive for this handler.
func parseAcmeIPv64Caddyfile(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	var m AcmeIPv64Module
	for h.Next() {
		for h.NextBlock(0) {
			switch h.Val() {
			case "token":
				if !h.NextArg() {
					return nil, h.ArgErr()
				}
				m.Token = h.Val()
			case "domain":
				if !h.NextArg() {
					return nil, h.ArgErr()
				}
				m.Domain = h.Val()
			case "update_on_start":
				m.UpdateOnStart = true
			case "interval_seconds":
				if !h.NextArg() {
					return nil, h.ArgErr()
				}
				var v int
				if _, err := fmt.Sscanf(h.Val(), "%d", &v); err != nil || v < 0 {
					return nil, h.Errf("invalid interval_seconds: %s", h.Val())
				}
				m.IntervalSeconds = v
			case "update_on_challenge":
				m.UpdateOnChallenge = true
			default:
				return nil, h.Errf("unrecognized option: %s", h.Val())
			}
		}
	}
	return &m, nil
}
