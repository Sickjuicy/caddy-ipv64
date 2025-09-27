package caddyipv64

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

// ModuleName is the module name for Caddy.
const ModuleName = "http.acme_ipv64"

// AcmeIPv64Module implements the Caddy HTTP handler for ACME HTTP-01 challenges via ipv64.net.
// (Stub: DNS-01 is handled by the dedicated DNS provider module.)
type AcmeIPv64Module struct {
	Token  string `json:"token,omitempty"`
	Domain string `json:"domain,omitempty"`
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
	// TODO: Challenge-Request erkennen und API-Call machen
	return next.ServeHTTP(w, r)
}

// Interface guards
var _ caddyhttp.MiddlewareHandler = (*AcmeIPv64Module)(nil)

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
	body, _ := ioutil.ReadAll(resp.Body)
	var result map[string]interface{}
	_ = json.Unmarshal(body, &result)
	return nil
}

// Register the module
func init() {
	caddy.RegisterModule(AcmeIPv64Module{})
}
