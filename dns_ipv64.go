package caddyipv64

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/libdns/libdns"
	"go.uber.org/zap"
)

// Provider implements libdns for ipv64.net and a Caddy DNS provider module.
type Provider struct {
	Token                string   `json:"api_token,omitempty" caddy:"namespace=dns.providers.ipv64"`
	Domain               string   `json:"domain,omitempty"`
	Resolvers            []string `json:"resolvers,omitempty"`
	TimeoutSeconds       int      `json:"timeout_seconds,omitempty"`
	MaxRetries           int      `json:"max_retries,omitempty"`
	InitialBackoffMillis int      `json:"initial_backoff_ms,omitempty"`
	DeleteDelaySeconds   int      `json:"delete_delay_seconds,omitempty"`

	logger *zap.Logger
}

// Note: We implement AppendRecords/DeleteRecords required by Caddy's libdns bridge.
// GetRecords/SetRecords are optional and implemented as stubs below.

// Caddy module registration
func (Provider) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "dns.providers.ipv64",
		New: func() caddy.Module { return new(Provider) },
	}
}

// Provision sets defaults and environment fallbacks.
func (p *Provider) Provision(ctx caddy.Context) error {
	p.logger = ctx.Logger(p)
	if p.Token == "" {
		p.Token = os.Getenv("IPV64_API_TOKEN")
	}
	if p.TimeoutSeconds <= 0 {
		p.TimeoutSeconds = 10
	}
	if p.MaxRetries <= 0 {
		p.MaxRetries = 5
	}
	if p.InitialBackoffMillis <= 0 {
		p.InitialBackoffMillis = 400
	}
	if p.DeleteDelaySeconds < 0 {
		p.DeleteDelaySeconds = 0
	}
	if len(p.Resolvers) == 0 {
		// Prefer ipv64 nameservers first, then common public resolvers
		p.Resolvers = []string{
			"ns1.ipv64.net:53",
			"ns2.ipv64.net:53",
			"1.1.1.1:53",
			"8.8.8.8:53",
			"9.9.9.9:53",
		}
	} else {
		// normalize to include :53 if missing
		for i, r := range p.Resolvers {
			if !strings.Contains(r, ":") {
				p.Resolvers[i] = r + ":53"
			}
		}
	}
	return nil
}

// Validate ensures required fields are present.
func (p *Provider) Validate() error {
	if p.Token == "" {
		return errors.New("api_token is required (or set IPV64_API_TOKEN)")
	}
	return nil
}

// SetResolvers can be used by tests to override resolvers.
func (p *Provider) SetResolvers(resolvers []string) {
	p.Resolvers = resolvers
}

// AppendRecords creates TXT records for the ACME dns-01 challenge.
func (p *Provider) AppendRecords(ctx context.Context, zone string, recs []libdns.Record) ([]libdns.Record, error) {
	if err := p.Validate(); err != nil {
		return nil, err
	}
	zone = normalizeZone(zone)
	client := &http.Client{Timeout: time.Duration(p.TimeoutSeconds) * time.Second}

	var appended []libdns.Record
	for _, r := range recs {
		rr := r.RR()
		fqdn := libdns.AbsoluteName(rr.Name, zone)
		value := rr.Data
		// ipv64.net expects relative label under the managed domain
		managed := p.deriveManagedZone(fqdn, zone)
		if managed == "" {
			return appended, fmt.Errorf("cannot derive managed zone for %s in zone %s", fqdn, zone)
		}
		// Compute relative prefix under managed zone
		prefix := strings.TrimSuffix(strings.TrimSuffix(fqdn, "."+managed), ".")
		if prefix == managed {
			prefix = "@"
		}

		reqBody := map[string]string{
			"domain":  managed,
			"type":    "TXT",
			"name":    prefix,
			"content": value,
		}
		enc, _ := json.Marshal(reqBody)
		url := "https://ipv64.net/api/dns/add"
		err := p.doWithRetry(ctx, client, http.MethodPost, url, enc)
		if err != nil {
			return appended, err
		}
		appended = append(appended, r)
		if p.logger != nil {
			p.logger.Debug("ipv64: appended TXT", zap.String("fqdn", fqdn), zap.String("zone", managed))
		}
	}
	return appended, nil
}

// DeleteRecords deletes TXT records, optionally with a configurable delay.
func (p *Provider) DeleteRecords(ctx context.Context, zone string, recs []libdns.Record) ([]libdns.Record, error) {
	if err := p.Validate(); err != nil {
		return nil, err
	}
	zone = normalizeZone(zone)
	client := &http.Client{Timeout: time.Duration(p.TimeoutSeconds) * time.Second}

	// Delay delete to reduce flakiness during secondary validation
	if p.DeleteDelaySeconds > 0 {
		select {
		case <-time.After(time.Duration(p.DeleteDelaySeconds) * time.Second):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}

	var deleted []libdns.Record
	for _, r := range recs {
		rr := r.RR()
		fqdn := libdns.AbsoluteName(rr.Name, zone)
		managed := p.deriveManagedZone(fqdn, zone)
		if managed == "" {
			continue
		}
		prefix := strings.TrimSuffix(strings.TrimSuffix(fqdn, "."+managed), ".")
		if prefix == managed {
			prefix = "@"
		}
		reqBody := map[string]string{
			"domain": managed,
			"type":   "TXT",
			"name":   prefix,
		}
		enc, _ := json.Marshal(reqBody)
		url := "https://ipv64.net/api/dns/delete"
		if err := p.doWithRetry(ctx, client, http.MethodPost, url, enc); err != nil {
			if p.logger != nil {
				p.logger.Warn("ipv64: delete failed", zap.String("fqdn", fqdn), zap.Error(err))
			}
			continue
		}
		deleted = append(deleted, r)
		if p.logger != nil {
			p.logger.Debug("ipv64: deleted TXT", zap.String("fqdn", fqdn), zap.String("zone", managed))
		}
	}
	return deleted, nil
}

// doWithRetry performs HTTP requests with backoff for 5xx and 429 statuses.
func (p *Provider) doWithRetry(ctx context.Context, client *http.Client, method, url string, body []byte) error {
	backoff := time.Duration(p.InitialBackoffMillis) * time.Millisecond
	for attempt := 0; attempt < p.MaxRetries; attempt++ {
		req, err := http.NewRequestWithContext(ctx, method, url, strings.NewReader(string(body)))
		if err != nil {
			return err
		}
		req.Header.Set("Authorization", "Bearer "+p.Token)
		req.Header.Set("Content-Type", "application/json")
		resp, err := client.Do(req)
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Temporary() {
				time.Sleep(backoff)
				backoff *= 2
				continue
			}
			return err
		}
		// Drain body
		_ = resp.Body.Close()
		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			return nil
		}
		if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500 {
			time.Sleep(backoff)
			backoff *= 2
			continue
		}
		return fmt.Errorf("ipv64 API error: %s", resp.Status)
	}
	return fmt.Errorf("ipv64 API failed after %d attempts", p.MaxRetries)
}

// deriveManagedZone tries to find the longest matching suffix of fqdn within zone.
func (p *Provider) deriveManagedZone(fqdn, zone string) string {
	fqdn = strings.TrimSuffix(fqdn, ".")
	zone = strings.TrimSuffix(zone, ".")
	if fqdn == zone {
		return zone
	}
	// Skip _acme-challenge when deriving
	parts := strings.Split(fqdn, ".")
	for i := 0; i < len(parts); i++ {
		cand := strings.Join(parts[i:], ".")
		if cand == zone || strings.HasSuffix(zone, "."+cand) || strings.HasSuffix(cand, "."+zone) {
			if strings.HasPrefix(parts[i], "_acme-challenge") && i+1 < len(parts) {
				return strings.Join(parts[i+1:], ".")
			}
			return cand
		}
	}
	return zone
}

func normalizeZone(z string) string {
	if !strings.HasSuffix(z, ".") {
		z += "."
	}
	return z
}

// UnmarshalCaddyfile implements caddyfile unmarshalling.
func (p *Provider) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	for d.Next() {
		for d.NextBlock(0) {
			switch d.Val() {
			case "api_token":
				if !d.NextArg() {
					return d.ArgErr()
				}
				p.Token = d.Val()
			case "domain":
				if !d.NextArg() {
					return d.ArgErr()
				}
				p.Domain = d.Val()
			case "resolver":
				// one or many
				for d.NextArg() {
					p.Resolvers = append(p.Resolvers, d.Val())
				}
			case "timeout_seconds":
				if !d.NextArg() {
					return d.ArgErr()
				}
				var v int
				if _, err := fmt.Sscanf(d.Val(), "%d", &v); err != nil || v < 0 {
					return d.Errf("invalid timeout_seconds: %s", d.Val())
				}
				p.TimeoutSeconds = v
			case "max_retries":
				if !d.NextArg() {
					return d.ArgErr()
				}
				var v int
				if _, err := fmt.Sscanf(d.Val(), "%d", &v); err != nil || v < 0 {
					return d.Errf("invalid max_retries: %s", d.Val())
				}
				p.MaxRetries = v
			case "initial_backoff_ms":
				if !d.NextArg() {
					return d.ArgErr()
				}
				var v int
				if _, err := fmt.Sscanf(d.Val(), "%d", &v); err != nil || v < 0 {
					return d.Errf("invalid initial_backoff_ms: %s", d.Val())
				}
				p.InitialBackoffMillis = v
			case "delete_delay_seconds":
				if !d.NextArg() {
					return d.ArgErr()
				}
				var v int
				if _, err := fmt.Sscanf(d.Val(), "%d", &v); err != nil || v < 0 {
					return d.Errf("invalid delete_delay_seconds: %s", d.Val())
				}
				p.DeleteDelaySeconds = v
			}
		}
	}
	return nil
}

func init() {
	caddy.RegisterModule(Provider{})
}

// GetRecords is optional for ACME and returns empty result (not required for issuance).
func (p *Provider) GetRecords(ctx context.Context, zone string) ([]libdns.Record, error) {
	return nil, nil
}

// SetRecords is not implemented; ACME flow uses Append/Delete.
func (p *Provider) SetRecords(ctx context.Context, zone string, recs []libdns.Record) ([]libdns.Record, error) {
	return nil, fmt.Errorf("SetRecords not implemented")
}
