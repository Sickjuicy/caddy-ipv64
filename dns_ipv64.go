package caddyipv64

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
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
	CreateDelaySeconds   int      `json:"create_delay_seconds,omitempty"`
	DeleteDelaySeconds   int      `json:"delete_delay_seconds,omitempty"`

	logger        *zap.Logger
	cachedDomains []string // Cache for available domains
	domainsCached bool     // Flag whether domains have been retrieved
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
		p.InitialBackoffMillis = 500
	}
	// Note: CreateDelaySeconds and DeleteDelaySeconds are no longer used
	// CertMagic's DNS-01 solver handles propagation delays internally
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
	
	// Log configuration for debugging
	if p.logger != nil {
		p.logger.Info("ipv64 DNS provider provisioned",
			zap.Int("max_retries", p.MaxRetries),
			zap.Int("timeout_seconds", p.TimeoutSeconds),
			zap.Int("initial_backoff_millis", p.InitialBackoffMillis),
			zap.Strings("resolvers", p.Resolvers))
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
		// Remove the managed zone and trailing dot from fqdn
		fqdnClean := strings.TrimSuffix(fqdn, ".")
		managedClean := strings.TrimSuffix(managed, ".")

		var prefix string
		if fqdnClean == managedClean {
			prefix = "@"
		} else if strings.HasSuffix(fqdnClean, "."+managedClean) {
			prefix = strings.TrimSuffix(fqdnClean, "."+managedClean)
		} else {
			// Fallback: use the first part before the first dot
			parts := strings.Split(fqdnClean, ".")
			prefix = parts[0]
		}

		if p.logger != nil {
			p.logger.Info("ipv64: creating DNS challenge record",
				zap.String("fqdn", fqdn),
				zap.String("zone", zone),
				zap.String("managed", managed),
				zap.String("prefix", prefix),
				zap.String("value", value))
		}

		// Use form-urlencoded format as per API documentation
		formData := url.Values{}
		formData.Set("add_record", managed)
		formData.Set("praefix", prefix)
		formData.Set("type", "TXT")
		formData.Set("content", value)

		apiURL := "https://ipv64.net/api"
		err := p.doWithRetryForm(ctx, client, http.MethodPost, apiURL, formData)
		if err != nil {
			return appended, err
		}
		appended = append(appended, r)
		if p.logger != nil {
			p.logger.Info("ipv64: DNS record created successfully", zap.String("fqdn", fqdn), zap.String("zone", managed))
		}
	}

	// Note: DNS propagation delay is handled by CertMagic's DNS-01 solver
	// No need to wait here - let CertMagic manage propagation timing
	return appended, nil
}

// DeleteRecords deletes TXT records, optionally with a configurable delay.
func (p *Provider) DeleteRecords(ctx context.Context, zone string, recs []libdns.Record) ([]libdns.Record, error) {
	if err := p.Validate(); err != nil {
		return nil, err
	}
	zone = normalizeZone(zone)
	client := &http.Client{Timeout: time.Duration(p.TimeoutSeconds) * time.Second}

	// Note: DNS cleanup delay is handled by CertMagic's DNS-01 solver
	// No need to wait here - CertMagic already waits between challenge verification and cleanup
	
	var deleted []libdns.Record
	for _, r := range recs {
		rr := r.RR()
		fqdn := libdns.AbsoluteName(rr.Name, zone)
		value := rr.Data // Get the TXT record content
		managed := p.deriveManagedZone(fqdn, zone)
		if managed == "" {
			continue
		}

		// Compute relative prefix under managed zone
		// Remove the managed zone and trailing dot from fqdn
		fqdnClean := strings.TrimSuffix(fqdn, ".")
		managedClean := strings.TrimSuffix(managed, ".")

		var prefix string
		if fqdnClean == managedClean {
			prefix = "@"
		} else if strings.HasSuffix(fqdnClean, "."+managedClean) {
			prefix = strings.TrimSuffix(fqdnClean, "."+managedClean)
		} else {
			// Fallback: use the first part before the first dot
			parts := strings.Split(fqdnClean, ".")
			prefix = parts[0]
		}

		// Use form-urlencoded format as per API documentation
		formData := url.Values{}
		formData.Set("del_record", managed)
		formData.Set("praefix", prefix)
		formData.Set("type", "TXT")
		formData.Set("content", value) // Include content parameter as required by API

		if p.logger != nil {
			p.logger.Debug("ipv64: DNS delete details",
				zap.String("fqdn", fqdn),
				zap.String("zone", zone),
				zap.String("managed", managed),
				zap.String("prefix", prefix),
				zap.String("value", value))
		}

		apiURL := "https://ipv64.net/api"
		if err := p.doWithRetryForm(ctx, client, http.MethodDelete, apiURL, formData); err != nil {
			if p.logger != nil {
				p.logger.Warn("ipv64: delete failed", zap.String("fqdn", fqdn), zap.Error(err))
			}
			continue
		}
		deleted = append(deleted, r)
		if p.logger != nil {
			p.logger.Info("ipv64: DNS record deleted successfully", zap.String("fqdn", fqdn), zap.String("zone", managed))
		}
	}
	return deleted, nil
}

// doWithRetryForm performs form-urlencoded HTTP requests with backoff for 5xx and 429 statuses.
func (p *Provider) doWithRetryForm(ctx context.Context, client *http.Client, method, apiURL string, formData url.Values) error {
	backoff := time.Duration(p.InitialBackoffMillis) * time.Millisecond
	for attempt := 0; attempt < p.MaxRetries; attempt++ {
		req, err := http.NewRequestWithContext(ctx, method, apiURL, strings.NewReader(formData.Encode()))
		if err != nil {
			return err
		}
		req.Header.Set("Authorization", "Bearer "+p.Token)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		resp, err := client.Do(req)
		if err != nil {
			// Retry on network timeouts and connection errors
			if strings.Contains(err.Error(), "timeout") || strings.Contains(err.Error(), "connection") {
				time.Sleep(backoff)
				backoff *= 2
				continue
			}
			return err
		}
		// Properly read and drain response body before closing
		respBody, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()

		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			return nil
		}
		if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500 {
			if p.logger != nil {
				p.logger.Warn("ipv64 API retrying",
					zap.Int("status", resp.StatusCode),
					zap.String("response", string(respBody)),
					zap.Int("attempt", attempt+1))
			}
			time.Sleep(backoff)
			backoff *= 2
			continue
		}
		return fmt.Errorf("ipv64 API error: %s (response: %s)", resp.Status, string(respBody))
	}
	return fmt.Errorf("ipv64 API failed after %d attempts", p.MaxRetries)
}

// testDomainExists tests if a domain is managed in the ipv64.net API
func (p *Provider) testDomainExists(ctx context.Context, domain string) bool {
	client := &http.Client{Timeout: time.Duration(p.TimeoutSeconds) * time.Second}

	// Use list_records to test if the domain exists
	formData := url.Values{}
	formData.Set("list_records", domain)

	apiURL := "https://ipv64.net/api"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, apiURL, strings.NewReader(formData.Encode()))
	if err != nil {
		return false
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer "+p.Token)

	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return false
	}

	// If status 200 and not "domain not found", then domain exists
	if resp.StatusCode == 200 {
		responseStr := string(respBody)
		// API responds with error if domain doesn't exist
		return !strings.Contains(responseStr, "domain not found") &&
			!strings.Contains(responseStr, "error")
	}

	return false
}

// parseDomainList extracts domain names from API response
func (p *Provider) parseDomainList(response string) []string {
	// TODO: Analyze API response format and parse accordingly
	// For now return empty list as fallback
	return []string{}
}

// deriveManagedZone tries to find the longest matching suffix of fqdn within zone.
func (p *Provider) deriveManagedZone(fqdn, zone string) string {
	fqdn = strings.TrimSuffix(fqdn, ".")
	zone = strings.TrimSuffix(zone, ".")
	if fqdn == zone {
		return zone
	}

	// If Domain is explicitly configured, use it
	if p.Domain != "" {
		domain := strings.TrimSuffix(p.Domain, ".")
		return domain
	}

	// Smart heuristic: Find the managed zone by looking for *64.de/*64.net pattern
	// This works for all ipv64.net-style domains without API calls

	// Remove _acme-challenge prefix if present
	workingFqdn := fqdn
	if strings.HasPrefix(fqdn, "_acme-challenge.") {
		workingFqdn = strings.TrimPrefix(fqdn, "_acme-challenge.")
	}

	parts := strings.Split(workingFqdn, ".")
	if len(parts) >= 3 {
		// Look for the *64.de or *64.net pattern from right to left
		for i := len(parts) - 2; i >= 0; i-- {
			candidate := strings.Join(parts[i:], ".")
			candidateParts := strings.Split(candidate, ".")

			// Check if this looks like a root managed domain (username.service64.tld)
			if len(candidateParts) == 3 {
				service := candidateParts[1] // e.g., "ipv64", "vpn64", "example64"
				tld := candidateParts[2]     // e.g., "de", "net"

				// If service ends with "64" and TLD is common, this is likely the managed zone
				if strings.HasSuffix(service, "64") && (tld == "de" || tld == "net") {
					return candidate
				}
			}
		}
	}

	// Fallback: use the domain as-is
	return workingFqdn // Generic fallback
	return zone
}

// isIpv64Domain checks if a domain uses any *64.de or *64.net pattern
func (p *Provider) isIpv64Domain(domain string) bool {
	domain = strings.TrimSuffix(domain, ".")
	parts := strings.Split(domain, ".")
	if len(parts) < 2 {
		return false
	}

	// Check for *64.de pattern (e.g., ipv64.de, any64.de, srv64.de)
	if len(parts) >= 2 {
		tld := parts[len(parts)-1]     // "de" or "net"
		service := parts[len(parts)-2] // "ipv64", "any64", etc.

		if (tld == "de" || tld == "net") && strings.HasSuffix(service, "64") {
			return true
		}
	}

	return false
}

// isRootIpv64Domain checks if a domain is a root *64.de/*64.net domain (e.g., "username.ipv64.de")
func (p *Provider) isRootIpv64Domain(domain string) bool {
	domain = strings.TrimSuffix(domain, ".")
	parts := strings.Split(domain, ".")

	// Root domain should have exactly 3 parts: username.service64.tld
	if len(parts) != 3 {
		return false
	}

	// Check if it matches *64.de or *64.net pattern
	return p.isIpv64Domain(domain)
}

// isIpv64Subzone checks if a domain looks like an ipv64.net managed subzone (legacy function)
func (p *Provider) isIpv64Subzone(domain string) bool {
	return p.isIpv64Domain(domain)
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
			case "create_delay_seconds":
				if !d.NextArg() {
					return d.ArgErr()
				}
				var v int
				if _, err := fmt.Sscanf(d.Val(), "%d", &v); err != nil || v < 0 {
					return d.Errf("invalid create_delay_seconds: %s", d.Val())
				}
				p.CreateDelaySeconds = v
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
