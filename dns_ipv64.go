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

const (
	// API Configuration
	apiEndpoint = "https://ipv64.net/api"

	// Default Provider Settings
	defaultTimeout       = 30 // seconds
	defaultMaxRetries    = 5
	defaultBackoffMillis = 500 // milliseconds

	// HTTP Status Codes
	statusTooManyRequests = 429
	statusServerErrorMin  = 500
)

var (
	// Default DNS resolvers (ipv64.net nameservers first, then public DNS)
	defaultResolvers = []string{
		"ns1.ipv64.net:53",
		"ns2.ipv64.net:53",
		"1.1.1.1:53",
		"8.8.8.8:53",
	}

	// Known ipv64.net service names (second-to-last part of domain)
	// Current as of October 2025 - see https://ipv64.net for latest list
	// Format: username.<service>.de or username.<service>.net
	knownServices = []string{
		"ipv64",    // ipv64.de, ipv64.net - Main service
		"any64",    // any64.de - Generic service
		"api64",    // api64.de - API service
		"dns64",    // dns64.de - DNS service
		"dyndns64", // dyndns64.de - DynDNS service
		"dynipv6",  // dynipv6.de - IPv6 DynDNS (exception: doesn't end in "64")
		"eth64",    // eth64.de - Ethernet service
		"home64",   // home64.de - Home service
		"iot64",    // iot64.de - IoT service
		"lan64",    // lan64.de - LAN service
		"nas64",    // nas64.de - NAS service
		"root64",   // root64.de - Root service
		"route64",  // route64.de - Routing service
		"srv64",    // srv64.de - Server service
		"tcp64",    // tcp64.de - TCP service
		"udp64",    // udp64.de - UDP service
		"vpn64",    // vpn64.de, vpn64.net - VPN service
		"wan64",    // wan64.de - WAN service
	}

	// Supported TLDs for ipv64.net services
	supportedTLDs = []string{"de", "net"}
)

// Provider implements the libdns.Provider interface for ipv64.net DNS-01 ACME challenges.
// It also serves as a Caddy module (dns.providers.ipv64).
type Provider struct {
	// API Configuration
	Token                string `json:"api_token,omitempty" caddy:"namespace=dns.providers.ipv64"`
	TimeoutSeconds       int    `json:"timeout_seconds,omitempty"`
	MaxRetries           int    `json:"max_retries,omitempty"`
	InitialBackoffMillis int    `json:"initial_backoff_ms,omitempty"`

	// DNS Resolver Configuration
	Resolvers []string `json:"resolvers,omitempty"`

	// Internal state
	httpClient *http.Client
	logger     *zap.Logger
}

// CaddyModule returns the Caddy module information.
func (Provider) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "dns.providers.ipv64",
		New: func() caddy.Module { return new(Provider) },
	}
}

// Provision sets up the provider with defaults and validates configuration.
func (p *Provider) Provision(ctx caddy.Context) error {
	p.logger = ctx.Logger(p)

	// Get API token from config or environment
	if p.Token == "" {
		p.Token = os.Getenv("IPV64_API_TOKEN")
	}

	// Set defaults using constants
	if p.TimeoutSeconds <= 0 {
		p.TimeoutSeconds = defaultTimeout
	}
	if p.MaxRetries <= 0 {
		p.MaxRetries = defaultMaxRetries
	}
	if p.InitialBackoffMillis <= 0 {
		p.InitialBackoffMillis = defaultBackoffMillis
	}

	// Initialize HTTP client once
	p.httpClient = &http.Client{
		Timeout: time.Duration(p.TimeoutSeconds) * time.Second,
	}

	// Set default resolvers if not configured
	if len(p.Resolvers) == 0 {
		p.Resolvers = defaultResolvers
		p.logger.Info("ipv64: using default resolvers (ipv64 nameservers + public DNS)")
	} else {
		// Normalize custom resolvers (add :53 port if missing)
		for i, r := range p.Resolvers {
			if !strings.Contains(r, ":") {
				p.Resolvers[i] = r + ":53"
			}
		}

		// Warn if ipv64 nameservers are missing
		hasIpv64NS := false
		for _, r := range p.Resolvers {
			if strings.Contains(r, "ns1.ipv64.net") || strings.Contains(r, "ns2.ipv64.net") {
				hasIpv64NS = true
				break
			}
		}
		if !hasIpv64NS {
			p.logger.Warn("ipv64: custom resolvers missing ipv64.net nameservers - may cause DNS propagation issues",
				zap.Strings("resolvers", p.Resolvers))
		}
	}

	p.logger.Info("ipv64 DNS provider provisioned",
		zap.Int("max_retries", p.MaxRetries),
		zap.Int("timeout_seconds", p.TimeoutSeconds),
		zap.Int("initial_backoff_millis", p.InitialBackoffMillis),
		zap.Strings("resolvers", p.Resolvers),
	)

	// Warn users about recommended TLS settings for reliable certificate issuance
	p.logger.Warn("ipv64: IMPORTANT - For reliable wildcard certificates, configure in your Caddyfile:",
		zap.String("propagation_delay", "15s (slower checks = more time before deletion)"),
		zap.String("propagation_timeout", "90s (ipv64.net DNS propagation time)"),
		zap.String("resolvers", "ns1.ipv64.net ns2.ipv64.net 1.1.1.1 8.8.8.8"),
		zap.String("example", "See README.md for complete configuration"),
	)

	return nil
}

// Validate ensures the API token is configured.
func (p *Provider) Validate() error {
	if p.Token == "" {
		return errors.New("api_token is required (or set IPV64_API_TOKEN)")
	}
	return nil
}

// isIpv64Domain checks if a zone matches the ipv64.net domain pattern.
// Valid patterns: username.ipv64.de, username.vpn64.net, username.dynipv6.de, etc.
// Requires at least 3 parts, second-to-last is a known service name, TLD is in supportedTLDs.
//
// Uses an explicit list of known services instead of pattern matching for:
//   - Explicit validation (no false positives)
//   - Easy maintenance (add new services to knownServices list)
//   - Clear documentation (list shows all supported services)
//
// To add support for new ipv64.net services, update the knownServices variable.
func isIpv64Domain(zone string) bool {
	parts := strings.Split(strings.TrimSuffix(zone, "."), ".")
	if len(parts) < 3 {
		return false
	}

	// Check if second-to-last part is a known ipv64.net service
	service := parts[len(parts)-2]
	tld := parts[len(parts)-1]

	// Check if service is in the known services list
	serviceFound := false
	for _, knownService := range knownServices {
		if service == knownService {
			serviceFound = true
			break
		}
	}
	if !serviceFound {
		return false
	}

	// Check if TLD is supported
	for _, supportedTLD := range supportedTLDs {
		if tld == supportedTLD {
			return true
		}
	}

	return false
}

// SetResolvers can be used by tests to override resolvers.
func (p *Provider) SetResolvers(resolvers []string) {
	p.Resolvers = resolvers
}

// AppendRecords creates TXT records for ACME DNS-01 challenges.
// This is the primary method used by Caddy's ACME automation.
func (p *Provider) AppendRecords(ctx context.Context, zone string, recs []libdns.Record) ([]libdns.Record, error) {
	if err := p.Validate(); err != nil {
		return nil, err
	}

	// Check if this is an ipv64.net domain
	if !isIpv64Domain(zone) {
		p.logger.Debug("ipv64: skipping non-ipv64 domain", zap.String("zone", zone))
		return recs, nil
	}

	zone = normalizeZone(zone)

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
		prefix := p.computePrefix(fqdn, managed)

		p.logger.Info("ipv64: creating DNS challenge record",
			zap.String("fqdn", fqdn),
			zap.String("zone", zone),
			zap.String("managed", managed),
			zap.String("prefix", prefix),
			zap.String("value", value))

		// Use ipv64.net API format (note: "praefix" is the German spelling used by the API)
		formData := url.Values{}
		formData.Set("add_record", managed)
		formData.Set("praefix", prefix)
		formData.Set("type", "TXT")
		formData.Set("content", value)

		err := p.doWithRetryForm(ctx, p.httpClient, http.MethodPost, apiEndpoint, formData)
		if err != nil {
			return appended, err
		}
		appended = append(appended, r)
		p.logger.Info("ipv64: DNS record created successfully", zap.String("fqdn", fqdn), zap.String("zone", managed))
	}

	return appended, nil
}

// DeleteRecords removes TXT records after ACME validation completes.
func (p *Provider) DeleteRecords(ctx context.Context, zone string, recs []libdns.Record) ([]libdns.Record, error) {
	if err := p.Validate(); err != nil {
		return nil, err
	}

	// Check if this is an ipv64.net domain
	if !isIpv64Domain(zone) {
		p.logger.Debug("ipv64: skipping non-ipv64 domain", zap.String("zone", zone))
		return recs, nil
	}

	zone = normalizeZone(zone)

	var deleted []libdns.Record
	for _, r := range recs {
		rr := r.RR()
		fqdn := libdns.AbsoluteName(rr.Name, zone)
		value := rr.Data
		managed := p.deriveManagedZone(fqdn, zone)
		if managed == "" {
			continue
		}

		prefix := p.computePrefix(fqdn, managed)

		formData := url.Values{}
		formData.Set("del_record", managed)
		formData.Set("praefix", prefix)
		formData.Set("type", "TXT")
		formData.Set("content", value)

		p.logger.Debug("ipv64: DNS delete details",
			zap.String("fqdn", fqdn),
			zap.String("zone", zone),
			zap.String("managed", managed),
			zap.String("prefix", prefix),
			zap.String("value", value))

		if err := p.doWithRetryForm(ctx, p.httpClient, http.MethodDelete, apiEndpoint, formData); err != nil {
			p.logger.Warn("ipv64: failed to delete DNS record (may already be gone)",
				zap.Error(err),
				zap.String("fqdn", fqdn))
		} else {
			p.logger.Info("ipv64: DNS record deleted successfully",
				zap.String("fqdn", fqdn),
				zap.String("zone", managed))
		}
		deleted = append(deleted, r)
	}
	return deleted, nil
}

// doWithRetryForm performs HTTP requests with exponential backoff retry logic.
// Retries on network errors, 5xx server errors, and 429 rate limiting.
func (p *Provider) doWithRetryForm(ctx context.Context, client *http.Client, method, apiURL string, formData url.Values) error {
	var lastErr error
	backoff := time.Duration(p.InitialBackoffMillis) * time.Millisecond

	for attempt := 0; attempt <= p.MaxRetries; attempt++ {
		if attempt > 0 {
			p.logger.Debug("ipv64: retrying API request",
				zap.Int("attempt", attempt),
				zap.Int("max_retries", p.MaxRetries),
				zap.Duration("backoff", backoff),
			)
			select {
			case <-time.After(backoff):
			case <-ctx.Done():
				return ctx.Err()
			}
			backoff *= 2
		}

		req, err := http.NewRequestWithContext(ctx, method, apiURL, strings.NewReader(formData.Encode()))
		if err != nil {
			return fmt.Errorf("creating request: %w", err)
		}

		req.Header.Set("Authorization", "Bearer "+p.Token)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		resp, err := client.Do(req)
		if err != nil {
			lastErr = err
			p.logger.Warn("ipv64: API request failed (network error)",
				zap.Error(err),
				zap.Int("attempt", attempt+1),
			)
			continue
		}
		defer resp.Body.Close()

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			lastErr = fmt.Errorf("reading response body: %w", err)
			p.logger.Warn("ipv64: failed to read response body",
				zap.Error(err),
				zap.Int("attempt", attempt+1),
			)
			continue
		}

		// Success
		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			p.logger.Debug("ipv64: API request successful",
				zap.Int("status", resp.StatusCode),
				zap.String("response", string(body)),
			)
			return nil
		}

		// Retryable errors (5xx server errors or rate limiting)
		if resp.StatusCode >= statusServerErrorMin || resp.StatusCode == statusTooManyRequests {
			lastErr = fmt.Errorf("ipv64 API error (status: %s): %s", resp.Status, string(body))
			p.logger.Warn("ipv64: API returned retryable error",
				zap.Int("status", resp.StatusCode),
				zap.String("body", string(body)),
				zap.Int("attempt", attempt+1),
			)
			continue
		}

		// Non-retryable error
		return fmt.Errorf("ipv64 API error (status: %s): %s", resp.Status, string(body))
	}

	return fmt.Errorf("max retries (%d) exceeded: %w", p.MaxRetries, lastErr)
}

// deriveManagedZone finds the managed ipv64.net zone for a given FQDN.
// It searches for the *64.de or *64.net pattern (e.g., yourdomain.ipv64.de).
// Examples:
//   - _acme-challenge.app.yourdomain.ipv64.de -> yourdomain.ipv64.de
//   - subdomain.yourdomain.ipv64.de -> yourdomain.ipv64.de
//   - yourdomain.ipv64.de -> yourdomain.ipv64.de
func (p *Provider) deriveManagedZone(fqdn, zone string) string {
	fqdn = strings.TrimSuffix(fqdn, ".")
	zone = strings.TrimSuffix(zone, ".")

	if fqdn == zone {
		return zone
	}

	// Remove _acme-challenge prefix for cleaner pattern matching
	workingFqdn := strings.TrimPrefix(fqdn, "_acme-challenge.")

	// Search from right to left for *64.de or *64.net pattern
	parts := strings.Split(workingFqdn, ".")
	// Need at least 3 parts for username.service64.tld (e.g., yourdomain.ipv64.de)
	// Start from len(parts)-3 to ensure we have enough parts
	for i := len(parts) - 3; i >= 0; i-- {
		candidate := strings.Join(parts[i:], ".")
		if isIpv64Domain(candidate + ".") {
			return candidate
		}
	}

	// Fallback: use the working FQDN as-is
	return workingFqdn
}

// computePrefix calculates the relative DNS prefix under the managed zone.
// Examples:
//   - FQDN: _acme-challenge.app.yourdomain.ipv64.de, Managed: yourdomain.ipv64.de -> "_acme-challenge.app"
//   - FQDN: yourdomain.ipv64.de, Managed: yourdomain.ipv64.de -> "@"
func (p *Provider) computePrefix(fqdn, managed string) string {
	fqdnClean := strings.TrimSuffix(fqdn, ".")
	managedClean := strings.TrimSuffix(managed, ".")

	// Root domain case
	if fqdnClean == managedClean {
		return "@"
	}

	// Subdomain case: strip managed zone suffix
	if strings.HasSuffix(fqdnClean, "."+managedClean) {
		return strings.TrimSuffix(fqdnClean, "."+managedClean)
	}

	// Fallback: return first label
	parts := strings.Split(fqdnClean, ".")
	return parts[0]
}

// normalizeZone ensures zone names end with a dot for libdns compatibility.
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
