package caddyipv64

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/libdns/libdns"
	"go.uber.org/zap"
)

const (
	apiEndpoint string = "https://ipv64.net/api"

	DefaultTimeoutSeconds       = 30
	DefaultMaxRetries          = 5
	DefaultInitialBackoffMillis = 500

	// DNS propagation checking: poll resolvers until the TXT record is visible.
	// Faster than a blind delay (best case ~10s) and more reliable (waits
	// longer if propagation is slow). LE uses multi-perspective validation.
	DefaultPropagationTimeoutSec = 60
	DefaultPropagationPollSec    = 5
	propagationMinDelay          = 10 * time.Second // let ipv64.net process before first poll

	statusTooManyRequests = 429
	statusServerErrorMin  = 500
)

var (
	defaultResolvers = []string{"ns1.ipv64.net:53", "ns2.ipv64.net:53"}
	knownServices    = []string{"ipv64", "any64", "api64", "dns64", "dyndns64", "dynipv6", "eth64", "home64", "iot64", "lan64", "nas64", "root64", "route64", "srv64", "tcp64", "udp64", "vpn64", "wan64"}
	supportedTLDs    = []string{"de", "net"}
)

// Provider implements the libdns.Provider interface for ipv64.net DNS-01 ACME challenges.
type Provider struct {
	Token                string `json:"api_token,omitempty" caddy:"namespace=dns.providers.ipv64"`
	TimeoutSeconds       int    `json:"timeout_seconds,omitempty"`
	MaxRetries           int    `json:"max_retries,omitempty"`
	InitialBackoffMillis int    `json:"initial_backoff_ms,omitempty"`

	// PropagationTimeoutSec is the max time to wait for DNS propagation
	// after creating a TXT record. Set to 0 to disable. Default: 60.
	PropagationTimeoutSec int `json:"propagation_timeout_seconds,omitempty"`
	// PropagationPollSec is the seconds between DNS propagation checks. Default: 5.
	PropagationPollSec int `json:"propagation_poll_interval,omitempty"`

	Resolvers []string `json:"resolvers,omitempty"`

	// DynIP enables optional DynDNS IP updates. When set, the provider
	// periodically updates A/AAAA records on ipv64.net.
	DynIP *DynIPUpdater `json:"dynip,omitempty"`

	httpClient *http.Client
	logger     *zap.Logger
	endpoint   string
}

func (Provider) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "dns.providers.ipv64",
		New: func() caddy.Module { return new(Provider) },
	}
}

func (p *Provider) Provision(ctx caddy.Context) error {
	p.logger = ctx.Logger(p)
	if p.Token == "" {
		p.Token = os.Getenv("IPV64_API_TOKEN")
	}
	if p.TimeoutSeconds <= 0 {
		p.TimeoutSeconds = DefaultTimeoutSeconds
	}
	if p.MaxRetries <= 0 {
		p.MaxRetries = DefaultMaxRetries
	}
	if p.InitialBackoffMillis <= 0 {
		p.InitialBackoffMillis = DefaultInitialBackoffMillis
	}
	if p.PropagationTimeoutSec == 0 {
		p.PropagationTimeoutSec = DefaultPropagationTimeoutSec
	}
	if p.PropagationPollSec <= 0 {
		p.PropagationPollSec = DefaultPropagationPollSec
	}

	p.httpClient = &http.Client{Timeout: time.Duration(p.TimeoutSeconds) * time.Second}
	p.endpoint = apiEndpoint

	if len(p.Resolvers) == 0 {
		p.Resolvers = defaultResolvers
	} else {
		for i, r := range p.Resolvers {
			if !strings.Contains(r, ":") {
				p.Resolvers[i] = r + ":53"
			}
		}
		if !hasIpv64NS(p.Resolvers) {
			p.logger.Warn("ipv64: custom resolvers missing ipv64.net nameservers - may cause DNS propagation issues", zap.Strings("resolvers", p.Resolvers))
		}
	}

	p.logger.Info("ipv64 DNS provider provisioned",
		zap.Int("max_retries", p.MaxRetries),
		zap.Int("timeout_seconds", p.TimeoutSeconds),
		zap.Int("propagation_timeout_seconds", p.PropagationTimeoutSec),
		zap.Int("propagation_poll_interval", p.PropagationPollSec),
		zap.Strings("resolvers", p.Resolvers),
		zap.Bool("dynip_enabled", p.DynIP != nil))

	if p.DynIP != nil {
		if err := p.DynIP.Provision(ctx, p); err != nil {
			return err
		}
		p.DynIP.Start(ctx)
	}

	return nil
}

func (p *Provider) Validate() error {
	if p.Token == "" {
		return errors.New("api_token is required")
	}
	return nil
}

// --- Setters for testing ---

func (p *Provider) SetEndpoint(endpoint string)  { p.endpoint = endpoint }
func (p *Provider) SetHttpClient(c *http.Client)  { p.httpClient = c }
func (p *Provider) SetLogger(l *zap.Logger)       { p.logger = l }
func (p *Provider) SetMaxRetries(n int)           { p.MaxRetries = n }
func (p *Provider) SetInitialBackoffMillis(ms int) { p.InitialBackoffMillis = ms }

// --- libdns.Provider interface ---

func (p *Provider) AppendRecords(ctx context.Context, zone string, recs []libdns.Record) ([]libdns.Record, error) {
	if err := p.Validate(); err != nil {
		return nil, err
	}

	var appended []libdns.Record
	for _, r := range recs {
		rr := r.RR()
		fqdn := libdns.AbsoluteName(rr.Name, zone)

		managed := p.deriveManagedZone(fqdn)
		if managed == "" {
			p.logger.Warn("ipv64: skipping non-ipv64 domain", zap.String("fqdn", fqdn), zap.String("zone", zone))
			continue
		}

		prefix := p.computePrefix(fqdn, managed)

		if err := p.apiCall(ctx, http.MethodPost, "add_record", managed, prefix, "TXT", rr.Data); err != nil {
			return appended, err
		}
		appended = append(appended, r)
		p.logger.Info("ipv64: DNS record created", zap.String("fqdn", fqdn), zap.String("zone", managed))

		if p.PropagationTimeoutSec > 0 {
			p.waitForPropagation(ctx, fqdn, rr.Data)
		}
	}

	return appended, nil
}

func (p *Provider) DeleteRecords(ctx context.Context, zone string, recs []libdns.Record) ([]libdns.Record, error) {
	if err := p.Validate(); err != nil {
		return nil, err
	}

	var deleted []libdns.Record
	for _, r := range recs {
		rr := r.RR()
		fqdn := libdns.AbsoluteName(rr.Name, zone)

		managed := p.deriveManagedZone(fqdn)
		if managed == "" {
			continue
		}

		prefix := p.computePrefix(fqdn, managed)

		if err := p.apiCall(ctx, http.MethodDelete, "del_record", managed, prefix, "TXT", rr.Data); err != nil {
			p.logger.Warn("ipv64: failed to delete DNS record (may already be gone)", zap.Error(err), zap.String("fqdn", fqdn))
		} else {
			p.logger.Info("ipv64: DNS record deleted", zap.String("fqdn", fqdn), zap.String("zone", managed))
		}
		deleted = append(deleted, r)
	}
	return deleted, nil
}

func (p *Provider) GetRecords(ctx context.Context, zone string) ([]libdns.Record, error) {
	return nil, nil
}

func (p *Provider) SetRecords(ctx context.Context, zone string, recs []libdns.Record) ([]libdns.Record, error) {
	return nil, errors.New("SetRecords not implemented")
}

// --- API client ---

// apiCall sends a form-encoded request to the ipv64.net API with retry logic.
func (p *Provider) apiCall(ctx context.Context, method, action, zone, prefix, recordType, content string) error {
	form := url.Values{}
	form.Set(action, zone)
	form.Set("praefix", prefix)
	form.Set("type", recordType)
	form.Set("content", content)

	var lastErr error
	backoff := time.Duration(p.InitialBackoffMillis) * time.Millisecond

	for attempt := 0; attempt <= p.MaxRetries; attempt++ {
		if attempt > 0 {
			select {
			case <-time.After(backoff):
			case <-ctx.Done():
				return ctx.Err()
			}
			backoff *= 2
		}

		req, err := http.NewRequestWithContext(ctx, method, p.endpoint, strings.NewReader(form.Encode()))
		if err != nil {
			return fmt.Errorf("creating request: %w", err)
		}
		req.Header.Set("Authorization", "Bearer "+p.Token)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		resp, err := p.httpClient.Do(req)
		if err != nil {
			lastErr = err
			continue
		}

		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			lastErr = fmt.Errorf("reading response body: %w", err)
			continue
		}

		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			return nil
		}

		if resp.StatusCode >= statusServerErrorMin || resp.StatusCode == statusTooManyRequests {
			lastErr = fmt.Errorf("ipv64 API error (status: %s): %s", resp.Status, string(body))
			continue
		}

		return fmt.Errorf("ipv64 API error (status: %s): %s", resp.Status, string(body))
	}

	return fmt.Errorf("max retries (%d) exceeded: %w", p.MaxRetries, lastErr)
}

// --- DNS propagation checking ---

// waitForPropagation polls DNS resolvers until the TXT record is visible on
// at least 2 resolvers, or the timeout is reached. Non-fatal on timeout.
func (p *Provider) waitForPropagation(ctx context.Context, fqdn, expectedValue string) {
	select {
	case <-time.After(propagationMinDelay):
	case <-ctx.Done():
		return
	}

	fqdnClean := strings.TrimSuffix(fqdn, ".")
	deadline := time.Now().Add(time.Duration(p.PropagationTimeoutSec) * time.Second)
	interval := time.Duration(p.PropagationPollSec) * time.Second

	for time.Now().Before(deadline) {
		visible := 0
		for _, resolver := range p.Resolvers {
			if p.checkTXT(ctx, resolver, fqdnClean, expectedValue) {
				visible++
			}
		}

		if visible >= 2 {
			p.logger.Info("ipv64: DNS propagation confirmed",
				zap.Int("visible_resolvers", visible),
				zap.String("fqdn", fqdnClean))
			return
		}

		select {
		case <-time.After(interval):
		case <-ctx.Done():
			return
		}
	}

	p.logger.Warn("ipv64: DNS propagation timeout, continuing anyway", zap.String("fqdn", fqdnClean))
}

// checkTXT queries a specific DNS resolver for the expected TXT record value.
func (p *Provider) checkTXT(ctx context.Context, resolver, fqdn, expectedValue string) bool {
	addr := strings.TrimSuffix(resolver, ":53")
	if !strings.Contains(addr, ":") {
		addr = addr + ":53"
	}

	r := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
			d := net.Dialer{Timeout: 5 * time.Second}
			return d.DialContext(ctx, "udp", addr)
		},
	}

	lookupCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	txts, err := r.LookupTXT(lookupCtx, fqdn)
	if err != nil {
		return false
	}
	return slices.Contains(txts, expectedValue)
}

// --- Domain parsing ---

// deriveManagedZone extracts the ipv64.net managed zone from an FQDN.
// Example: "_acme-challenge.test.user.ipv64.de" → "user.ipv64.de"
func (p *Provider) deriveManagedZone(fqdn string) string {
	fqdn = strings.TrimSuffix(fqdn, ".")
	fqdn = strings.TrimPrefix(fqdn, "_acme-challenge.")

	parts := strings.Split(fqdn, ".")
	for i := len(parts) - 1; i >= 0; i-- {
		candidate := strings.Join(parts[i:], ".")
		if isIpv64Domain(candidate + ".") {
			return candidate
		}
	}
	return ""
}

// computePrefix calculates the relative prefix for the ipv64.net API.
// Example: "_acme-challenge.test.user.ipv64.de" with zone "user.ipv64.de" → "_acme-challenge.test"
func (p *Provider) computePrefix(fqdn, managed string) string {
	fqdn = strings.TrimSuffix(fqdn, ".")
	managed = strings.TrimSuffix(managed, ".")

	if fqdn == managed {
		return "@"
	}
	return strings.TrimSuffix(fqdn, "."+managed)
}

// isIpv64Domain checks if a domain belongs to the ipv64.net service.
// Both the service label (e.g. "ipv64") AND the TLD (e.g. "de") must match.
func isIpv64Domain(domain string) bool {
	parts := strings.Split(strings.TrimSuffix(domain, "."), ".")
	if len(parts) < 3 {
		return false
	}
	service := parts[len(parts)-2]
	tld := parts[len(parts)-1]
	return slices.Contains(knownServices, service) && slices.Contains(supportedTLDs, tld)
}

// hasIpv64NS checks if any resolver contains ipv64.net nameservers.
func hasIpv64NS(resolvers []string) bool {
	for _, r := range resolvers {
		if strings.Contains(r, "ns1.ipv64.net") || strings.Contains(r, "ns2.ipv64.net") {
			return true
		}
	}
	return false
}

// --- Caddyfile parsing ---

func (p *Provider) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	for d.Next() {
		for d.NextBlock(0) {
			switch d.Val() {
			case "api_token":
				if !d.NextArg() {
					return d.ArgErr()
				}
				p.Token = expandEnv(d.Val())
			case "resolver":
				for d.NextArg() {
					p.Resolvers = append(p.Resolvers, d.Val())
				}
			case "timeout_seconds":
				p.TimeoutSeconds = parseIntArg(d)
			case "max_retries":
				p.MaxRetries = parseIntArg(d)
			case "initial_backoff_ms":
				p.InitialBackoffMillis = parseIntArg(d)
			case "propagation_timeout_seconds":
				p.PropagationTimeoutSec = parseIntArg(d)
			case "propagation_poll_interval":
				p.PropagationPollSec = parseIntArg(d)
			case "dynip":
				p.DynIP = &DynIPUpdater{}
				if err := p.DynIP.UnmarshalCaddyfile(d); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// parseIntArg reads the next argument as a non-negative integer, or returns an error.
func parseIntArg(d *caddyfile.Dispenser) int {
	if !d.NextArg() {
		d.ArgErr()
		return 0
	}
	v, err := strconv.Atoi(d.Val())
	if err != nil || v < 0 {
		d.Errf("invalid value: %s", d.Val())
		return 0
	}
	return v
}

// expandEnv replaces {env.VAR_NAME} patterns with the corresponding environment variable value.
// This allows Caddyfile users to reference environment variables in the dns ipv64 block,
// e.g.: api_token {env.IPV64_API_TOKEN}
func expandEnv(s string) string {
	for {
		idx := strings.Index(s, "{env.")
		if idx == -1 {
			break
		}
		end := strings.Index(s[idx:], "}")
		if end == -1 {
			break
		}
		end += idx
		varName := s[idx+5 : end] // skip "{env."
		envVal := os.Getenv(varName)
		s = s[:idx] + envVal + s[end+1:]
	}
	return s
}

func init() {
	caddy.RegisterModule(Provider{})
}