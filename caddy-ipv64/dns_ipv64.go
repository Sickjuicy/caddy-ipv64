package caddyipv64

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	caddy "github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/certmagic"
	"github.com/libdns/libdns"
	"go.uber.org/zap"
)

// DnsIPv64Provider is a Caddy DNS provider for ACME DNS-01 challenges via ipv64.net.
// It creates and deletes TXT records for the challenge.

type DnsIPv64Provider struct {
	Token    string   `json:"api_token,omitempty"`
	Domain   string   `json:"domain,omitempty"`
	Resolver []string `json:"resolver,omitempty"`
	// Optional tuning parameters
	TimeoutSeconds       int `json:"timeout_seconds,omitempty"`
	MaxRetries           int `json:"max_retries,omitempty"`
	InitialBackoffMillis int `json:"initial_backoff_ms,omitempty"`
	// Delay before deleting TXT records (in seconds) to allow ACME secondary validation
	DeleteDelaySeconds int `json:"delete_delay_seconds,omitempty"`
}

func (DnsIPv64Provider) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "dns.providers.ipv64",
		New: func() caddy.Module { return new(DnsIPv64Provider) },
	}
}

func (p *DnsIPv64Provider) Provision(ctx caddy.Context) error {
	// Defaults
	if p.TimeoutSeconds <= 0 {
		p.TimeoutSeconds = 10
	}
	if p.MaxRetries <= 0 {
		p.MaxRetries = 4
	}
	if p.InitialBackoffMillis <= 0 {
		p.InitialBackoffMillis = 300
	}
	if p.DeleteDelaySeconds <= 0 {
		// Default to 20s to give secondary validators time to see the TXT record.
		// Set to 0 explicitly in config to disable the delay.
		p.DeleteDelaySeconds = 20
	}
	// Default resolvers: ipv64 nameservers first, then public fallbacks (Cloudflare, Google, Quad9)
	if len(p.Resolver) == 0 {
		p.Resolver = []string{
			"ns1.ipv64.de", "ns2.ipv64.de",
			// Public fallbacks
			"1.1.1.1", "1.0.0.1", // Cloudflare
			"8.8.8.8", "8.8.4.4", // Google
			"9.9.9.9", "149.112.112.112", // Quad9
		}
	}
	return nil
}

func (p *DnsIPv64Provider) Validate() error {
	if p.Token == "" {
		return fmt.Errorf("api_token must be set")
	}
	if p.Domain == "" {
		return fmt.Errorf("domain must be set")
	}
	return nil
}

func (p *DnsIPv64Provider) NewDNSProvider() (certmagic.DNSProvider, error) {
	return p, nil
}

// AppendRecords implements libdns.Provider to create DNS records (used by CertMagic).
func (p *DnsIPv64Provider) AppendRecords(ctx context.Context, zone string, recs []libdns.Record) ([]libdns.Record, error) {
	apiURL := "https://ipv64.net/api.php"
	client := &http.Client{Timeout: time.Duration(p.TimeoutSeconds) * time.Second}
	var created []libdns.Record
	logger := caddy.Log().Named("dns.providers.ipv64")
	for _, r := range recs {
		form := url.Values{}
		// Always operate within the configured domain/zone
		cfgDomain := strings.TrimSuffix(p.Domain, ".")
		// Build full FQDN from libdns parts, then reduce to prefix relative to cfgDomain
		fullName := strings.TrimSuffix(cfgDomain, ".")
		if r.Name != "" && r.Name != "@" {
			// libdns names are relative to the provided zone; compute FQDN using input zone
			z := strings.TrimSuffix(zone, ".")
			if z != "" {
				fullName = strings.TrimSuffix(r.Name, ".") + "." + z
			} else {
				fullName = strings.TrimSuffix(r.Name, ".")
			}
		} else {
			// apex record name
			z := strings.TrimSuffix(zone, ".")
			if z != "" {
				fullName = z
			}
		}
		prefix := relativePrefix(fullName, cfgDomain)

		logger.Debug("append record begin",
			zap.String("zone", zone),
			zap.String("cfg_domain", cfgDomain),
			zap.String("name", r.Name),
			zap.String("type", r.Type),
			zap.String("full_name", fullName),
			zap.String("prefix", prefix),
			zap.String("value", r.Value),
		)

		form.Set("add_record", cfgDomain)
		form.Set("praefix", prefix)
		if r.Type == "" {
			form.Set("type", "TXT")
		} else {
			form.Set("type", strings.ToUpper(r.Type))
		}
		form.Set("content", r.Value)
		req, err := http.NewRequestWithContext(ctx, "POST", apiURL, strings.NewReader(form.Encode()))
		if err != nil {
			return created, err
		}
		req.Header.Set("Authorization", "Bearer "+p.Token)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("User-Agent", "caddy-ipv64/1.0")

		resp, err := doWithRetry(ctx, client, req, p.MaxRetries, time.Duration(p.InitialBackoffMillis)*time.Millisecond, logger)
		if err != nil {
			return created, err
		}
		func() {
			defer resp.Body.Close()
			body, _ := io.ReadAll(resp.Body)
			if resp.StatusCode != 200 && resp.StatusCode != 201 && resp.StatusCode != 202 {
				logger.Error("ipv64 api create failed",
					zap.Int("status", resp.StatusCode),
					zap.String("status_text", resp.Status),
					zap.String("response", string(body)),
				)
				err = fmt.Errorf("ipv64.net API error: %s %s", resp.Status, string(body))
				return
			}
			logger.Debug("ipv64 api create ok",
				zap.Int("status", resp.StatusCode),
				zap.String("status_text", resp.Status),
				zap.String("response", string(body)),
			)
			created = append(created, r)
		}()
		if err != nil {
			return created, err
		}
	}
	return created, nil
}

// DeleteRecords implements libdns.Provider to delete DNS records.
func (p *DnsIPv64Provider) DeleteRecords(ctx context.Context, zone string, recs []libdns.Record) ([]libdns.Record, error) {
	// Perform deletion asynchronously with an independent context and timeout to avoid cancellation
	logger := caddy.Log().Named("dns.providers.ipv64")
	delay := time.Duration(p.DeleteDelaySeconds) * time.Second
	// Copy inputs for async routine
	recsCopy := make([]libdns.Record, len(recs))
	copy(recsCopy, recs)
	zoneCopy := zone

	go func() {
		if delay > 0 {
			logger.Debug("delaying delete to allow secondary validation", zap.Duration("delay", delay))
			timer := time.NewTimer(delay)
			select {
			case <-timer.C:
			case <-ctx.Done():
				// Even if ACME context is cancelled, we continue cleanup shortly after to avoid leaks.
				// Give a small grace period then proceed.
				time.Sleep(2 * time.Second)
			}
		}

		// Independent context with its own timeout
		cleanupTimeout := time.Duration(p.TimeoutSeconds+10) * time.Second
		ctx2, cancel := context.WithTimeout(context.Background(), cleanupTimeout)
		defer cancel()

		apiURL := "https://ipv64.net/api.php"
		client := &http.Client{Timeout: time.Duration(p.TimeoutSeconds) * time.Second}

		for _, r := range recsCopy {
			form := url.Values{}
			cfgDomain := strings.TrimSuffix(p.Domain, ".")
			// Build full name relative to provided zone and reduce to cfgDomain
			fullName := strings.TrimSuffix(cfgDomain, ".")
			if r.Name != "" && r.Name != "@" {
				z := strings.TrimSuffix(zoneCopy, ".")
				if z != "" {
					fullName = strings.TrimSuffix(r.Name, ".") + "." + z
				} else {
					fullName = strings.TrimSuffix(r.Name, ".")
				}
			} else {
				z := strings.TrimSuffix(zoneCopy, ".")
				if z != "" {
					fullName = z
				}
			}
			prefix := relativePrefix(fullName, cfgDomain)

			logger.Debug("delete record begin",
				zap.String("zone", zoneCopy),
				zap.String("cfg_domain", cfgDomain),
				zap.String("name", r.Name),
				zap.String("type", r.Type),
				zap.String("full_name", fullName),
				zap.String("prefix", prefix),
				zap.String("value", r.Value),
			)

			form.Set("del_record", cfgDomain)
			form.Set("praefix", prefix)
			if r.Type == "" {
				form.Set("type", "TXT")
			} else {
				form.Set("type", strings.ToUpper(r.Type))
			}
			form.Set("content", r.Value)
			req, err := http.NewRequestWithContext(ctx2, "DELETE", apiURL, strings.NewReader(form.Encode()))
			if err != nil {
				logger.Warn("build delete request failed", zap.Error(err))
				continue
			}
			req.Header.Set("Authorization", "Bearer "+p.Token)
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			req.Header.Set("User-Agent", "caddy-ipv64/1.0")

			resp, err := doWithRetry(ctx2, client, req, p.MaxRetries, time.Duration(p.InitialBackoffMillis)*time.Millisecond, logger)
			if err != nil {
				logger.Warn("ipv64 api delete failed (after retries)", zap.Error(err))
				continue
			}
			func() {
				defer resp.Body.Close()
				body, _ := io.ReadAll(resp.Body)
				if resp.StatusCode != 200 && resp.StatusCode != 201 && resp.StatusCode != 202 {
					logger.Error("ipv64 api delete failed",
						zap.Int("status", resp.StatusCode),
						zap.String("status_text", resp.Status),
						zap.String("response", string(body)),
					)
					return
				}
				logger.Debug("ipv64 api delete ok",
					zap.Int("status", resp.StatusCode),
					zap.String("status_text", resp.Status),
					zap.String("response", string(body)),
				)
			}()
		}
	}()

	// Return immediately; cleanup continues asynchronously.
	return recs, nil
}

// doWithRetry performs an HTTP request with limited retries and exponential backoff.
func doWithRetry(ctx context.Context, client *http.Client, req *http.Request, maxRetries int, initialBackoff time.Duration, logger *zap.Logger) (*http.Response, error) {
	var lastErr error
	backoff := initialBackoff
	for attempt := 0; attempt <= maxRetries; attempt++ {
		resp, err := client.Do(req)
		if err == nil {
			// Retry on 5xx responses
			if resp.StatusCode >= 500 {
				// Must read and close the body before retrying
				body, _ := io.ReadAll(resp.Body)
				resp.Body.Close()
				logger.Warn("ipv64 api 5xx, retrying",
					zap.Int("status", resp.StatusCode),
					zap.String("status_text", resp.Status),
					zap.Int("attempt", attempt),
				)
				lastErr = fmt.Errorf("server error %d: %s", resp.StatusCode, string(body))
			} else if resp.StatusCode == 429 {
				// Respect Retry-After on rate limiting
				ra := resp.Header.Get("Retry-After")
				resp.Body.Close()
				sleep := backoff
				if ra != "" {
					if secs, parseErr := time.ParseDuration(ra + "s"); parseErr == nil {
						sleep = secs
					}
				}
				logger.Warn("ipv64 api 429, retrying", zap.Duration("sleep", sleep), zap.Int("attempt", attempt))
				select {
				case <-time.After(sleep):
				case <-ctx.Done():
					return nil, ctx.Err()
				}
				backoff *= 2
				continue
			} else {
				// Success (no retry)
				return resp, nil
			}
		} else {
			lastErr = err
		}

		if attempt == maxRetries {
			break
		}

		// Backoff before next attempt
		select {
		case <-time.After(backoff):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		backoff *= 2
	}
	return nil, lastErr
}

// relativePrefix returns left-hand label(s) for FQDN within the configured domain.
// Example: fullName=_acme-challenge.sickcloud.ipv64.de, domain=sickcloud.ipv64.de => _acme-challenge
func relativePrefix(fullName, domain string) string {
	f := strings.TrimSuffix(strings.ToLower(fullName), ".")
	d := strings.TrimSuffix(strings.ToLower(domain), ".")
	if f == d {
		return "@"
	}
	if strings.HasSuffix(f, "."+d) {
		return strings.TrimSuffix(f, "."+d)
	}
	// If unrelated, fall back to original name (best effort)
	return f
}

// GetRecords is optional for ACME and returns empty result (not required for issuance).
func (p *DnsIPv64Provider) GetRecords(ctx context.Context, zone string) ([]libdns.Record, error) {
	return nil, nil
}

// SetRecords is not implemented; ACME flow uses Append/Delete.
func (p *DnsIPv64Provider) SetRecords(ctx context.Context, zone string, recs []libdns.Record) ([]libdns.Record, error) {
	return nil, fmt.Errorf("SetRecords not implemented")
}

// Note: For libdns flows, Caddy/CertMagic provides record names; no extra prefix processing needed here.

func (p *DnsIPv64Provider) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
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
				for d.NextArg() {
					p.Resolver = append(p.Resolver, d.Val())
				}
			case "timeout_seconds":
				if !d.NextArg() {
					return d.ArgErr()
				}
				if v, err := strconv.Atoi(d.Val()); err == nil {
					p.TimeoutSeconds = v
				} else {
					return d.Errf("invalid timeout_seconds: %v", err)
				}
			case "max_retries":
				if !d.NextArg() {
					return d.ArgErr()
				}
				if v, err := strconv.Atoi(d.Val()); err == nil {
					p.MaxRetries = v
				} else {
					return d.Errf("invalid max_retries: %v", err)
				}
			case "initial_backoff_ms":
				if !d.NextArg() {
					return d.ArgErr()
				}
				if v, err := strconv.Atoi(d.Val()); err == nil {
					p.InitialBackoffMillis = v
				} else {
					return d.Errf("invalid initial_backoff_ms: %v", err)
				}
			case "delete_delay_seconds":
				if !d.NextArg() {
					return d.ArgErr()
				}
				if v, err := strconv.Atoi(d.Val()); err == nil {
					p.DeleteDelaySeconds = v
				} else {
					return d.Errf("invalid delete_delay_seconds: %v", err)
				}
			}
		}
	}
	return nil
}

// Optional: allow Caddy/CertMagic to set resolvers if supported.
func (p *DnsIPv64Provider) SetResolvers(resolvers []string) {
	if len(resolvers) > 0 {
		p.Resolver = append([]string(nil), resolvers...)
	}
}

func init() {
	caddy.RegisterModule(DnsIPv64Provider{})
}

// Interface assertion: ensure we satisfy certmagic.DNSProvider
var _ certmagic.DNSProvider = (*DnsIPv64Provider)(nil)
