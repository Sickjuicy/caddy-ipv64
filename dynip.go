package caddyipv64

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"go.uber.org/zap"
)

// dynipUpdaterEndpoint is the ipv64.net DynDNS2 update endpoint.
// It performs an in-place update for A/AAAA records without requiring
// a separate delete call. Supports Bearer token auth and explicit ip/ip6 params.
const dynipUpdaterEndpoint = "https://ipv64.net/nic/update"

// DynIPUpdater provides optional DynDNS IP update functionality.
// It periodically creates/updates A and AAAA records on ipv64.net for one or
// more subdomains by detecting the server's public IPv4 and IPv6 addresses.
//
//	dns ipv64 {
//	  api_token ...
//	  dynip {
//	    subdomain example.ipv64.de
//	    subdomain vpn.example.ipv64.de
//	    interval 30m
//	    ipv4_only    # only A records
//	    # ipv6_only  # only AAAA records
//	    # dslite     # DS-Lite mode: IPv6 only, skip IPv4 detection entirely
//	  }
//	}
type DynIPUpdater struct {
	Subdomains []string       `json:"subdomains,omitempty"`
	Interval   caddy.Duration `json:"interval,omitempty"`
	// IPv4Only disables IPv6 (AAAA) record updates.
	IPv4Only bool `json:"ipv4_only,omitempty"`
	// IPv6Only disables IPv4 (A) record updates.
	IPv6Only bool `json:"ipv6_only,omitempty"`
	// DSLite enables DS-Lite mode: only detects IPv6 and sets AAAA records.
	// Skips IPv4 detection entirely (DS-Lite users have no public IPv4).
	DSLite bool `json:"dslite,omitempty"`

	provider        *Provider
	logger          *zap.Logger
	cancel          context.CancelFunc
	lastIPv4        string
	lastIPv6        string
	updaterEndpoint string // overridden in tests
	// autoDetected tracks whether the first-run auto-detection has happened.
	autoDetected bool
	// dsliteDetected is set by auto-detection when no IPv4 is available.
	dsliteDetected bool
	// updateCount tracks how many update cycles have run since last forced update.
	// Every forceUpdateEvery cycles, an update is sent even if the IP is unchanged,
	// to correct any external modifications to the DNS records at ipv64.net.
	updateCount int
	// forceUpdateEvery forces an update every N cycles (default: every 12th cycle
	// = ~6h at 30m interval). This corrects cases where another tool or manual
	// change overwrote the IP at ipv64.net while the local IP stayed the same.
	forceUpdateEvery int
}

func (d *DynIPUpdater) Provision(ctx caddy.Context, p *Provider) error {
	d.provider = p
	d.logger = p.logger.Named("dynip")

	if len(d.Subdomains) == 0 {
		return fmt.Errorf("dynip: at least one subdomain is required")
	}
	if d.Interval <= 0 {
		d.Interval = caddy.Duration(30 * time.Minute)
	}
	if d.forceUpdateEvery == 0 {
		d.forceUpdateEvery = 12 // ~6h at 30m interval
	}
	// DS-Lite implies IPv6-only mode.
	if d.DSLite {
		d.IPv6Only = false
		d.IPv4Only = false
	}

	// Auto-detect DS-Lite on first run if not explicitly configured.
	// We can't detect here (no HTTP context yet), so we do it in updateIP.
	// But we log the configured mode now.
	mode := "dual-stack"
	if d.DSLite {
		mode = "dslite"
	} else if d.IPv4Only {
		mode = "ipv4_only"
	} else if d.IPv6Only {
		mode = "ipv6_only"
	} else {
		mode = "auto" // will auto-detect on first update
	}

	d.logger.Info("ipv64 dynip updater provisioned",
		zap.Strings("subdomains", d.Subdomains),
		zap.Duration("interval", time.Duration(d.Interval)),
		zap.String("mode", mode))
	return nil
}

func (d *DynIPUpdater) Start(ctx context.Context) {
	if d.cancel != nil {
		return
	}
	ctx, d.cancel = context.WithCancel(ctx)
	go func() {
		ticker := time.NewTicker(time.Duration(d.Interval))
		defer ticker.Stop()
		d.updateIP(ctx)
		for {
			select {
			case <-ticker.C:
				d.updateIP(ctx)
			case <-ctx.Done():
				return
			}
		}
	}()
}

func (d *DynIPUpdater) Stop() {
	if d.cancel != nil {
		d.cancel()
		d.cancel = nil
	}
}

// updateIP detects the public IPv4/IPv6, then creates or updates A/AAAA records
// for all configured subdomains. Skips if the IP hasn't changed since last update.
//
// Auto-detection: If no explicit mode is set (ipv4_only/ipv6_only/dslite),
// the provider auto-detects DS-Lite by checking if IPv4 is reachable.
// If IPv4 detection fails but IPv6 works → DS-Lite mode (AAAA only).
func (d *DynIPUpdater) updateIP(ctx context.Context) {
	ipv4, ipv6 := d.detectPublicIPs(ctx)
	prevIPv4 := d.lastIPv4
	prevIPv6 := d.lastIPv6

	// Auto-detect DS-Lite on first run (no explicit mode configured).
	if !d.IPv4Only && !d.IPv6Only && !d.DSLite && !d.autoDetected {
		d.autoDetected = true
		if ipv4 == "" && ipv6 != "" {
			d.dsliteDetected = true
			d.logger.Info("ipv64 dynip: auto-detected DS-Lite mode (no public IPv4, IPv6 available)")
		} else if ipv4 != "" && ipv6 == "" {
			d.logger.Info("ipv64 dynip: auto-detected IPv4-only mode (no public IPv6)")
		} else if ipv4 != "" && ipv6 != "" {
			d.logger.Info("ipv64 dynip: auto-detected dual-stack mode (IPv4 + IPv6)")
		}
	}

	// Determine which records to set based on mode.
	want4 := !d.IPv6Only && !d.DSLite && !d.dsliteDetected
	want6 := !d.IPv4Only

	// Force an update every N cycles to correct external modifications.
	d.updateCount++
	forceUpdate := d.updateCount >= d.forceUpdateEvery
	if forceUpdate {
		d.updateCount = 0
	}

	updateIPv4 := want4 && ipv4 != "" && (ipv4 != prevIPv4 || forceUpdate)
	updateIPv6 := want6 && ipv6 != "" && (ipv6 != prevIPv6 || forceUpdate)
	changed := updateIPv4 || updateIPv6

	if !changed {
		if d.lastIPv4 == "" && d.lastIPv6 == "" {
			d.logger.Warn("ipv64 dynip: no public IP detected")
		} else {
			d.logger.Debug("ipv64 dynip: IP unchanged, skipping update")
		}
		return
	}

	if forceUpdate {
		d.logger.Info("ipv64 dynip: forced update (periodic sync)")
	}

	for _, sub := range d.Subdomains {
		var ip4, ip6 string
		if updateIPv4 {
			ip4 = ipv4
		}
		if updateIPv6 {
			ip6 = ipv6
		}
		d.updateRecord(ctx, sub, ip4, ip6)
	}

	if updateIPv4 {
		d.lastIPv4 = ipv4
	}
	if updateIPv6 {
		d.lastIPv6 = ipv6
	}
}

// detectPublicIPs queries external services to find the server's public IPv4 and IPv6.
func (d *DynIPUpdater) detectPublicIPs(ctx context.Context) (ipv4, ipv6 string) {
	ipv4 = d.fetchIP(ctx, "https://ipv4.ipv64.net/ipcheck.php")
	ipv6 = d.fetchIP(ctx, "https://ipv6.ipv64.net/ipcheck.php")
	if ipv4 == "" {
		ipv4 = d.fetchIP(ctx, "https://api.ipify.org")
	}
	if ipv6 == "" {
		ipv6 = d.fetchIP(ctx, "https://api64.ipify.org")
	}
	return
}

func (d *DynIPUpdater) fetchIP(ctx context.Context, url string) string {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return ""
	}
	req.Header.Set("User-Agent", "caddy-ipv64/dynip")

	resp, err := d.provider.httpClient.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return ""
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(body))
}

// updateRecord updates A and/or AAAA records on ipv64.net for the given subdomain
// using the DynDNS2 nic/update endpoint. A single GET request handles both IPv4
// and IPv6 in one call — no delete needed, the endpoint performs an in-place update.
//
// "example.ipv64.de"     → domain="example.ipv64.de", praefix=""
// "vpn.example.ipv64.de" → domain="example.ipv64.de", praefix="vpn"
func (d *DynIPUpdater) updateRecord(ctx context.Context, subdomain, ipv4, ipv6 string) {
	managed := d.provider.deriveManagedZone(subdomain + ".")
	if managed == "" {
		d.logger.Error("ipv64 dynip: cannot derive managed zone", zap.String("subdomain", subdomain))
		return
	}

	prefix := ""
	if subdomain != managed {
		prefix = strings.TrimSuffix(subdomain, "."+managed)
	}

	params := url.Values{}
	params.Set("domain", managed)
	params.Set("praefix", prefix)
	params.Set("key", d.provider.Token)
	if ipv4 != "" {
		params.Set("ip", ipv4)
	}
	if ipv6 != "" {
		params.Set("ip6", ipv6)
	}

	endpoint := d.updaterEndpoint
	if endpoint == "" {
		endpoint = dynipUpdaterEndpoint
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint+"?"+params.Encode(), nil)
	if err != nil {
		d.logger.Error("ipv64 dynip: creating request", zap.Error(err))
		return
	}
	req.SetBasicAuth("none", d.provider.Token)
	req.Header.Set("User-Agent", "caddy-ipv64/dynip")

	resp, err := d.provider.httpClient.Do(req)
	if err != nil {
		d.logger.Error("ipv64 dynip: update request failed",
			zap.String("subdomain", subdomain),
			zap.Error(err))
		return
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		d.logger.Info("ipv64 dynip: record updated",
			zap.String("subdomain", subdomain),
			zap.String("ipv4", ipv4),
			zap.String("ipv6", ipv6),
			zap.String("response", strings.TrimSpace(string(body))))
	} else {
		d.logger.Warn("ipv64 dynip: update failed",
			zap.String("subdomain", subdomain),
			zap.String("status", resp.Status),
			zap.String("body", strings.TrimSpace(string(body))))
	}
}

func (d *DynIPUpdater) UnmarshalCaddyfile(d2 *caddyfile.Dispenser) error {
	for d2.Next() {
		for d2.NextBlock(0) {
			switch d2.Val() {
			case "subdomain":
				if !d2.NextArg() {
					return d2.ArgErr()
				}
				d.Subdomains = append(d.Subdomains, d2.Val())
			case "interval":
				if !d2.NextArg() {
					return d2.ArgErr()
				}
				dur, err := time.ParseDuration(d2.Val())
				if err != nil {
					return d2.Errf("invalid interval: %s", d2.Val())
				}
				d.Interval = caddy.Duration(dur)
			case "ipv4_only":
				d.IPv4Only = true
			case "ipv6_only":
				d.IPv6Only = true
			case "dslite":
				d.DSLite = true
			}
		}
	}
	return nil
}