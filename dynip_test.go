package caddyipv64

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"go.uber.org/zap"
)

func TestDynIPUpdateRecord_IPv4Only(t *testing.T) {
	var got []url.Values
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = append(got, r.URL.Query())
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"success","ip":["203.0.113.1"]}`))
	}))
	defer srv.Close()

	p := &Provider{Token: "token", httpClient: srv.Client(), endpoint: srv.URL, logger: zap.NewNop()}
	d := &DynIPUpdater{provider: p, logger: zap.NewNop(), updaterEndpoint: srv.URL}

	d.updateRecord(context.Background(), "vpn.example.ipv64.de", "203.0.113.1", "")

	if len(got) != 1 {
		t.Fatalf("expected exactly 1 API call, got %d", len(got))
	}
	if got[0].Get("domain") != "example.ipv64.de" {
		t.Errorf("domain: want example.ipv64.de, got %q", got[0].Get("domain"))
	}
	if got[0].Get("praefix") != "vpn" {
		t.Errorf("praefix: want vpn, got %q", got[0].Get("praefix"))
	}
	if got[0].Get("ip") != "203.0.113.1" {
		t.Errorf("ip: want 203.0.113.1, got %q", got[0].Get("ip"))
	}
	if got[0].Get("ip6") != "" {
		t.Errorf("ip6: want empty, got %q", got[0].Get("ip6"))
	}
}

func TestDynIPUpdateRecord_DualStack(t *testing.T) {
	var got []url.Values
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = append(got, r.URL.Query())
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"success"}`))
	}))
	defer srv.Close()

	p := &Provider{Token: "token", httpClient: srv.Client(), endpoint: srv.URL, logger: zap.NewNop()}
	d := &DynIPUpdater{provider: p, logger: zap.NewNop(), updaterEndpoint: srv.URL}

	d.updateRecord(context.Background(), "example.ipv64.de", "203.0.113.1", "2001:db8::1")

	if len(got) != 1 {
		t.Fatalf("expected exactly 1 API call for dual-stack, got %d", len(got))
	}
	if got[0].Get("domain") != "example.ipv64.de" {
		t.Errorf("domain: want example.ipv64.de, got %q", got[0].Get("domain"))
	}
	if got[0].Get("praefix") != "" {
		t.Errorf("praefix: want empty string, got %q", got[0].Get("praefix"))
	}
	if got[0].Get("ip") != "203.0.113.1" {
		t.Errorf("ip: want 203.0.113.1, got %q", got[0].Get("ip"))
	}
	if got[0].Get("ip6") != "2001:db8::1" {
		t.Errorf("ip6: want 2001:db8::1, got %q", got[0].Get("ip6"))
	}
}

func TestDynIPUpdateRecord_ApexPrefix(t *testing.T) {
	var got []url.Values
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = append(got, r.URL.Query())
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"success"}`))
	}))
	defer srv.Close()

	p := &Provider{Token: "token", httpClient: srv.Client(), endpoint: srv.URL, logger: zap.NewNop()}
	d := &DynIPUpdater{provider: p, logger: zap.NewNop(), updaterEndpoint: srv.URL}

	d.updateRecord(context.Background(), "example.ipv64.de", "203.0.113.1", "")

	if got[0].Get("praefix") != "" {
		t.Errorf("apex prefix: want empty string, got %q", got[0].Get("praefix"))
	}
	if got[0].Get("domain") != "example.ipv64.de" {
		t.Errorf("domain: want example.ipv64.de, got %q", got[0].Get("domain"))
	}
}

func TestDynIPUpdateRecord_UsesDynDNSAuth(t *testing.T) {
	var gotAuth string
	var gotQuery url.Values
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotQuery = r.URL.Query()
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"success"}`))
	}))
	defer srv.Close()

	p := &Provider{Token: "token", httpClient: srv.Client(), endpoint: srv.URL, logger: zap.NewNop()}
	d := &DynIPUpdater{provider: p, logger: zap.NewNop(), updaterEndpoint: srv.URL}

	d.updateRecord(context.Background(), "example.ipv64.de", "203.0.113.1", "")

	if gotQuery.Get("key") != "token" {
		t.Errorf("auth key: want token, got %q", gotQuery.Get("key"))
	}
	if gotAuth == "" {
		t.Fatal("expected basic auth header to be set")
	}
}

