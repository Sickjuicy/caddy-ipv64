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
	var got []struct {
		method string
		form   url.Values
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		got = append(got, struct {
			method string
			form   url.Values
		}{method: r.Method, form: r.Form})
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"success"}`))
	}))
	defer srv.Close()

	p := &Provider{Token: "token", httpClient: srv.Client(), endpoint: srv.URL, logger: zap.NewNop()}
	d := &DynIPUpdater{provider: p, logger: zap.NewNop(), updaterEndpoint: srv.URL}

	d.updateRecord(context.Background(), "vpn.example.ipv64.de", "", "", "203.0.113.1", "")

	if len(got) != 1 {
		t.Fatalf("expected exactly 1 API call, got %d", len(got))
	}
	if got[0].method != http.MethodPost {
		t.Fatalf("method: want POST, got %s", got[0].method)
	}
	if got[0].form.Get("add_record") != "example.ipv64.de" {
		t.Errorf("domain: want example.ipv64.de, got %q", got[0].form.Get("add_record"))
	}
	if got[0].form.Get("praefix") != "vpn" {
		t.Errorf("praefix: want vpn, got %q", got[0].form.Get("praefix"))
	}
	if got[0].form.Get("type") != "A" {
		t.Errorf("type: want A, got %q", got[0].form.Get("type"))
	}
	if got[0].form.Get("content") != "203.0.113.1" {
		t.Errorf("content: want 203.0.113.1, got %q", got[0].form.Get("content"))
	}
}

func TestDynIPUpdateRecord_DualStack(t *testing.T) {
	var got []struct {
		method string
		form   url.Values
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		got = append(got, struct {
			method string
			form   url.Values
		}{method: r.Method, form: r.Form})
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"success"}`))
	}))
	defer srv.Close()

	p := &Provider{Token: "token", httpClient: srv.Client(), endpoint: srv.URL, logger: zap.NewNop()}
	d := &DynIPUpdater{provider: p, logger: zap.NewNop(), updaterEndpoint: srv.URL}

	d.updateRecord(context.Background(), "example.ipv64.de", "", "", "203.0.113.1", "2001:db8::1")

	if len(got) != 2 {
		t.Fatalf("expected exactly 2 API calls for dual-stack, got %d", len(got))
	}
	if got[0].method != http.MethodPost || got[1].method != http.MethodPost {
		t.Fatalf("expected POST requests for both records, got %s and %s", got[0].method, got[1].method)
	}
	if got[0].form.Get("type") != "A" || got[1].form.Get("type") != "AAAA" {
		t.Fatalf("expected A and AAAA record types, got %q and %q", got[0].form.Get("type"), got[1].form.Get("type"))
	}
	if got[0].form.Get("content") != "203.0.113.1" || got[1].form.Get("content") != "2001:db8::1" {
		t.Fatalf("unexpected contents: %q and %q", got[0].form.Get("content"), got[1].form.Get("content"))
	}
}

func TestDynIPUpdateRecord_ApexPrefix(t *testing.T) {
	var got []struct {
		method string
		form   url.Values
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		got = append(got, struct {
			method string
			form   url.Values
		}{method: r.Method, form: r.Form})
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"success"}`))
	}))
	defer srv.Close()

	p := &Provider{Token: "token", httpClient: srv.Client(), endpoint: srv.URL, logger: zap.NewNop()}
	d := &DynIPUpdater{provider: p, logger: zap.NewNop(), updaterEndpoint: srv.URL}

	d.updateRecord(context.Background(), "example.ipv64.de", "", "", "203.0.113.1", "")

	if len(got) != 1 {
		t.Fatalf("expected exactly 1 API call for apex update, got %d", len(got))
	}
	if got[0].form.Get("praefix") != "" {
		t.Errorf("apex prefix: want empty string, got %q", got[0].form.Get("praefix"))
	}
	if got[0].form.Get("add_record") != "example.ipv64.de" {
		t.Errorf("domain: want example.ipv64.de, got %q", got[0].form.Get("add_record"))
	}
}

func TestDynIPUpdateRecord_UsesBearerAuth(t *testing.T) {
	var gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"success"}`))
	}))
	defer srv.Close()

	p := &Provider{Token: "token", httpClient: srv.Client(), endpoint: srv.URL, logger: zap.NewNop()}
	d := &DynIPUpdater{provider: p, logger: zap.NewNop(), updaterEndpoint: srv.URL}

	d.updateRecord(context.Background(), "example.ipv64.de", "", "", "203.0.113.1", "")

	if gotAuth != "Bearer token" {
		t.Errorf("auth header: want Bearer token, got %q", gotAuth)
	}
}


