package caddyipv64

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"go.uber.org/zap"
)

func TestDynIPSetRecord_DeletesOldBeforeAdd(t *testing.T) {
	t.Helper()

	var got []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		_ = r.Body.Close()
		v, _ := url.ParseQuery(string(body))

		switch {
		case v.Get("del_record") != "":
			got = append(got, "del:"+v.Get("content"))
		case v.Get("add_record") != "":
			got = append(got, "add:"+v.Get("content"))
		default:
			t.Fatalf("unexpected action payload: %s", string(body))
		}

		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	p := &Provider{
		Token:      "token",
		httpClient: srv.Client(),
		endpoint:   srv.URL,
		logger:     zap.NewNop(),
	}
	d := &DynIPUpdater{provider: p, logger: zap.NewNop()}

	d.setRecord(context.Background(), "vpn.sickcloud.ipv64.de", "A", "87.123.22.12", "87.123.22.246")

	if len(got) != 2 {
		t.Fatalf("expected 2 API calls (delete + add), got %d (%v)", len(got), got)
	}
	if got[0] != "del:87.123.22.12" {
		t.Fatalf("first call should delete old IP, got %q", got[0])
	}
	if got[1] != "add:87.123.22.246" {
		t.Fatalf("second call should add new IP, got %q", got[1])
	}
}

func TestDynIPSetRecord_SameIPOnlyAdds(t *testing.T) {
	t.Helper()

	var got []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		_ = r.Body.Close()
		got = append(got, string(body))
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	p := &Provider{
		Token:      "token",
		httpClient: srv.Client(),
		endpoint:   srv.URL,
		logger:     zap.NewNop(),
	}
	d := &DynIPUpdater{provider: p, logger: zap.NewNop()}

	d.setRecord(context.Background(), "sickcloud.ipv64.de", "A", "87.123.22.246", "87.123.22.246")

	if len(got) != 1 {
		t.Fatalf("expected exactly 1 API call, got %d", len(got))
	}
	if !strings.Contains(got[0], "add_record=sickcloud.ipv64.de") {
		t.Fatalf("expected add_record payload, got %q", got[0])
	}
	if strings.Contains(got[0], "del_record=") {
		t.Fatalf("expected no delete call for unchanged IP, got %q", got[0])
	}
}
