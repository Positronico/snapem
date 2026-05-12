package cli

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/positronico/snapem/internal/config"
)

func TestCheckSocketToken(t *testing.T) {
	cfg := config.Defaults()
	cfg.Scanning.Socket.APIToken = ""
	if r := checkSocketToken(context.Background(), cfg); r.Status != checkWarn {
		t.Errorf("missing token should warn, got %v (%s)", r.Status, r.Detail)
	}

	cfg.Scanning.Socket.APIToken = "fake-token"
	if r := checkSocketToken(context.Background(), cfg); r.Status != checkOK {
		t.Errorf("present token should pass, got %v (%s)", r.Status, r.Detail)
	}
}

func TestCheckCacheDir(t *testing.T) {
	cfg := config.Defaults()

	cfg.Scanning.Cache.Directory = ""
	if r := checkCacheDir(context.Background(), cfg); r.Status != checkWarn {
		t.Errorf("empty cache dir should warn, got %v", r.Status)
	}

	// Writable path — fresh tempdir.
	dir := filepath.Join(t.TempDir(), "snapem-cache")
	cfg.Scanning.Cache.Directory = dir
	r := checkCacheDir(context.Background(), cfg)
	if r.Status != checkOK {
		t.Errorf("writable dir should pass, got %v (%s)", r.Status, r.Detail)
	}
	// Probe file must not linger.
	if _, err := os.Stat(filepath.Join(dir, ".snapem-doctor-write-test")); !os.IsNotExist(err) {
		t.Errorf("probe file leaked: %v", err)
	}

	// Unwritable path — point at a file rather than a directory.
	bogus := filepath.Join(t.TempDir(), "actually-a-file")
	if err := os.WriteFile(bogus, []byte("x"), 0o644); err != nil {
		t.Fatalf("seed: %v", err)
	}
	cfg.Scanning.Cache.Directory = bogus
	if r := checkCacheDir(context.Background(), cfg); r.Status != checkFail {
		t.Errorf("non-dir path should fail, got %v (%s)", r.Status, r.Detail)
	}
}

func TestCheckHTTPReachable(t *testing.T) {
	cases := []struct {
		name       string
		statusCode int
		want       checkStatus
	}{
		{"200 OK", http.StatusOK, checkOK},
		{"404 still means reachable", http.StatusNotFound, checkOK},
		{"500 means degraded", http.StatusInternalServerError, checkWarn},
		{"503 means degraded", http.StatusServiceUnavailable, checkWarn},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tc.statusCode)
			}))
			defer srv.Close()

			r := checkHTTPReachable(context.Background(), "test API", srv.URL)
			if r.Status != tc.want {
				t.Errorf("status %d → check=%v, want %v (%s)", tc.statusCode, r.Status, tc.want, r.Detail)
			}
		})
	}
}

func TestCheckHTTPUnreachable(t *testing.T) {
	// Closed listener — connection refused on next dial.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	url := srv.URL
	srv.Close()

	r := checkHTTPReachable(context.Background(), "down API", url)
	if r.Status != checkFail {
		t.Errorf("connection refused should fail, got %v (%s)", r.Status, r.Detail)
	}
	if r.Hint == "" {
		t.Errorf("unreachable check should provide a remediation hint")
	}
}
