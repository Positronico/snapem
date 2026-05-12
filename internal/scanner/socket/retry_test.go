package socket

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hashicorp/go-retryablehttp"
	"github.com/positronico/snapem/internal/manifest"
)

// TestScan_RetriesOn429 confirms that Socket's free-tier 429 responses
// are retried automatically instead of failing the scan. Without this,
// transient rate-limit blips block any install/scan run.
func TestScan_RetriesOn429(t *testing.T) {
	var attempts int32

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt32(&attempts, 1)
		if n < 3 {
			// Tell the retry layer to back off briefly so the test
			// finishes quickly rather than waiting the default
			// exponential delay.
			w.Header().Set("Retry-After", "0")
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(batchResponse{
			Results: []packageResult{{PURL: "pkg:npm/lodash@1.0.0"}},
		})
	}))
	defer srv.Close()

	// Hand-construct a retryable client with the same policy as production
	// but a shorter overall budget so the test runs in seconds, not minutes.
	retryClient := retryablehttp.NewClient()
	retryClient.RetryMax = 3
	retryClient.Logger = nil
	retryClient.CheckRetry = retryOn429
	retryClient.Backoff = retryablehttp.DefaultBackoff
	retryClient.ErrorHandler = rateLimitAwareErrorHandler

	c := &Client{
		httpClient: retryClient.StandardClient(),
		apiToken:   "test",
		timeout:    5 * time.Second,
		endpoint:   srv.URL,
		batchSize:  maxBatchSize,
	}

	_, err := c.Scan(context.Background(), []manifest.Package{
		{Name: "lodash", Version: "1.0.0", Ecosystem: "npm"},
	})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if got := atomic.LoadInt32(&attempts); got != 3 {
		t.Errorf("server attempts=%d, want 3 (two 429s + one 200)", got)
	}
}

// If 429 persists past the retry budget, the user-visible error must still
// be the "Socket API rate limit exceeded" message rather than a generic
// transport failure.
func TestScan_RateLimitExhausted(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Retry-After", "0")
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer srv.Close()

	retryClient := retryablehttp.NewClient()
	retryClient.RetryMax = 1 // small budget so the test finishes fast
	retryClient.Logger = nil
	retryClient.CheckRetry = retryOn429
	retryClient.Backoff = retryablehttp.DefaultBackoff
	retryClient.ErrorHandler = rateLimitAwareErrorHandler

	c := &Client{
		httpClient: retryClient.StandardClient(),
		apiToken:   "test",
		timeout:    5 * time.Second,
		endpoint:   srv.URL,
		batchSize:  maxBatchSize,
	}

	_, err := c.Scan(context.Background(), []manifest.Package{
		{Name: "lodash", Version: "1.0.0", Ecosystem: "npm"},
	})
	if err == nil {
		t.Fatal("expected error after exhausting retry budget on persistent 429")
	}
	if msg := err.Error(); !contains(msg, "rate limit") {
		t.Errorf("error should mention rate limit: %q", msg)
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
