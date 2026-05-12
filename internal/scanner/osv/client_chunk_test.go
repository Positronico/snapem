package osv

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/positronico/snapem/internal/manifest"
)

func TestScan_ChunksLargeBatches(t *testing.T) {
	var (
		requestCount int32
		totalQueries int32
		maxChunkSeen int32
	)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&requestCount, 1)
		var req batchRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		atomic.AddInt32(&totalQueries, int32(len(req.Queries)))
		for {
			cur := atomic.LoadInt32(&maxChunkSeen)
			if int32(len(req.Queries)) <= cur || atomic.CompareAndSwapInt32(&maxChunkSeen, cur, int32(len(req.Queries))) {
				break
			}
		}

		// Empty per-query results — no enrichment fan-out triggered.
		resp := batchResponse{Results: make([]queryResult, len(req.Queries))}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	c := &Client{
		httpClient: srv.Client(),
		timeout:    5 * time.Second,
		endpoint:   srv.URL,
		batchSize:  4,
	}

	const total = 11
	packages := make([]manifest.Package, total)
	for i := range packages {
		packages[i] = manifest.Package{
			Name:      "pkg-" + strconv.Itoa(i),
			Version:   "1.0.0",
			Ecosystem: "npm",
		}
	}

	result, err := c.Scan(context.Background(), packages)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if got := atomic.LoadInt32(&requestCount); got != 3 {
		t.Errorf("requests=%d, want 3 (chunks of 4,4,3)", got)
	}
	if got := atomic.LoadInt32(&maxChunkSeen); got > 4 {
		t.Errorf("max chunk size sent=%d, exceeded batchSize=4", got)
	}
	if got := atomic.LoadInt32(&totalQueries); int(got) != total {
		t.Errorf("total queries sent=%d, want %d", got, total)
	}
	if result.Packages != total {
		t.Errorf("result.Packages=%d, want %d", result.Packages, total)
	}
}

// TestScan_EnrichesVulnDetails confirms that /v1/querybatch shallow IDs are
// followed up with /v1/vulns/{id} fetches and the merged data shows up on
// the resulting Finding. Without this, findings carry empty Title and
// severity defaults to medium for every CVE.
func TestScan_EnrichesVulnDetails(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/querybatch", func(w http.ResponseWriter, r *http.Request) {
		resp := batchResponse{
			Results: []queryResult{
				{Vulns: []vulnerability{{ID: "GHSA-abc-123"}}},
			},
		}
		_ = json.NewEncoder(w).Encode(resp)
	})

	var enrichHits int32
	mux.HandleFunc("/vulns/", func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&enrichHits, 1)
		full := vulnerability{
			ID:               "GHSA-abc-123",
			Summary:          "Prototype pollution in lodash",
			Details:          "Long form details would appear here.",
			DatabaseSpecific: databaseSpecific{Severity: "HIGH"},
			References: []reference{
				{Type: "ADVISORY", URL: "https://example.com/ghsa-abc-123"},
			},
		}
		_ = json.NewEncoder(w).Encode(full)
	})

	srv := httptest.NewServer(mux)
	defer srv.Close()

	c := &Client{
		httpClient:    srv.Client(),
		timeout:       5 * time.Second,
		endpoint:      srv.URL + "/querybatch",
		vulnsEndpoint: srv.URL + "/vulns/",
		batchSize:     maxBatchSize,
	}

	result, err := c.Scan(context.Background(), []manifest.Package{
		{Name: "lodash", Version: "4.17.20", Ecosystem: "npm"},
	})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if atomic.LoadInt32(&enrichHits) != 1 {
		t.Errorf("expected 1 enrichment GET, got %d", enrichHits)
	}
	if len(result.Findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(result.Findings))
	}
	f := result.Findings[0]
	if f.Title != "Prototype pollution in lodash" {
		t.Errorf("title not enriched: %q", f.Title)
	}
	if f.Severity != "high" {
		t.Errorf("severity not propagated: %q", f.Severity)
	}
	if len(f.References) != 1 || f.References[0] != "https://example.com/ghsa-abc-123" {
		t.Errorf("references not enriched: %v", f.References)
	}
}

// Enrichment must dedupe IDs: the same advisory often hits multiple
// packages, but we only need one GET per unique ID.
func TestScan_EnrichDedupesIDs(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/querybatch", func(w http.ResponseWriter, r *http.Request) {
		// All three packages share the same advisory.
		resp := batchResponse{
			Results: []queryResult{
				{Vulns: []vulnerability{{ID: "GHSA-shared"}}},
				{Vulns: []vulnerability{{ID: "GHSA-shared"}}},
				{Vulns: []vulnerability{{ID: "GHSA-shared"}}},
			},
		}
		_ = json.NewEncoder(w).Encode(resp)
	})
	var hits int32
	mux.HandleFunc("/vulns/", func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		_ = json.NewEncoder(w).Encode(vulnerability{
			ID:               "GHSA-shared",
			Summary:          "Shared advisory",
			DatabaseSpecific: databaseSpecific{Severity: "MEDIUM"},
		})
	})

	srv := httptest.NewServer(mux)
	defer srv.Close()

	c := &Client{
		httpClient:    srv.Client(),
		timeout:       5 * time.Second,
		endpoint:      srv.URL + "/querybatch",
		vulnsEndpoint: srv.URL + "/vulns/",
		batchSize:     maxBatchSize,
	}

	_, err := c.Scan(context.Background(), []manifest.Package{
		{Name: "a", Version: "1", Ecosystem: "npm"},
		{Name: "b", Version: "1", Ecosystem: "npm"},
		{Name: "c", Version: "1", Ecosystem: "npm"},
	})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if got := atomic.LoadInt32(&hits); got != 1 {
		t.Errorf("enrichment GETs=%d, want 1 (deduped)", got)
	}
}
