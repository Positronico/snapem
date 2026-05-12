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
		requestCount  int32
		totalQueries  int32
		maxChunkSeen  int32
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

		// Echo an empty result per query so the response stays valid.
		resp := batchResponse{Results: make([]queryResult, len(req.Queries))}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	c := &Client{
		httpClient: srv.Client(),
		timeout:    5 * time.Second,
		endpoint:   srv.URL,
		batchSize:  4, // small for the test
	}

	const total = 11 // expect ceil(11/4) = 3 chunks
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
