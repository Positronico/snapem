package osv

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/hashicorp/go-retryablehttp"
	"github.com/positronico/snapem/internal/config"
	"github.com/positronico/snapem/internal/manifest"
	"github.com/positronico/snapem/internal/types"
)

const (
	baseURL  = "https://api.osv.dev/v1"
	batchURL = baseURL + "/querybatch"
	vulnsURL = baseURL + "/vulns/" // appended with the vuln ID
	// OSV /v1/querybatch caps requests at 1000 queries. We chunk eagerly
	// instead of letting the API reject oversized batches.
	maxBatchSize = 1000
	// enrichConcurrency bounds parallel /v1/vulns/{id} fetches. OSV's
	// public API has a soft rate limit; staying low is friendly.
	enrichConcurrency = 8
)

// Client handles Google OSV API interactions
type Client struct {
	httpClient    *http.Client
	timeout       time.Duration
	endpoint      string // overrideable in tests (POST /querybatch)
	vulnsEndpoint string // overrideable in tests (GET /vulns/{id})
	batchSize     int    // overrideable in tests
}

// NewClient creates a new OSV client
func NewClient(cfg config.OSVConfig) *Client {
	retryClient := retryablehttp.NewClient()
	retryClient.RetryMax = 3
	retryClient.Logger = nil // Disable logging
	// Same rationale as the Socket client: extend the retry policy to
	// cover 429 so a brief OSV rate-limit doesn't fail the scan. Backoff
	// already honors Retry-After.
	retryClient.CheckRetry = retryOn429
	retryClient.Backoff = retryablehttp.DefaultBackoff
	retryClient.ErrorHandler = rateLimitAwareErrorHandler

	return &Client{
		httpClient:    retryClient.StandardClient(),
		timeout:       cfg.Timeout,
		endpoint:      batchURL,
		vulnsEndpoint: vulnsURL,
		batchSize:     maxBatchSize,
	}
}

func retryOn429(ctx context.Context, resp *http.Response, err error) (bool, error) {
	if resp != nil && resp.StatusCode == http.StatusTooManyRequests {
		return true, nil
	}
	return retryablehttp.DefaultRetryPolicy(ctx, resp, err)
}

func rateLimitAwareErrorHandler(resp *http.Response, err error, numTries int) (*http.Response, error) {
	if resp != nil {
		status := resp.StatusCode
		resp.Body.Close()
		if status == http.StatusTooManyRequests {
			return nil, fmt.Errorf("OSV API rate limit exceeded after %d attempts (Retry-After honored)", numTries)
		}
	}
	return nil, err
}

// Name returns the scanner name
func (c *Client) Name() string {
	return "Google OSV"
}

// IsAvailable returns true (OSV API is always available, no auth required)
func (c *Client) IsAvailable() bool {
	return true
}

// Scan queries OSV for vulnerabilities in the given packages. Packages are
// chunked to respect the /v1/querybatch limit; chunks fire sequentially to
// keep memory pressure low (the OSV response can be large per chunk).
func (c *Client) Scan(ctx context.Context, packages []manifest.Package) (*types.ScanResult, error) {
	start := time.Now()

	if len(packages) == 0 {
		return &types.ScanResult{
			Scanner:      c.Name(),
			Packages:     0,
			Findings:     []types.Finding{},
			ScanDuration: time.Since(start),
		}, nil
	}

	batch := c.batchSize
	if batch <= 0 {
		batch = maxBatchSize
	}

	var findings []types.Finding
	for offset := 0; offset < len(packages); offset += batch {
		end := offset + batch
		if end > len(packages) {
			end = len(packages)
		}
		chunk := packages[offset:end]

		req := batchRequest{Queries: make([]query, len(chunk))}
		for i, pkg := range chunk {
			req.Queries[i] = query{
				Package: packageInfo{Name: pkg.Name, Ecosystem: "npm"},
				Version: pkg.Version,
			}
		}

		resp, err := c.doBatchQuery(ctx, req)
		if err != nil {
			return nil, err
		}

		// /v1/querybatch returns only vulnerability IDs. Fetch full
		// records for the unique IDs in this chunk so findings carry
		// severity, summary, and references.
		details, _ := c.enrich(ctx, collectVulnIDs(resp))

		findings = append(findings, c.convertToFindings(chunk, resp, details)...)
	}

	return &types.ScanResult{
		Scanner:      c.Name(),
		Packages:     len(packages),
		Findings:     findings,
		ScanDuration: time.Since(start),
	}, nil
}

func (c *Client) doBatchQuery(ctx context.Context, req batchRequest) (*batchResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()

	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	endpoint := c.endpoint
	if endpoint == "" {
		endpoint = batchURL
	}
	httpReq, err := http.NewRequestWithContext(ctx, "POST", endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("failed to query OSV API: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("OSV API returned status %d: %s", resp.StatusCode, string(respBody))
	}

	var batchResp batchResponse
	if err := json.NewDecoder(resp.Body).Decode(&batchResp); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return &batchResp, nil
}

func (c *Client) convertToFindings(packages []manifest.Package, resp *batchResponse, details map[string]vulnerability) []types.Finding {
	var findings []types.Finding

	for i, result := range resp.Results {
		if i >= len(packages) {
			break
		}
		pkg := packages[i]

		for _, vuln := range result.Vulns {
			// Merge the shallow batch record with the enriched one. The
			// batch record only reliably carries ID; everything else comes
			// from /v1/vulns/{id}.
			merged := vuln
			if d, ok := details[vuln.ID]; ok {
				merged = d
				if merged.ID == "" {
					merged.ID = vuln.ID
				}
			}

			finding := types.Finding{
				Package:     pkg.Name,
				Version:     pkg.Version,
				Type:        types.FindingTypeCVE,
				Severity:    c.mapSeverity(merged),
				Title:       merged.Summary,
				Description: truncate(merged.Details, 500),
				ID:          merged.ID,
				References:  c.extractReferences(merged.References),
				Remediation: remediationFor(merged, pkg.Name),
			}
			findings = append(findings, finding)
		}
	}

	return findings
}

// collectVulnIDs returns the unique vuln IDs referenced anywhere in resp,
// in deterministic order so tests can pin behavior.
func collectVulnIDs(resp *batchResponse) []string {
	if resp == nil {
		return nil
	}
	seen := make(map[string]struct{})
	var ids []string
	for _, r := range resp.Results {
		for _, v := range r.Vulns {
			if v.ID == "" {
				continue
			}
			if _, ok := seen[v.ID]; ok {
				continue
			}
			seen[v.ID] = struct{}{}
			ids = append(ids, v.ID)
		}
	}
	return ids
}

// enrich fetches /v1/vulns/{id} for each id in parallel (bounded). Returns
// whatever it managed to collect plus the first error seen; the caller
// degrades to shallow findings if enrichment fails partially.
func (c *Client) enrich(ctx context.Context, ids []string) (map[string]vulnerability, error) {
	if len(ids) == 0 {
		return nil, nil
	}
	out := make(map[string]vulnerability, len(ids))
	var (
		mu       sync.Mutex
		firstErr error
		wg       sync.WaitGroup
	)
	sem := make(chan struct{}, enrichConcurrency)

	for _, id := range ids {
		wg.Add(1)
		sem <- struct{}{}
		go func(id string) {
			defer wg.Done()
			defer func() { <-sem }()

			v, err := c.fetchVuln(ctx, id)
			if err != nil {
				mu.Lock()
				if firstErr == nil {
					firstErr = err
				}
				mu.Unlock()
				return
			}
			mu.Lock()
			out[id] = *v
			mu.Unlock()
		}(id)
	}
	wg.Wait()
	return out, firstErr
}

func (c *Client) fetchVuln(ctx context.Context, id string) (*vulnerability, error) {
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()

	endpoint := c.vulnsEndpoint
	if endpoint == "" {
		endpoint = vulnsURL
	}
	httpReq, err := http.NewRequestWithContext(ctx, "GET", endpoint+id, nil)
	if err != nil {
		return nil, fmt.Errorf("create vuln request: %w", err)
	}

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("fetch vuln %s: %w", id, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("vuln %s: status %d: %s", id, resp.StatusCode, string(body))
	}
	var v vulnerability
	if err := json.NewDecoder(resp.Body).Decode(&v); err != nil {
		return nil, fmt.Errorf("decode vuln %s: %w", id, err)
	}
	return &v, nil
}

// mapSeverity resolves a vulnerability to one of our internal severity
// buckets. Precedence (highest confidence first):
//
//  1. database_specific.severity string (GHSA-published level).
//  2. CVSS v3 vector or numeric score parsed via cvssScore().
//  3. Ecosystem-typed severity strings (legacy OSV form).
//  4. Medium as last resort — see CLAUDE.md §8.2 for why this matters.
func (c *Client) mapSeverity(vuln vulnerability) types.Severity {
	if s := normalizeSeverityString(vuln.DatabaseSpecific.Severity); s != "" {
		return s
	}

	for _, sev := range vuln.Severity {
		switch sev.Type {
		case "CVSS_V3", "CVSS_V4":
			if score, ok := cvssScore(sev.Score); ok {
				return severityFromCVSS(score)
			}
		}
	}

	for _, sev := range vuln.Severity {
		if sev.Type == "ECOSYSTEM" {
			if s := normalizeSeverityString(sev.Score); s != "" {
				return s
			}
		}
	}

	return types.SeverityMedium
}

func severityFromCVSS(score float64) types.Severity {
	switch {
	case score >= 9.0:
		return types.SeverityCritical
	case score >= 7.0:
		return types.SeverityHigh
	case score >= 4.0:
		return types.SeverityMedium
	case score > 0:
		return types.SeverityLow
	default:
		// 0.0 base score still represents a tracked finding; report it as
		// the lowest non-zero bucket rather than dropping it.
		return types.SeverityLow
	}
}

func normalizeSeverityString(s string) types.Severity {
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case "CRITICAL":
		return types.SeverityCritical
	case "HIGH":
		return types.SeverityHigh
	case "MODERATE", "MEDIUM":
		return types.SeverityMedium
	case "LOW":
		return types.SeverityLow
	}
	return ""
}

func (c *Client) extractReferences(refs []reference) []string {
	var urls []string
	for _, ref := range refs {
		if ref.URL != "" {
			urls = append(urls, ref.URL)
		}
	}
	return urls
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}

// Request/Response types

type batchRequest struct {
	Queries []query `json:"queries"`
}

type query struct {
	Package packageInfo `json:"package"`
	Version string      `json:"version,omitempty"`
}

type packageInfo struct {
	Name      string `json:"name"`
	Ecosystem string `json:"ecosystem"`
}

type batchResponse struct {
	Results []queryResult `json:"results"`
}

type queryResult struct {
	Vulns []vulnerability `json:"vulns,omitempty"`
}

type vulnerability struct {
	ID               string           `json:"id"`
	Summary          string           `json:"summary"`
	Details          string           `json:"details"`
	Severity         []severity       `json:"severity,omitempty"`
	References       []reference      `json:"references,omitempty"`
	Affected         []affected       `json:"affected,omitempty"`
	DatabaseSpecific databaseSpecific `json:"database_specific,omitempty"`
}

// databaseSpecific carries fields the OSV record source attached. For npm
// GHSA records, severity is consistently populated.
type databaseSpecific struct {
	Severity string `json:"severity,omitempty"`
}

type severity struct {
	Type  string `json:"type"`
	Score string `json:"score"`
}

type reference struct {
	Type string `json:"type"`
	URL  string `json:"url"`
}

type affected struct {
	Package  packageInfo `json:"package"`
	Ranges   []rangeInfo `json:"ranges,omitempty"`
	Versions []string    `json:"versions,omitempty"`
}

type rangeInfo struct {
	Type   string  `json:"type"`
	Events []event `json:"events"`
}

type event struct {
	Introduced string `json:"introduced,omitempty"`
	Fixed      string `json:"fixed,omitempty"`
}
