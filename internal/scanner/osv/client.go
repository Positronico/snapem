package osv

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/hashicorp/go-retryablehttp"
	"github.com/positronico/snapem/internal/config"
	"github.com/positronico/snapem/internal/manifest"
	"github.com/positronico/snapem/internal/types"
)

const (
	baseURL      = "https://api.osv.dev/v1"
	batchURL     = baseURL + "/querybatch"
	maxBatchSize = 1000
)

// Client handles Google OSV API interactions
type Client struct {
	httpClient *http.Client
	timeout    time.Duration
}

// NewClient creates a new OSV client
func NewClient(cfg config.OSVConfig) *Client {
	retryClient := retryablehttp.NewClient()
	retryClient.RetryMax = 3
	retryClient.Logger = nil // Disable logging

	return &Client{
		httpClient: retryClient.StandardClient(),
		timeout:    cfg.Timeout,
	}
}

// Name returns the scanner name
func (c *Client) Name() string {
	return "Google OSV"
}

// IsAvailable returns true (OSV API is always available, no auth required)
func (c *Client) IsAvailable() bool {
	return true
}

// Scan queries OSV for vulnerabilities in the given packages
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

	// Build batch request
	req := batchRequest{
		Queries: make([]query, len(packages)),
	}

	for i, pkg := range packages {
		req.Queries[i] = query{
			Package: packageInfo{
				Name:      pkg.Name,
				Ecosystem: "npm",
			},
			Version: pkg.Version,
		}
	}

	// Execute request
	resp, err := c.doBatchQuery(ctx, req)
	if err != nil {
		return nil, err
	}

	// Convert to findings
	findings := c.convertToFindings(packages, resp)

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

	httpReq, err := http.NewRequestWithContext(ctx, "POST", batchURL, bytes.NewReader(body))
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

func (c *Client) convertToFindings(packages []manifest.Package, resp *batchResponse) []types.Finding {
	var findings []types.Finding

	for i, result := range resp.Results {
		if i >= len(packages) {
			break
		}
		pkg := packages[i]

		for _, vuln := range result.Vulns {
			severity := c.mapSeverity(vuln)
			finding := types.Finding{
				Package:     pkg.Name,
				Version:     pkg.Version,
				Type:        types.FindingTypeCVE,
				Severity:    severity,
				Title:       vuln.Summary,
				Description: truncate(vuln.Details, 500),
				ID:          vuln.ID,
				References:  c.extractReferences(vuln.References),
			}
			findings = append(findings, finding)
		}
	}

	return findings
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
