package osv

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
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

func (c *Client) mapSeverity(vuln vulnerability) types.Severity {
	// Check CVSS scores first
	for _, sev := range vuln.Severity {
		if sev.Type == "CVSS_V3" {
			score := parseCVSSScore(sev.Score)
			if score >= 9.0 {
				return types.SeverityCritical
			} else if score >= 7.0 {
				return types.SeverityHigh
			} else if score >= 4.0 {
				return types.SeverityMedium
			}
			return types.SeverityLow
		}
	}

	// Check database-specific severity
	for _, sev := range vuln.Severity {
		switch sev.Type {
		case "ECOSYSTEM":
			// Some ecosystems provide severity directly
			switch sev.Score {
			case "CRITICAL":
				return types.SeverityCritical
			case "HIGH":
				return types.SeverityHigh
			case "MODERATE", "MEDIUM":
				return types.SeverityMedium
			case "LOW":
				return types.SeverityLow
			}
		}
	}

	// Check database ID prefix as fallback
	if len(vuln.ID) >= 4 && vuln.ID[:4] == "GHSA" {
		// GitHub Security Advisories usually have severity in details
		return types.SeverityMedium // Default for unknown GHSA
	}

	return types.SeverityMedium
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

func parseCVSSScore(vector string) float64 {
	// Simple extraction of base score from CVSS vector
	// Format: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
	// We'd need to calculate, but for simplicity, let's estimate from vector
	// A proper implementation would parse and calculate

	// Count high-impact indicators
	highCount := 0
	if contains(vector, "/C:H") {
		highCount++
	}
	if contains(vector, "/I:H") {
		highCount++
	}
	if contains(vector, "/A:H") {
		highCount++
	}
	if contains(vector, "/AV:N") {
		highCount++
	}
	if contains(vector, "/PR:N") {
		highCount++
	}

	switch {
	case highCount >= 4:
		return 9.0
	case highCount >= 3:
		return 7.5
	case highCount >= 2:
		return 5.0
	default:
		return 3.0
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > len(substr) && (s[:len(substr)] == substr || s[len(s)-len(substr):] == substr || containsMiddle(s, substr)))
}

func containsMiddle(s, substr string) bool {
	for i := 1; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
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
	ID         string      `json:"id"`
	Summary    string      `json:"summary"`
	Details    string      `json:"details"`
	Severity   []severity  `json:"severity,omitempty"`
	References []reference `json:"references,omitempty"`
	Affected   []affected  `json:"affected,omitempty"`
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
