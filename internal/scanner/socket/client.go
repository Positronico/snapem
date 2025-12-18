package socket

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
	baseURL = "https://api.socket.dev/v0"
)

// Client handles Socket.dev API interactions
type Client struct {
	httpClient *http.Client
	apiToken   string
	timeout    time.Duration
}

// NewClient creates a new Socket.dev client
func NewClient(cfg config.SocketConfig) *Client {
	retryClient := retryablehttp.NewClient()
	retryClient.RetryMax = 3
	retryClient.Logger = nil // Disable logging

	return &Client{
		httpClient: retryClient.StandardClient(),
		apiToken:   cfg.APIToken,
		timeout:    cfg.Timeout,
	}
}

// Name returns the scanner name
func (c *Client) Name() string {
	return "Socket.dev"
}

// IsAvailable returns true if API token is configured
func (c *Client) IsAvailable() bool {
	return c.apiToken != ""
}

// Scan queries Socket.dev for security issues in the given packages
func (c *Client) Scan(ctx context.Context, packages []manifest.Package) (*types.ScanResult, error) {
	start := time.Now()

	if !c.IsAvailable() {
		return &types.ScanResult{
			Scanner:      c.Name(),
			Packages:     0,
			Findings:     []types.Finding{},
			ScanDuration: time.Since(start),
		}, nil
	}

	if len(packages) == 0 {
		return &types.ScanResult{
			Scanner:      c.Name(),
			Packages:     0,
			Findings:     []types.Finding{},
			ScanDuration: time.Since(start),
		}, nil
	}

	// Build batch request with PURLs
	req := batchRequest{
		Packages: make([]packageIdentifier, len(packages)),
	}

	for i, pkg := range packages {
		req.Packages[i] = packageIdentifier{
			PURL: pkg.PURL(),
		}
	}

	// Execute request
	resp, err := c.doBatchQuery(ctx, req)
	if err != nil {
		return nil, err
	}

	// Convert to findings
	findings := c.convertToFindings(resp)

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

	httpReq, err := http.NewRequestWithContext(ctx, "POST", baseURL+"/purl", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", "Bearer "+c.apiToken)

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("failed to query Socket API: %w", err)
	}
	defer resp.Body.Close()

	// Handle different status codes
	switch resp.StatusCode {
	case http.StatusOK:
		// Success
	case http.StatusUnauthorized:
		return nil, fmt.Errorf("invalid Socket API token")
	case http.StatusForbidden:
		return nil, fmt.Errorf("Socket API access denied - check your subscription")
	case http.StatusTooManyRequests:
		return nil, fmt.Errorf("Socket API rate limit exceeded")
	default:
		respBody, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("Socket API returned status %d: %s", resp.StatusCode, string(respBody))
	}

	var batchResp batchResponse
	if err := json.NewDecoder(resp.Body).Decode(&batchResp); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return &batchResp, nil
}

func (c *Client) convertToFindings(resp *batchResponse) []types.Finding {
	var findings []types.Finding

	for _, result := range resp.Results {
		// Parse package name and version from PURL
		name, version := parsePURL(result.PURL)

		for _, alert := range result.Alerts {
			findingType := c.mapAlertType(alert.Type)
			severity := c.mapSeverity(alert.Severity)

			finding := types.Finding{
				Package:     name,
				Version:     version,
				Type:        findingType,
				Severity:    severity,
				Title:       alert.Type,
				Description: alert.Message,
				ID:          alert.Key,
			}
			findings = append(findings, finding)
		}
	}

	return findings
}

func (c *Client) mapAlertType(alertType string) types.FindingType {
	switch alertType {
	case "malware", "potentialVulnerability", "protestware":
		return types.FindingTypeMalware
	case "typosquat", "socketPkgWithoutProvenance":
		return types.FindingTypeTyposquat
	case "cve", "vulnerability":
		return types.FindingTypeCVE
	case "copyleftLicense", "nonpermissiveLicense", "unknownLicense":
		return types.FindingTypeLicense
	case "criticalCVE", "highCVE", "moderateCVE", "lowCVE":
		return types.FindingTypeCVE
	case "newAuthor", "noAuthor", "suspiciousAuthorEmail":
		return types.FindingTypeMaintainer
	default:
		return types.FindingTypeQuality
	}
}

func (c *Client) mapSeverity(severity string) types.Severity {
	switch severity {
	case "critical":
		return types.SeverityCritical
	case "high":
		return types.SeverityHigh
	case "medium", "moderate":
		return types.SeverityMedium
	case "low":
		return types.SeverityLow
	default:
		return types.SeverityInfo
	}
}

func parsePURL(purl string) (name, version string) {
	// Parse: pkg:npm/lodash@4.17.21
	if len(purl) < 8 {
		return "", ""
	}

	// Remove "pkg:npm/" prefix
	rest := purl
	if len(rest) > 8 && rest[:8] == "pkg:npm/" {
		rest = rest[8:]
	}

	// Find @ separator
	for i := len(rest) - 1; i >= 0; i-- {
		if rest[i] == '@' {
			return rest[:i], rest[i+1:]
		}
	}

	return rest, ""
}

// Request/Response types

type batchRequest struct {
	Packages []packageIdentifier `json:"packages"`
}

type packageIdentifier struct {
	PURL string `json:"purl"`
}

type batchResponse struct {
	Results []packageResult `json:"results"`
}

type packageResult struct {
	PURL   string  `json:"purl"`
	Score  float64 `json:"score"`
	Alerts []alert `json:"alerts,omitempty"`
}

type alert struct {
	Key      string `json:"key"`
	Type     string `json:"type"`
	Severity string `json:"severity"`
	Message  string `json:"message"`
}
