// Package metadata implements a scanner that surfaces actionable
// package-metadata facts: maintainer-marked deprecation and license
// posture. Data comes from deps.dev — the same upstream the
// Scorecard scanner uses — but via a separate cached call so the
// two scanners can be enabled/disabled independently.
//
// Today's findings:
//
//   - isDeprecated → medium advisory with the npm deprecation reason
//     in the description. The maintainer is telling you to stop using
//     this version; that's actionable supply-chain information.
//
//   - Unknown / non-standard license (opt-in via WarnUnknownLicense)
//     → low advisory. Off by default because many real packages
//     report "non-standard" from deps.dev simply because their
//     license string isn't a strict SPDX identifier — noisy.
//
// Other deps.dev signal (weekly downloads, stars, archived) is not
// surfaced as findings in this release. They'd need a "popularity"
// policy that's hard to tune without false positives.
package metadata

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/hashicorp/go-retryablehttp"

	"github.com/positronico/snapem/internal/config"
	"github.com/positronico/snapem/internal/manifest"
	"github.com/positronico/snapem/internal/types"
)

const (
	depsdevBase = "https://api.deps.dev/v3"
	versionPath = "/systems/npm/packages/%s/versions/%s"

	// concurrency bounds parallel deps.dev calls. deps.dev's public
	// rate limit is undocumented but generous; staying low stays
	// well below any throttling threshold.
	concurrency = 8
)

// Client is the metadata scanner.
type Client struct {
	httpClient         *http.Client
	timeout            time.Duration
	warnUnknownLicense bool
	enabled            bool
	baseURL            string // overrideable in tests
}

// NewClient returns a configured metadata client.
func NewClient(cfg config.MetadataConfig) *Client {
	retry := retryablehttp.NewClient()
	retry.RetryMax = 3
	retry.Logger = nil
	retry.CheckRetry = retryOn429
	retry.Backoff = retryablehttp.DefaultBackoff

	return &Client{
		httpClient:         retry.StandardClient(),
		timeout:            cfg.Timeout,
		warnUnknownLicense: cfg.WarnUnknownLicense,
		enabled:            cfg.Enabled,
		baseURL:            depsdevBase,
	}
}

func retryOn429(ctx context.Context, resp *http.Response, err error) (bool, error) {
	if resp != nil && resp.StatusCode == http.StatusTooManyRequests {
		return true, nil
	}
	return retryablehttp.DefaultRetryPolicy(ctx, resp, err)
}

// Name returns "metadata".
func (c *Client) Name() string { return "metadata" }

// IsAvailable mirrors the config toggle.
func (c *Client) IsAvailable() bool { return c.enabled }

// versionInfo is the subset of deps.dev's versions response we use.
type versionInfo struct {
	IsDeprecated     bool     `json:"isDeprecated"`
	DeprecatedReason string   `json:"deprecatedReason"`
	Licenses         []string `json:"licenses"`
}

// Scan emits findings per the configured policy.
func (c *Client) Scan(ctx context.Context, packages []manifest.Package) (*types.ScanResult, error) {
	result := &types.ScanResult{Scanner: c.Name(), Findings: []types.Finding{}}
	if len(packages) == 0 {
		return result, nil
	}

	// Dedupe (name, version).
	seen := make(map[string]struct{}, len(packages))
	deduped := make([]manifest.Package, 0, len(packages))
	for _, p := range packages {
		key := p.Name + "@" + p.Version
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		deduped = append(deduped, p)
	}

	jobs := make(chan manifest.Package)
	var (
		mu       sync.Mutex
		findings []types.Finding
		wg       sync.WaitGroup
	)

	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for p := range jobs {
				select {
				case <-ctx.Done():
					return
				default:
				}
				for _, f := range c.scanOne(ctx, p) {
					mu.Lock()
					findings = append(findings, f)
					mu.Unlock()
				}
			}
		}()
	}

	for _, p := range deduped {
		select {
		case <-ctx.Done():
			close(jobs)
			wg.Wait()
			return nil, ctx.Err()
		case jobs <- p:
		}
	}
	close(jobs)
	wg.Wait()

	if err := ctx.Err(); err != nil {
		return nil, err
	}

	sort.Slice(findings, func(i, j int) bool {
		if findings[i].Package != findings[j].Package {
			return findings[i].Package < findings[j].Package
		}
		return findings[i].Title < findings[j].Title
	})
	result.Findings = findings
	return result, nil
}

// scanOne fetches the version's deps.dev record and returns 0, 1, or
// 2 findings. Multiple findings are possible: a package can be both
// deprecated AND have an unknown license.
func (c *Client) scanOne(ctx context.Context, pkg manifest.Package) []types.Finding {
	v, ok := c.fetchVersion(ctx, pkg)
	if !ok {
		// Couldn't reach deps.dev or package not indexed. Not a
		// metadata problem; silently skip.
		return nil
	}

	var out []types.Finding
	if v.IsDeprecated {
		out = append(out, c.deprecationFinding(pkg, v))
	}
	if c.warnUnknownLicense && isUnknownLicense(v.Licenses) {
		out = append(out, c.licenseFinding(pkg, v))
	}
	return out
}

// isUnknownLicense reports whether the license field signals no
// confident classification. deps.dev returns the literal string
// "non-standard" when it found a license but couldn't map it to an
// SPDX identifier; that's the common "noisy" case we only flag
// behind warn_unknown_license.
func isUnknownLicense(licenses []string) bool {
	if len(licenses) == 0 {
		return true
	}
	for _, l := range licenses {
		s := strings.ToLower(strings.TrimSpace(l))
		if s != "" && s != "non-standard" && s != "unknown" {
			return false
		}
	}
	return true
}

func (c *Client) deprecationFinding(pkg manifest.Package, v *versionInfo) types.Finding {
	desc := "Maintainer marked this version deprecated."
	if reason := strings.TrimSpace(v.DeprecatedReason); reason != "" {
		desc = "Maintainer marked this version deprecated: " + reason
	}
	return types.Finding{
		Type:        types.FindingTypeQuality,
		Severity:    types.SeverityMedium,
		Package:     pkg.Name,
		Version:     pkg.Version,
		Title:       "Deprecated package version",
		Description: desc,
		References:  []string{fmt.Sprintf("https://www.npmjs.com/package/%s/v/%s", pkg.Name, pkg.Version)},
	}
}

func (c *Client) licenseFinding(pkg manifest.Package, v *versionInfo) types.Finding {
	got := "missing"
	if len(v.Licenses) > 0 {
		got = strings.Join(v.Licenses, ", ")
	}
	return types.Finding{
		Type:        types.FindingTypeLicense,
		Severity:    types.SeverityLow,
		Package:     pkg.Name,
		Version:     pkg.Version,
		Title:       "Unknown or non-standard license",
		Description: "deps.dev reports license as: " + got + ". Compliance review may be required.",
	}
}

func (c *Client) fetchVersion(ctx context.Context, pkg manifest.Package) (*versionInfo, bool) {
	path := fmt.Sprintf(versionPath, url.PathEscape(pkg.Name), url.PathEscape(pkg.Version))
	if c.timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, c.timeout)
		defer cancel()
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+path, nil)
	if err != nil {
		return nil, false
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "snapem")
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, false
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		_, _ = io.Copy(io.Discard, resp.Body)
		return nil, false
	}
	var v versionInfo
	if err := json.NewDecoder(resp.Body).Decode(&v); err != nil {
		return nil, false
	}
	return &v, true
}
