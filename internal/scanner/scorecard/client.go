// Package scorecard implements a scanner that surfaces OSSF Scorecard
// findings (https://github.com/ossf/scorecard) for npm packages.
//
// Scorecard measures *maintainer hygiene* rather than malware or known
// CVEs — recent activity, code review enforcement, signed releases,
// branch protection, dangerous workflows, pinned dependencies, etc.
// A 1-person side project with no CI and no review will score poorly
// even if it ships clean code today; that's the supply-chain risk
// snapem's other scanners can't see.
//
// Data source: deps.dev (Google), which embeds Scorecard's per-repo
// score in its /v3/projects response. We hit deps.dev rather than
// Scorecard's API directly because deps.dev also resolves the
// npm-name → GitHub-repo mapping in one place — no extra hop to the
// npm registry.
//
// Per-package flow (two HTTP calls, both cacheable):
//  1. GET /v3/systems/npm/packages/{name}/versions/{version}
//     → parse relatedProjects for a SOURCE_REPO on github.com/
//  2. GET /v3/projects/{urlencoded-repo-id}
//     → parse scorecard.overallScore and scorecard.checks
//
// Packages without a github.com source link, or whose repos haven't
// been scanned by Scorecard yet, are silently skipped — surfacing
// "no data" as a finding would dwarf real signals.
package scorecard

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
	depsdevBase  = "https://api.deps.dev/v3"
	versionPath  = "/systems/npm/packages/%s/versions/%s"
	projectsPath = "/projects/%s"

	// concurrency bounds parallel deps.dev requests. deps.dev's public
	// rate limit is undocumented but generous; staying low keeps us
	// well below any throttling threshold.
	concurrency = 8
)

// Client is the Scorecard scanner. It satisfies the parent package's
// Scanner interface via Name / IsAvailable / Scan.
type Client struct {
	httpClient *http.Client
	timeout    time.Duration
	threshold  float64
	baseURL    string // overrideable in tests
	enabled    bool
}

// NewClient returns a configured Scorecard client. Concurrency and
// retry behavior mirror the OSV/Socket clients so 429s are honored
// transparently and a brief outage doesn't fail the scan.
func NewClient(cfg config.ScorecardConfig) *Client {
	retry := retryablehttp.NewClient()
	retry.RetryMax = 3
	retry.Logger = nil
	retry.CheckRetry = retryOn429
	retry.Backoff = retryablehttp.DefaultBackoff

	return &Client{
		httpClient: retry.StandardClient(),
		timeout:    cfg.Timeout,
		threshold:  cfg.Threshold,
		baseURL:    depsdevBase,
		enabled:    cfg.Enabled,
	}
}

func retryOn429(ctx context.Context, resp *http.Response, err error) (bool, error) {
	if resp != nil && resp.StatusCode == http.StatusTooManyRequests {
		return true, nil
	}
	return retryablehttp.DefaultRetryPolicy(ctx, resp, err)
}

// Name returns "scorecard".
func (c *Client) Name() string { return "scorecard" }

// IsAvailable mirrors the config toggle. The deps.dev API is
// unauthenticated, so there's no credential check to perform.
func (c *Client) IsAvailable() bool { return c.enabled }

// versionResponse is the subset of /v3/systems/.../versions/... we care
// about. We pull the SOURCE_REPO link, ignoring HOMEPAGE/ISSUE_TRACKER/
// ORIGIN entries.
type versionResponse struct {
	RelatedProjects []struct {
		ProjectKey struct {
			ID string `json:"id"`
		} `json:"projectKey"`
		RelationType string `json:"relationType"`
	} `json:"relatedProjects"`
}

// projectResponse is the subset of /v3/projects/... we surface.
type projectResponse struct {
	Scorecard *struct {
		Date         string `json:"date"`
		OverallScore float64 `json:"overallScore"`
		Checks       []struct {
			Name   string  `json:"name"`
			Score  float64 `json:"score"`
			Reason string  `json:"reason"`
		} `json:"checks"`
	} `json:"scorecard"`
}

// Scan returns a finding for every package whose Scorecard score is
// below the configured threshold. Packages with no github.com source
// link or no Scorecard data return nothing.
func (c *Client) Scan(ctx context.Context, packages []manifest.Package) (*types.ScanResult, error) {
	result := &types.ScanResult{Scanner: c.Name(), Findings: []types.Finding{}}
	if len(packages) == 0 {
		return result, nil
	}

	// Dedupe (name, version) — workspace monorepos commonly resolve
	// the same package twice.
	seen := make(map[string]struct{}, len(packages))
	deduped := packages[:0:0]
	for _, p := range packages {
		key := p.Name + "@" + p.Version
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		deduped = append(deduped, p)
	}

	type job struct{ pkg manifest.Package }

	jobs := make(chan job)
	var (
		mu       sync.Mutex
		findings []types.Finding
		wg       sync.WaitGroup
	)

	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range jobs {
				select {
				case <-ctx.Done():
					return
				default:
				}
				f, ok := c.scanOne(ctx, j.pkg)
				if !ok {
					continue
				}
				mu.Lock()
				findings = append(findings, f)
				mu.Unlock()
			}
		}()
	}

	for _, p := range deduped {
		select {
		case <-ctx.Done():
			close(jobs)
			wg.Wait()
			return nil, ctx.Err()
		case jobs <- job{pkg: p}:
		}
	}
	close(jobs)
	wg.Wait()

	// Surface a cancellation that fired after the producer finished
	// queueing but before workers drained. Without this, a pre-canceled
	// ctx whose Done() lost the producer's select race would silently
	// return whatever (probably empty) findings the workers collected.
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	sort.Slice(findings, func(i, j int) bool {
		return findings[i].Package < findings[j].Package
	})
	result.Findings = findings
	return result, nil
}

// scanOne runs the two-call flow for a single package. Returns
// (finding, true) when a sub-threshold score was found, otherwise
// (zero, false). All failure modes (no source repo, non-github,
// 404, decode error) return (zero, false) — Scorecard is advisory.
func (c *Client) scanOne(ctx context.Context, pkg manifest.Package) (types.Finding, bool) {
	repoID, ok := c.lookupRepo(ctx, pkg)
	if !ok {
		return types.Finding{}, false
	}
	if !strings.HasPrefix(repoID, "github.com/") {
		// Scorecard only covers GitHub. Skip GitLab / Bitbucket / etc.
		return types.Finding{}, false
	}
	proj, ok := c.lookupProject(ctx, repoID)
	if !ok || proj.Scorecard == nil {
		return types.Finding{}, false
	}
	score := proj.Scorecard.OverallScore
	if score >= c.threshold {
		return types.Finding{}, false
	}

	return c.buildFinding(pkg, repoID, *proj.Scorecard), true
}

// lookupRepo hits the npm versions endpoint and returns the first
// SOURCE_REPO link's project ID. Returns ok=false when there's no
// source-repo entry.
func (c *Client) lookupRepo(ctx context.Context, pkg manifest.Package) (string, bool) {
	path := fmt.Sprintf(versionPath, url.PathEscape(pkg.Name), url.PathEscape(pkg.Version))
	var resp versionResponse
	if !c.getJSON(ctx, c.baseURL+path, &resp) {
		return "", false
	}
	for _, rp := range resp.RelatedProjects {
		if rp.RelationType == "SOURCE_REPO" && rp.ProjectKey.ID != "" {
			return rp.ProjectKey.ID, true
		}
	}
	return "", false
}

// lookupProject hits the projects endpoint and returns the parsed
// response. ok=false when the repo hasn't been scanned by Scorecard
// (404) or any error occurred.
func (c *Client) lookupProject(ctx context.Context, repoID string) (projectResponse, bool) {
	path := fmt.Sprintf(projectsPath, url.PathEscape(repoID))
	var resp projectResponse
	if !c.getJSON(ctx, c.baseURL+path, &resp) {
		return projectResponse{}, false
	}
	return resp, true
}

// getJSON is the shared GET-and-decode used by both endpoints. Any
// non-2xx (including 404, which is the common "no data" signal from
// deps.dev) returns false.
func (c *Client) getJSON(ctx context.Context, fullURL string, out any) bool {
	if c.timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, c.timeout)
		defer cancel()
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, fullURL, nil)
	if err != nil {
		return false
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "snapem")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		// Drain so the connection can be reused.
		_, _ = io.Copy(io.Discard, resp.Body)
		return false
	}
	if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
		return false
	}
	return true
}

// buildFinding renders the per-package Finding shown in scan output.
// The description names the two weakest checks so the user knows what
// specifically is wrong (e.g. "Maintained 0/10, Code-Review 2/10")
// without having to open the Scorecard report.
func (c *Client) buildFinding(pkg manifest.Package, repoID string, sc struct {
	Date         string  `json:"date"`
	OverallScore float64 `json:"overallScore"`
	Checks       []struct {
		Name   string  `json:"name"`
		Score  float64 `json:"score"`
		Reason string  `json:"reason"`
	} `json:"checks"`
}) types.Finding {
	severity := types.SeverityLow
	switch {
	case sc.OverallScore < 2:
		severity = types.SeverityHigh
	case sc.OverallScore < 4:
		severity = types.SeverityMedium
	}

	checks := append([]struct {
		Name   string  `json:"name"`
		Score  float64 `json:"score"`
		Reason string  `json:"reason"`
	}{}, sc.Checks...)
	sort.SliceStable(checks, func(i, j int) bool {
		// Treat -1 ("not applicable") as 11 so it doesn't masquerade
		// as the worst check; Scorecard uses -1 for "N/A".
		ai, aj := checks[i].Score, checks[j].Score
		if ai < 0 {
			ai = 11
		}
		if aj < 0 {
			aj = 11
		}
		return ai < aj
	})

	var weakest []string
	for i, c := range checks {
		if i >= 2 || c.Score < 0 {
			break
		}
		weakest = append(weakest, fmt.Sprintf("%s %.0f/10", c.Name, c.Score))
	}

	// Fold the weakest-check detail into Title — the UI's ThreatLine
	// renders only (severity, id, title, fix, url). Description is
	// available to consumers (JSON/SARIF) but not the text renderer.
	title := fmt.Sprintf("OSSF Scorecard %.1f/10 (low maintainer hygiene)", sc.OverallScore)
	if len(weakest) > 0 {
		title += " — weakest: " + strings.Join(weakest, ", ")
	}

	return types.Finding{
		Type:        types.FindingTypeQuality,
		Severity:    severity,
		Package:     pkg.Name,
		Version:     pkg.Version,
		Title:       title,
		Description: title,
		References:  []string{"https://deps.dev/" + repoID},
	}
}
