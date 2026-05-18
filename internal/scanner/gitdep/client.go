// Package gitdep implements a scanner that flags published npm
// packages whose dependency specifiers point at a git repository,
// tarball URL, or local path rather than a published registry
// version range.
//
// Why this is a signal
//
// A registry version range ("^1.0.0", "1.x", "1.2.3") is something
// every other scanner in this tool can reason about: OSV knows the
// CVEs, Socket knows the malware verdict, Scorecard knows the repo
// posture. A git URL pointing at "github:owner/repo#<sha>" or an
// arbitrary HTTPS tarball bypasses every one of those signals — the
// installer will fetch and execute code from a location none of the
// supply-chain databases describe. The `prepare` lifecycle hook fires
// automatically on git-URL installs, which means arbitrary build-time
// code executes before any post-install scanner gets a chance.
//
// Some legitimate packages do this (monorepo-internal forks,
// pre-release work). snapem surfaces them at high severity so the
// user makes the trust decision explicitly; the per-package allowlist
// is the escape hatch.
//
// What this scanner is NOT
//
// It is not a database of "known bad" packages or versions. It looks
// at the structure of a published package.json and asks whether its
// declared dependencies can be reasoned about by the rest of the
// scanner stack. Anything that can't is a behavioral red flag worth
// surfacing — independent of which specific package or campaign
// happens to be exploiting it this week.
package gitdep

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
	registryBase = "https://registry.npmjs.org"

	// concurrency bounds parallel registry lookups. The npm registry
	// is generous; we stay polite. Matches the provenance scanner.
	concurrency = 8
)

// Client is the gitdep scanner.
type Client struct {
	httpClient *http.Client
	timeout    time.Duration
	enabled    bool
	baseURL    string // overrideable in tests
}

// NewClient returns a configured gitdep scanner.
func NewClient(cfg config.GitDepConfig) *Client {
	retry := retryablehttp.NewClient()
	retry.RetryMax = 3
	retry.Logger = nil
	retry.CheckRetry = retryOn429
	retry.Backoff = retryablehttp.DefaultBackoff

	return &Client{
		httpClient: retry.StandardClient(),
		timeout:    cfg.Timeout,
		enabled:    cfg.Enabled,
		baseURL:    registryBase,
	}
}

func retryOn429(ctx context.Context, resp *http.Response, err error) (bool, error) {
	if resp != nil && resp.StatusCode == http.StatusTooManyRequests {
		return true, nil
	}
	return retryablehttp.DefaultRetryPolicy(ctx, resp, err)
}

// Name returns "gitdep".
func (c *Client) Name() string { return "gitdep" }

// IsAvailable mirrors the config toggle. The npm registry is public.
func (c *Client) IsAvailable() bool { return c.enabled }

// versionMetadata is the subset of the npm registry's per-version
// document we use. Dependency fields are flat maps spec → spec-string.
type versionMetadata struct {
	Dependencies         map[string]string `json:"dependencies"`
	OptionalDependencies map[string]string `json:"optionalDependencies"`
	PeerDependencies     map[string]string `json:"peerDependencies"`
}

// Scan returns a finding per package whose published manifest
// references a git/URL/path specifier. One finding per package, with
// the offending entries listed in the description.
func (c *Client) Scan(ctx context.Context, packages []manifest.Package) (*types.ScanResult, error) {
	result := &types.ScanResult{Scanner: c.Name(), Findings: []types.Finding{}}
	if len(packages) == 0 {
		return result, nil
	}

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
				if f, ok := c.scanOne(ctx, p); ok {
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

	sort.Slice(findings, func(i, j int) bool { return findings[i].Package < findings[j].Package })
	result.Findings = findings
	return result, nil
}

// scanOne fetches one version's manifest from the registry and emits
// at most one finding listing every git/URL/path specifier it carries.
func (c *Client) scanOne(ctx context.Context, pkg manifest.Package) (types.Finding, bool) {
	meta, ok := c.fetchVersion(ctx, pkg)
	if !ok {
		// Network or 404. Not a structural problem we can attribute
		// to this scanner; silently skip — provenance and metadata
		// scanners surface registry-side issues if they exist.
		return types.Finding{}, false
	}

	type offender struct{ field, dep, spec string }
	var hits []offender
	collect := func(field string, m map[string]string) {
		// Stable order so the rendered description is deterministic
		// across runs (useful for tests and snapshots).
		keys := make([]string, 0, len(m))
		for k := range m {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			if cat := classifySpec(m[k]); cat != "" {
				hits = append(hits, offender{field, k, m[k]})
			}
		}
	}
	collect("dependencies", meta.Dependencies)
	collect("optionalDependencies", meta.OptionalDependencies)
	collect("peerDependencies", meta.PeerDependencies)

	if len(hits) == 0 {
		return types.Finding{}, false
	}

	const cap = 5
	rendered := make([]string, 0, min(cap, len(hits)))
	for i, h := range hits {
		if i >= cap {
			rendered = append(rendered, fmt.Sprintf("…and %d more", len(hits)-cap))
			break
		}
		rendered = append(rendered, fmt.Sprintf("%s.%s = %q", h.field, h.dep, h.spec))
	}

	return types.Finding{
		Type:     types.FindingTypeQuality,
		Severity: types.SeverityHigh,
		Package:  pkg.Name,
		Version:  pkg.Version,
		Title:    "Git or URL dependency in published package",
		Description: "Published package declares dependencies that bypass the registry " +
			"(git URLs, tarball URLs, or local paths). Installing it executes code from " +
			"a source that other scanners cannot reason about, and a `prepare` lifecycle " +
			"hook runs automatically on git-URL installs. Specifiers: " +
			strings.Join(rendered, "; "),
		References: []string{fmt.Sprintf("https://www.npmjs.com/package/%s/v/%s?activeTab=code", pkg.Name, pkg.Version)},
	}, true
}

// classifySpec returns a non-empty category string when spec is a
// git/URL/path reference, or "" when it's a normal registry version
// range. The category itself is informational; callers only check for
// non-empty.
//
// npm accepts a long list of specifier shapes; we recognize the ones
// that route the installer somewhere other than the configured npm
// registry:
//
//   - "git+ssh://", "git+https://", "git+http://", "git://"
//   - "ssh://" (when host looks gitlike — handled via prefix)
//   - "github:owner/repo[#ref]"
//   - "gitlab:owner/repo[#ref]"
//   - "bitbucket:owner/repo[#ref]"
//   - "gist:hash[#ref]"
//   - bare "owner/repo[#ref]" GitHub short-form
//   - "http://" / "https://" pointing at a .tgz
//   - "file:" local-path refs
//
// Everything else (semver ranges, "*", "latest", "npm:alias@range",
// "workspace:*") is treated as a registry-resolvable reference.
func classifySpec(spec string) string {
	s := strings.TrimSpace(spec)
	if s == "" {
		return ""
	}

	switch {
	case strings.HasPrefix(s, "git+"),
		strings.HasPrefix(s, "git://"),
		strings.HasPrefix(s, "git@"):
		return "git"
	case strings.HasPrefix(s, "github:"),
		strings.HasPrefix(s, "gitlab:"),
		strings.HasPrefix(s, "bitbucket:"),
		strings.HasPrefix(s, "gist:"):
		return "git-shortcut"
	case strings.HasPrefix(s, "ssh://"):
		return "git"
	case strings.HasPrefix(s, "file:"):
		return "file"
	case strings.HasPrefix(s, "http://"), strings.HasPrefix(s, "https://"):
		// An HTTP(S) URL in a dependency spec is always a tarball
		// fetch — npm does not let you point at a registry over an
		// arbitrary URL. Flag.
		return "tarball-url"
	}

	// Bare "owner/repo" GitHub short-form. Disambiguate from
	// "@scope/name" (which is a registry package name, not a git
	// ref) and from semver ranges.
	if strings.HasPrefix(s, "@") {
		return ""
	}
	if slash := strings.IndexByte(s, '/'); slash > 0 {
		// Before the slash: only letters/digits/hyphens/underscores
		// look like a GitHub owner. A semver range never contains a
		// slash, so any slash is suspicious unless it's clearly an
		// alias like "npm:foo/bar" (which we excluded above).
		owner := s[:slash]
		for i := 0; i < len(owner); i++ {
			ch := owner[i]
			if !(ch >= 'a' && ch <= 'z') &&
				!(ch >= 'A' && ch <= 'Z') &&
				!(ch >= '0' && ch <= '9') &&
				ch != '-' && ch != '_' && ch != '.' {
				return ""
			}
		}
		return "github-short"
	}

	return ""
}

func (c *Client) fetchVersion(ctx context.Context, pkg manifest.Package) (*versionMetadata, bool) {
	u := c.baseURL + "/" + url.PathEscape(pkg.Name) + "/" + url.PathEscape(pkg.Version)
	if c.timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, c.timeout)
		defer cancel()
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
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
	var v versionMetadata
	if err := json.NewDecoder(resp.Body).Decode(&v); err != nil {
		return nil, false
	}
	return &v, true
}
