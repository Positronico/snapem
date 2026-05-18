// Package tarball implements a scanner that audits the contents of a
// published npm tarball against the `files` whitelist declared in its
// own package.json.
//
// Why this is a signal
//
// When a maintainer sets the `files` field in package.json, they are
// making a claim: "these are the files that should appear in the
// published tarball". npm itself uses this list during `npm pack` to
// decide what goes in. A file that ends up inside the tarball without
// being covered by `files` is either:
//
//   1. A package that npm always includes regardless (package.json,
//      README, LICENSE, CHANGELOG, the entry-point file). Expected;
//      ignored by this scanner.
//
//   2. A genuine maintainer oversight (build artifact, stray script).
//      Worth surfacing — even when benign it's a hint the build
//      pipeline isn't quite what its author thinks it is.
//
//   3. Tampering. If a file landed in the tarball without going
//      through the maintainer's `npm pack`, the publishing pipeline
//      did not behave as the manifest describes. Lifecycle hooks
//      (postinstall, prepare) execute whatever JavaScript they find
//      at install time, so the existence of an undeclared root file
//      is a credible install-time-execution risk.
//
// What this scanner is NOT
//
// It is not a malware classifier. It does not name specific files or
// match against any known-bad list. It implements one mechanical
// check: does the tarball's content match the package's own published
// claim about what its content should be? That is package-agnostic
// and version-agnostic by construction — it's a structural integrity
// test, not a signature lookup.
//
// Limitations
//
// npm's pack algorithm honors patterns beyond plain filepath globs
// (notably `**` recursive matches, leading `!` negations, and
// .gitignore-style precedence). When the `files` field uses any of
// those, this scanner disables the audit for the package rather than
// emit false positives. The simpler-shaped `files` arrays — directory
// names and basic glob patterns — are what most published packages
// use and what this scanner can faithfully evaluate.
package tarball

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"path/filepath"
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

	// concurrency bounds parallel registry + tarball downloads. We
	// stay lower than the other scanners because each task includes
	// a tarball fetch (typically tens to hundreds of KB) rather than
	// a JSON-only round trip.
	concurrency = 4

	// maxTarballBytes caps the per-package tarball read. A 25 MiB
	// ceiling covers ~99% of real-world npm tarballs (the median is
	// under 100 KiB) without letting a hostile registry stream
	// unbounded bytes into memory.
	maxTarballBytes = 25 * 1024 * 1024
)

// Client is the tarball-audit scanner.
type Client struct {
	httpClient *http.Client
	timeout    time.Duration
	enabled    bool
	baseURL    string // overrideable in tests
}

// NewClient returns a configured tarball-audit client.
func NewClient(cfg config.TarballConfig) *Client {
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

// Name returns "tarball".
func (c *Client) Name() string { return "tarball" }

// IsAvailable mirrors the config toggle.
func (c *Client) IsAvailable() bool { return c.enabled }

// versionMetadata is the subset of the npm registry's per-version
// document we need: the entry-point hints (so we never flag them) and
// the `files` whitelist, plus the tarball URL.
type versionMetadata struct {
	Main    string          `json:"main"`
	Module  string          `json:"module"`
	Types   string          `json:"types"`
	Typings string          `json:"typings"`
	Bin     json.RawMessage `json:"bin"` // string or object
	Files   []string        `json:"files"`
	Dist    struct {
		Tarball string `json:"tarball"`
	} `json:"dist"`
}

// Scan emits at most one finding per package: a list of tarball
// entries that the package's own `files` whitelist did not cover.
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

// scanOne runs the per-package audit and returns (finding, true) when
// the tarball contains paths not covered by the `files` whitelist
// (excluding always-included files and declared entry points).
func (c *Client) scanOne(ctx context.Context, pkg manifest.Package) (types.Finding, bool) {
	meta, ok := c.fetchVersion(ctx, pkg)
	if !ok {
		return types.Finding{}, false
	}

	// Without a `files` whitelist there's no claim to audit — npm
	// falls back to .npmignore / .gitignore behavior, which lives
	// outside the registry. Quietly skip rather than emit noise.
	if len(meta.Files) == 0 {
		return types.Finding{}, false
	}

	// Patterns we can't faithfully match → skip. False positives
	// here would teach users to ignore this scanner.
	for _, p := range meta.Files {
		if strings.Contains(p, "**") || strings.HasPrefix(strings.TrimSpace(p), "!") {
			return types.Finding{}, false
		}
	}

	if meta.Dist.Tarball == "" {
		return types.Finding{}, false
	}

	paths, ok := c.listTarballPaths(ctx, meta.Dist.Tarball)
	if !ok {
		return types.Finding{}, false
	}

	always := alwaysIncluded(meta)
	var undeclared []string
	for _, p := range paths {
		if isAlwaysIncluded(p, always) {
			continue
		}
		if matchesFilesField(p, meta.Files) {
			continue
		}
		undeclared = append(undeclared, p)
	}

	if len(undeclared) == 0 {
		return types.Finding{}, false
	}

	sort.Strings(undeclared)

	const cap = 5
	rendered := make([]string, 0, min(cap, len(undeclared)))
	for i, u := range undeclared {
		if i >= cap {
			rendered = append(rendered, fmt.Sprintf("…and %d more", len(undeclared)-cap))
			break
		}
		rendered = append(rendered, u)
	}

	return types.Finding{
		Type:     types.FindingTypeQuality,
		Severity: types.SeverityMedium,
		Package:  pkg.Name,
		Version:  pkg.Version,
		Title:    "Tarball contains files not declared in `files`",
		Description: fmt.Sprintf(
			"%d file(s) in the published tarball are outside the `files` whitelist declared in package.json. "+
				"This is the shape of a tampered or surprise-content publish. "+
				"Unexpected entries: %s. Declared files: %v.",
			len(undeclared), strings.Join(rendered, ", "), meta.Files),
		References: []string{fmt.Sprintf("https://www.npmjs.com/package/%s/v/%s?activeTab=code", pkg.Name, pkg.Version)},
	}, true
}

// alwaysIncluded builds the set of file basenames + entry paths that
// npm publishes regardless of the `files` field. Returns lowercased
// basenames for case-insensitive matching of README/LICENSE variants
// plus the exact paths from main/module/bin/types/typings.
type alwaysSet struct {
	basenamesLower map[string]struct{} // README, LICENSE, CHANGELOG, …
	exactPaths     map[string]struct{} // main, bin, etc., already normalized
}

func alwaysIncluded(meta *versionMetadata) alwaysSet {
	// npm publishes these regardless of `files` (see npm-packlist's
	// "must include" set: package.json, README*, LICENSE*/LICENCE*,
	// CHANGELOG*, HISTORY*, NOTICE*). We match case-insensitively on
	// the basename. Extensions vary (README.md, LICENSE.txt, etc.),
	// so we treat any basename starting with one of these prefixes as
	// always-included.
	out := alwaysSet{
		basenamesLower: map[string]struct{}{},
		exactPaths:     map[string]struct{}{},
	}
	out.basenamesLower["package.json"] = struct{}{}
	out.basenamesLower["readme"] = struct{}{}
	out.basenamesLower["license"] = struct{}{}
	out.basenamesLower["licence"] = struct{}{}
	out.basenamesLower["changelog"] = struct{}{}
	out.basenamesLower["history"] = struct{}{}
	out.basenamesLower["notice"] = struct{}{}

	add := func(p string) {
		if p == "" {
			return
		}
		out.exactPaths[normalizePath(p)] = struct{}{}
	}
	add(meta.Main)
	add(meta.Module)
	add(meta.Types)
	add(meta.Typings)

	// `bin` is either a string (single binary) or an object map
	// (multi-binary). Both shapes route to paths inside the package.
	if len(meta.Bin) > 0 {
		var s string
		if err := json.Unmarshal(meta.Bin, &s); err == nil {
			add(s)
		} else {
			var m map[string]string
			if err := json.Unmarshal(meta.Bin, &m); err == nil {
				for _, p := range m {
					add(p)
				}
			}
		}
	}

	return out
}

func isAlwaysIncluded(p string, always alwaysSet) bool {
	if _, ok := always.exactPaths[normalizePath(p)]; ok {
		return true
	}
	base := strings.ToLower(path.Base(p))
	if _, ok := always.basenamesLower[base]; ok {
		return true
	}
	// Match basenames with extension variants: README.md, LICENSE.txt, etc.
	for prefix := range always.basenamesLower {
		if prefix == "package.json" {
			continue
		}
		if strings.HasPrefix(base, prefix+".") {
			return true
		}
	}
	return false
}

// matchesFilesField returns true when p (relative to the package root)
// is covered by any entry in the `files` array. Supported entry
// shapes: exact path, directory prefix, simple glob (filepath.Match).
func matchesFilesField(p string, files []string) bool {
	p = normalizePath(p)
	for _, entry := range files {
		entry = normalizePath(strings.TrimSpace(entry))
		if entry == "" {
			continue
		}
		entry = strings.TrimSuffix(entry, "/")

		if entry == p {
			return true
		}
		if strings.HasPrefix(p, entry+"/") {
			return true
		}
		// Glob over the full path.
		if matched, err := filepath.Match(entry, p); err == nil && matched {
			return true
		}
		// Glob over the basename (handles e.g. "*.d.ts" patterns at root).
		if matched, err := filepath.Match(entry, path.Base(p)); err == nil && matched {
			return true
		}
	}
	return false
}

// normalizePath drops leading "./" and "/", uses forward slashes, and
// lowercases nothing (file paths are case-sensitive in npm tarballs).
func normalizePath(p string) string {
	p = strings.ReplaceAll(p, "\\", "/")
	p = strings.TrimPrefix(p, "./")
	p = strings.TrimPrefix(p, "/")
	return p
}

// listTarballPaths streams the tarball and returns the list of
// file paths it contains (regular files only, with the leading
// "package/" prefix stripped). Returns ok=false on any error; the
// caller treats that as "skip this scan", not "fail the run".
func (c *Client) listTarballPaths(ctx context.Context, tarballURL string) ([]string, bool) {
	if c.timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, c.timeout)
		defer cancel()
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, tarballURL, nil)
	if err != nil {
		return nil, false
	}
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

	limited := io.LimitReader(resp.Body, maxTarballBytes+1)
	gz, err := gzip.NewReader(limited)
	if err != nil {
		return nil, false
	}
	defer gz.Close()

	tr := tar.NewReader(gz)
	var paths []string
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, false
		}
		if hdr.Typeflag != tar.TypeReg && hdr.Typeflag != tar.TypeRegA { //nolint:staticcheck // TypeRegA exists for older tarballs
			continue
		}
		name := strings.TrimPrefix(hdr.Name, "package/")
		if name == hdr.Name {
			// Entry not under the conventional "package/" prefix.
			// Keep it under its raw name so the audit still sees it.
			name = strings.TrimPrefix(name, "./")
		}
		if name == "" {
			continue
		}
		paths = append(paths, name)
	}
	return paths, true
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
