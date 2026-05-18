package scanner

import (
	"context"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/positronico/snapem/internal/config"
	"github.com/positronico/snapem/internal/manifest"
	"github.com/positronico/snapem/internal/scanner/cache"
	"github.com/positronico/snapem/internal/scanner/gitdep"
	"github.com/positronico/snapem/internal/scanner/metadata"
	"github.com/positronico/snapem/internal/scanner/osv"
	"github.com/positronico/snapem/internal/scanner/provenance"
	"github.com/positronico/snapem/internal/scanner/scorecard"
	"github.com/positronico/snapem/internal/scanner/socket"
	"github.com/positronico/snapem/internal/scanner/tarball"
)

// ProgressFunc is called when an individual scanner starts (done=false) and
// finishes (done=true). It may be nil.
// ProgressFunc receives per-scanner lifecycle events: called once with
// done=false when a scanner starts and once with done=true when it
// completes (successfully or not). The UI layer uses this to update
// the user-visible "scanning..." → "complete" status. Nil is allowed —
// the orchestrator silently drops events when no callback is supplied.
type ProgressFunc func(scanner string, done bool)

// Orchestrator owns the configured set of Scanners and runs them in
// parallel against a package list. It applies allowlist / blocklist
// transforms before delegating, aggregates the results, and is the
// single entry point used by `snapem scan`, `install`, and `upgrade`
// so all three share identical scan semantics.
type Orchestrator struct {
	scanners []Scanner
	config   *config.Config
}

// NewOrchestrator creates a new scanner orchestrator. When caching is
// enabled (scanning.cache.enabled), each scanner is wrapped in a file-cache
// decorator so repeat invocations against unchanged (name, version) tuples
// don't re-hit the upstream APIs. A cache directory that can't be created
// disables caching rather than failing the run.
func NewOrchestrator(cfg *config.Config) *Orchestrator {
	o := &Orchestrator{config: cfg}

	store, ttl := buildCache(cfg)

	if cfg.Scanning.Socket.Enabled {
		o.scanners = append(o.scanners, wrapCache(socket.NewClient(cfg.Scanning.Socket), store, ttl))
	}
	if cfg.Scanning.OSV.Enabled {
		o.scanners = append(o.scanners, wrapCache(osv.NewClient(cfg.Scanning.OSV), store, ttl))
	}
	if cfg.Scanning.Scorecard.Enabled {
		o.scanners = append(o.scanners, wrapCache(scorecard.NewClient(cfg.Scanning.Scorecard), store, ttl))
	}
	if cfg.Scanning.Provenance.Enabled {
		o.scanners = append(o.scanners, wrapCache(provenance.NewClient(cfg.Scanning.Provenance), store, ttl))
	}
	if cfg.Scanning.Metadata.Enabled {
		o.scanners = append(o.scanners, wrapCache(metadata.NewClient(cfg.Scanning.Metadata), store, ttl))
	}
	if cfg.Scanning.GitDep.Enabled {
		o.scanners = append(o.scanners, wrapCache(gitdep.NewClient(cfg.Scanning.GitDep), store, ttl))
	}
	if cfg.Scanning.Tarball.Enabled {
		o.scanners = append(o.scanners, wrapCache(tarball.NewClient(cfg.Scanning.Tarball), store, ttl))
	}

	return o
}

// buildCache returns (store, ttl) for use by wrapCache. Either may be the
// zero value, which makes wrapCache a pass-through.
func buildCache(cfg *config.Config) (cache.Store, time.Duration) {
	if !cfg.Scanning.Cache.Enabled || cfg.Scanning.Cache.TTL <= 0 {
		return nil, 0
	}
	dir := cfg.Scanning.Cache.Directory
	if dir == "" {
		return nil, 0
	}
	store, err := cache.NewFileStore(dir)
	if err != nil {
		// Degrade gracefully: a misconfigured cache must not break a scan.
		fmt.Fprintln(os.Stderr, "snapem: cache disabled —", err)
		return nil, 0
	}
	return store, cfg.Scanning.Cache.TTL
}

// wrapCache wraps inner in a caching Scanner if store is non-nil. The
// concrete *cache.Scanner satisfies our local Scanner interface because
// it exposes Name/IsAvailable/Scan with matching signatures.
func wrapCache(inner Scanner, store cache.Store, ttl time.Duration) Scanner {
	if store == nil || ttl <= 0 {
		return inner
	}
	return cache.NewScanner(inner, store, ttl)
}

// Scan runs all configured scanners concurrently and applies policy
// (allowlist/blocklist).
func (o *Orchestrator) Scan(ctx context.Context, packages []manifest.Package) (*AggregatedResult, error) {
	return o.scan(ctx, packages, nil)
}

// ScanWithProgress is identical to Scan but reports per-scanner progress via
// the supplied callback. Both entry points share the same policy + aggregation
// path; do not fork them again — the historic divergence caused the blocklist
// to be silently ignored on install/scan (see CLAUDE.md §8.1).
func (o *Orchestrator) ScanWithProgress(ctx context.Context, packages []manifest.Package, onProgress ProgressFunc) (*AggregatedResult, error) {
	return o.scan(ctx, packages, onProgress)
}

func (o *Orchestrator) scan(ctx context.Context, packages []manifest.Package, onProgress ProgressFunc) (*AggregatedResult, error) {
	start := time.Now()

	if len(packages) == 0 {
		return &AggregatedResult{
			Results:       []*ScanResult{},
			TotalPackages: 0,
			TotalFindings: 0,
			Duration:      time.Since(start),
		}, nil
	}

	filteredPackages := dedupePackages(o.filterAllowlisted(packages))

	results, failures := o.runScanners(ctx, filteredPackages, onProgress)

	// If every scanner failed AND we have no policy-derived findings to
	// report, surface the first error so the caller can decide what to
	// do. Partial-failure scans (some scanners succeeded, some didn't)
	// surface via AggregatedResult.ScannerErrors so the user sees which
	// signal is missing.
	if len(results) == 0 && len(failures) > 0 && !o.hasBlocklistHit(packages) {
		return nil, failures[0].err
	}

	aggregated := o.aggregate(results)
	aggregated.TotalPackages = len(filteredPackages)
	aggregated.Duration = time.Since(start)
	if len(failures) > 0 {
		aggregated.ScannerErrors = make(map[string]string, len(failures))
		for _, f := range failures {
			aggregated.ScannerErrors[f.scanner] = f.err.Error()
		}
	}

	o.applyBlocklist(packages, aggregated)
	return aggregated, nil
}

// scannerFailure carries one failed scanner's identity + error so the
// orchestrator can attribute the failure when surfacing it to the user.
// Historic behavior was to drop the scanner name and aggregate only
// "the first error"; the result was that a Socket rate-limit looked
// identical to an OSV outage at the CLI layer.
type scannerFailure struct {
	scanner string
	err     error
}

// runScanners fans the package list out to every available scanner
// concurrently and returns the collected results plus per-scanner
// failures. Caller decides whether partial success (some scanners
// succeeded, some failed) is an error: that's a policy question, not
// a scan-mechanics one.
func (o *Orchestrator) runScanners(ctx context.Context, packages []manifest.Package, onProgress ProgressFunc) ([]*ScanResult, []scannerFailure) {
	if len(o.scanners) == 0 {
		return nil, nil
	}

	var wg sync.WaitGroup
	resultsChan := make(chan *ScanResult, len(o.scanners))
	failChan := make(chan scannerFailure, len(o.scanners))

	for _, s := range o.scanners {
		if !s.IsAvailable() {
			continue
		}
		wg.Add(1)
		go func(scanner Scanner) {
			defer wg.Done()
			if onProgress != nil {
				onProgress(scanner.Name(), false)
			}
			result, err := scanner.Scan(ctx, packages)
			if onProgress != nil {
				onProgress(scanner.Name(), true)
			}
			if err != nil {
				failChan <- scannerFailure{scanner: scanner.Name(), err: err}
				return
			}
			resultsChan <- result
		}(s)
	}

	go func() {
		wg.Wait()
		close(resultsChan)
		close(failChan)
	}()

	var results []*ScanResult
	var failures []scannerFailure
	for {
		select {
		case result, ok := <-resultsChan:
			if !ok {
				resultsChan = nil
			} else {
				results = append(results, result)
			}
		case fail, ok := <-failChan:
			if !ok {
				failChan = nil
			} else {
				failures = append(failures, fail)
			}
		}
		if resultsChan == nil && failChan == nil {
			break
		}
	}

	return results, failures
}

// dedupePackages collapses duplicate (name, version) pairs, preserving the
// first-seen order. Lockfile traversal commonly produces the same package
// many times via nested node_modules paths, which would otherwise inflate
// the bytes shipped to OSV/Socket and waste rate limits.
func dedupePackages(packages []manifest.Package) []manifest.Package {
	if len(packages) == 0 {
		return packages
	}
	seen := make(map[string]struct{}, len(packages))
	out := make([]manifest.Package, 0, len(packages))
	for _, p := range packages {
		key := p.Name + "@" + p.Version + "/" + p.Ecosystem
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, p)
	}
	return out
}

func (o *Orchestrator) filterAllowlisted(packages []manifest.Package) []manifest.Package {
	if len(o.config.Scanning.Policy.Allowlist) == 0 {
		return packages
	}
	filtered := make([]manifest.Package, 0, len(packages))
	for _, pkg := range packages {
		if !o.config.IsPackageAllowlisted(pkg.Name, pkg.Version) {
			filtered = append(filtered, pkg)
		}
	}
	return filtered
}

// applyBlocklist appends a critical malware finding for every package in the
// original (unfiltered) list that the user blocklisted. Blocklist intentionally
// trumps allowlist.
func (o *Orchestrator) applyBlocklist(packages []manifest.Package, aggregated *AggregatedResult) {
	if len(o.config.Scanning.Policy.Blocklist) == 0 {
		return
	}
	for _, pkg := range packages {
		if !o.config.IsPackageBlocklisted(pkg.Name, pkg.Version) {
			continue
		}
		aggregated.Results = append(aggregated.Results, &ScanResult{
			Scanner:  "policy",
			Packages: 1,
			Findings: []Finding{
				{
					Package:     pkg.Name,
					Version:     pkg.Version,
					Type:        FindingTypeMalware,
					Severity:    SeverityCritical,
					Title:       "Blocklisted package",
					Description: "This package is in your blocklist",
				},
			},
		})
		aggregated.HasMalware = true
		aggregated.HasCritical = true
		aggregated.TotalFindings++
	}
}

func (o *Orchestrator) hasBlocklistHit(packages []manifest.Package) bool {
	if len(o.config.Scanning.Policy.Blocklist) == 0 {
		return false
	}
	for _, pkg := range packages {
		if o.config.IsPackageBlocklisted(pkg.Name, pkg.Version) {
			return true
		}
	}
	return false
}

func (o *Orchestrator) aggregate(results []*ScanResult) *AggregatedResult {
	aggregated := &AggregatedResult{Results: results}

	for _, result := range results {
		for _, finding := range result.Findings {
			aggregated.TotalFindings++

			if finding.Type == FindingTypeMalware || finding.Type == FindingTypeTyposquat {
				aggregated.HasMalware = true
			}

			switch finding.Severity {
			case SeverityCritical:
				aggregated.HasCritical = true
			case SeverityHigh:
				aggregated.HasHigh = true
			}
		}
	}

	return aggregated
}

// HasSocketScanner returns true if Socket scanner is enabled and reachable.
func (o *Orchestrator) HasSocketScanner() bool {
	for _, s := range o.scanners {
		if s.Name() == "Socket.dev" && s.IsAvailable() {
			return true
		}
	}
	return false
}

// AvailableScanners returns names of scanners that report IsAvailable().
func (o *Orchestrator) AvailableScanners() []string {
	var names []string
	for _, s := range o.scanners {
		if s.IsAvailable() {
			names = append(names, s.Name())
		}
	}
	return names
}
