package cache

import (
	"context"
	"time"

	"github.com/positronico/snapem/internal/manifest"
	"github.com/positronico/snapem/internal/types"
)

// scannerLike is the subset of internal/scanner.Scanner we depend on. We
// declare it locally to avoid an import cycle (scanner imports cache to
// wrap its scanners, so cache cannot import scanner).
type scannerLike interface {
	Name() string
	Scan(ctx context.Context, packages []manifest.Package) (*types.ScanResult, error)
	IsAvailable() bool
}

// Scanner wraps an underlying scanner with the file cache. On Scan it:
//
//  1. Looks up each package in the cache; bypasses the upstream call for
//     hits.
//  2. Sends the remaining miss list to the wrapped scanner.
//  3. Splits the fresh result by (package, version) and writes one cache
//     entry per package — including packages that came back with no
//     findings, since "no CVEs in lodash@4.17.21" is also worth caching.
//
// Cache failures (read or write) never bubble up: callers always get an
// answer, just possibly via the live API.
type Scanner struct {
	Inner  scannerLike
	Store  Store
	MaxAge time.Duration
}

// NewScanner wraps inner with a cache backed by store, applying TTL maxAge.
// If store is nil or MaxAge<=0 the wrapper is transparent: it forwards
// everything to inner.
func NewScanner(inner scannerLike, store Store, maxAge time.Duration) *Scanner {
	return &Scanner{Inner: inner, Store: store, MaxAge: maxAge}
}

func (s *Scanner) Name() string         { return s.Inner.Name() }
func (s *Scanner) IsAvailable() bool    { return s.Inner.IsAvailable() }

func (s *Scanner) Scan(ctx context.Context, packages []manifest.Package) (*types.ScanResult, error) {
	start := time.Now()

	if s.Store == nil || s.MaxAge <= 0 {
		return s.Inner.Scan(ctx, packages)
	}

	scannerName := s.Inner.Name()
	var (
		cachedFindings []types.Finding
		misses         []manifest.Package
	)
	for _, p := range packages {
		eco := p.Ecosystem
		if eco == "" {
			eco = "npm"
		}
		entry, _ := s.Store.Get(scannerName, eco, p.Name, p.Version, s.MaxAge)
		if entry == nil {
			misses = append(misses, p)
			continue
		}
		cachedFindings = append(cachedFindings, entry.Findings...)
	}

	// Fast path: everything was cached.
	if len(misses) == 0 {
		return &types.ScanResult{
			Scanner:      scannerName,
			Packages:     len(packages),
			Findings:     cachedFindings,
			ScanDuration: time.Since(start),
			Cached:       true,
		}, nil
	}

	// Live call for the miss list.
	fresh, err := s.Inner.Scan(ctx, misses)
	if err != nil {
		return nil, err
	}

	// Bucket fresh findings by (name, version) so we can write one entry
	// per miss — including misses that resolved to zero findings.
	freshByKey := make(map[string][]types.Finding, len(misses))
	for _, f := range fresh.Findings {
		key := f.Package + "@" + f.Version
		freshByKey[key] = append(freshByKey[key], f)
	}
	for _, p := range misses {
		eco := p.Ecosystem
		if eco == "" {
			eco = "npm"
		}
		key := p.Name + "@" + p.Version
		_ = s.Store.Put(&Entry{
			Scanner:   scannerName,
			Ecosystem: eco,
			Package:   p.Name,
			Version:   p.Version,
			Findings:  freshByKey[key],
		})
	}

	merged := make([]types.Finding, 0, len(cachedFindings)+len(fresh.Findings))
	merged = append(merged, cachedFindings...)
	merged = append(merged, fresh.Findings...)

	return &types.ScanResult{
		Scanner:      scannerName,
		Packages:     len(packages),
		Findings:     merged,
		ScanDuration: time.Since(start),
		Cached:       false, // partial cache; flag as "did a live call"
	}, nil
}
