package cache

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/positronico/snapem/internal/manifest"
	"github.com/positronico/snapem/internal/types"
)

// fakeScanner records what was passed to Scan and returns a configurable
// finding per package so cache hits are observable.
type fakeScanner struct {
	name     string
	calls    int32
	lastSent []manifest.Package
	findings func(p manifest.Package) []types.Finding
	err      error
}

func (f *fakeScanner) Name() string      { return f.name }
func (f *fakeScanner) IsAvailable() bool { return true }
func (f *fakeScanner) Scan(_ context.Context, packages []manifest.Package) (*types.ScanResult, error) {
	atomic.AddInt32(&f.calls, 1)
	f.lastSent = append([]manifest.Package(nil), packages...)
	if f.err != nil {
		return nil, f.err
	}
	var all []types.Finding
	for _, p := range packages {
		all = append(all, f.findings(p)...)
	}
	return &types.ScanResult{
		Scanner:  f.name,
		Packages: len(packages),
		Findings: all,
	}, nil
}

func vulnFinding(p manifest.Package) []types.Finding {
	return []types.Finding{{
		Package: p.Name, Version: p.Version,
		Type: types.FindingTypeCVE, Severity: types.SeverityMedium,
		ID: "GHSA-" + p.Name,
	}}
}

func TestScanner_CacheMissThenHit(t *testing.T) {
	store, _ := NewFileStore(t.TempDir())
	inner := &fakeScanner{name: "Test", findings: vulnFinding}
	c := NewScanner(inner, store, time.Hour)

	pkgs := []manifest.Package{
		{Name: "lodash", Version: "4.17.21", Ecosystem: "npm"},
		{Name: "express", Version: "4.18.0", Ecosystem: "npm"},
	}

	r1, err := c.Scan(context.Background(), pkgs)
	if err != nil {
		t.Fatalf("first Scan: %v", err)
	}
	if len(r1.Findings) != 2 {
		t.Errorf("first Scan findings=%d, want 2", len(r1.Findings))
	}
	if got := atomic.LoadInt32(&inner.calls); got != 1 {
		t.Errorf("inner calls after first Scan=%d, want 1", got)
	}

	// Same input again — should be 100% cache hit, no inner call.
	r2, err := c.Scan(context.Background(), pkgs)
	if err != nil {
		t.Fatalf("second Scan: %v", err)
	}
	if got := atomic.LoadInt32(&inner.calls); got != 1 {
		t.Errorf("inner calls after second Scan=%d, want still 1", got)
	}
	if !r2.Cached {
		t.Errorf("expected Cached=true on second Scan")
	}
	if len(r2.Findings) != 2 {
		t.Errorf("second Scan findings=%d, want 2", len(r2.Findings))
	}
}

func TestScanner_PartialHitOnlyMissesGoUpstream(t *testing.T) {
	store, _ := NewFileStore(t.TempDir())
	inner := &fakeScanner{name: "Test", findings: vulnFinding}
	c := NewScanner(inner, store, time.Hour)

	a := manifest.Package{Name: "a", Version: "1", Ecosystem: "npm"}
	b := manifest.Package{Name: "b", Version: "1", Ecosystem: "npm"}

	// Seed cache with only "a".
	_, _ = c.Scan(context.Background(), []manifest.Package{a})
	if got := atomic.LoadInt32(&inner.calls); got != 1 {
		t.Fatalf("setup calls=%d", got)
	}

	// Now request both. Only "b" should hit the inner scanner.
	_, err := c.Scan(context.Background(), []manifest.Package{a, b})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if got := atomic.LoadInt32(&inner.calls); got != 2 {
		t.Errorf("inner calls=%d, want 2 (one per miss)", got)
	}
	if len(inner.lastSent) != 1 || inner.lastSent[0].Name != "b" {
		t.Errorf("inner received %+v, want only [b]", inner.lastSent)
	}
}

func TestScanner_CachesEmptyResultsToo(t *testing.T) {
	store, _ := NewFileStore(t.TempDir())
	inner := &fakeScanner{
		name:     "Test",
		findings: func(p manifest.Package) []types.Finding { return nil },
	}
	c := NewScanner(inner, store, time.Hour)

	pkgs := []manifest.Package{{Name: "clean", Version: "1", Ecosystem: "npm"}}

	_, _ = c.Scan(context.Background(), pkgs)
	_, _ = c.Scan(context.Background(), pkgs)
	if got := atomic.LoadInt32(&inner.calls); got != 1 {
		t.Errorf("inner calls=%d, want 1 (second scan must hit cache)", got)
	}
}

func TestScanner_TransparentWhenStoreNil(t *testing.T) {
	inner := &fakeScanner{name: "Test", findings: vulnFinding}
	c := NewScanner(inner, nil, time.Hour)

	pkgs := []manifest.Package{{Name: "x", Version: "1", Ecosystem: "npm"}}
	_, _ = c.Scan(context.Background(), pkgs)
	_, _ = c.Scan(context.Background(), pkgs)
	if got := atomic.LoadInt32(&inner.calls); got != 2 {
		t.Errorf("without store, every Scan must go upstream; got %d calls", got)
	}
}

func TestScanner_TransparentWhenTTLZero(t *testing.T) {
	store, _ := NewFileStore(t.TempDir())
	inner := &fakeScanner{name: "Test", findings: vulnFinding}
	c := NewScanner(inner, store, 0)

	pkgs := []manifest.Package{{Name: "x", Version: "1", Ecosystem: "npm"}}
	_, _ = c.Scan(context.Background(), pkgs)
	_, _ = c.Scan(context.Background(), pkgs)
	if got := atomic.LoadInt32(&inner.calls); got != 2 {
		t.Errorf("with MaxAge=0, every Scan must go upstream; got %d calls", got)
	}
}

func TestScanner_UpstreamErrorPropagates(t *testing.T) {
	store, _ := NewFileStore(t.TempDir())
	wantErr := errors.New("boom")
	inner := &fakeScanner{name: "Test", err: wantErr, findings: vulnFinding}
	c := NewScanner(inner, store, time.Hour)

	_, err := c.Scan(context.Background(), []manifest.Package{{Name: "x", Version: "1", Ecosystem: "npm"}})
	if !errors.Is(err, wantErr) {
		t.Errorf("err=%v, want wrapping of boom", err)
	}
}
