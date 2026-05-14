package scanner

import (
	"context"
	"errors"
	"testing"

	"github.com/positronico/snapem/internal/config"
	"github.com/positronico/snapem/internal/manifest"
	"github.com/positronico/snapem/internal/types"
)

// stubScanner is a minimal Scanner used to drive orchestrator branching
// (partial-failure, all-failed) without standing up an httptest server.
type stubScanner struct {
	name      string
	available bool
	result    *types.ScanResult
	err       error
}

func (s *stubScanner) Name() string         { return s.name }
func (s *stubScanner) IsAvailable() bool    { return s.available }
func (s *stubScanner) Scan(ctx context.Context, packages []manifest.Package) (*types.ScanResult, error) {
	return s.result, s.err
}

// newOrchestratorWithScanners builds an Orchestrator whose only
// scanners are the given stubs, bypassing config-driven wiring.
func newOrchestratorWithScanners(cfg *config.Config, scanners ...Scanner) *Orchestrator {
	return &Orchestrator{config: cfg, scanners: scanners}
}

// newTestConfig returns a Config with both upstream scanners disabled so the
// orchestrator's only job is policy application (allowlist / blocklist).
func newTestConfig() *config.Config {
	return &config.Config{
		Scanning: config.ScanningConfig{
			Enabled: true,
			Socket:  config.SocketConfig{Enabled: false},
			OSV:     config.OSVConfig{Enabled: false},
		},
	}
}

func TestScan_AppliesBlocklist(t *testing.T) {
	cfg := newTestConfig()
	cfg.Scanning.Policy.Blocklist = []string{"evil-pkg"}

	orch := NewOrchestrator(cfg)

	packages := []manifest.Package{
		{Name: "evil-pkg", Version: "1.0.0", Ecosystem: "npm"},
		{Name: "innocent-pkg", Version: "2.0.0", Ecosystem: "npm"},
	}

	result, err := orch.Scan(context.Background(), packages)
	if err != nil {
		t.Fatalf("Scan returned error: %v", err)
	}
	if result.TotalFindings != 1 {
		t.Fatalf("expected 1 blocklist finding, got %d", result.TotalFindings)
	}
	if !result.HasMalware {
		t.Errorf("expected HasMalware=true after blocklist hit")
	}
}

// Regression test for the blocklist gap: ScanWithProgress was historically a
// near-duplicate of Scan that omitted the blocklist injection, so install/scan
// (which both use ScanWithProgress) silently ignored snapem.yaml's blocklist.
func TestScanWithProgress_AppliesBlocklist(t *testing.T) {
	cfg := newTestConfig()
	cfg.Scanning.Policy.Blocklist = []string{"evil-pkg"}

	orch := NewOrchestrator(cfg)

	packages := []manifest.Package{
		{Name: "evil-pkg", Version: "1.0.0", Ecosystem: "npm"},
		{Name: "innocent-pkg", Version: "2.0.0", Ecosystem: "npm"},
	}

	result, err := orch.ScanWithProgress(context.Background(), packages, nil)
	if err != nil {
		t.Fatalf("ScanWithProgress returned error: %v", err)
	}
	if result.TotalFindings != 1 {
		t.Fatalf("expected 1 blocklist finding, got %d", result.TotalFindings)
	}
	if !result.HasMalware {
		t.Errorf("expected HasMalware=true after blocklist hit")
	}

	// The blocklist finding should name the right package + version.
	var found *Finding
	for _, r := range result.Results {
		for i := range r.Findings {
			if r.Findings[i].Package == "evil-pkg" {
				found = &r.Findings[i]
			}
		}
	}
	if found == nil {
		t.Fatalf("blocklisted package not present in findings")
	}
	if found.Version != "1.0.0" {
		t.Errorf("blocklist finding has wrong version: %q", found.Version)
	}
	if found.Type != FindingTypeMalware {
		t.Errorf("blocklist finding has wrong type: %q", found.Type)
	}
	if found.Severity != SeverityCritical {
		t.Errorf("blocklist finding has wrong severity: %q", found.Severity)
	}
}

func TestScan_RespectsAllowlist(t *testing.T) {
	cfg := newTestConfig()
	cfg.Scanning.Policy.Allowlist = []string{"trusted-pkg"}
	cfg.Scanning.Policy.Blocklist = []string{"evil-pkg"}

	orch := NewOrchestrator(cfg)

	packages := []manifest.Package{
		{Name: "trusted-pkg", Version: "1.0.0", Ecosystem: "npm"},
		{Name: "evil-pkg", Version: "1.0.0", Ecosystem: "npm"},
	}

	// Allowlisted packages skip scanners; blocklist still wins for evil-pkg.
	result, err := orch.Scan(context.Background(), packages)
	if err != nil {
		t.Fatalf("Scan returned error: %v", err)
	}
	if result.TotalFindings != 1 {
		t.Fatalf("expected 1 finding (blocklist only), got %d", result.TotalFindings)
	}
}

func TestDedupePackages(t *testing.T) {
	in := []manifest.Package{
		{Name: "lodash", Version: "4.17.21", Ecosystem: "npm"},
		{Name: "express", Version: "4.18.0", Ecosystem: "npm"},
		{Name: "lodash", Version: "4.17.21", Ecosystem: "npm"}, // dup
		{Name: "lodash", Version: "4.17.20", Ecosystem: "npm"}, // different version, keep
		{Name: "express", Version: "4.18.0", Ecosystem: "npm"}, // dup
	}
	out := dedupePackages(in)
	if len(out) != 3 {
		t.Fatalf("got %d packages, want 3 (lodash@4.17.21, express@4.18.0, lodash@4.17.20)", len(out))
	}
	// Order preserved (first-seen).
	if out[0].Name != "lodash" || out[0].Version != "4.17.21" {
		t.Errorf("out[0]=%v, want lodash@4.17.21", out[0])
	}
	if out[1].Name != "express" {
		t.Errorf("out[1]=%v, want express", out[1])
	}
	if out[2].Name != "lodash" || out[2].Version != "4.17.20" {
		t.Errorf("out[2]=%v, want lodash@4.17.20", out[2])
	}
}

func TestScan_EmptyPackagesNoCrash(t *testing.T) {
	cfg := newTestConfig()
	orch := NewOrchestrator(cfg)

	for _, name := range []string{"Scan", "ScanWithProgress"} {
		t.Run(name, func(t *testing.T) {
			var (
				result *AggregatedResult
				err    error
			)
			switch name {
			case "Scan":
				result, err = orch.Scan(context.Background(), nil)
			case "ScanWithProgress":
				result, err = orch.ScanWithProgress(context.Background(), nil, nil)
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if result.TotalFindings != 0 {
				t.Errorf("expected 0 findings for empty input, got %d", result.TotalFindings)
			}
		})
	}
}

// TestScan_PartialFailure_SurfacesViaScannerErrors verifies the post-
// audit fix: when one scanner fails and another succeeds, the
// orchestrator no longer drops the failure silently. The succeeding
// scanner's result is returned, and the failure surfaces via the
// AggregatedResult.ScannerErrors map so the CLI layer can warn the
// user that their malware (or CVE, or hygiene) signal didn't run.
func TestScan_PartialFailure_SurfacesViaScannerErrors(t *testing.T) {
	good := &stubScanner{
		name:      "good-scanner",
		available: true,
		result: &types.ScanResult{
			Scanner:  "good-scanner",
			Findings: []types.Finding{},
		},
	}
	bad := &stubScanner{
		name:      "bad-scanner",
		available: true,
		err:       errors.New("upstream rate limit"),
	}
	orch := newOrchestratorWithScanners(newTestConfig(), good, bad)

	pkgs := []manifest.Package{{Name: "p", Version: "1", Ecosystem: "npm"}}
	result, err := orch.Scan(context.Background(), pkgs)
	if err != nil {
		t.Fatalf("partial failure should not return an error; got %v", err)
	}
	if result == nil {
		t.Fatal("partial failure should still return aggregated result")
	}
	if result.ScannerErrors == nil {
		t.Fatal("ScannerErrors should be populated on partial failure")
	}
	if got := result.ScannerErrors["bad-scanner"]; got != "upstream rate limit" {
		t.Errorf("ScannerErrors[bad-scanner] = %q, want %q", got, "upstream rate limit")
	}
	if _, ok := result.ScannerErrors["good-scanner"]; ok {
		t.Error("good-scanner should not appear in ScannerErrors")
	}
}

// TestScan_AllScannersFailed_ReturnsError verifies the historic
// behavior is preserved: when EVERY scanner fails and there's no
// blocklist override, surface the failure as an error rather than
// returning empty findings that look clean.
func TestScan_AllScannersFailed_ReturnsError(t *testing.T) {
	bad1 := &stubScanner{name: "s1", available: true, err: errors.New("e1")}
	bad2 := &stubScanner{name: "s2", available: true, err: errors.New("e2")}
	orch := newOrchestratorWithScanners(newTestConfig(), bad1, bad2)

	pkgs := []manifest.Package{{Name: "p", Version: "1", Ecosystem: "npm"}}
	_, err := orch.Scan(context.Background(), pkgs)
	if err == nil {
		t.Fatal("expected error when all scanners failed and no blocklist hits")
	}
}

// TestScan_AllFailed_ButBlocklistHit_ReturnsResult: the blocklist
// produces synthetic findings without any scanner running, so a
// run where every real scanner failed but the user has a blocklisted
// package present should still return the blocklist-injected
// AggregatedResult rather than the network error.
func TestScan_AllFailed_ButBlocklistHit_ReturnsResult(t *testing.T) {
	cfg := newTestConfig()
	cfg.Scanning.Policy.Blocklist = []string{"evil"}

	bad := &stubScanner{name: "s1", available: true, err: errors.New("e1")}
	orch := newOrchestratorWithScanners(cfg, bad)

	pkgs := []manifest.Package{{Name: "evil", Version: "1", Ecosystem: "npm"}}
	result, err := orch.Scan(context.Background(), pkgs)
	if err != nil {
		t.Fatalf("blocklist hit should override all-scanners-failed error path; got %v", err)
	}
	if result == nil || result.TotalFindings == 0 {
		t.Fatal("expected blocklist-injected finding")
	}
	if result.ScannerErrors["s1"] == "" {
		t.Error("ScannerErrors should still carry the failure even with blocklist override")
	}
}
