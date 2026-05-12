package scanner

import (
	"context"
	"testing"

	"github.com/positronico/snapem/internal/config"
	"github.com/positronico/snapem/internal/manifest"
)

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
