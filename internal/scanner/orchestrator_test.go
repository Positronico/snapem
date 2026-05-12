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
