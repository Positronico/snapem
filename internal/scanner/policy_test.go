package scanner

import (
	"testing"

	"github.com/positronico/snapem/internal/config"
)

func policyConfig(malware string, cve map[string]string) *config.Config {
	return &config.Config{
		Scanning: config.ScanningConfig{
			Policy: config.PolicyConfig{
				Malware: malware,
				CVE:     cve,
			},
		},
	}
}

func resultWith(findings ...Finding) *AggregatedResult {
	return &AggregatedResult{
		Results: []*ScanResult{{Findings: findings}},
	}
}

func TestEvaluatePolicy_PerPackageOverrides(t *testing.T) {
	cfg := policyConfig("block", map[string]string{
		"high":   "block",
		"medium": "block",
	})
	cfg.Scanning.Policy.Packages = map[string]config.PackagePolicyOverride{
		"lodash": {
			CVE: map[string]string{"high": "warn"}, // accept high lodash findings
		},
	}

	// lodash high finding → warn (per-package override)
	lodashResult := resultWith(Finding{
		Type: FindingTypeCVE, Severity: SeverityHigh, Package: "lodash", Version: "4.0.0",
	})
	if d := EvaluatePolicy(cfg, lodashResult); d.ShouldBlock {
		t.Errorf("lodash high should NOT block (override=warn), got block (reasons=%v)", d.Reasons)
	}

	// axios high finding → block (falls back to global)
	axiosResult := resultWith(Finding{
		Type: FindingTypeCVE, Severity: SeverityHigh, Package: "axios", Version: "0.21.0",
	})
	if d := EvaluatePolicy(cfg, axiosResult); !d.ShouldBlock {
		t.Errorf("axios high should block (no override), got pass")
	}

	// lodash medium finding → still blocks because the override only
	// touched cve.high; cve.medium falls back to global "block".
	lodashMedResult := resultWith(Finding{
		Type: FindingTypeCVE, Severity: SeverityMedium, Package: "lodash", Version: "4.0.0",
	})
	if d := EvaluatePolicy(cfg, lodashMedResult); !d.ShouldBlock {
		t.Errorf("lodash medium should block (partial override, no medium override), got pass")
	}
}

func TestEvaluatePolicy_BlockingCases(t *testing.T) {
	tests := []struct {
		name    string
		cfg     *config.Config
		result  *AggregatedResult
		blocked bool
	}{
		{
			name: "malware policy=block + malware finding blocks",
			cfg:  policyConfig("block", nil),
			result: resultWith(Finding{
				Type: FindingTypeMalware, Severity: SeverityHigh, Package: "p", Version: "1",
			}),
			blocked: true,
		},
		{
			name: "malware policy=warn does not block on malware",
			cfg:  policyConfig("warn", nil),
			result: resultWith(Finding{
				Type: FindingTypeMalware, Severity: SeverityHigh, Package: "p", Version: "1",
			}),
			blocked: false,
		},
		{
			name: "typosquat counted under malware policy",
			cfg:  policyConfig("block", nil),
			result: resultWith(Finding{
				Type: FindingTypeTyposquat, Severity: SeverityHigh, Package: "lod-ash", Version: "1",
			}),
			blocked: true,
		},
		{
			name: "CVE high blocks when policy is block",
			cfg:  policyConfig("warn", map[string]string{"high": "block"}),
			result: resultWith(Finding{
				Type: FindingTypeCVE, Severity: SeverityHigh, Package: "p", Version: "1",
			}),
			blocked: true,
		},
		{
			name: "CVE medium under policy=warn does not block",
			cfg:  policyConfig("warn", map[string]string{"medium": "warn"}),
			result: resultWith(Finding{
				Type: FindingTypeCVE, Severity: SeverityMedium, Package: "p", Version: "1",
			}),
			blocked: false,
		},
		{
			name: "missing severity entry treated as ignore",
			cfg:  policyConfig("warn", map[string]string{}),
			result: resultWith(Finding{
				Type: FindingTypeCVE, Severity: SeverityCritical, Package: "p", Version: "1",
			}),
			blocked: false,
		},
		{
			name:    "no findings, no block",
			cfg:     policyConfig("block", map[string]string{"critical": "block"}),
			result:  resultWith(),
			blocked: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := EvaluatePolicy(tt.cfg, tt.result)
			if d.ShouldBlock != tt.blocked {
				t.Errorf("ShouldBlock=%v, want %v (reasons=%v)", d.ShouldBlock, tt.blocked, d.Reasons)
			}
		})
	}
}
