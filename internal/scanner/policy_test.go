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
