package cli

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/positronico/snapem/internal/scanner"
)

func TestEmitSARIF_ShapeAndDedup(t *testing.T) {
	// Two scanners; one with two findings sharing an advisory ID, one
	// with a unique finding. Result: 2 runs, rule dedup observable on
	// the first run.
	agg := &scanner.AggregatedResult{
		Results: []*scanner.ScanResult{
			{
				Scanner: "Google OSV",
				Findings: []scanner.Finding{
					{
						Package: "lodash", Version: "4.17.20",
						Type:     scanner.FindingTypeCVE,
						Severity: scanner.SeverityHigh,
						ID:       "GHSA-abc",
						Title:    "Prototype pollution in lodash",
						Remediation: "Fixed in 4.17.21",
					},
					{
						// SAME advisory affecting another package — rules
						// table should dedup by ID.
						Package: "loose", Version: "1.0.0",
						Type:     scanner.FindingTypeCVE,
						Severity: scanner.SeverityHigh,
						ID:       "GHSA-abc",
						Title:    "Prototype pollution in lodash",
					},
					{
						Package: "express", Version: "4.0.0",
						Type:     scanner.FindingTypeCVE,
						Severity: scanner.SeverityMedium,
						ID:       "CVE-2024-9999",
						Title:    "Some express issue",
					},
				},
			},
			{
				Scanner: "Socket.dev",
				Findings: []scanner.Finding{
					{
						Package: "evil-pkg", Version: "1.0.0",
						Type:     scanner.FindingTypeMalware,
						Severity: scanner.SeverityCritical,
						ID:       "",
						Title:    "Known malware",
					},
				},
			},
		},
	}

	var buf bytes.Buffer
	if err := emitSARIF(&buf, agg); err != nil {
		t.Fatalf("emitSARIF: %v", err)
	}

	// Parse it back to a generic map so we exercise schema shape rather
	// than re-using our own structs.
	var got map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}

	if got["version"] != "2.1.0" {
		t.Errorf("version = %v, want 2.1.0", got["version"])
	}
	if got["$schema"] == nil {
		t.Error("$schema missing")
	}
	runs, ok := got["runs"].([]interface{})
	if !ok || len(runs) != 2 {
		t.Fatalf("expected 2 runs, got %T len %d", got["runs"], len(runs))
	}

	// First run is OSV. Expect 2 rules (GHSA-abc deduped, CVE-2024-9999).
	osv := runs[0].(map[string]interface{})
	osvTool := osv["tool"].(map[string]interface{})
	osvDriver := osvTool["driver"].(map[string]interface{})
	if name := osvDriver["name"]; name != "Google OSV" {
		t.Errorf("first run tool name = %v, want Google OSV", name)
	}
	rules, _ := osvDriver["rules"].([]interface{})
	if len(rules) != 2 {
		t.Errorf("OSV rules = %d, want 2 (deduped by ID)", len(rules))
	}
	results, _ := osv["results"].([]interface{})
	if len(results) != 3 {
		t.Errorf("OSV results = %d, want 3 (one per finding)", len(results))
	}

	// Second run is Socket. Single malware finding.
	sock := runs[1].(map[string]interface{})
	sockDriver := sock["tool"].(map[string]interface{})["driver"].(map[string]interface{})
	if name := sockDriver["name"]; name != "Socket.dev" {
		t.Errorf("second run tool name = %v, want Socket.dev", name)
	}
	sockResults, _ := sock["results"].([]interface{})
	if len(sockResults) != 1 {
		t.Errorf("Socket results = %d, want 1", len(sockResults))
	}

	// The malware finding had no ID — verify the fallback rule ID was used.
	first := sockResults[0].(map[string]interface{})
	if got := first["ruleId"]; got != "snapem.malware" {
		t.Errorf("missing-ID malware → ruleId=%v, want snapem.malware", got)
	}
	if got := first["level"]; got != "error" {
		t.Errorf("critical → level=%v, want error", got)
	}
}

func TestSARIFLevel(t *testing.T) {
	cases := map[scanner.Severity]string{
		scanner.SeverityCritical: "error",
		scanner.SeverityHigh:     "error",
		scanner.SeverityMedium:   "warning",
		scanner.SeverityLow:      "note",
		scanner.SeverityInfo:     "note",
		"":                       "note",
	}
	for in, want := range cases {
		got := sarifLevel(in)
		if got != want {
			t.Errorf("sarifLevel(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestSARIFRuleID_Fallback(t *testing.T) {
	cases := map[scanner.FindingType]string{
		scanner.FindingTypeMalware:    "snapem.malware",
		scanner.FindingTypeTyposquat:  "snapem.typosquat",
		scanner.FindingTypeLicense:    "snapem.license",
		scanner.FindingTypeMaintainer: "snapem.maintainer",
		scanner.FindingTypeQuality:    "snapem.quality",
		scanner.FindingType("other"):  "snapem.finding",
	}
	for in, want := range cases {
		got := sarifRuleID(scanner.Finding{Type: in})
		if got != want {
			t.Errorf("sarifRuleID(type=%q) = %q, want %q", in, got, want)
		}
	}
}

func TestSARIFRuleID_PrefersAdvisoryID(t *testing.T) {
	got := sarifRuleID(scanner.Finding{ID: "GHSA-xxxx", Type: scanner.FindingTypeMalware})
	if got != "GHSA-xxxx" {
		t.Errorf("got %q, want GHSA-xxxx (advisory ID should win over type fallback)", got)
	}
}

func TestEmitSARIF_EmptyResult(t *testing.T) {
	var buf bytes.Buffer
	if err := emitSARIF(&buf, &scanner.AggregatedResult{}); err != nil {
		t.Fatalf("emitSARIF(empty): %v", err)
	}
	var got map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}
	runs, _ := got["runs"].([]interface{})
	if len(runs) != 0 {
		t.Errorf("empty AggregatedResult should produce 0 runs, got %d", len(runs))
	}
}
