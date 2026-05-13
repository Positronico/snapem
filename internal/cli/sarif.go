package cli

import (
	"encoding/json"
	"io"
	"sort"

	"github.com/positronico/snapem/internal/scanner"
)

// SARIF v2.1.0 emission. Spec:
// https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/sarif-v2.1.0-os.html
//
// We deliberately model only the subset needed for security findings to
// be ingested by GitHub code scanning and equivalent SARIF consumers.
// Every Finding becomes one Result; every unique advisory ID becomes
// one Rule that the Result references. Each scanner (Google OSV,
// Socket.dev) ends up in a separate Run so the consumer can attribute
// findings to a specific upstream source.

const (
	sarifSchema  = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
	sarifVersion = "2.1.0"
)

type sarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool      `json:"tool"`
	Results []sarifResult  `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	InformationURI string      `json:"informationUri,omitempty"`
	Rules          []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID               string                 `json:"id"`
	Name             string                 `json:"name,omitempty"`
	ShortDescription sarifMessage           `json:"shortDescription"`
	FullDescription  *sarifMessage          `json:"fullDescription,omitempty"`
	HelpURI          string                 `json:"helpUri,omitempty"`
	Properties       map[string]interface{} `json:"properties,omitempty"`
}

type sarifResult struct {
	RuleID    string          `json:"ruleId"`
	Level     string          `json:"level"`           // "error" / "warning" / "note"
	Message   sarifMessage    `json:"message"`
	Locations []sarifLocation `json:"locations,omitempty"`
}

type sarifLocation struct {
	LogicalLocations []sarifLogicalLocation `json:"logicalLocations,omitempty"`
}

type sarifLogicalLocation struct {
	Name string `json:"name"`           // e.g. "lodash@4.17.20"
	Kind string `json:"kind,omitempty"` // "package"
}

type sarifMessage struct {
	Text string `json:"text"`
}

// emitSARIF writes the SARIF v2.1.0 document for result to w.
func emitSARIF(w io.Writer, result *scanner.AggregatedResult) error {
	log := sarifLog{
		Schema:  sarifSchema,
		Version: sarifVersion,
		Runs:    buildSARIFRuns(result),
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(log)
}

// buildSARIFRuns groups findings by scanner so the SARIF consumer can
// attribute each Result to its upstream source.
func buildSARIFRuns(result *scanner.AggregatedResult) []sarifRun {
	if result == nil {
		return []sarifRun{}
	}
	runs := make([]sarifRun, 0, len(result.Results))
	for _, sr := range result.Results {
		if sr == nil {
			continue
		}
		run := sarifRun{
			Tool: sarifTool{
				Driver: sarifDriver{
					Name:           sr.Scanner,
					InformationURI: scannerInformationURI(sr.Scanner),
					Rules:          buildSARIFRules(sr.Findings),
				},
			},
			Results: buildSARIFResults(sr.Findings),
		}
		runs = append(runs, run)
	}
	return runs
}

func scannerInformationURI(name string) string {
	switch name {
	case "Google OSV":
		return "https://osv.dev"
	case "Socket.dev":
		return "https://socket.dev"
	}
	return ""
}

// buildSARIFRules emits one Rule per unique finding ID, sorted for
// deterministic output. The Rule carries the human-readable title and
// the advisory URL so GitHub's code-scanning UI can render the right
// "Learn more" link.
func buildSARIFRules(findings []scanner.Finding) []sarifRule {
	type ruleSeed struct {
		id      string
		title   string
		details string
		uri     string
	}
	seen := make(map[string]ruleSeed)
	for _, f := range findings {
		ruleID := sarifRuleID(f)
		if _, ok := seen[ruleID]; ok {
			continue
		}
		seen[ruleID] = ruleSeed{
			id:      ruleID,
			title:   sarifRuleTitle(f),
			details: f.Description,
			uri:     advisoryURL(f),
		}
	}

	ids := make([]string, 0, len(seen))
	for k := range seen {
		ids = append(ids, k)
	}
	sort.Strings(ids)

	rules := make([]sarifRule, 0, len(seen))
	for _, id := range ids {
		s := seen[id]
		r := sarifRule{
			ID:               s.id,
			Name:             s.id,
			ShortDescription: sarifMessage{Text: s.title},
			HelpURI:          s.uri,
		}
		if s.details != "" {
			r.FullDescription = &sarifMessage{Text: s.details}
		}
		rules = append(rules, r)
	}
	return rules
}

// buildSARIFResults emits one Result per Finding.
func buildSARIFResults(findings []scanner.Finding) []sarifResult {
	results := make([]sarifResult, 0, len(findings))
	for _, f := range findings {
		msg := sarifRuleTitle(f)
		if f.Remediation != "" {
			msg = msg + " — " + f.Remediation
		}
		results = append(results, sarifResult{
			RuleID:  sarifRuleID(f),
			Level:   sarifLevel(f.Severity),
			Message: sarifMessage{Text: msg},
			Locations: []sarifLocation{{
				LogicalLocations: []sarifLogicalLocation{{
					Name: f.Package + "@" + f.Version,
					Kind: "package",
				}},
			}},
		})
	}
	return results
}

// sarifRuleID returns the stable identifier for the rule a finding maps
// to. Prefer the advisory ID; fall back to a category bucket so findings
// without an ID don't collide.
func sarifRuleID(f scanner.Finding) string {
	if f.ID != "" {
		return f.ID
	}
	switch f.Type {
	case scanner.FindingTypeMalware:
		return "snapem.malware"
	case scanner.FindingTypeTyposquat:
		return "snapem.typosquat"
	case scanner.FindingTypeLicense:
		return "snapem.license"
	case scanner.FindingTypeMaintainer:
		return "snapem.maintainer"
	case scanner.FindingTypeQuality:
		return "snapem.quality"
	}
	return "snapem.finding"
}

// sarifRuleTitle is the human-readable shortDescription. Prefer Title,
// fall back to a category label so the SARIF UI always renders something.
func sarifRuleTitle(f scanner.Finding) string {
	if f.Title != "" {
		return f.Title
	}
	return string(f.Type) + " finding"
}

// sarifLevel maps our Severity to SARIF's three-level scale.
// SARIF only has error / warning / note (and "none"); we collapse:
//
//	critical, high       -> error
//	medium               -> warning
//	low, info, default   -> note
func sarifLevel(s scanner.Severity) string {
	switch s {
	case scanner.SeverityCritical, scanner.SeverityHigh:
		return "error"
	case scanner.SeverityMedium:
		return "warning"
	}
	return "note"
}
