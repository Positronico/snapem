package types

import (
	"time"
)

// ScanResult contains findings from a scan
type ScanResult struct {
	Scanner      string        `json:"scanner"`
	Packages     int           `json:"packages_scanned"`
	Findings     []Finding     `json:"findings"`
	ScanDuration time.Duration `json:"scan_duration"`
	Cached       bool          `json:"cached"`
}

// Finding represents a security issue
type Finding struct {
	Package     string      `json:"package"`
	Version     string      `json:"version"`
	Type        FindingType `json:"type"`
	Severity    Severity    `json:"severity"`
	Title       string      `json:"title"`
	Description string      `json:"description"`
	ID          string      `json:"id,omitempty"`
	References  []string    `json:"references,omitempty"`
	Remediation string      `json:"remediation,omitempty"`
}

// FindingType categorizes the type of security issue
type FindingType string

const (
	FindingTypeMalware    FindingType = "malware"
	FindingTypeCVE        FindingType = "cve"
	FindingTypeTyposquat  FindingType = "typosquat"
	FindingTypeLicense    FindingType = "license"
	FindingTypeMaintainer FindingType = "maintainer"
	FindingTypeQuality    FindingType = "quality"
)

// Severity levels for findings
type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
	SeverityInfo     Severity = "info"
)

// AggregatedResult contains results from all scanners
type AggregatedResult struct {
	Results       []*ScanResult `json:"results"`
	TotalPackages int           `json:"total_packages"`
	TotalFindings int           `json:"total_findings"`
	HasMalware    bool          `json:"has_malware"`
	HasCritical   bool          `json:"has_critical"`
	HasHigh       bool          `json:"has_high"`
	Duration      time.Duration `json:"duration"`
}

// CountBySeverity returns the count of findings by severity
func (ar *AggregatedResult) CountBySeverity(sev Severity) int {
	count := 0
	for _, result := range ar.Results {
		for _, finding := range result.Findings {
			if finding.Severity == sev {
				count++
			}
		}
	}
	return count
}

// CountByType returns the count of findings by type
func (ar *AggregatedResult) CountByType(typ FindingType) int {
	count := 0
	for _, result := range ar.Results {
		for _, finding := range result.Findings {
			if finding.Type == typ {
				count++
			}
		}
	}
	return count
}

// AllFindings returns a flat list of all findings
func (ar *AggregatedResult) AllFindings() []Finding {
	var findings []Finding
	for _, result := range ar.Results {
		findings = append(findings, result.Findings...)
	}
	return findings
}

// MalwareFindings returns only malware findings
func (ar *AggregatedResult) MalwareFindings() []Finding {
	var findings []Finding
	for _, result := range ar.Results {
		for _, finding := range result.Findings {
			if finding.Type == FindingTypeMalware || finding.Type == FindingTypeTyposquat {
				findings = append(findings, finding)
			}
		}
	}
	return findings
}

// CVEFindings returns only CVE findings
func (ar *AggregatedResult) CVEFindings() []Finding {
	var findings []Finding
	for _, result := range ar.Results {
		for _, finding := range result.Findings {
			if finding.Type == FindingTypeCVE {
				findings = append(findings, finding)
			}
		}
	}
	return findings
}

// SeverityOrder returns the numeric order for sorting
func SeverityOrder(s Severity) int {
	switch s {
	case SeverityCritical:
		return 0
	case SeverityHigh:
		return 1
	case SeverityMedium:
		return 2
	case SeverityLow:
		return 3
	default:
		return 4
	}
}
