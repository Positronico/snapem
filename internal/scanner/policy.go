package scanner

import (
	"fmt"

	"github.com/positronico/snapem/internal/config"
)

// PolicyDecision is the outcome of applying the user's configured policy to
// a set of scan findings. Reasons holds human-readable strings that explain
// each block-triggering finding for surfacing to the CLI.
type PolicyDecision struct {
	ShouldBlock bool
	Reasons     []string
}

// EvaluatePolicy applies cfg.Scanning.Policy to result and returns whether
// the run must be blocked. Used by both `snapem install` and `snapem scan`
// to keep their blocking semantics identical; previously the scan command
// only blocked on malware + critical CVE and silently ignored a high/medium
// policy of "block". See CLAUDE.md §8.1.
func EvaluatePolicy(cfg *config.Config, result *AggregatedResult) PolicyDecision {
	d := PolicyDecision{}
	if result == nil {
		return d
	}

	for _, sr := range result.Results {
		for _, f := range sr.Findings {
			action := actionFor(cfg, f)
			if !cfg.ShouldBlock(action) {
				continue
			}
			d.ShouldBlock = true
			d.Reasons = append(d.Reasons, fmt.Sprintf("%s %s in %s@%s",
				severityLabel(f.Severity), typeLabel(f.Type), f.Package, f.Version))
		}
	}
	return d
}

func actionFor(cfg *config.Config, f Finding) string {
	switch f.Type {
	case FindingTypeMalware, FindingTypeTyposquat:
		return cfg.Scanning.Policy.Malware
	case FindingTypeCVE:
		return cfg.GetCVEAction(string(f.Severity))
	}
	// License, maintainer, quality findings are advisory by default — not
	// driven by a policy key today. Treat as ignore so they show up but
	// don't gate installs.
	return "ignore"
}

func severityLabel(s Severity) string {
	if s == "" {
		return "unknown"
	}
	return string(s)
}

func typeLabel(t FindingType) string {
	switch t {
	case FindingTypeMalware:
		return "malware"
	case FindingTypeTyposquat:
		return "typosquat"
	case FindingTypeCVE:
		return "CVE"
	case FindingTypeLicense:
		return "license issue"
	case FindingTypeMaintainer:
		return "maintainer issue"
	case FindingTypeQuality:
		return "quality issue"
	}
	return "finding"
}
