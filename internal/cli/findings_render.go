package cli

import (
	"sort"
	"strings"

	"github.com/positronico/snapem/internal/scanner"
	"github.com/positronico/snapem/internal/ui"
)

// advisoryURL returns the canonical advisory page for a finding's ID, or
// the first available reference URL if no canonical form is recognized.
// We prefer the GHSA/CVE canonical because OSV's References list is often
// padded with vendor mirrors (Oracle, Snyk, etc.) and the GHSA page is the
// most actionable summary for npm consumers.
func advisoryURL(f scanner.Finding) string {
	switch {
	case strings.HasPrefix(f.ID, "GHSA-"):
		return "https://github.com/advisories/" + f.ID
	case strings.HasPrefix(f.ID, "CVE-"):
		return "https://nvd.nist.gov/vuln/detail/" + f.ID
	}
	for _, ref := range f.References {
		if ref != "" {
			return ref
		}
	}
	return ""
}

// renderFindingsGrouped prints findings grouped by package@version, with
// each package's findings sorted critical → low. Used by both install
// (post-scan) and scan (text output) so they stay visually consistent.
func renderFindingsGrouped(display *ui.UI, findings []scanner.Finding) {
	if len(findings) == 0 {
		return
	}

	type pkgKey struct {
		name, version string
	}
	bucket := make(map[pkgKey][]scanner.Finding)
	var order []pkgKey
	for _, f := range findings {
		k := pkgKey{f.Package, f.Version}
		if _, seen := bucket[k]; !seen {
			order = append(order, k)
		}
		bucket[k] = append(bucket[k], f)
	}

	// Order packages by worst severity descending, then alphabetical.
	sort.Slice(order, func(i, j int) bool {
		wi := worstSeverityRank(bucket[order[i]])
		wj := worstSeverityRank(bucket[order[j]])
		if wi != wj {
			return wi < wj
		}
		if order[i].name != order[j].name {
			return order[i].name < order[j].name
		}
		return order[i].version < order[j].version
	})

	for _, k := range order {
		fs := bucket[k]
		// Sort findings within a package critical → low.
		sort.SliceStable(fs, func(i, j int) bool {
			return scanner.SeverityOrder(fs[i].Severity) < scanner.SeverityOrder(fs[j].Severity)
		})
		display.PackageHeader(k.name+"@"+k.version, len(fs), string(fs[0].Severity))
		for _, f := range fs {
			display.ThreatLine(string(f.Severity), f.ID, displayTitle(f), f.Remediation, advisoryURL(f))
		}
	}
}

// displayTitle picks the best human label for a finding. Falls back from
// Title to Description (truncated) to "<no description>" so the line never
// renders empty for older OSV records.
func displayTitle(f scanner.Finding) string {
	if f.Title != "" {
		return f.Title
	}
	if f.Description != "" {
		desc := f.Description
		if len(desc) > 120 {
			desc = desc[:117] + "..."
		}
		return desc
	}
	return "(no description available)"
}

// worstSeverityRank returns the lowest scanner.SeverityOrder value across
// findings (lower number = more severe, per the existing convention).
func worstSeverityRank(fs []scanner.Finding) int {
	worst := scanner.SeverityOrder("") // largest value sentinel
	for _, f := range fs {
		if r := scanner.SeverityOrder(f.Severity); r < worst {
			worst = r
		}
	}
	return worst
}
