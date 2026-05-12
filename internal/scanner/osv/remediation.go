package osv

import (
	"sort"
	"strings"
)

// remediationFor returns the structured list of fixed versions plus a
// human-readable summary line for pkgName, derived from OSV's
// Affected[].Ranges[].Events.Fixed records (per
// https://ossf.github.io/osv-schema/).
//
// When a package was patched in multiple major versions (e.g. backports),
// multiple ranges each carry their own Fixed event. We surface all of
// them so the caller — including `snapem upgrade` — can pick the right
// target for the user's current major instead of forcing a specific
// upgrade path.
//
// Returns (nil, "") when no fix is published.
func remediationFor(vuln vulnerability, pkgName string) ([]string, string) {
	fixedSet := make(map[string]struct{})
	for _, a := range vuln.Affected {
		if a.Package.Name != "" && !strings.EqualFold(a.Package.Name, pkgName) {
			continue
		}
		for _, r := range a.Ranges {
			for _, e := range r.Events {
				if e.Fixed != "" {
					fixedSet[e.Fixed] = struct{}{}
				}
			}
		}
	}
	if len(fixedSet) == 0 {
		return nil, ""
	}

	versions := make([]string, 0, len(fixedSet))
	for v := range fixedSet {
		versions = append(versions, v)
	}
	sort.Strings(versions)

	if len(versions) == 1 {
		return versions, "Fixed in " + versions[0]
	}
	return versions, "Fixed in " + strings.Join(versions, ", ")
}
