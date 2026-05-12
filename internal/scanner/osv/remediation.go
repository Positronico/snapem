package osv

import (
	"sort"
	"strings"
)

// remediationFor returns a human-readable suggestion describing the version(s)
// in which the vulnerability is fixed for pkgName, or "" if OSV did not
// publish a fix.
//
// OSV records the patch metadata in vuln.Affected[].Ranges[].Events.Fixed
// (per https://ossf.github.io/osv-schema/). When a package was patched in
// multiple major versions (e.g. backports), Affected may contain several
// Ranges each with their own Fixed event; we surface all of them so the
// caller can pick the one matching their current major instead of forcing
// them into a specific upgrade path.
func remediationFor(vuln vulnerability, pkgName string) string {
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
		return ""
	}

	versions := make([]string, 0, len(fixedSet))
	for v := range fixedSet {
		versions = append(versions, v)
	}
	sort.Strings(versions)

	if len(versions) == 1 {
		return "Fixed in " + versions[0]
	}
	return "Fixed in " + strings.Join(versions, ", ")
}
