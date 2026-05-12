package cli

import (
	"strconv"
	"strings"
)

// compareVersions returns -1 / 0 / 1 like strings.Compare, but on
// dot-separated numeric versions with optional `-prerelease` suffix
// (e.g. "1.0.0-beta.1"). Sufficient for npm versions in practice; we
// don't take a real semver dependency because the only consumer is
// pickUpgradeTarget below and the rules we need are simple:
//
//   - "9.0.0" < "10.0.0" (numeric, not lexical)
//   - "1.0.0-beta" < "1.0.0" (prerelease sorts before release)
//   - missing trailing components compare as 0 ("1.2" == "1.2.0")
//
// Garbage input (non-numeric components) falls back to byte compare so
// the function never panics.
func compareVersions(a, b string) int {
	a = strings.TrimPrefix(a, "v")
	b = strings.TrimPrefix(b, "v")

	aBase, aPre, _ := strings.Cut(a, "-")
	bBase, bPre, _ := strings.Cut(b, "-")

	aParts := strings.Split(aBase, ".")
	bParts := strings.Split(bBase, ".")

	maxLen := len(aParts)
	if len(bParts) > maxLen {
		maxLen = len(bParts)
	}
	for i := 0; i < maxLen; i++ {
		var aVal, bVal int
		var aHasNum, bHasNum bool

		if i < len(aParts) {
			n, err := strconv.Atoi(aParts[i])
			if err == nil {
				aVal, aHasNum = n, true
			}
		} else {
			aHasNum = true // missing components compare as zero
		}
		if i < len(bParts) {
			n, err := strconv.Atoi(bParts[i])
			if err == nil {
				bVal, bHasNum = n, true
			}
		} else {
			bHasNum = true
		}

		// If either side is non-numeric, fall back to string compare
		// on the original (potentially missing) components for this
		// position. Stable, deterministic, "good enough".
		if !aHasNum || !bHasNum {
			var aStr, bStr string
			if i < len(aParts) {
				aStr = aParts[i]
			}
			if i < len(bParts) {
				bStr = bParts[i]
			}
			if c := strings.Compare(aStr, bStr); c != 0 {
				return c
			}
			continue
		}

		if aVal != bVal {
			if aVal < bVal {
				return -1
			}
			return 1
		}
	}

	// Base versions equal — handle prerelease. Per semver, a release
	// sorts higher than any prerelease.
	switch {
	case aPre == "" && bPre == "":
		return 0
	case aPre == "" && bPre != "":
		return 1
	case aPre != "" && bPre == "":
		return -1
	default:
		return strings.Compare(aPre, bPre)
	}
}

// majorOf returns the major component of a version (everything before the
// first '.'). "4.17.21" → "4", "v3.0.0-beta" → "3". Returns "" for empty.
func majorOf(version string) string {
	v := strings.TrimPrefix(version, "v")
	if i := strings.IndexByte(v, '.'); i >= 0 {
		return v[:i]
	}
	if i := strings.IndexByte(v, '-'); i >= 0 {
		return v[:i]
	}
	return v
}

// pickUpgradeTarget computes the version a package needs to be on to
// resolve every finding, given the user's current version. If allowMajor
// is false, the target stays within the user's current major (e.g.
// 4.17.20 → 4.x); a major bump is left for explicit opt-in.
//
// Algorithm:
//
//  1. For each finding's FixedVersions, pick the lowest fix that's both
//     ≥ current and (optionally) in the current major.
//  2. The package target is the MAX of those per-finding minimums — i.e.
//     the lowest version that simultaneously resolves all findings.
//  3. If any finding has no in-major fix and allowMajor is false, the
//     package is "unfixable in major" and returns ok=false.
func pickUpgradeTarget(current string, findings []fixCandidate, allowMajor bool) (string, bool) {
	if len(findings) == 0 {
		return "", false
	}

	currentMajor := majorOf(current)
	var bestSoFar string

	for _, f := range findings {
		var perFinding string
		for _, fix := range f.FixedVersions {
			if compareVersions(fix, current) <= 0 {
				continue // a "fix" at or below current doesn't help us
			}
			if !allowMajor && majorOf(fix) != currentMajor {
				continue
			}
			if perFinding == "" || compareVersions(fix, perFinding) < 0 {
				perFinding = fix
			}
		}
		if perFinding == "" {
			// This finding can't be auto-fixed under the current
			// constraints. Surface the package as unfixable rather
			// than picking a target that leaves a CVE on the table.
			return "", false
		}
		if bestSoFar == "" || compareVersions(perFinding, bestSoFar) > 0 {
			bestSoFar = perFinding
		}
	}

	return bestSoFar, bestSoFar != ""
}

// fixCandidate is the minimal slice of a Finding that pickUpgradeTarget
// needs. Decouples the picker from scanner.Finding for easy testing.
type fixCandidate struct {
	FixedVersions []string
}
