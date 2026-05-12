package cli

import (
	"testing"

	"github.com/positronico/snapem/internal/scanner"
)

func TestBuildPlan_GroupsByPackageAndPicksTarget(t *testing.T) {
	// Save and restore the package-level upgradeAllowMajor used by buildPlan.
	prev := upgradeAllowMajor
	defer func() { upgradeAllowMajor = prev }()
	upgradeAllowMajor = false

	directIndex := map[string]string{
		"lodash":  "^4.17.20",
		"axios":   "^0.21.0",
		"express": "^4.18.0",
	}

	findings := []scanner.Finding{
		{Package: "lodash", Version: "4.17.20", ID: "GHSA-a", Severity: scanner.SeverityHigh, FixedVersions: []string{"4.17.21"}},
		{Package: "lodash", Version: "4.17.20", ID: "GHSA-b", Severity: scanner.SeverityMedium, FixedVersions: []string{"4.18.0"}},
		// Transitive — not in directIndex.
		{Package: "deep-transitive", Version: "1.0.0", ID: "GHSA-c", Severity: scanner.SeverityHigh, FixedVersions: []string{"1.0.1"}},
		// Single finding on a different direct dep.
		{Package: "axios", Version: "0.21.0", ID: "GHSA-d", Severity: scanner.SeverityHigh, FixedVersions: []string{"0.21.1"}},
		// express IS in directIndex but has no findings — must not appear in any plan list.
	}

	plan := buildPlan(findings, directIndex)

	// express has no findings so it must not appear in upgrades, unfixable,
	// or transitive.
	for _, u := range append(append(plan.upgrades, plan.unfixableInMaj...), plan.transitive...) {
		if u.Name == "express" {
			t.Errorf("express has no findings; should not appear in plan: %+v", u)
		}
	}

	if got, want := len(plan.upgrades), 2; got != want {
		t.Fatalf("upgrades=%d, want %d (%+v)", got, want, plan.upgrades)
	}
	if got, want := len(plan.transitive), 1; got != want {
		t.Fatalf("transitive=%d, want %d (%+v)", got, want, plan.transitive)
	}
	if got, want := plan.totalFindings, 4; got != want {
		t.Errorf("totalFindings=%d, want %d", got, want)
	}

	// Upgrades sorted alphabetically: axios, lodash.
	if plan.upgrades[0].Name != "axios" || plan.upgrades[1].Name != "lodash" {
		t.Errorf("upgrades not sorted by name: %+v", plan.upgrades)
	}
	// lodash target should be 4.18.0 — max of per-finding minimums.
	for _, u := range plan.upgrades {
		if u.Name != "lodash" {
			continue
		}
		if u.TargetVer != "4.18.0" {
			t.Errorf("lodash target=%q, want 4.18.0", u.TargetVer)
		}
		if u.FindingCount != 2 {
			t.Errorf("lodash finding count=%d, want 2", u.FindingCount)
		}
	}

	// Transitive entry is reported but carries no target.
	if plan.transitive[0].Name != "deep-transitive" || plan.transitive[0].TargetVer != "" {
		t.Errorf("transitive entry malformed: %+v", plan.transitive[0])
	}
}

func TestBuildPlan_UnfixableInMajor(t *testing.T) {
	prev := upgradeAllowMajor
	defer func() { upgradeAllowMajor = prev }()
	upgradeAllowMajor = false

	directIndex := map[string]string{"oldpkg": "^2.0.0"}
	findings := []scanner.Finding{
		// Only fix is a major bump from 2.x to 3.0.0.
		{Package: "oldpkg", Version: "2.0.0", ID: "GHSA-x", Severity: scanner.SeverityHigh, FixedVersions: []string{"3.0.0"}},
	}

	plan := buildPlan(findings, directIndex)

	if len(plan.upgrades) != 0 {
		t.Errorf("should have 0 upgrades, got %d", len(plan.upgrades))
	}
	if len(plan.unfixableInMaj) != 1 {
		t.Fatalf("should have 1 unfixable entry, got %d", len(plan.unfixableInMaj))
	}
	if plan.unfixableInMaj[0].Reason == "" {
		t.Errorf("unfixable entry should carry a Reason")
	}
}

func TestBuildPlan_NoFindingsEmptyPlan(t *testing.T) {
	plan := buildPlan(nil, map[string]string{"x": "1"})
	if !plan.empty() {
		t.Error("plan should be empty when there are no findings")
	}
}

func TestBuildPlan_AllowMajorPromotesUnfixable(t *testing.T) {
	prev := upgradeAllowMajor
	defer func() { upgradeAllowMajor = prev }()
	upgradeAllowMajor = true

	directIndex := map[string]string{"oldpkg": "^2.0.0"}
	findings := []scanner.Finding{
		{Package: "oldpkg", Version: "2.0.0", ID: "GHSA-x", Severity: scanner.SeverityHigh, FixedVersions: []string{"3.0.0"}},
	}
	plan := buildPlan(findings, directIndex)

	if len(plan.upgrades) != 1 || plan.upgrades[0].TargetVer != "3.0.0" {
		t.Errorf("with --major, should suggest 3.0.0: %+v", plan.upgrades)
	}
	if len(plan.unfixableInMaj) != 0 {
		t.Errorf("with --major, unfixable list should be empty: %+v", plan.unfixableInMaj)
	}
}
