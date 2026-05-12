package cli

import "testing"

func TestCompareVersions(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"1.0.0", "1.0.0", 0},
		{"1.0.0", "1.0.1", -1},
		{"1.0.1", "1.0.0", 1},

		// Numeric, not lexical — the classic 9 vs 10 trap.
		{"9.0.0", "10.0.0", -1},
		{"10.0.0", "9.0.0", 1},

		// Missing trailing components.
		{"1.2", "1.2.0", 0},
		{"1.2.0", "1.2", 0},

		// Prerelease: a release sorts higher than any prerelease.
		{"1.0.0-beta", "1.0.0", -1},
		{"1.0.0", "1.0.0-beta", 1},
		{"1.0.0-alpha", "1.0.0-beta", -1},

		// Leading 'v' stripped.
		{"v1.0.0", "1.0.0", 0},

		// Different majors.
		{"0.2.4", "1.2.6", -1},
	}
	for _, tc := range cases {
		got := compareVersions(tc.a, tc.b)
		if got != tc.want {
			t.Errorf("compareVersions(%q, %q) = %d, want %d", tc.a, tc.b, got, tc.want)
		}
	}
}

func TestMajorOf(t *testing.T) {
	cases := map[string]string{
		"":              "",
		"4":             "4",
		"4.17.21":       "4",
		"v4.17.21":      "4",
		"10.0.0":        "10",
		"1.0.0-beta.1":  "1",
		"2-pre":         "2",
	}
	for in, want := range cases {
		if got := majorOf(in); got != want {
			t.Errorf("majorOf(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestPickUpgradeTarget_InMajor(t *testing.T) {
	// User on lodash@4.17.20 with five findings whose fix versions are:
	//   4.17.21, 4.17.21, 4.18.0, 4.18.0, 4.17.23
	// Each finding's minimum fix is fix-list[0]. The package target is
	// the MAX of those minimums — 4.18.0 — because it's the lowest
	// version that resolves all five findings simultaneously.
	findings := []fixCandidate{
		{FixedVersions: []string{"4.17.21"}},
		{FixedVersions: []string{"4.17.21"}},
		{FixedVersions: []string{"4.18.0"}},
		{FixedVersions: []string{"4.18.0"}},
		{FixedVersions: []string{"4.17.23"}},
	}
	target, ok := pickUpgradeTarget("4.17.20", findings, false)
	if !ok {
		t.Fatal("expected ok=true")
	}
	if target != "4.18.0" {
		t.Errorf("target=%q, want 4.18.0", target)
	}
}

func TestPickUpgradeTarget_StaysInMajorByDefault(t *testing.T) {
	// minimist 1.2.5 has a fix backported to 0.2.4 AND a forward fix in
	// 1.2.6. A 1.x user must land on 1.2.6, NOT 0.2.4.
	findings := []fixCandidate{
		{FixedVersions: []string{"0.2.4", "1.2.6"}},
	}
	target, ok := pickUpgradeTarget("1.2.5", findings, false)
	if !ok {
		t.Fatal("expected ok=true")
	}
	if target != "1.2.6" {
		t.Errorf("target=%q, want 1.2.6 (stay in current major)", target)
	}
}

func TestPickUpgradeTarget_AllowMajorOptIn(t *testing.T) {
	// If the user explicitly says they want major bumps, the picker can
	// suggest the lowest fix across all majors when no in-major option
	// exists. User on 2.0.0 with a fix only in 3.0.0:
	findings := []fixCandidate{
		{FixedVersions: []string{"3.0.0"}},
	}
	if _, ok := pickUpgradeTarget("2.0.0", findings, false); ok {
		t.Error("without --major, no in-major fix should refuse")
	}
	target, ok := pickUpgradeTarget("2.0.0", findings, true)
	if !ok || target != "3.0.0" {
		t.Errorf("with --major: target=%q ok=%v, want 3.0.0 / true", target, ok)
	}
}

func TestPickUpgradeTarget_NoFixForOneFindingMeansUnfixable(t *testing.T) {
	// If any one finding has no in-major fix, the whole package is
	// unfixable under current constraints — we don't silently leave a
	// CVE on the table by picking a partial target.
	findings := []fixCandidate{
		{FixedVersions: []string{"4.17.21"}},
		{FixedVersions: []string{"5.0.0"}}, // jumps major, refuses without --major
	}
	if _, ok := pickUpgradeTarget("4.17.20", findings, false); ok {
		t.Error("should refuse to pick a target when one finding has no in-major fix")
	}
}

func TestPickUpgradeTarget_EmptyFindings(t *testing.T) {
	if _, ok := pickUpgradeTarget("1.0.0", nil, false); ok {
		t.Error("no findings → no target")
	}
}

// A "fix" version that is at or below the user's current version is not
// actually a fix (the user already has it). Reject those silently.
func TestPickUpgradeTarget_IgnoresFixesAtOrBelowCurrent(t *testing.T) {
	findings := []fixCandidate{
		{FixedVersions: []string{"4.17.20", "4.17.21"}},
	}
	target, ok := pickUpgradeTarget("4.17.20", findings, false)
	if !ok || target != "4.17.21" {
		t.Errorf("target=%q ok=%v, want 4.17.21 (4.17.20 isn't progress)", target, ok)
	}
}
