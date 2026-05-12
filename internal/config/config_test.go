package config

import (
	"strings"
	"testing"
)

func TestValidate_RejectsUnknownPackageManager(t *testing.T) {
	cfg := Defaults()
	cfg.PackageManager.Preferred = "yarn" // not yet supported

	if err := cfg.validate(); err == nil {
		t.Fatalf("expected validation error for yarn, got nil")
	} else if !strings.Contains(err.Error(), "package_manager.preferred") {
		t.Errorf("error message missing key reference: %v", err)
	}
}

func TestValidate_RejectsUnknownNetwork(t *testing.T) {
	cfg := Defaults()
	cfg.Container.Network = "bridge2"

	if err := cfg.validate(); err == nil {
		t.Fatalf("expected validation error for bridge2, got nil")
	}
}

func TestValidate_RejectsUnknownPolicyAction(t *testing.T) {
	cfg := Defaults()
	cfg.Scanning.Policy.Malware = "nuke"

	if err := cfg.validate(); err == nil {
		t.Fatalf("expected validation error for nuke, got nil")
	}
}

func TestValidate_RejectsUnknownCVESeverityAction(t *testing.T) {
	cfg := Defaults()
	cfg.Scanning.Policy.CVE["high"] = "explode"

	if err := cfg.validate(); err == nil {
		t.Fatalf("expected validation error for cve.high=explode, got nil")
	}
}

func TestValidate_AcceptsDefaults(t *testing.T) {
	if err := Defaults().validate(); err != nil {
		t.Errorf("Defaults() failed validation: %v", err)
	}
}

func TestSplitListEntry(t *testing.T) {
	cases := []struct {
		entry        string
		wantName     string
		wantVersion  string
		wantHasVer   bool
	}{
		{"", "", "", false},
		{"lodash", "lodash", "", false},
		{"lodash@4.17.21", "lodash", "4.17.21", true},
		{"@types/node", "@types/node", "", false},
		{"@types/node@20.10.0", "@types/node", "20.10.0", true},
		{"@scope/pkg@1.0.0-beta.1", "@scope/pkg", "1.0.0-beta.1", true},
	}
	for _, tc := range cases {
		t.Run(tc.entry, func(t *testing.T) {
			n, v, has := splitListEntry(tc.entry)
			if n != tc.wantName || v != tc.wantVersion || has != tc.wantHasVer {
				t.Errorf("splitListEntry(%q)=(%q,%q,%v), want (%q,%q,%v)",
					tc.entry, n, v, has, tc.wantName, tc.wantVersion, tc.wantHasVer)
			}
		})
	}
}

func TestIsPackageAllowlisted_NameOnlyMatchesAllVersions(t *testing.T) {
	cfg := &Config{
		Scanning: ScanningConfig{
			Policy: PolicyConfig{
				Allowlist: []string{"lodash"},
			},
		},
	}
	for _, v := range []string{"1.0.0", "4.17.20", "99.0.0-beta.1"} {
		if !cfg.IsPackageAllowlisted("lodash", v) {
			t.Errorf("expected lodash@%s to be allowlisted by name-only entry", v)
		}
	}
	if cfg.IsPackageAllowlisted("express", "4.18.0") {
		t.Errorf("express should not match a 'lodash' entry")
	}
}

func TestIsPackageAllowlisted_VersionPinDoesNotExemptOthers(t *testing.T) {
	cfg := &Config{
		Scanning: ScanningConfig{
			Policy: PolicyConfig{
				Allowlist: []string{"lodash@4.17.21"},
			},
		},
	}
	if !cfg.IsPackageAllowlisted("lodash", "4.17.21") {
		t.Error("exact match should be allowlisted")
	}
	// This is the security fix: name-only matching previously exempted
	// every future version of lodash. The pinned entry must not.
	if cfg.IsPackageAllowlisted("lodash", "4.17.20") {
		t.Error("non-matching version must not be allowlisted by a pinned entry")
	}
	if cfg.IsPackageAllowlisted("lodash", "5.0.0") {
		t.Error("future versions must not be allowlisted by a pinned entry")
	}
}

func TestIsPackageBlocklisted_VersionAware(t *testing.T) {
	cfg := &Config{
		Scanning: ScanningConfig{
			Policy: PolicyConfig{
				Blocklist: []string{"evil-pkg", "lodash@1.0.0-known-bad"},
			},
		},
	}
	if !cfg.IsPackageBlocklisted("evil-pkg", "9.9.9") {
		t.Error("name-only blocklist must match all versions")
	}
	if !cfg.IsPackageBlocklisted("lodash", "1.0.0-known-bad") {
		t.Error("pinned blocklist entry must match its version")
	}
	if cfg.IsPackageBlocklisted("lodash", "4.17.21") {
		t.Error("pinned blocklist entry must not match other versions")
	}
}

func TestIsPackageAllowlisted_ScopedPackages(t *testing.T) {
	cfg := &Config{
		Scanning: ScanningConfig{
			Policy: PolicyConfig{
				Allowlist: []string{"@types/node@20.10.0"},
			},
		},
	}
	if !cfg.IsPackageAllowlisted("@types/node", "20.10.0") {
		t.Error("scoped package with pinned version must match")
	}
	if cfg.IsPackageAllowlisted("@types/node", "20.10.1") {
		t.Error("scoped package other version must not match")
	}
}
