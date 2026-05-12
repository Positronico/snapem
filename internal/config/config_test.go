package config

import (
	"strings"
	"testing"
)

func TestValidate_RejectsUnknownPackageManager(t *testing.T) {
	cfg := Defaults()
	cfg.PackageManager.Preferred = "pnpm"

	if err := cfg.validate(); err == nil {
		t.Fatalf("expected validation error for pnpm, got nil")
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
