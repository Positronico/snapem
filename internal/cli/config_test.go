package cli

import (
	"bytes"
	"reflect"
	"testing"

	"github.com/spf13/viper"

	"github.com/positronico/snapem/internal/config"
)

// TestDefaultConfigTemplateMatchesDefaults guards the three-place defaults
// problem described in CLAUDE.md §8.3: the YAML template emitted by
// `snapem config init` MUST parse to the same values as config.Defaults().
func TestDefaultConfigTemplateMatchesDefaults(t *testing.T) {
	v := viper.New()
	v.SetConfigType("yaml")
	if err := v.ReadConfig(bytes.NewBufferString(defaultConfigTemplate)); err != nil {
		t.Fatalf("template failed to parse as YAML: %v", err)
	}

	var fromTemplate config.Config
	if err := v.Unmarshal(&fromTemplate); err != nil {
		t.Fatalf("template failed to unmarshal: %v", err)
	}

	want := config.Defaults()

	// Compare the policy-shaped subset: this is what diverged historically.
	if fromTemplate.Scanning.Policy.Malware != want.Scanning.Policy.Malware {
		t.Errorf("malware policy: template=%q defaults=%q",
			fromTemplate.Scanning.Policy.Malware, want.Scanning.Policy.Malware)
	}
	if !reflect.DeepEqual(fromTemplate.Scanning.Policy.CVE, want.Scanning.Policy.CVE) {
		t.Errorf("CVE policy: template=%v defaults=%v",
			fromTemplate.Scanning.Policy.CVE, want.Scanning.Policy.CVE)
	}
	if fromTemplate.Scanning.Policy.AllowOverride != want.Scanning.Policy.AllowOverride {
		t.Errorf("allow_override: template=%v defaults=%v",
			fromTemplate.Scanning.Policy.AllowOverride, want.Scanning.Policy.AllowOverride)
	}

	// Scanning + container core defaults
	if fromTemplate.Scanning.Enabled != want.Scanning.Enabled {
		t.Errorf("scanning.enabled mismatch: template=%v defaults=%v",
			fromTemplate.Scanning.Enabled, want.Scanning.Enabled)
	}
	if fromTemplate.Container.Network != want.Container.Network {
		t.Errorf("container.network mismatch: template=%q defaults=%q",
			fromTemplate.Container.Network, want.Container.Network)
	}
	if fromTemplate.Container.Image["npm"] != want.Container.Image["npm"] {
		t.Errorf("container.image.npm mismatch: template=%q defaults=%q",
			fromTemplate.Container.Image["npm"], want.Container.Image["npm"])
	}
}

// TestRegisterDefaultsMatchesDefaults asserts viper SetDefault registration
// produces the same Config as config.Defaults() when nothing else is set.
func TestRegisterDefaultsMatchesDefaults(t *testing.T) {
	v := viper.New()
	config.RegisterDefaults(v)

	var got config.Config
	if err := v.Unmarshal(&got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	want := config.Defaults()

	if got.Scanning.Policy.Malware != want.Scanning.Policy.Malware {
		t.Errorf("malware policy: viper=%q defaults=%q",
			got.Scanning.Policy.Malware, want.Scanning.Policy.Malware)
	}
	if !reflect.DeepEqual(got.Scanning.Policy.CVE, want.Scanning.Policy.CVE) {
		t.Errorf("CVE policy: viper=%v defaults=%v",
			got.Scanning.Policy.CVE, want.Scanning.Policy.CVE)
	}
	if got.Scanning.Policy.AllowOverride != want.Scanning.Policy.AllowOverride {
		t.Errorf("allow_override: viper=%v defaults=%v",
			got.Scanning.Policy.AllowOverride, want.Scanning.Policy.AllowOverride)
	}
}
