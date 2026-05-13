package config

import (
	"fmt"
	"os"
	"time"

	"github.com/spf13/viper"
)

// Config holds all configuration for snapem
type Config struct {
	PackageManager PackageManagerConfig `mapstructure:"package_manager"`
	Scanning       ScanningConfig       `mapstructure:"scanning"`
	Container      ContainerConfig      `mapstructure:"container"`
	UI             UIConfig             `mapstructure:"ui"`
}

// PackageManagerConfig holds package manager settings
type PackageManagerConfig struct {
	Preferred string `mapstructure:"preferred"` // "auto", "npm", "bun"
}

// ScanningConfig holds security scanning settings
type ScanningConfig struct {
	Enabled bool         `mapstructure:"enabled"`
	Socket  SocketConfig `mapstructure:"socket"`
	OSV     OSVConfig    `mapstructure:"osv"`
	Cache   CacheConfig  `mapstructure:"cache"`
	Policy  PolicyConfig `mapstructure:"policy"`
}

// SocketConfig holds Socket.dev settings
type SocketConfig struct {
	Enabled  bool          `mapstructure:"enabled"`
	APIToken string        `mapstructure:"api_token"`
	Timeout  time.Duration `mapstructure:"timeout"`
}

// OSVConfig holds Google OSV settings
type OSVConfig struct {
	Enabled bool          `mapstructure:"enabled"`
	Timeout time.Duration `mapstructure:"timeout"`
}

// CacheConfig holds scan result caching settings
type CacheConfig struct {
	Enabled   bool          `mapstructure:"enabled"`
	TTL       time.Duration `mapstructure:"ttl"`
	Directory string        `mapstructure:"directory"`
}

// PolicyConfig holds security policy settings
type PolicyConfig struct {
	Malware       string            `mapstructure:"malware"` // "block", "warn", "ignore"
	CVE           map[string]string `mapstructure:"cve"`     // severity -> action
	AllowOverride bool              `mapstructure:"allow_override"`
	Allowlist     []string          `mapstructure:"allowlist"`
	Blocklist     []string          `mapstructure:"blocklist"`

	// Packages override the global policy on a per-package basis. Keys are
	// package names ("lodash" / "@types/node"). Values are partial
	// PolicyConfigs — set only the fields you want to override; missing
	// fields fall back to the global policy.
	//
	// Example use case: "lodash" warnings are informational because we've
	// reviewed every release we use, but the global policy still blocks
	// the rest of the dependency tree.
	Packages map[string]PackagePolicyOverride `mapstructure:"packages"`
}

// PackagePolicyOverride is the subset of PolicyConfig fields meaningful
// as a per-package override. We don't allow per-package allowlist /
// blocklist (those are already version-aware lists at the global level)
// or per-package allow_override (UX is confusing).
type PackagePolicyOverride struct {
	Malware string            `mapstructure:"malware"` // optional
	CVE     map[string]string `mapstructure:"cve"`     // optional
}

// ContainerConfig holds container execution settings
type ContainerConfig struct {
	Enabled     bool              `mapstructure:"enabled"`
	Image       map[string]string `mapstructure:"image"`       // "npm" -> "node:lts-slim"
	Network     string            `mapstructure:"network"`     // "host", "none"
	Environment []string          `mapstructure:"environment"` // env vars to pass through

	// MountNpmrc enables the read-only mount of the host's ~/.npmrc at
	// /root/.npmrc inside the container. Needed for installs from a
	// private registry — npm/yarn/pnpm all read /root/.npmrc when the
	// process runs as root, which is the case in every default image.
	//
	// Security tradeoff: when enabled, a malicious post-install script
	// can read your npmrc and exfiltrate any auth tokens in it. This
	// is the same exposure you accept by running `npm install`
	// directly. Disable (false) to keep credentials out of the
	// container; installs from private registries will then fail with
	// a 401/403 from the registry. See SECURITY.md.
	MountNpmrc bool `mapstructure:"mount_npmrc"`
}

// UIConfig holds UI settings
type UIConfig struct {
	Color   bool `mapstructure:"color"`
	Verbose bool `mapstructure:"verbose"`
	Quiet   bool `mapstructure:"quiet"`
}

// Load loads configuration from viper. Defaults must already have been
// registered via RegisterDefaults.
func Load() (*Config, error) {
	cfg := &Config{}
	if err := viper.Unmarshal(cfg); err != nil {
		return nil, err
	}

	// SOCKET_API_TOKEN is intentionally not exposed as a viper key because
	// users shouldn't put secrets in snapem.yaml. Read it from env only.
	if cfg.Scanning.Socket.APIToken == "" {
		cfg.Scanning.Socket.APIToken = os.Getenv("SOCKET_API_TOKEN")
	}

	// Cache directory isn't a viper default because it's user-specific.
	if cfg.Scanning.Cache.Directory == "" {
		cacheDir, _ := os.UserCacheDir()
		cfg.Scanning.Cache.Directory = cacheDir + "/snapem"
	}

	if err := cfg.validate(); err != nil {
		return nil, err
	}

	return cfg, nil
}

func (c *Config) validate() error {
	if err := requireOneOf("package_manager.preferred",
		c.PackageManager.Preferred, "auto", "npm", "bun", "pnpm", "yarn"); err != nil {
		return err
	}
	if err := requireOneOf("container.network",
		c.Container.Network, "host", "none", "bridge"); err != nil {
		return err
	}
	if err := requireOneOf("scanning.policy.malware",
		c.Scanning.Policy.Malware, "block", "warn", "ignore"); err != nil {
		return err
	}
	for sev, action := range c.Scanning.Policy.CVE {
		if err := requireOneOf("scanning.policy.cve."+sev,
			action, "block", "warn", "ignore"); err != nil {
			return err
		}
	}
	return nil
}

func requireOneOf(key, value string, allowed ...string) error {
	for _, a := range allowed {
		if value == a {
			return nil
		}
	}
	return fmt.Errorf("config: %s=%q is not one of %v", key, value, allowed)
}

// HasSocketToken returns true if Socket API token is configured
func (c *Config) HasSocketToken() bool {
	return c.Scanning.Socket.APIToken != ""
}

// GetImage returns the container image for the given package manager
func (c *Config) GetImage(pkgManager string) string {
	if img, ok := c.Container.Image[pkgManager]; ok {
		return img
	}
	return c.Container.Image["npm"]
}

// ShouldBlock returns true if the given action is "block"
func (c *Config) ShouldBlock(action string) bool {
	return action == "block"
}

// ShouldWarn returns true if the given action is "warn"
func (c *Config) ShouldWarn(action string) bool {
	return action == "warn"
}

// GetCVEAction returns the action for a given CVE severity at the global
// level. For per-package decisions, callers should use
// GetCVEActionForPackage.
func (c *Config) GetCVEAction(severity string) string {
	if action, ok := c.Scanning.Policy.CVE[severity]; ok {
		return action
	}
	return "ignore"
}

// GetCVEActionForPackage returns the CVE-severity action that applies to
// pkgName, consulting any per-package override first and falling back to
// the global policy when the override is unset or doesn't cover this
// severity. The fallback is partial: a package override that defines
// cve.high but not cve.medium still inherits cve.medium from global.
func (c *Config) GetCVEActionForPackage(pkgName, severity string) string {
	if override, ok := c.Scanning.Policy.Packages[pkgName]; ok {
		if action, ok := override.CVE[severity]; ok {
			return action
		}
	}
	return c.GetCVEAction(severity)
}

// GetMalwareActionForPackage returns the malware-policy action for
// pkgName, consulting per-package override first.
func (c *Config) GetMalwareActionForPackage(pkgName string) string {
	if override, ok := c.Scanning.Policy.Packages[pkgName]; ok {
		if override.Malware != "" {
			return override.Malware
		}
	}
	return c.Scanning.Policy.Malware
}

// IsPackageAllowlisted reports whether (name, version) matches any entry
// in policy.allowlist. Entries may be either "name" (any version) or
// "name@version" (exact version). The version match is case-sensitive
// because npm versions are.
//
// Historically this matched on name alone, which meant allowlisting one
// vulnerable version of a package exempted every future version of it
// forever — a real security regression. The new shape is backwards
// compatible: existing "name" entries still allow all versions.
func (c *Config) IsPackageAllowlisted(name, version string) bool {
	return matchesPackageList(c.Scanning.Policy.Allowlist, name, version)
}

// IsPackageBlocklisted reports whether (name, version) matches any entry
// in policy.blocklist. Semantics mirror IsPackageAllowlisted.
func (c *Config) IsPackageBlocklisted(name, version string) bool {
	return matchesPackageList(c.Scanning.Policy.Blocklist, name, version)
}

// matchesPackageList walks `entries` and returns true when one matches
// the (name, version) tuple under the allowlist/blocklist rules:
//
//   - "lodash"           matches lodash at every version
//   - "lodash@4.17.21"   matches lodash 4.17.21 exactly
//   - "@scope/pkg@1"     matches @scope/pkg at version "1"
//
// Empty entries are skipped.
func matchesPackageList(entries []string, name, version string) bool {
	for _, entry := range entries {
		entryName, entryVersion, hasVersion := splitListEntry(entry)
		if entryName != name {
			continue
		}
		if !hasVersion {
			return true
		}
		if entryVersion == version {
			return true
		}
	}
	return false
}

// splitListEntry parses "name", "name@version", or "@scope/pkg@version"
// into its components. hasVersion=false means the entry omitted a version
// and matches any.
func splitListEntry(entry string) (name, version string, hasVersion bool) {
	if entry == "" {
		return "", "", false
	}
	// Mirror parsePackageArg's scoped-package handling: the leading '@'
	// of a scope is not the version separator.
	if entry[0] == '@' {
		rest := entry[1:]
		for i := len(rest) - 1; i >= 0; i-- {
			if rest[i] == '@' {
				idx := i + 1
				return entry[:idx], entry[idx+1:], true
			}
		}
		return entry, "", false
	}
	for i := len(entry) - 1; i >= 0; i-- {
		if entry[i] == '@' {
			return entry[:i], entry[i+1:], true
		}
	}
	return entry, "", false
}

