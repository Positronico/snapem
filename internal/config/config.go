package config

import (
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
}

// ContainerConfig holds container execution settings
type ContainerConfig struct {
	Enabled     bool              `mapstructure:"enabled"`
	Image       map[string]string `mapstructure:"image"`       // "npm" -> "node:lts-slim"
	Network     string            `mapstructure:"network"`     // "host", "none"
	Environment []string          `mapstructure:"environment"` // env vars to pass through
}

// UIConfig holds UI settings
type UIConfig struct {
	Color   bool `mapstructure:"color"`
	Verbose bool `mapstructure:"verbose"`
	Quiet   bool `mapstructure:"quiet"`
}

// Load loads configuration from viper
func Load() (*Config, error) {
	cfg := &Config{}

	// Unmarshal entire config
	if err := viper.Unmarshal(cfg); err != nil {
		return nil, err
	}

	// Handle Socket API token from environment
	if cfg.Scanning.Socket.APIToken == "" {
		cfg.Scanning.Socket.APIToken = os.Getenv("SOCKET_API_TOKEN")
	}

	// Set default cache directory
	if cfg.Scanning.Cache.Directory == "" {
		cacheDir, _ := os.UserCacheDir()
		cfg.Scanning.Cache.Directory = cacheDir + "/snapem"
	}

	// Set default CVE policy if not set - block by default for security
	if cfg.Scanning.Policy.CVE == nil {
		cfg.Scanning.Policy.CVE = map[string]string{
			"critical": "block",
			"high":     "block",
			"medium":   "block",
			"low":      "warn",
		}
	}

	// Set default images if not set
	if cfg.Container.Image == nil {
		cfg.Container.Image = map[string]string{
			"npm": "node:lts-slim",
			"bun": "oven/bun:latest",
		}
	}

	return cfg, nil
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

// GetCVEAction returns the action for a given CVE severity
func (c *Config) GetCVEAction(severity string) string {
	if action, ok := c.Scanning.Policy.CVE[severity]; ok {
		return action
	}
	return "ignore"
}

// IsPackageAllowlisted returns true if the package is in the allowlist
func (c *Config) IsPackageAllowlisted(name string) bool {
	for _, pkg := range c.Scanning.Policy.Allowlist {
		if pkg == name {
			return true
		}
	}
	return false
}

// IsPackageBlocklisted returns true if the package is in the blocklist
func (c *Config) IsPackageBlocklisted(name string) bool {
	for _, pkg := range c.Scanning.Policy.Blocklist {
		if pkg == name {
			return true
		}
	}
	return false
}
