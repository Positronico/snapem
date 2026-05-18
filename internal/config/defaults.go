package config

import (
	"time"

	"github.com/spf13/viper"
)

// Defaults returns the single source of truth for snapem's default
// configuration. Every other layer (viper SetDefault, the YAML template
// emitted by `snapem config init`, the post-load fallback in Load) must
// agree with this. See CLAUDE.md §8.3.
func Defaults() *Config {
	return &Config{
		PackageManager: PackageManagerConfig{
			Preferred: "auto",
		},
		Scanning: ScanningConfig{
			Enabled: true,
			Socket: SocketConfig{
				Enabled: true,
				Timeout: 30 * time.Second,
			},
			OSV: OSVConfig{
				Enabled: true,
				Timeout: 30 * time.Second,
			},
			Scorecard: ScorecardConfig{
				Enabled:   true,
				Timeout:   30 * time.Second,
				Threshold: 5.0,
			},
			Provenance: ProvenanceConfig{
				Enabled:     true,
				Timeout:     30 * time.Second,
				WarnMissing: false,
			},
			Metadata: MetadataConfig{
				Enabled:            true,
				Timeout:            30 * time.Second,
				WarnUnknownLicense: false,
			},
			GitDep: GitDepConfig{
				Enabled: true,
				Timeout: 30 * time.Second,
			},
			Tarball: TarballConfig{
				Enabled: true,
				Timeout: 30 * time.Second,
			},
			Cache: CacheConfig{
				Enabled: true,
				TTL:     24 * time.Hour,
			},
			Policy: PolicyConfig{
				Malware: "block",
				CVE: map[string]string{
					"critical": "block",
					"high":     "block",
					"medium":   "block",
					"low":      "warn",
				},
				AllowOverride: false,
				Allowlist:     []string{},
				Blocklist:     []string{},
			},
		},
		Container: ContainerConfig{
			Enabled: true,
			Image: map[string]string{
				"npm":  "node:lts-slim",
				"bun":  "oven/bun:latest",
				"pnpm": "node:lts-slim", // pnpm runs via corepack inside node
				"yarn": "node:lts-slim", // yarn also via corepack
			},
			Network:     "host",
			Environment: []string{},
			// MountNpmrc is opt-in. Enabling it exposes whatever auth
			// tokens live in ~/.npmrc to every install script that
			// runs in the container — the same exposure as bare
			// `npm install`, but a regression vs. snapem's default
			// posture of withholding credentials from install scripts.
			// Users with private registries flip this to true after
			// reading SECURITY.md.
			MountNpmrc: false,
		},
		UI: UIConfig{
			Color:   true,
			Verbose: false,
			Quiet:   false,
		},
	}
}

// RegisterDefaults wires the canonical defaults into a viper instance. Call
// before reading config so missing keys fall through to these values.
func RegisterDefaults(v *viper.Viper) {
	d := Defaults()

	v.SetDefault("package_manager.preferred", d.PackageManager.Preferred)

	v.SetDefault("scanning.enabled", d.Scanning.Enabled)
	v.SetDefault("scanning.socket.enabled", d.Scanning.Socket.Enabled)
	v.SetDefault("scanning.socket.timeout", d.Scanning.Socket.Timeout)
	v.SetDefault("scanning.osv.enabled", d.Scanning.OSV.Enabled)
	v.SetDefault("scanning.osv.timeout", d.Scanning.OSV.Timeout)
	v.SetDefault("scanning.scorecard.enabled", d.Scanning.Scorecard.Enabled)
	v.SetDefault("scanning.scorecard.timeout", d.Scanning.Scorecard.Timeout)
	v.SetDefault("scanning.scorecard.threshold", d.Scanning.Scorecard.Threshold)
	v.SetDefault("scanning.provenance.enabled", d.Scanning.Provenance.Enabled)
	v.SetDefault("scanning.provenance.timeout", d.Scanning.Provenance.Timeout)
	v.SetDefault("scanning.provenance.warn_missing", d.Scanning.Provenance.WarnMissing)
	v.SetDefault("scanning.metadata.enabled", d.Scanning.Metadata.Enabled)
	v.SetDefault("scanning.metadata.timeout", d.Scanning.Metadata.Timeout)
	v.SetDefault("scanning.metadata.warn_unknown_license", d.Scanning.Metadata.WarnUnknownLicense)
	v.SetDefault("scanning.gitdep.enabled", d.Scanning.GitDep.Enabled)
	v.SetDefault("scanning.gitdep.timeout", d.Scanning.GitDep.Timeout)
	v.SetDefault("scanning.tarball.enabled", d.Scanning.Tarball.Enabled)
	v.SetDefault("scanning.tarball.timeout", d.Scanning.Tarball.Timeout)
	v.SetDefault("scanning.cache.enabled", d.Scanning.Cache.Enabled)
	v.SetDefault("scanning.cache.ttl", d.Scanning.Cache.TTL)
	v.SetDefault("scanning.policy.malware", d.Scanning.Policy.Malware)
	for sev, action := range d.Scanning.Policy.CVE {
		v.SetDefault("scanning.policy.cve."+sev, action)
	}
	v.SetDefault("scanning.policy.allow_override", d.Scanning.Policy.AllowOverride)

	v.SetDefault("container.enabled", d.Container.Enabled)
	v.SetDefault("container.image.npm", d.Container.Image["npm"])
	v.SetDefault("container.image.bun", d.Container.Image["bun"])
	v.SetDefault("container.image.pnpm", d.Container.Image["pnpm"])
	v.SetDefault("container.image.yarn", d.Container.Image["yarn"])
	v.SetDefault("container.network", d.Container.Network)
	v.SetDefault("container.mount_npmrc", d.Container.MountNpmrc)

	v.SetDefault("ui.color", d.UI.Color)
	v.SetDefault("ui.verbose", d.UI.Verbose)
	v.SetDefault("ui.quiet", d.UI.Quiet)
}
