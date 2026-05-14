package cli

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/positronico/snapem/internal/errors"
	"github.com/positronico/snapem/internal/ui"
)

var configCmd = &cobra.Command{
	Use:   "config",
	Short: "Manage snapem configuration",
	Long:  `View and manage snapem configuration settings.`,
}

var configInitCmd = &cobra.Command{
	Use:   "init",
	Short: "Create a default configuration file",
	Long: `Creates a snapem.yaml configuration file in the current directory
with default settings that you can customize.`,
	RunE: runConfigInit,
}

var configShowCmd = &cobra.Command{
	Use:   "show",
	Short: "Show current configuration",
	Long:  `Displays the current configuration values.`,
	RunE:  runConfigShow,
}

func init() {
	configCmd.AddCommand(configInitCmd)
	configCmd.AddCommand(configShowCmd)
	rootCmd.AddCommand(configCmd)
}

const defaultConfigTemplate = `# snapem Configuration
# https://github.com/positronico/snapem

# Package manager settings
package_manager:
  # Which package manager to use: auto, npm, bun, pnpm, yarn
  preferred: auto

# Security scanning settings
scanning:
  enabled: true

  # Socket.dev settings (malware detection)
  socket:
    enabled: true
    # Set SOCKET_API_TOKEN environment variable for authentication
    # Get a free API key at https://socket.dev
    timeout: 30s

  # Google OSV settings (CVE detection)
  osv:
    enabled: true
    timeout: 30s

  # npm provenance attestations. When a package was published with
  # 'npm publish --provenance', npm stores a SLSA-format attestation
  # binding the tarball to (source repo, git ref, builder identity).
  # snapem fetches and decodes this attestation, surfacing subject-PURL
  # mismatches (the shape of an attestation-confusion attack) and —
  # when warn_missing is true — packages without any attestation.
  #
  # Cryptographic verification of the Sigstore signature chain is a
  # planned follow-up; today the scanner trusts the npm registry over
  # HTTPS to serve genuine metadata.
  provenance:
    enabled: true
    timeout: 30s
    # When true, packages without provenance emit a low-severity
    # advisory finding. Default false because most of npm hasn't
    # adopted provenance yet — enabling this on a typical project
    # would flag the majority of dependencies.
    warn_missing: false

  # Package metadata enrichment (via deps.dev). Surfaces maintainer-
  # marked deprecation as a medium finding (always, when enabled).
  # Optional license posture surfacing.
  metadata:
    enabled: true
    timeout: 30s
    # When true, packages with unknown/non-standard licenses emit a
    # low advisory. Default false because deps.dev returns
    # "non-standard" for many real packages whose license string
    # isn't a strict SPDX identifier — noisy.
    warn_unknown_license: false

  # OSSF Scorecard (via deps.dev) — measures maintainer hygiene
  # rather than malware or CVEs. Emits an advisory finding when a
  # package's repo scores below threshold. Findings are FindingTypeQuality
  # and never block installs (advisory only) regardless of severity.
  scorecard:
    enabled: true
    timeout: 30s
    # Score range is 0-10. Anything below this triggers a finding.
    # 5.0 is a reasonable cutoff for "noticeably below mid-range".
    threshold: 5.0

  # Result caching
  cache:
    enabled: true
    ttl: 24h

  # Security policy
  policy:
    # Action on malware detection: block, warn, ignore
    malware: block

    # Action by CVE severity. NOTE: these must agree with the defaults in
    # internal/config/defaults.go — there is a test asserting they do.
    cve:
      critical: block
      high: block
      medium: block
      low: warn

    # Allow user to override blocks with 'force'
    allow_override: false

    # Packages to skip scanning (trusted). Entries can be:
    #   - "lodash"           — every version of lodash is allowlisted
    #   - "lodash@4.17.21"   — only this exact version
    #   - "@types/node"      — works for scoped packages too
    # Prefer pinning a version: a name-only allowlist exempts every
    # future version of the package from scanning forever.
    allowlist: []

    # Packages to always block. Same shape as allowlist; pinning a
    # version blocks only that release.
    blocklist: []

    # Per-package overrides. Use sparingly — they exempt a package from
    # the project-wide policy. Set only the keys you want to override;
    # everything else falls back to the global policy above.
    #
    # packages:
    #   lodash:
    #     cve:
    #       high: warn   # we've reviewed every lodash release we use
    #   flagged-but-trusted:
    #     malware: warn
    packages: {}

# Container settings
container:
  enabled: true

  # Container images by package manager
  image:
    npm: node:lts-slim
    bun: oven/bun:latest
    pnpm: node:lts-slim       # pnpm uses corepack inside the node image
    yarn: node:lts-slim       # yarn also uses corepack

  # Network mode: host, none
  network: host

  # Environment variables to pass into the container. Snapem does NOT
  # forward host environment by default — list each variable you want the
  # container to see. NEVER add registry tokens (NPM_TOKEN, etc.) here
  # unless you trust every package in your dependency tree, because a
  # malicious install script can read this env.
  environment:
    - NODE_ENV

  # Mount ~/.npmrc read-only at /root/.npmrc inside the container.
  # OPT-IN. Required for installs from a private registry (npm, yarn
  # classic, and pnpm all read /root/.npmrc when running as root).
  #
  # SECURITY WARNING: enabling this exposes any auth tokens in your
  # npmrc to every install script that runs in the container — the
  # same exposure as 'npm install' directly. Snapem prints a warning
  # on every command when this mount is active. Keep it disabled
  # unless you actually need a private registry, then read SECURITY.md
  # to understand the tradeoff before flipping it on.
  mount_npmrc: false

# UI settings
ui:
  color: true
  verbose: false
  quiet: false
`

func runConfigInit(cmd *cobra.Command, args []string) error {
	display := ui.New(verbose, quiet, !noColor)

	configPath := filepath.Join(".", "snapem.yaml")

	// Check if config already exists
	if _, err := os.Stat(configPath); err == nil {
		display.Warning("Configuration file already exists: snapem.yaml")
		display.Info("Use --config flag to specify a different location")
		return nil
	}

	// Write default config
	if err := os.WriteFile(configPath, []byte(defaultConfigTemplate), 0644); err != nil {
		return errors.New(errors.ExitGeneralError, "failed to write config file")
	}

	display.Success("Created snapem.yaml")
	display.Info("Edit this file to customize your settings")
	display.Info("Set SOCKET_API_TOKEN for malware detection")

	return nil
}

func runConfigShow(cmd *cobra.Command, args []string) error {
	display := ui.New(verbose, quiet, !noColor)

	// Show config file location
	configFile := viper.ConfigFileUsed()
	if configFile != "" {
		display.Info(fmt.Sprintf("Config file: %s", configFile))
	} else {
		display.Info("Config file: (using defaults)")
	}

	display.Print("")

	// Show key settings
	display.Print("Package Manager:")
	display.Print(fmt.Sprintf("  preferred: %s", viper.GetString("package_manager.preferred")))

	display.Print("")
	display.Print("Scanning:")
	display.Print(fmt.Sprintf("  enabled: %v", viper.GetBool("scanning.enabled")))

	// Socket.dev
	display.Print(fmt.Sprintf("  socket.enabled: %v", viper.GetBool("scanning.socket.enabled")))
	if os.Getenv("SOCKET_API_TOKEN") != "" {
		display.Print("  socket.api_token: (set via SOCKET_API_TOKEN)")
	} else {
		display.Print("  socket.api_token: (not set)")
	}
	display.Print(fmt.Sprintf("  socket.timeout: %s", viper.GetDuration("scanning.socket.timeout")))

	// OSV
	display.Print(fmt.Sprintf("  osv.enabled: %v", viper.GetBool("scanning.osv.enabled")))
	display.Print(fmt.Sprintf("  osv.timeout: %s", viper.GetDuration("scanning.osv.timeout")))

	// OSSF Scorecard
	display.Print(fmt.Sprintf("  scorecard.enabled: %v", viper.GetBool("scanning.scorecard.enabled")))
	display.Print(fmt.Sprintf("  scorecard.threshold: %v", viper.GetFloat64("scanning.scorecard.threshold")))

	// npm provenance
	display.Print(fmt.Sprintf("  provenance.enabled: %v", viper.GetBool("scanning.provenance.enabled")))
	display.Print(fmt.Sprintf("  provenance.warn_missing: %v", viper.GetBool("scanning.provenance.warn_missing")))

	// deps.dev metadata
	display.Print(fmt.Sprintf("  metadata.enabled: %v", viper.GetBool("scanning.metadata.enabled")))
	display.Print(fmt.Sprintf("  metadata.warn_unknown_license: %v", viper.GetBool("scanning.metadata.warn_unknown_license")))

	// Cache
	display.Print(fmt.Sprintf("  cache.enabled: %v", viper.GetBool("scanning.cache.enabled")))
	display.Print(fmt.Sprintf("  cache.ttl: %s", viper.GetDuration("scanning.cache.ttl")))

	// Policy
	display.Print(fmt.Sprintf("  policy.malware: %s", viper.GetString("scanning.policy.malware")))
	if cveMap := viper.GetStringMapString("scanning.policy.cve"); len(cveMap) > 0 {
		for _, lvl := range []string{"critical", "high", "medium", "low"} {
			if action := cveMap[lvl]; action != "" {
				display.Print(fmt.Sprintf("  policy.cve.%s: %s", lvl, action))
			}
		}
	}
	if al := viper.GetStringSlice("scanning.policy.allowlist"); len(al) > 0 {
		display.Print(fmt.Sprintf("  policy.allowlist: %d entries", len(al)))
	}
	if bl := viper.GetStringSlice("scanning.policy.blocklist"); len(bl) > 0 {
		display.Print(fmt.Sprintf("  policy.blocklist: %d entries", len(bl)))
	}
	if pkgs := viper.GetStringMap("scanning.policy.packages"); len(pkgs) > 0 {
		display.Print(fmt.Sprintf("  policy.packages: %d per-package override(s)", len(pkgs)))
	}

	display.Print("")
	display.Print("Container:")
	display.Print(fmt.Sprintf("  enabled: %v", viper.GetBool("container.enabled")))
	display.Print(fmt.Sprintf("  network: %s", viper.GetString("container.network")))
	display.Print(fmt.Sprintf("  mount_npmrc: %v", viper.GetBool("container.mount_npmrc")))
	display.Print(fmt.Sprintf("  image.npm: %s", viper.GetString("container.image.npm")))
	display.Print(fmt.Sprintf("  image.bun: %s", viper.GetString("container.image.bun")))
	display.Print(fmt.Sprintf("  image.pnpm: %s", viper.GetString("container.image.pnpm")))
	display.Print(fmt.Sprintf("  image.yarn: %s", viper.GetString("container.image.yarn")))
	if env := viper.GetStringSlice("container.environment"); len(env) > 0 {
		display.Print(fmt.Sprintf("  environment: %v", env))
	}

	display.Print("")
	display.Print("UI:")
	display.Print(fmt.Sprintf("  color: %v", viper.GetBool("ui.color")))
	display.Print(fmt.Sprintf("  verbose: %v", viper.GetBool("ui.verbose")))
	display.Print(fmt.Sprintf("  quiet: %v", viper.GetBool("ui.quiet")))

	return nil
}
