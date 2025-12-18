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
  # Which package manager to use: auto, npm, bun
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

  # Result caching
  cache:
    enabled: true
    ttl: 24h

  # Security policy
  policy:
    # Action on malware detection: block, warn, ignore
    malware: block

    # Action by CVE severity
    cve:
      critical: block
      high: warn
      medium: warn
      low: ignore

    # Allow user to override blocks with 'force'
    allow_override: true

    # Packages to skip scanning (trusted)
    allowlist: []

    # Packages to always block
    blocklist: []

# Container settings
container:
  enabled: true

  # Container images by package manager
  image:
    npm: node:lts-slim
    bun: oven/bun:latest

  # Network mode: host, none
  network: host

  # Environment variables to pass to container
  environment:
    - NODE_ENV
    - NPM_TOKEN

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
	display.Print(fmt.Sprintf("  socket.enabled: %v", viper.GetBool("scanning.socket.enabled")))

	// Check for Socket token
	token := os.Getenv("SOCKET_API_TOKEN")
	if token != "" {
		display.Print("  socket.api_token: (set via SOCKET_API_TOKEN)")
	} else {
		display.Print("  socket.api_token: (not set)")
	}

	display.Print(fmt.Sprintf("  osv.enabled: %v", viper.GetBool("scanning.osv.enabled")))
	display.Print(fmt.Sprintf("  policy.malware: %s", viper.GetString("scanning.policy.malware")))

	display.Print("")
	display.Print("Container:")
	display.Print(fmt.Sprintf("  enabled: %v", viper.GetBool("container.enabled")))
	display.Print(fmt.Sprintf("  network: %s", viper.GetString("container.network")))
	display.Print(fmt.Sprintf("  image.npm: %s", viper.GetString("container.image.npm")))
	display.Print(fmt.Sprintf("  image.bun: %s", viper.GetString("container.image.bun")))

	return nil
}
