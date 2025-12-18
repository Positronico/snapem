package cli

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var (
	cfgFile string
	verbose bool
	quiet   bool
	noColor bool
	pkgMgr  string
)

var rootCmd = &cobra.Command{
	Use:   "snapem",
	Short: "Secure npm/bun wrapper with pre-flight scanning and container isolation",
	Long: `snapem provides a Zero-Trust Development Environment for Node.js developers
on macOS Silicon by scanning dependencies for malware and vulnerabilities
before running them in isolated Apple containers.

Features:
  - Pre-flight scanning using Socket.dev (malware) and OSV (CVEs)
  - Container isolation via Apple's native Containerization framework
  - Drop-in replacement for npm/bun commands
  - Configurable security policies

Examples:
  snapem install              # Scan and install dependencies
  snapem install lodash       # Scan and install a specific package
  snapem run dev              # Run 'npm run dev' in a container
  snapem exec node index.js   # Execute a command in a container
  snapem scan                 # Run security scan without installing`,
	SilenceUsage:  true,
	SilenceErrors: true,
}

// Execute runs the root command
func Execute() error {
	return rootCmd.Execute()
}

func init() {
	cobra.OnInitialize(initConfig)

	// Global flags
	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default: ./snapem.yaml or ~/.config/snapem/config.yaml)")
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "enable verbose output")
	rootCmd.PersistentFlags().BoolVarP(&quiet, "quiet", "q", false, "suppress non-error output")
	rootCmd.PersistentFlags().BoolVar(&noColor, "no-color", false, "disable colored output")
	rootCmd.PersistentFlags().StringVar(&pkgMgr, "package-manager", "", "force package manager (npm or bun)")

	// Bind flags to viper
	viper.BindPFlag("ui.verbose", rootCmd.PersistentFlags().Lookup("verbose"))
	viper.BindPFlag("ui.quiet", rootCmd.PersistentFlags().Lookup("quiet"))
	viper.BindPFlag("ui.color", rootCmd.PersistentFlags().Lookup("no-color"))
	viper.BindPFlag("package_manager.preferred", rootCmd.PersistentFlags().Lookup("package-manager"))
}

func initConfig() {
	if cfgFile != "" {
		// Use config file from the flag
		viper.SetConfigFile(cfgFile)
	} else {
		// Search for config in current directory and home config
		viper.SetConfigName("snapem")
		viper.SetConfigType("yaml")
		viper.AddConfigPath(".")
		viper.AddConfigPath("$HOME/.config/snapem")
	}

	// Environment variables
	viper.SetEnvPrefix("SNAPEM")
	viper.AutomaticEnv()

	// Read config file (ignore if not found)
	if err := viper.ReadInConfig(); err == nil {
		if verbose {
			fmt.Fprintln(os.Stderr, "Using config file:", viper.ConfigFileUsed())
		}
	}

	// Set defaults
	setDefaults()
}

func setDefaults() {
	// Package manager defaults
	viper.SetDefault("package_manager.preferred", "auto")

	// Scanning defaults
	viper.SetDefault("scanning.enabled", true)
	viper.SetDefault("scanning.socket.enabled", true)
	viper.SetDefault("scanning.socket.timeout", "30s")
	viper.SetDefault("scanning.osv.enabled", true)
	viper.SetDefault("scanning.osv.timeout", "30s")
	viper.SetDefault("scanning.cache.enabled", true)
	viper.SetDefault("scanning.cache.ttl", "24h")
	viper.SetDefault("scanning.policy.malware", "block")
	viper.SetDefault("scanning.policy.cve.critical", "block")
	viper.SetDefault("scanning.policy.cve.high", "block")
	viper.SetDefault("scanning.policy.cve.medium", "block")
	viper.SetDefault("scanning.policy.cve.low", "warn")
	viper.SetDefault("scanning.policy.allow_override", false)

	// Container defaults
	viper.SetDefault("container.enabled", true)
	viper.SetDefault("container.image.npm", "node:lts-slim")
	viper.SetDefault("container.image.bun", "oven/bun:latest")
	viper.SetDefault("container.network", "host")

	// UI defaults
	viper.SetDefault("ui.color", true)
	viper.SetDefault("ui.progress", true)
	viper.SetDefault("ui.verbose", false)
	viper.SetDefault("ui.quiet", false)
}
