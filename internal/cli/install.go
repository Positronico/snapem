package cli

import (
	"context"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/positronico/snapem/internal/config"
	"github.com/positronico/snapem/internal/container"
	"github.com/positronico/snapem/internal/errors"
	"github.com/positronico/snapem/internal/manifest"
	"github.com/positronico/snapem/internal/pkgmanager"
	"github.com/positronico/snapem/internal/scanner"
	"github.com/positronico/snapem/internal/ui"
)

var (
	skipScan    bool
	force       bool
	noContainer bool
	saveDev     bool
)

var installCmd = &cobra.Command{
	Use:   "install [packages...]",
	Short: "Install dependencies with security scanning",
	Long: `Scans dependencies for vulnerabilities and malware before installing
in an isolated container.

If no packages are specified, installs all dependencies from package.json.

Examples:
  snapem install              # Install all dependencies
  snapem install lodash       # Install lodash
  snapem install -D jest      # Install jest as dev dependency
  snapem install --skip-scan  # Install without scanning`,
	RunE: runInstall,
}

func init() {
	installCmd.Flags().BoolVar(&skipScan, "skip-scan", false, "skip security scanning")
	installCmd.Flags().BoolVar(&force, "force", false, "override security blocks")
	installCmd.Flags().BoolVar(&noContainer, "no-container", false, "run without container isolation")
	installCmd.Flags().BoolVarP(&saveDev, "save-dev", "D", false, "install as devDependency")

	rootCmd.AddCommand(installCmd)
}

func runInstall(cmd *cobra.Command, args []string) error {
	ctx := cmd.Context()

	// Load configuration
	cfg, err := config.Load()
	if err != nil {
		return errors.ConfigError(err.Error())
	}

	// Initialize UI
	display := ui.New(cfg.UI.Verbose, cfg.UI.Quiet, cfg.UI.Color && !noColor)

	// Get current directory
	projectDir, err := os.Getwd()
	if err != nil {
		display.Error("Failed to get current directory")
		return errors.New(errors.ExitGeneralError, "failed to get current directory")
	}

	// Check for package.json
	parser := manifest.NewParser(projectDir)
	if !parser.HasManifest() {
		display.Error("No package.json found in current directory")
		return errors.ManifestError("no package.json found", nil)
	}

	// Detect package manager
	mgr := pkgmanager.Detect(projectDir, pkgMgr, cfg.Container.Image)
	display.Verbose(fmt.Sprintf("Using package manager: %s", mgr.Name()))

	// Run security scan (unless skipped)
	if cfg.Scanning.Enabled && !skipScan {
		if err := runSecurityScan(ctx, cfg, display, parser, args); err != nil {
			if !force && !cfg.Scanning.Policy.AllowOverride {
				return err
			}
			// If force flag or override allowed, prompt user
			if cfg.Scanning.Policy.AllowOverride && !force {
				if !display.PromptForce() {
					return errors.UserAbortError()
				}
			}
			display.Warning("Proceeding despite security warnings...")
		}
	}

	// Build container options
	installCmd := mgr.InstallCommand(args, saveDev)
	networkMode := container.NetworkMode(cfg.Container.Network)
	opts := pkgmanager.BuildContainerOptions(mgr, projectDir, networkMode, installCmd)

	// Run in container (unless disabled)
	if cfg.Container.Enabled && !noContainer {
		runtime := container.NewAppleRuntime()
		if !runtime.IsAvailable() {
			display.Error("Apple container runtime not available")
			display.Info("Install with: brew install --cask container")
			return errors.ContainerNotAvailableError()
		}

		display.ContainerHeader(runtime.CommandString(opts))

		if err := runtime.Run(ctx, opts); err != nil {
			return err
		}

		display.Success("Installation complete")
	} else {
		// Run without container - just warn
		display.Warning("Running without container isolation (--no-container)")
		display.Info(fmt.Sprintf("Command: %s %v", mgr.Name(), installCmd))
		display.Info("For security, consider using container isolation")
	}

	return nil
}

func runSecurityScan(ctx context.Context, cfg *config.Config, display *ui.UI, parser *manifest.Parser, newPackages []string) error {
	display.ScanningHeader()

	// Check for Socket API token
	if !cfg.HasSocketToken() && cfg.Scanning.Socket.Enabled {
		if !display.PromptUnsecure() {
			return errors.UserAbortError()
		}
		cfg.Scanning.Socket.Enabled = false
	}

	// Get packages to scan
	packages, err := parser.GetDependencies(true)
	if err != nil {
		display.Warning("Could not parse dependencies, scanning new packages only")
		packages = []manifest.Package{}
	}

	// Add new packages being installed (parse name@version format)
	for _, pkg := range newPackages {
		name, version := parsePackageArg(pkg)
		packages = append(packages, manifest.Package{
			Name:      name,
			Version:   version,
			Ecosystem: "npm",
		})
	}

	if len(packages) == 0 {
		display.Info("No packages to scan")
		return nil
	}

	display.Verbose(fmt.Sprintf("Scanning %d packages...", len(packages)))

	// Create orchestrator and scan
	orch := scanner.NewOrchestrator(cfg)

	scanners := orch.AvailableScanners()
	if len(scanners) == 0 {
		display.Warning("No scanners available")
		return nil
	}

	result, err := orch.ScanWithProgress(ctx, packages, func(name string, done bool) {
		if done {
			display.ScannerStatus(name, "complete", false)
		} else {
			display.ScannerStatus(name, "scanning...", true)
		}
	})

	if err != nil {
		return errors.ScannerError("security", err)
	}

	// Display results
	return evaluateScanResults(cfg, display, result)
}

func evaluateScanResults(cfg *config.Config, display *ui.UI, result *scanner.AggregatedResult) error {
	if result.TotalFindings == 0 {
		display.Success("No security issues found")
		return nil
	}

	display.Print(fmt.Sprintf("\nFound %d issue(s):", result.TotalFindings))

	var hasBlockingIssue bool

	// Display malware findings
	malwareFindings := result.MalwareFindings()
	if len(malwareFindings) > 0 {
		display.Print("")
		display.Error("Malware/Supply Chain Threats:")
		for _, f := range malwareFindings {
			display.ThreatFound(string(f.Severity), f.Package+"@"+f.Version, f.Description)
		}
		if cfg.ShouldBlock(cfg.Scanning.Policy.Malware) {
			hasBlockingIssue = true
		}
	}

	// Display CVE findings by severity
	cveFindings := result.CVEFindings()
	if len(cveFindings) > 0 {
		display.Print("")
		display.Warning("Vulnerabilities (CVEs):")

		// Group by severity
		severities := []scanner.Severity{
			scanner.SeverityCritical,
			scanner.SeverityHigh,
			scanner.SeverityMedium,
			scanner.SeverityLow,
		}

		for _, sev := range severities {
			count := 0
			for _, f := range cveFindings {
				if f.Severity == sev {
					count++
					display.ThreatFound(string(sev), f.Package+"@"+f.Version, f.Title)

					// Check if this severity blocks
					action := cfg.GetCVEAction(string(sev))
					if cfg.ShouldBlock(action) {
						hasBlockingIssue = true
					}
				}
			}
		}
	}

	if hasBlockingIssue {
		display.Print("")
		display.Error("Security scan blocked installation due to detected threats")
		return errors.SecurityBlockError("security threats detected")
	}

	return nil
}

// parsePackageArg parses a package argument like "lodash@4.17.20" into name and version
func parsePackageArg(pkg string) (name, version string) {
	// Handle scoped packages like @types/node@1.0.0
	if len(pkg) > 0 && pkg[0] == '@' {
		// Find the second @ (version separator)
		rest := pkg[1:]
		idx := -1
		for i := len(rest) - 1; i >= 0; i-- {
			if rest[i] == '@' {
				idx = i + 1 // +1 because we skipped the first @
				break
			}
		}
		if idx > 0 {
			return pkg[:idx], pkg[idx+1:]
		}
		return pkg, "latest"
	}

	// Regular package like lodash@4.17.20
	for i := len(pkg) - 1; i >= 0; i-- {
		if pkg[i] == '@' {
			return pkg[:i], pkg[i+1:]
		}
	}
	return pkg, "latest"
}
