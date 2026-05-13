package cli

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/positronico/snapem/internal/config"
	"github.com/positronico/snapem/internal/errors"
	"github.com/positronico/snapem/internal/manifest"
	"github.com/positronico/snapem/internal/scanner"
	"github.com/positronico/snapem/internal/ui"
)

var (
	scanJSON    bool
	scanFormat  string
	scanInclude string
)

var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Run security scan on dependencies",
	Long: `Scans all dependencies in package.json and package-lock.json for
known vulnerabilities (CVEs) and malicious packages.

Uses Socket.dev for malware detection and Google OSV for CVE lookup.

Examples:
  snapem scan                       # Scan all dependencies (text output)
  snapem scan --format json         # JSON output for scripting
  snapem scan --format sarif        # SARIF v2.1.0 for CI integration
  snapem scan --include dev         # Include devDependencies`,
	PreRunE: func(cmd *cobra.Command, args []string) error {
		// --json is the legacy shorthand for --format json; honor it so
		// existing scripts keep working but normalize to scanFormat.
		if scanJSON && scanFormat == "text" {
			scanFormat = "json"
		}
		if err := validateEnum("format", scanFormat, []string{"text", "json", "sarif"}); err != nil {
			return err
		}
		return validateEnum("include", scanInclude, []string{"all", "prod", "dev"})
	},
	RunE: runScan,
}

func init() {
	scanCmd.Flags().BoolVar(&scanJSON, "json", false, "shorthand for --format json (kept for backward compat)")
	scanCmd.Flags().StringVar(&scanFormat, "format", "text", "output format: text, json, sarif")
	scanCmd.Flags().StringVar(&scanInclude, "include", "all", "which dependencies to scan: all, prod, dev")

	rootCmd.AddCommand(scanCmd)
}

func runScan(cmd *cobra.Command, args []string) error {
	ctx := cmd.Context()

	// Load configuration
	cfg, err := config.Load()
	if err != nil {
		return errors.ConfigError(err.Error())
	}

	// Initialize UI
	display := ui.New(cfg.UI.Verbose, cfg.UI.Quiet, useColor(cfg.UI.Color, noColor))

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

	// "Machine" output suppresses the human progress UI so consumers get
	// pure JSON / SARIF on stdout.
	machineOutput := scanFormat != "text"

	if !machineOutput {
		display.ScanningHeader()
	}

	// Check for Socket API token
	if !cfg.HasSocketToken() && cfg.Scanning.Socket.Enabled {
		if !machineOutput {
			if !display.PromptUnsecure() {
				return errors.UserAbortError()
			}
		}
		cfg.Scanning.Socket.Enabled = false
	}

	// Determine which dependencies to include
	includeDev := scanInclude == "all" || scanInclude == "dev"

	// Get packages to scan
	packages, notes, err := parser.GetDependenciesWithNotes(includeDev)
	if err != nil {
		return errors.ManifestError("failed to parse dependencies", err)
	}
	if !machineOutput {
		for _, n := range notes {
			display.Warning(n)
		}
	}

	if len(packages) == 0 {
		if machineOutput {
			return emitMachineResult(scanFormat, &scanner.AggregatedResult{})
		}
		display.Info("No packages to scan")
		return nil
	}

	if !machineOutput {
		display.Verbose(fmt.Sprintf("Scanning %d packages...", len(packages)))
	}

	// Create orchestrator and scan
	orch := scanner.NewOrchestrator(cfg)

	scanners := orch.AvailableScanners()
	if len(scanners) == 0 {
		if !machineOutput {
			display.Warning("No scanners available")
		}
		return nil
	}

	var result *scanner.AggregatedResult
	if machineOutput {
		result, err = orch.Scan(ctx, packages)
	} else {
		prog := display.NewProgress()
		result, err = orch.ScanWithProgress(ctx, packages, func(name string, done bool) {
			if done {
				prog.Done(name)
			} else {
				prog.Add(name)
			}
		})
		prog.Stop()
	}

	if err != nil {
		return errors.ScannerError("security", err)
	}

	// Output results
	if machineOutput {
		return emitMachineResult(scanFormat, result)
	}

	return outputTextResult(cfg, display, result)
}

// emitMachineResult dispatches to the chosen non-text formatter.
func emitMachineResult(format string, result *scanner.AggregatedResult) error {
	switch format {
	case "json":
		return outputJSONResult(result)
	case "sarif":
		return emitSARIF(os.Stdout, result)
	}
	return errors.New(errors.ExitConfigError, "unknown output format: "+format)
}

func outputJSONResult(result *scanner.AggregatedResult) error {
	output := struct {
		Packages int               `json:"packages_scanned"`
		Findings []scanner.Finding `json:"findings"`
		Summary  struct {
			Total    int `json:"total"`
			Critical int `json:"critical"`
			High     int `json:"high"`
			Medium   int `json:"medium"`
			Low      int `json:"low"`
			Malware  int `json:"malware"`
		} `json:"summary"`
	}{
		Packages: result.TotalPackages,
		Findings: result.AllFindings(),
	}

	output.Summary.Total = result.TotalFindings
	output.Summary.Critical = result.CountBySeverity(scanner.SeverityCritical)
	output.Summary.High = result.CountBySeverity(scanner.SeverityHigh)
	output.Summary.Medium = result.CountBySeverity(scanner.SeverityMedium)
	output.Summary.Low = result.CountBySeverity(scanner.SeverityLow)
	output.Summary.Malware = result.CountByType(scanner.FindingTypeMalware) + result.CountByType(scanner.FindingTypeTyposquat)

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(output)
}

func outputTextResult(cfg *config.Config, display *ui.UI, result *scanner.AggregatedResult) error {
	display.Print("")
	display.Print(fmt.Sprintf("Scanned %d packages in %s", result.TotalPackages, result.Duration.Round(1e6)))

	if result.TotalFindings == 0 {
		display.Success("No security issues found")
		return nil
	}

	display.Print(fmt.Sprintf("\nFound %d issue(s):", result.TotalFindings))

	// Summary counts
	critical := result.CountBySeverity(scanner.SeverityCritical)
	high := result.CountBySeverity(scanner.SeverityHigh)
	medium := result.CountBySeverity(scanner.SeverityMedium)
	low := result.CountBySeverity(scanner.SeverityLow)
	malware := result.CountByType(scanner.FindingTypeMalware) + result.CountByType(scanner.FindingTypeTyposquat)

	if malware > 0 {
		display.Error(fmt.Sprintf("  Malware/Supply Chain: %d", malware))
	}
	if critical > 0 {
		display.Error(fmt.Sprintf("  Critical: %d", critical))
	}
	if high > 0 {
		display.Warning(fmt.Sprintf("  High: %d", high))
	}
	if medium > 0 {
		display.Info(fmt.Sprintf("  Medium: %d", medium))
	}
	if low > 0 {
		display.Verbose(fmt.Sprintf("  Low: %d", low))
	}

	// Render all findings grouped by package@version. The malware /
	// CVE distinction is implicit in the per-finding severity styling.
	renderFindingsGrouped(display, result.AllFindings())

	// Block based on the full policy table, not just malware + critical.
	if decision := scanner.EvaluatePolicy(cfg, result); decision.ShouldBlock {
		return errors.SecurityBlockError("security threats detected")
	}
	return nil
}
