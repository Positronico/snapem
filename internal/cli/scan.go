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
	scanInclude string
)

var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Run security scan on dependencies",
	Long: `Scans all dependencies in package.json and package-lock.json for
known vulnerabilities (CVEs) and malicious packages.

Uses Socket.dev for malware detection and Google OSV for CVE lookup.

Examples:
  snapem scan                # Scan all dependencies
  snapem scan --json         # Output results as JSON
  snapem scan --include dev  # Include devDependencies`,
	RunE: runScan,
}

func init() {
	scanCmd.Flags().BoolVar(&scanJSON, "json", false, "output results as JSON")
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

	if !scanJSON {
		display.ScanningHeader()
	}

	// Check for Socket API token
	if !cfg.HasSocketToken() && cfg.Scanning.Socket.Enabled {
		if !scanJSON {
			if !display.PromptUnsecure() {
				return errors.UserAbortError()
			}
		}
		cfg.Scanning.Socket.Enabled = false
	}

	// Determine which dependencies to include
	includeDev := scanInclude == "all" || scanInclude == "dev"

	// Get packages to scan
	packages, err := parser.GetDependencies(includeDev)
	if err != nil {
		return errors.ManifestError("failed to parse dependencies", err)
	}

	if len(packages) == 0 {
		if scanJSON {
			outputJSONResult(&scanner.AggregatedResult{})
		} else {
			display.Info("No packages to scan")
		}
		return nil
	}

	if !scanJSON {
		display.Verbose(fmt.Sprintf("Scanning %d packages...", len(packages)))
	}

	// Create orchestrator and scan
	orch := scanner.NewOrchestrator(cfg)

	scanners := orch.AvailableScanners()
	if len(scanners) == 0 {
		if !scanJSON {
			display.Warning("No scanners available")
		}
		return nil
	}

	var result *scanner.AggregatedResult
	if scanJSON {
		result, err = orch.Scan(ctx, packages)
	} else {
		result, err = orch.ScanWithProgress(ctx, packages, func(name string, done bool) {
			if done {
				display.ScannerStatus(name, "complete", false)
			} else {
				display.ScannerStatus(name, "scanning...", true)
			}
		})
	}

	if err != nil {
		return errors.ScannerError("security", err)
	}

	// Output results
	if scanJSON {
		return outputJSONResult(result)
	}

	return outputTextResult(cfg, display, result)
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

	// Display malware findings
	malwareFindings := result.MalwareFindings()
	if len(malwareFindings) > 0 {
		display.Print("")
		display.Error("Malware/Supply Chain Threats:")
		for _, f := range malwareFindings {
			display.ThreatFound(string(f.Severity), f.Package+"@"+f.Version, f.Description)
		}
	}

	// Display CVE findings by severity
	cveFindings := result.CVEFindings()
	if len(cveFindings) > 0 {
		display.Print("")
		display.Warning("Vulnerabilities (CVEs):")

		severities := []scanner.Severity{
			scanner.SeverityCritical,
			scanner.SeverityHigh,
			scanner.SeverityMedium,
			scanner.SeverityLow,
		}

		for _, sev := range severities {
			for _, f := range cveFindings {
				if f.Severity == sev {
					desc := f.Title
					if f.ID != "" {
						desc = f.ID + ": " + f.Title
					}
					display.ThreatFound(string(sev), f.Package+"@"+f.Version, desc)
				}
			}
		}
	}

	// Return error if blocking issues
	if result.HasMalware && cfg.ShouldBlock(cfg.Scanning.Policy.Malware) {
		return errors.SecurityBlockError("malware detected")
	}
	if result.HasCritical && cfg.ShouldBlock(cfg.GetCVEAction("critical")) {
		return errors.SecurityBlockError("critical vulnerabilities detected")
	}

	return nil
}
