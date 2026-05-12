package cli

import (
	"context"
	"fmt"
	"os"
	"sort"
	"strings"

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
	upgradeYes        bool
	upgradeDryRun     bool
	upgradeAllowMajor bool
)

var upgradeCmd = &cobra.Command{
	Use:   "upgrade",
	Short: "Apply remediations from the most recent scan",
	Long: `Scans the current dependency tree, groups findings by package, and proposes
a version upgrade for each vulnerable direct dependency that lands on the
lowest version resolving every finding for that package.

By default, upgrades stay within the current major version — pass
--major to allow major-version bumps when no in-major fix exists.

Transitive dependencies (packages not in your package.json directly)
are reported but not auto-fixed. Upgrade the parent dependency, run
`+"`npm dedupe`"+`, or pin via npm overrides / pnpm resolutions.

Examples:
  snapem upgrade               # propose + confirm + apply
  snapem upgrade --dry-run     # propose + exit
  snapem upgrade --yes         # apply without confirmation
  snapem upgrade --major       # allow cross-major upgrades when needed`,
	RunE: runUpgrade,
}

func init() {
	upgradeCmd.Flags().BoolVarP(&upgradeYes, "yes", "y", false, "apply the upgrade plan without confirmation")
	upgradeCmd.Flags().BoolVar(&upgradeDryRun, "dry-run", false, "print the plan and exit without applying")
	upgradeCmd.Flags().BoolVar(&upgradeAllowMajor, "major", false, "allow major-version bumps when no in-major fix exists")
	rootCmd.AddCommand(upgradeCmd)
}

func runUpgrade(cmd *cobra.Command, args []string) error {
	ctx := cmd.Context()

	cfg, err := config.Load()
	if err != nil {
		return errors.ConfigError(err.Error())
	}
	display := ui.New(cfg.UI.Verbose, cfg.UI.Quiet, useColor(cfg.UI.Color, noColor))

	projectDir, err := os.Getwd()
	if err != nil {
		return errors.New(errors.ExitGeneralError, "failed to get current directory")
	}

	parser := manifest.NewParser(projectDir)
	if !parser.HasManifest() {
		display.Error("No package.json found in current directory")
		return errors.ManifestError("no package.json found", nil)
	}

	plan, err := computeUpgradePlan(ctx, cfg, display, parser)
	if err != nil {
		return err
	}

	renderUpgradePlan(display, plan)

	if plan.empty() {
		return nil
	}

	if upgradeDryRun {
		display.Info("Dry run — not applying changes. Re-run without --dry-run to apply.")
		return nil
	}

	if !upgradeYes {
		if !display.PromptConfirm("Apply this upgrade plan?", true) {
			return errors.UserAbortError()
		}
	}

	return applyUpgrades(ctx, cfg, display, projectDir, plan.upgrades)
}

// upgradePlan is the structured result of analyzing findings vs. the
// project's direct dependency list.
type upgradePlan struct {
	upgrades       []packageUpgrade // direct deps we can move
	unfixableInMaj []packageUpgrade // direct deps with no in-major fix
	transitive     []packageUpgrade // findings on packages not in package.json
	totalFindings  int
}

func (p *upgradePlan) empty() bool {
	return p.totalFindings == 0
}

type packageUpgrade struct {
	Name         string
	CurrentVer   string
	TargetVer    string   // empty when unfixable / transitive
	FindingCount int
	IDs          []string // GHSA / CVE IDs being addressed
	Reason       string   // why we couldn't fix (only for unfixable / transitive)
}

func computeUpgradePlan(ctx context.Context, cfg *config.Config, display *ui.UI, parser *manifest.Parser) (*upgradePlan, error) {
	directDeps, err := parser.GetDirectDependencies(true)
	if err != nil {
		return nil, errors.ManifestError("failed to read package.json", err)
	}
	directIndex := make(map[string]string, len(directDeps))
	for _, d := range directDeps {
		directIndex[d.Name] = d.Version
	}

	// Honor the SOCKET_API_TOKEN-absent prompt path the same way scan does.
	if !cfg.HasSocketToken() && cfg.Scanning.Socket.Enabled {
		if !display.PromptUnsecure() {
			return nil, errors.UserAbortError()
		}
		cfg.Scanning.Socket.Enabled = false
	}

	packages, notes, err := parser.GetDependenciesWithNotes(true)
	if err != nil {
		return nil, errors.ManifestError("failed to parse dependencies", err)
	}
	for _, n := range notes {
		display.Warning(n)
	}
	if len(packages) == 0 {
		return &upgradePlan{}, nil
	}

	display.ScanningHeader()
	orch := scanner.NewOrchestrator(cfg)
	if len(orch.AvailableScanners()) == 0 {
		display.Warning("No scanners available")
		return &upgradePlan{}, nil
	}
	result, err := orch.ScanWithProgress(ctx, packages, func(name string, done bool) {
		if done {
			display.ScannerStatus(name, "complete", false)
		} else {
			display.ScannerStatus(name, "scanning...", true)
		}
	})
	if err != nil {
		return nil, errors.ScannerError("security", err)
	}

	return buildPlan(result.AllFindings(), directIndex), nil
}

// buildPlan groups findings by package and decides per-package whether
// they're directly upgradable, unfixable in major, or transitive.
func buildPlan(findings []scanner.Finding, directIndex map[string]string) *upgradePlan {
	type key struct{ name, version string }
	byPkg := make(map[key][]scanner.Finding)
	for _, f := range findings {
		k := key{f.Package, f.Version}
		byPkg[k] = append(byPkg[k], f)
	}

	plan := &upgradePlan{totalFindings: len(findings)}
	for k, fs := range byPkg {
		ids := make([]string, 0, len(fs))
		candidates := make([]fixCandidate, 0, len(fs))
		for _, f := range fs {
			if f.ID != "" {
				ids = append(ids, f.ID)
			}
			candidates = append(candidates, fixCandidate{FixedVersions: f.FixedVersions})
		}
		sort.Strings(ids)

		pu := packageUpgrade{
			Name:         k.name,
			CurrentVer:   k.version,
			FindingCount: len(fs),
			IDs:          ids,
		}

		// Direct vs transitive. We compare against the version declared
		// in package.json — if it matches (or it's a name match — declared
		// version may be a range like ^4.0.0 while the installed is 4.17.20),
		// treat as direct.
		if _, isDirect := directIndex[k.name]; !isDirect {
			pu.Reason = "transitive dependency"
			plan.transitive = append(plan.transitive, pu)
			continue
		}

		target, ok := pickUpgradeTarget(k.version, candidates, upgradeAllowMajor)
		if !ok {
			if upgradeAllowMajor {
				pu.Reason = "no published fix"
			} else {
				pu.Reason = "no fix in current major (try --major)"
			}
			plan.unfixableInMaj = append(plan.unfixableInMaj, pu)
			continue
		}
		pu.TargetVer = target
		plan.upgrades = append(plan.upgrades, pu)
	}

	// Deterministic ordering — useful for the rendered plan and for tests.
	sort.Slice(plan.upgrades, func(i, j int) bool { return plan.upgrades[i].Name < plan.upgrades[j].Name })
	sort.Slice(plan.unfixableInMaj, func(i, j int) bool { return plan.unfixableInMaj[i].Name < plan.unfixableInMaj[j].Name })
	sort.Slice(plan.transitive, func(i, j int) bool { return plan.transitive[i].Name < plan.transitive[j].Name })
	return plan
}

func renderUpgradePlan(display *ui.UI, plan *upgradePlan) {
	display.Print("")
	if plan.empty() {
		display.Success("No findings — nothing to upgrade.")
		return
	}

	if len(plan.upgrades) > 0 {
		display.Print("Upgrade plan:")
		for _, u := range plan.upgrades {
			display.Print(fmt.Sprintf("  %s %s → %s  (%d finding%s)",
				u.Name, u.CurrentVer, u.TargetVer, u.FindingCount, plural(u.FindingCount)))
		}
	}
	if len(plan.unfixableInMaj) > 0 {
		display.Print("")
		display.Warning("Direct dependencies with no auto-fixable upgrade:")
		for _, u := range plan.unfixableInMaj {
			display.Print(fmt.Sprintf("  %s@%s — %s (%d finding%s)",
				u.Name, u.CurrentVer, u.Reason, u.FindingCount, plural(u.FindingCount)))
		}
	}
	if len(plan.transitive) > 0 {
		display.Print("")
		display.Info("Transitive findings (upgrade the parent, run `npm dedupe`, or pin via overrides):")
		for _, u := range plan.transitive {
			display.Print(fmt.Sprintf("  %s@%s (%d finding%s)",
				u.Name, u.CurrentVer, u.FindingCount, plural(u.FindingCount)))
		}
	}
	display.Print("")
}

func plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}

// applyUpgrades shells the install through the container, exactly as
// `snapem install pkg1@ver1 pkg2@ver2 ...` would. We pin versions so
// the next scan can verify the fix actually landed.
func applyUpgrades(ctx context.Context, cfg *config.Config, display *ui.UI, projectDir string, upgrades []packageUpgrade) error {
	if len(upgrades) == 0 {
		return nil
	}

	mgr := pkgmanager.Detect(projectDir, pkgMgr, cfg.Container.Image)

	specs := make([]string, 0, len(upgrades))
	for _, u := range upgrades {
		specs = append(specs, u.Name+"@"+u.TargetVer)
	}

	installArgs := mgr.InstallCommand(specs, false)
	networkMode := container.NetworkMode(cfg.Container.Network)
	opts := pkgmanager.BuildContainerOptions(mgr, projectDir, networkMode, installArgs)

	runtime := container.NewAppleRuntime()
	if !runtime.IsAvailable() {
		display.Error("Apple container runtime not available")
		display.Info("Install with: brew install container")
		return errors.ContainerNotAvailableError()
	}

	display.Info(fmt.Sprintf("Applying: %s install %s", mgr.Name(), strings.Join(specs, " ")))
	display.ContainerHeader(runtime.CommandString(opts))

	if err := runtime.Run(ctx, opts); err != nil {
		return err
	}
	display.Success("Upgrade applied. Run `snapem scan` to verify the fix landed.")
	return nil
}
