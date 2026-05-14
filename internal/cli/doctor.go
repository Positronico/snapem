package cli

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/positronico/snapem/internal/config"
	"github.com/positronico/snapem/internal/errors"
	"github.com/positronico/snapem/internal/ui"
)

// checkStatus is the outcome of a single doctor check.
type checkStatus int

const (
	checkOK checkStatus = iota
	checkWarn
	checkFail
)

// checkResult is what a single check function returns.
type checkResult struct {
	Name    string
	Status  checkStatus
	Detail  string // one-line description, OK or otherwise
	Hint    string // optional remediation hint shown indented under the line
}

var doctorCmd = &cobra.Command{
	Use:   "doctor",
	Short: "Diagnose snapem's runtime environment",
	Long: `Inspects the runtime and prints a checklist:

  - Apple container CLI installed
  - container service running (apiserver up)
  - SOCKET_API_TOKEN configured (malware scanning needs it)
  - Cache directory writable
  - Reachability of every scanner upstream: api.osv.dev,
    api.socket.dev, api.deps.dev (Scorecard + metadata), and
    registry.npmjs.org (provenance)

Exits non-zero if any check fails; warnings (e.g. missing SOCKET_API_TOKEN)
do not cause a failing exit but are printed prominently. Run this first
when something feels broken before opening an issue.`,
	RunE: runDoctor,
}

func init() {
	rootCmd.AddCommand(doctorCmd)
}

func runDoctor(cmd *cobra.Command, args []string) error {
	cfg, err := config.Load()
	if err != nil {
		return errors.ConfigError(err.Error())
	}
	display := ui.New(cfg.UI.Verbose, false, useColor(cfg.UI.Color, noColor))

	ctx, cancel := context.WithTimeout(cmd.Context(), 10*time.Second)
	defer cancel()

	checks := []func(context.Context, *config.Config) checkResult{
		checkContainerCLI,
		checkContainerService,
		checkSocketToken,
		checkCacheDir,
		checkOSVReachable,
		checkSocketReachable,
		checkDepsdevReachable,
		checkNpmRegistryReachable,
	}

	display.Print("snapem doctor")
	display.Print("")

	var failed bool
	for _, check := range checks {
		r := check(ctx, cfg)
		renderCheck(display, r)
		if r.Status == checkFail {
			failed = true
		}
	}

	display.Print("")
	if failed {
		display.Error("One or more checks failed. Address the items marked ✗ above before running snapem install or scan.")
		return errors.New(errors.ExitGeneralError, "doctor: failing checks")
	}
	display.Success("All checks passed.")
	return nil
}

func renderCheck(display *ui.UI, r checkResult) {
	var marker string
	switch r.Status {
	case checkOK:
		display.Success(fmt.Sprintf("%s: %s", r.Name, r.Detail))
		marker = ""
	case checkWarn:
		display.Warning(fmt.Sprintf("%s: %s", r.Name, r.Detail))
		marker = "warn"
	case checkFail:
		display.Error(fmt.Sprintf("%s: %s", r.Name, r.Detail))
		marker = "fail"
	}
	if r.Hint != "" && marker != "" {
		display.Info("    " + r.Hint)
	}
}

func checkContainerCLI(_ context.Context, _ *config.Config) checkResult {
	r := checkResult{Name: "container CLI"}
	if path, err := exec.LookPath("container"); err == nil {
		r.Status = checkOK
		r.Detail = "installed at " + path
		return r
	}
	r.Status = checkFail
	r.Detail = "not on PATH"
	r.Hint = "Install with: brew install container"
	return r
}

func checkContainerService(ctx context.Context, _ *config.Config) checkResult {
	r := checkResult{Name: "container service"}
	if _, err := exec.LookPath("container"); err != nil {
		r.Status = checkWarn
		r.Detail = "skipped (container CLI not installed)"
		return r
	}
	out, err := exec.CommandContext(ctx, "container", "system", "status").CombinedOutput()
	if err == nil && strings.Contains(string(out), "apiserver is running") {
		r.Status = checkOK
		r.Detail = "apiserver running"
		return r
	}
	r.Status = checkFail
	r.Detail = "apiserver not running"
	r.Hint = "Start it with: container system start"
	return r
}

func checkSocketToken(_ context.Context, cfg *config.Config) checkResult {
	r := checkResult{Name: "SOCKET_API_TOKEN"}
	if cfg.HasSocketToken() {
		r.Status = checkOK
		r.Detail = "configured"
		return r
	}
	r.Status = checkWarn
	r.Detail = "not set — malware scanning will be disabled"
	r.Hint = "Get a free key at https://socket.dev and export SOCKET_API_TOKEN"
	return r
}

func checkCacheDir(_ context.Context, cfg *config.Config) checkResult {
	r := checkResult{Name: "cache directory"}
	dir := cfg.Scanning.Cache.Directory
	if dir == "" {
		r.Status = checkWarn
		r.Detail = "no path configured (caching disabled)"
		return r
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		r.Status = checkFail
		r.Detail = fmt.Sprintf("could not create %s: %v", dir, err)
		return r
	}
	probe := filepath.Join(dir, ".snapem-doctor-write-test")
	if err := os.WriteFile(probe, []byte("ok"), 0o644); err != nil {
		r.Status = checkFail
		r.Detail = fmt.Sprintf("not writable: %v", err)
		return r
	}
	_ = os.Remove(probe)
	r.Status = checkOK
	r.Detail = dir
	return r
}

func checkOSVReachable(ctx context.Context, _ *config.Config) checkResult {
	return checkHTTPReachable(ctx, "OSV API", "https://api.osv.dev/")
}

func checkSocketReachable(ctx context.Context, _ *config.Config) checkResult {
	return checkHTTPReachable(ctx, "Socket API", "https://api.socket.dev/")
}

// checkDepsdevReachable probes the upstream used by the Scorecard and
// metadata scanners. They both hit the same host so one probe covers
// two scanner dependencies.
func checkDepsdevReachable(ctx context.Context, _ *config.Config) checkResult {
	return checkHTTPReachable(ctx, "deps.dev API", "https://api.deps.dev/")
}

// checkNpmRegistryReachable probes the upstream used by the provenance
// scanner. The npm registry is so widely depended-on that an outage is
// usually obvious to the user already, but verifying here means a
// brand-new install gets a clear signal about what's failing.
func checkNpmRegistryReachable(ctx context.Context, _ *config.Config) checkResult {
	return checkHTTPReachable(ctx, "npm registry", "https://registry.npmjs.org/")
}

// checkHTTPReachable is a soft probe: any HTTP response (even 404) means
// the network path is up. Connection refused / DNS failure is the only
// real fail. Status codes ≥500 are treated as warn since the API is
// reachable but currently sick.
func checkHTTPReachable(ctx context.Context, name, url string) checkResult {
	r := checkResult{Name: name}
	req, _ := http.NewRequestWithContext(ctx, "HEAD", url, nil)
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		r.Status = checkFail
		r.Detail = fmt.Sprintf("unreachable: %v", err)
		r.Hint = "Check your network connection / corporate proxy settings"
		return r
	}
	defer resp.Body.Close()

	switch {
	case resp.StatusCode >= 500:
		r.Status = checkWarn
		r.Detail = fmt.Sprintf("reachable but degraded (HTTP %d)", resp.StatusCode)
	default:
		r.Status = checkOK
		r.Detail = fmt.Sprintf("reachable (HTTP %d)", resp.StatusCode)
	}
	return r
}
