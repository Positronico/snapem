package cli

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/positronico/snapem/internal/config"
	"github.com/positronico/snapem/internal/container"
	"github.com/positronico/snapem/internal/errors"
	"github.com/positronico/snapem/internal/manifest"
	"github.com/positronico/snapem/internal/pkgmanager"
	"github.com/positronico/snapem/internal/ui"
)

var (
	runNoNetwork    bool
	runNoPorts      bool
	runPublishPorts []string
)

var runCmd = &cobra.Command{
	Use:   "run <script> [args...]",
	Short: "Run a package.json script in a container",
	Long: `Runs a script defined in package.json inside an isolated container.

The script runs with the project directory mounted at /app.
By default, the container has host network access for dev servers.

Port auto-detection: For dev/start/serve scripts, snapem automatically
detects and publishes the framework's default port (e.g., 3000 for Next.js,
5173 for Vite). Use -p to override or --no-ports to disable.

Examples:
  snapem run dev                 # Auto-detects and exposes port
  snapem run dev -p 8080         # Override with custom port
  snapem run dev --no-ports      # Disable auto port detection
  snapem run build               # No port needed for build
  snapem run test -- --watch     # Run 'npm run test -- --watch'`,
	Args: cobra.MinimumNArgs(1),
	RunE: runRun,
}

func init() {
	runCmd.Flags().BoolVar(&runNoNetwork, "no-network", false, "disable network access in container")
	runCmd.Flags().BoolVar(&runNoPorts, "no-ports", false, "disable automatic port detection")
	runCmd.Flags().BoolVar(&noContainer, "no-container", false, "run without container isolation")
	runCmd.Flags().StringArrayVarP(&runPublishPorts, "publish", "p", nil, "publish container port to host (e.g., -p 3000 or -p 8080:80)")

	rootCmd.AddCommand(runCmd)
}

func runRun(cmd *cobra.Command, args []string) error {
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

	// Parse script and args
	script := args[0]
	scriptArgs := args[1:]

	// Build container options
	runCommand := mgr.RunCommand(script, scriptArgs)
	networkMode := container.NetworkHost
	if runNoNetwork {
		networkMode = container.NetworkNone
	} else if cfg.Container.Network == "none" {
		networkMode = container.NetworkNone
	}

	opts := pkgmanager.BuildContainerOptions(mgr, projectDir, networkMode, runCommand)

	// Port handling: explicit -p flags take precedence
	if len(runPublishPorts) > 0 {
		for _, portSpec := range runPublishPorts {
			parts := strings.SplitN(portSpec, ":", 2)
			var pm container.PortMapping
			if len(parts) == 2 {
				pm = container.PortMapping{HostPort: parts[0], ContainerPort: parts[1]}
			} else {
				pm = container.PortMapping{HostPort: parts[0], ContainerPort: parts[0]}
			}
			opts.Ports = append(opts.Ports, pm)
		}
	} else if !runNoPorts && isDevScript(script) {
		// Auto-detect port for dev-like scripts
		if detectedPort := parser.DetectPort(); detectedPort > 0 {
			portStr := fmt.Sprintf("%d", detectedPort)
			opts.Ports = append(opts.Ports, container.PortMapping{
				HostPort:      portStr,
				ContainerPort: portStr,
			})
			display.Info(fmt.Sprintf("Auto-detected port %d (use -p to override, --no-ports to disable)", detectedPort))
		}
	}

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
	} else {
		display.Warning("Running without container isolation (--no-container)")
		display.Info(fmt.Sprintf("Command: %s run %s %v", mgr.Name(), script, scriptArgs))
	}

	return nil
}

// isDevScript returns true if the script name suggests a development server
func isDevScript(script string) bool {
	devScripts := []string{"dev", "start", "serve", "develop", "server"}
	for _, s := range devScripts {
		if script == s {
			return true
		}
	}
	return false
}
