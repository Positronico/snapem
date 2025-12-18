package cli

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/positronico/snapem/internal/config"
	"github.com/positronico/snapem/internal/container"
	"github.com/positronico/snapem/internal/errors"
	"github.com/positronico/snapem/internal/pkgmanager"
	"github.com/positronico/snapem/internal/ui"
)

var (
	execNoNetwork bool
	execImage     string
)

var execCmd = &cobra.Command{
	Use:   "exec <command> [args...]",
	Short: "Execute a command in a container",
	Long: `Executes an arbitrary command inside an isolated container.

The project directory is mounted at /app, and /app is the working directory.
This is useful for running node, npx, or any other command in isolation.

Examples:
  snapem exec node index.js       # Run node directly
  snapem exec npx prisma migrate  # Run npx command
  snapem exec sh -c "ls -la"      # Run shell command
  snapem exec --no-network curl   # Run without network`,
	Args: cobra.MinimumNArgs(1),
	RunE: runExec,
}

func init() {
	execCmd.Flags().BoolVar(&execNoNetwork, "no-network", false, "disable network access in container")
	execCmd.Flags().BoolVar(&noContainer, "no-container", false, "run without container isolation")
	execCmd.Flags().StringVar(&execImage, "image", "", "custom container image")

	rootCmd.AddCommand(execCmd)
}

func runExec(cmd *cobra.Command, args []string) error {
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

	// Detect package manager for default image
	mgr := pkgmanager.Detect(projectDir, pkgMgr, cfg.Container.Image)

	// Use custom image if specified
	image := mgr.Image()
	if execImage != "" {
		image = execImage
	}

	// Build container options
	networkMode := container.NetworkHost
	if execNoNetwork {
		networkMode = container.NetworkNone
	} else if cfg.Container.Network == "none" {
		networkMode = container.NetworkNone
	}

	opts := &container.RunOptions{
		Image:       image,
		Command:     args,
		WorkDir:     "/app",
		Network:     networkMode,
		Interactive: true,
		TTY:         true,
		Remove:      true,
		Volumes: []container.VolumeMount{
			{
				HostPath:      projectDir,
				ContainerPath: "/app",
				ReadOnly:      false,
			},
		},
		Environment: make(map[string]string),
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
		display.Info(fmt.Sprintf("Command: %v", args))
	}

	return nil
}
