package container

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/positronico/snapem/internal/errors"
	"golang.org/x/term"
)

const (
	containerBinary = "container"
)

// AppleRuntime implements the Runtime interface for Apple's container CLI
type AppleRuntime struct {
	binaryPath string
}

// NewAppleRuntime creates a new Apple container runtime
func NewAppleRuntime() *AppleRuntime {
	path, _ := exec.LookPath(containerBinary)
	return &AppleRuntime{
		binaryPath: path,
	}
}

// Name returns the runtime name
func (r *AppleRuntime) Name() string {
	return "Apple Container"
}

// IsAvailable checks if the Apple container CLI is installed
func (r *AppleRuntime) IsAvailable() bool {
	return r.binaryPath != ""
}

// Run executes a command in an Apple container
func (r *AppleRuntime) Run(ctx context.Context, opts *RunOptions) error {
	if !r.IsAvailable() {
		return errors.ContainerNotAvailableError()
	}

	// Check if stdin is a terminal - only use TTY flags if it is
	isTTY := term.IsTerminal(int(os.Stdin.Fd()))
	if !isTTY {
		opts.Interactive = false
		opts.TTY = false
	}

	args := r.buildArgs(opts)
	cmd := exec.CommandContext(ctx, r.binaryPath, args...)

	// Connect stdio
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	// Run the command
	if err := cmd.Run(); err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			// Return the exit code from the container
			return &errors.SnapemError{
				Code:    exitErr.ExitCode(),
				Message: "container command failed",
				Cause:   err,
			}
		}
		return errors.ContainerError(err)
	}

	return nil
}

// buildArgs constructs the container CLI arguments
func (r *AppleRuntime) buildArgs(opts *RunOptions) []string {
	args := []string{"run"}

	// Remove container after exit
	if opts.Remove {
		args = append(args, "--rm")
	}

	// Interactive mode
	if opts.Interactive {
		args = append(args, "--interactive")
	}

	// TTY allocation
	if opts.TTY {
		args = append(args, "--tty")
	}

	// Container name
	if opts.Name != "" {
		args = append(args, "--name", opts.Name)
	}

	// Volume mounts
	for _, v := range opts.Volumes {
		mount := fmt.Sprintf("%s:%s", v.HostPath, v.ContainerPath)
		if v.ReadOnly {
			mount += ":ro"
		}
		args = append(args, "--volume", mount)
	}

	// Working directory
	if opts.WorkDir != "" {
		args = append(args, "--workdir", opts.WorkDir)
	}

	// Port mappings (format: host-port:container-port)
	for _, p := range opts.Ports {
		args = append(args, "--publish", fmt.Sprintf("%s:%s", p.HostPort, p.ContainerPort))
	}

	// Network mode.
	//
	// container v0.9.0 takes --network <name> (a network *name*, NOT a
	// Docker-style mode). The default network is created automatically
	// as "default" when the container service starts. There is no
	// equivalent of "--network host" — every container runs in its own
	// vmnet namespace. We emit nothing for NetworkHost and rely on the
	// default network attachment.
	//
	// "none" is a recognized name that disables outbound network. Live
	// verified: DNS resolution inside a `--network none` container
	// returns EAI_AGAIN, so registry installs fail closed.
	switch opts.Network {
	case NetworkNone:
		args = append(args, "--network", "none")
	}

	// Environment variables
	for k, v := range opts.Environment {
		args = append(args, "--env", fmt.Sprintf("%s=%s", k, v))
	}

	// Image
	args = append(args, opts.Image)

	// Command
	args = append(args, opts.Command...)

	return args
}

// CommandString returns the full command as a string for display
func (r *AppleRuntime) CommandString(opts *RunOptions) string {
	args := r.buildArgs(opts)
	return containerBinary + " " + strings.Join(args, " ")
}

// BuildNpmOptions creates RunOptions for npm commands
func BuildNpmOptions(projectDir string, image string, network NetworkMode, args ...string) *RunOptions {
	opts := DefaultRunOptions()
	opts.Image = image
	opts.Network = network
	opts.Command = append([]string{"npm"}, args...)
	opts.Volumes = []VolumeMount{
		{
			HostPath:      projectDir,
			ContainerPath: "/app",
			ReadOnly:      false,
		},
	}
	return opts
}

// BuildBunOptions creates RunOptions for bun commands
func BuildBunOptions(projectDir string, image string, network NetworkMode, args ...string) *RunOptions {
	opts := DefaultRunOptions()
	opts.Image = image
	opts.Network = network
	opts.Command = append([]string{"bun"}, args...)
	opts.Volumes = []VolumeMount{
		{
			HostPath:      projectDir,
			ContainerPath: "/app",
			ReadOnly:      false,
		},
	}
	return opts
}

// BuildExecOptions creates RunOptions for arbitrary commands
func BuildExecOptions(projectDir string, image string, network NetworkMode, command []string) *RunOptions {
	opts := DefaultRunOptions()
	opts.Image = image
	opts.Network = network
	opts.Command = command
	opts.Volumes = []VolumeMount{
		{
			HostPath:      projectDir,
			ContainerPath: "/app",
			ReadOnly:      false,
		},
	}
	return opts
}
