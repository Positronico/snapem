package pkgmanager

import (
	"path/filepath"

	"github.com/positronico/snapem/internal/container"
	"github.com/positronico/snapem/internal/manifest"
)

// Manager defines the interface for package managers
type Manager interface {
	// Name returns the package manager name
	Name() string

	// InstallCommand returns the container command for install
	InstallCommand(packages []string, saveDev bool) []string

	// RunCommand returns the container command for running a script
	RunCommand(script string, args []string) []string

	// ExecCommand returns the container command for executing an arbitrary command
	ExecCommand(command []string) []string

	// Image returns the default container image
	Image() string
}

// NPM implements the Manager interface for npm
type NPM struct {
	image string
}

// NewNPM creates a new npm manager
func NewNPM(image string) *NPM {
	if image == "" {
		image = "node:lts-slim"
	}
	return &NPM{image: image}
}

// Name returns "npm"
func (n *NPM) Name() string {
	return "npm"
}

// InstallCommand returns npm install command
func (n *NPM) InstallCommand(packages []string, saveDev bool) []string {
	cmd := []string{"npm", "install"}
	if saveDev {
		cmd = append(cmd, "--save-dev")
	}
	cmd = append(cmd, packages...)
	return cmd
}

// RunCommand returns npm run command wrapped for clean signal handling
func (n *NPM) RunCommand(script string, args []string) []string {
	// Build the npm command
	npmCmd := "npm run " + script
	if len(args) > 0 {
		npmCmd += " --"
		for _, arg := range args {
			npmCmd += " " + arg
		}
	}
	// Wrap with signal trap so Ctrl+C exits cleanly (npm as PID 1 has issues)
	return []string{"sh", "-c", "trap 'exit 0' INT TERM; " + npmCmd}
}

// ExecCommand returns the command as-is for exec
func (n *NPM) ExecCommand(command []string) []string {
	return command
}

// Image returns the npm container image
func (n *NPM) Image() string {
	return n.image
}

// Bun implements the Manager interface for bun
type Bun struct {
	image string
}

// NewBun creates a new bun manager
func NewBun(image string) *Bun {
	if image == "" {
		image = "oven/bun:latest"
	}
	return &Bun{image: image}
}

// Name returns "bun"
func (b *Bun) Name() string {
	return "bun"
}

// InstallCommand returns bun install command
func (b *Bun) InstallCommand(packages []string, saveDev bool) []string {
	cmd := []string{"bun", "install"}
	if saveDev {
		cmd = append(cmd, "--dev")
	}
	cmd = append(cmd, packages...)
	return cmd
}

// RunCommand returns bun run command
func (b *Bun) RunCommand(script string, args []string) []string {
	cmd := []string{"bun", "run", script}
	cmd = append(cmd, args...)
	return cmd
}

// ExecCommand returns bun exec or the command directly
func (b *Bun) ExecCommand(command []string) []string {
	return command
}

// Image returns the bun container image
func (b *Bun) Image() string {
	return b.image
}

// Detect determines which package manager to use based on the project
func Detect(projectDir string, preferred string, images map[string]string) Manager {
	npmImage := images["npm"]
	bunImage := images["bun"]

	// If user specified a preference, use it
	switch preferred {
	case "npm":
		return NewNPM(npmImage)
	case "bun":
		return NewBun(bunImage)
	}

	// Auto-detect based on lockfiles
	parser := manifest.NewParser(projectDir)
	if parser.HasBunLockfile() {
		return NewBun(bunImage)
	}

	// Default to npm
	return NewNPM(npmImage)
}

// BuildContainerOptions creates container run options for the given manager and command
func BuildContainerOptions(mgr Manager, projectDir string, network container.NetworkMode, command []string) *container.RunOptions {
	absPath, _ := filepath.Abs(projectDir)

	return &container.RunOptions{
		Image:       mgr.Image(),
		Command:     command,
		WorkDir:     "/app",
		Network:     network,
		Interactive: true,
		TTY:         true,
		Remove:      true,
		Volumes: []container.VolumeMount{
			{
				HostPath:      absPath,
				ContainerPath: "/app",
				ReadOnly:      false,
			},
		},
		Environment: make(map[string]string),
	}
}
