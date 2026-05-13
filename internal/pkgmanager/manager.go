package pkgmanager

import (
	"path/filepath"
	"strings"

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

// PNPM implements the Manager interface for pnpm.
//
// pnpm isn't pre-installed in the standard node image. We rely on Node's
// built-in corepack (shipped with node:lts since 16.13) to materialize
// pnpm at runtime. First container start downloads the binary; subsequent
// starts use whatever the previous run left in the corepack cache.
type PNPM struct {
	image string
}

// NewPNPM creates a new pnpm manager.
func NewPNPM(image string) *PNPM {
	if image == "" {
		image = "node:lts-slim"
	}
	return &PNPM{image: image}
}

// Name returns "pnpm".
func (p *PNPM) Name() string { return "pnpm" }

// InstallCommand returns the corepack-enabled pnpm install command.
func (p *PNPM) InstallCommand(packages []string, saveDev bool) []string {
	cmd := "corepack pnpm install"
	if saveDev {
		cmd += " --save-dev"
	}
	for _, pkg := range packages {
		cmd += " " + shellQuote(pkg)
	}
	return []string{"sh", "-c", "corepack enable >/dev/null 2>&1; " + cmd}
}

// RunCommand returns the corepack-enabled pnpm run command, wrapped so
// Ctrl+C cleanly exits when pnpm runs as PID 1.
func (p *PNPM) RunCommand(script string, args []string) []string {
	cmdLine := "corepack pnpm run " + shellQuote(script)
	for _, a := range args {
		cmdLine += " " + shellQuote(a)
	}
	return []string{"sh", "-c", "trap 'exit 0' INT TERM; corepack enable >/dev/null 2>&1; " + cmdLine}
}

// ExecCommand passes the user's command through unchanged. pnpm itself
// isn't on PATH unless corepack has prepared it, so non-pnpm commands
// run cleanly via this path.
func (p *PNPM) ExecCommand(command []string) []string { return command }

// Image returns the pnpm container image.
func (p *PNPM) Image() string { return p.image }

// shellQuote returns s wrapped in single quotes with any embedded single
// quotes escaped, safe for splicing into a `sh -c` command line.
func shellQuote(s string) string {
	if s == "" {
		return "''"
	}
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// Yarn implements the Manager interface for yarn (classic v1 and Berry
// via corepack). Same corepack pattern as PNPM — node:lts-slim already
// ships corepack which can materialize whichever yarn is pinned by the
// project's packageManager field or just fetch the latest.
type Yarn struct {
	image string
}

// NewYarn creates a new yarn manager.
func NewYarn(image string) *Yarn {
	if image == "" {
		image = "node:lts-slim"
	}
	return &Yarn{image: image}
}

// Name returns "yarn".
func (y *Yarn) Name() string { return "yarn" }

// InstallCommand returns the corepack-enabled yarn install command.
// yarn install with no args installs everything; yarn add <pkg> for
// specific packages. `-D` for dev deps maps to `--dev` in classic
// yarn and is a no-op flag in Berry (which uses --dev too).
func (y *Yarn) InstallCommand(packages []string, saveDev bool) []string {
	var cmd string
	if len(packages) == 0 {
		cmd = "corepack yarn install"
	} else {
		cmd = "corepack yarn add"
		if saveDev {
			cmd += " --dev"
		}
		for _, pkg := range packages {
			cmd += " " + shellQuote(pkg)
		}
	}
	return []string{"sh", "-c", "corepack enable >/dev/null 2>&1; " + cmd}
}

// RunCommand returns the corepack-enabled yarn run command, wrapped so
// Ctrl+C cleanly exits when yarn runs as PID 1.
func (y *Yarn) RunCommand(script string, args []string) []string {
	cmdLine := "corepack yarn run " + shellQuote(script)
	for _, a := range args {
		cmdLine += " " + shellQuote(a)
	}
	return []string{"sh", "-c", "trap 'exit 0' INT TERM; corepack enable >/dev/null 2>&1; " + cmdLine}
}

// ExecCommand passes the user's command through unchanged.
func (y *Yarn) ExecCommand(command []string) []string { return command }

// Image returns the yarn container image.
func (y *Yarn) Image() string { return y.image }

// Detect determines which package manager to use based on the project
func Detect(projectDir string, preferred string, images map[string]string) Manager {
	npmImage := images["npm"]
	bunImage := images["bun"]
	pnpmImage := images["pnpm"]
	yarnImage := images["yarn"]

	// If user specified a preference, use it
	switch preferred {
	case "npm":
		return NewNPM(npmImage)
	case "bun":
		return NewBun(bunImage)
	case "pnpm":
		return NewPNPM(pnpmImage)
	case "yarn":
		return NewYarn(yarnImage)
	}

	// Auto-detect based on lockfiles. Prefer bun.lock (text) since it's
	// the format bun 1.2+ writes by default; bun.lockb (binary) is the
	// legacy fallback for older bun installs.
	parser := manifest.NewParser(projectDir)
	if parser.HasBunTextLockfile() || parser.HasBunLockfile() {
		return NewBun(bunImage)
	}
	if parser.HasPnpmLockfile() {
		return NewPNPM(pnpmImage)
	}
	if parser.HasYarnLockfile() {
		return NewYarn(yarnImage)
	}

	// Default to npm
	return NewNPM(npmImage)
}

// BuildContainerOptions creates container run options for the given
// manager and command. Mounts the project directory at /app read-write
// by default; callers can flip readOnly=true via BuildContainerOptionsRO
// for `snapem exec --read-only` / `snapem run --read-only`.
//
// Install paths must NOT use read-only: npm writes node_modules,
// package-lock.json, and (sometimes) the cache directory back through
// the bind mount. Read-only would fail the install before the lockfile
// is created.
func BuildContainerOptions(mgr Manager, projectDir string, network container.NetworkMode, command []string) *container.RunOptions {
	return BuildContainerOptionsRO(mgr, projectDir, network, command, false)
}

// BuildContainerOptionsRO is BuildContainerOptions with explicit control
// over the read-only bit on the project volume mount.
func BuildContainerOptionsRO(mgr Manager, projectDir string, network container.NetworkMode, command []string, readOnly bool) *container.RunOptions {
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
				ReadOnly:      readOnly,
			},
		},
		Environment: make(map[string]string),
	}
}
