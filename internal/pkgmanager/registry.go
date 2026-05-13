package pkgmanager

import (
	"os"
	"path/filepath"

	"github.com/positronico/snapem/internal/container"
)

// AddPrivateRegistryMount appends a read-only mount of the host's
// ~/.npmrc to opts.Volumes when the file exists. npm, yarn classic,
// and pnpm all read /root/.npmrc when the process runs as root, which
// is the default in node:lts-slim and oven/bun. bun's own bunfig.toml
// is not handled here — bun reads ~/.npmrc for authentication compat,
// so this still covers the common private-registry case.
//
// The mount is a no-op when ~/.npmrc doesn't exist on the host (most
// users without private registries). Callers should gate this on
// cfg.Container.MountNpmrc so users can opt out for tighter credential
// isolation. See SECURITY.md for the tradeoff.
//
// Returns true if a mount was added — useful for logging "mounted
// ~/.npmrc" in verbose mode.
func AddPrivateRegistryMount(opts *container.RunOptions) bool {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return false
	}
	npmrc := filepath.Join(home, ".npmrc")
	info, err := os.Stat(npmrc)
	if err != nil || info.IsDir() {
		return false
	}
	opts.Volumes = append(opts.Volumes, container.VolumeMount{
		HostPath:      npmrc,
		ContainerPath: "/root/.npmrc",
		ReadOnly:      true,
	})
	return true
}
