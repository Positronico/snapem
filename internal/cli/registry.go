package cli

import (
	"github.com/positronico/snapem/internal/config"
	"github.com/positronico/snapem/internal/container"
	"github.com/positronico/snapem/internal/pkgmanager"
	"github.com/positronico/snapem/internal/ui"
)

// mountPrivateRegistryIfEnabled appends the ~/.npmrc mount to opts when
// cfg.Container.MountNpmrc is true AND the file exists on the host. It
// prints a per-invocation warning whenever a mount actually happens so
// the credential exposure is never silent — even users who deliberately
// flipped the config knob should be reminded each run.
//
// Returns true when a mount was added, false when skipped (config off,
// or ~/.npmrc absent). The boolean is rarely consulted; callers chain
// this between option construction and runtime.Run.
func mountPrivateRegistryIfEnabled(opts *container.RunOptions, cfg *config.Config, display *ui.UI) bool {
	if !cfg.Container.MountNpmrc {
		return false
	}
	if !pkgmanager.AddPrivateRegistryMount(opts) {
		return false
	}
	display.Warning("Mounting ~/.npmrc into the container — auth tokens it contains will be readable by every install script that runs.")
	display.Info("Disable with `container.mount_npmrc: false` in snapem.yaml. See SECURITY.md for the tradeoff.")
	return true
}
