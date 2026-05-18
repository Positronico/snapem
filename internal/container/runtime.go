package container

import (
	"context"
)

// Runtime defines the interface for container execution
type Runtime interface {
	// Run executes a command in a container and waits for completion
	Run(ctx context.Context, opts *RunOptions) error

	// IsAvailable checks if the container runtime is available
	IsAvailable() bool

	// Name returns the runtime name
	Name() string
}

// RunOptions configures container execution
type RunOptions struct {
	// Image is the container image to use
	Image string

	// Command is the command and arguments to run
	Command []string

	// WorkDir is the working directory in the container
	WorkDir string

	// Volumes are the volume mounts
	Volumes []VolumeMount

	// Ports are the port mappings (host:container)
	Ports []PortMapping

	// Network is the network mode
	Network NetworkMode

	// Environment variables to pass to container
	Environment map[string]string

	// Interactive enables stdin
	Interactive bool

	// TTY allocates a pseudo-TTY
	TTY bool

	// Remove container after exit
	Remove bool

	// Name is an optional container name
	Name string
}

// PortMapping represents a port mapping from host to container
type PortMapping struct {
	HostPort      string
	ContainerPort string
}

// VolumeMount represents a volume mount
type VolumeMount struct {
	HostPath      string
	ContainerPath string
	ReadOnly      bool
}

// NetworkMode is the value of `container.network` in snapem.yaml.
//
// IMPORTANT — these names predate snapem's port to Apple's `container`
// runtime and DO NOT carry Docker semantics. As of `container` CLI
// v0.9.0 the only flag form is `--network <network-name>`; there is
// no `--network host` and no `--network bridge` mode. Quoting the
// real `container run --help`:
//
//   --network <network>   Attach the container to a network (format:
//                         <name>[,mac=XX:XX:XX:XX:XX:XX])
//
// What each NetworkMode value actually does in the apple.go translator:
//
//   NetworkHost   — emits NO `--network` flag. The container attaches
//                   to the auto-created `default` named network
//                   (192.168.64.0/24). This is NOT host networking;
//                   the container cannot reach host loopback services
//                   or the host's `~/.aws`, `~/.ssh`, Keychain, etc.
//                   The label "host" is a backwards-compat name from
//                   when snapem targeted Docker.
//   NetworkNone   — emits `--network none`. Outbound network fully
//                   disabled; DNS resolution fails with EAI_AGAIN
//                   (live verified against container v0.9.0).
//   NetworkBridge — emits NO `--network` flag. Same effect as
//                   NetworkHost today. The label is kept for config
//                   backwards compatibility; future work could map
//                   it to a per-project named network.
//
// Snapem's default is NetworkHost — i.e. the `default` named network
// — because that's what npm/bun/pnpm/yarn need to reach the registry.
// `--network none` is the strictest posture and the right choice for
// `snapem exec` of a script that shouldn't phone home.
type NetworkMode string

const (
	// NetworkHost is the historical name for "use the default named
	// network." Does NOT give host networking on Apple `container`.
	// See the type comment for the full table.
	NetworkHost NetworkMode = "host"

	// NetworkNone disables outbound networking entirely. Emits
	// `--network none` to `container`.
	NetworkNone NetworkMode = "none"

	// NetworkBridge is currently equivalent to NetworkHost — both
	// fall through to `container`'s default named network. Kept as
	// a config-level alias; do not rely on Docker-style bridge
	// semantics.
	NetworkBridge NetworkMode = "bridge"
)

// DefaultRunOptions returns sensible defaults for container execution
func DefaultRunOptions() *RunOptions {
	return &RunOptions{
		Image:       "node:lts-slim",
		WorkDir:     "/app",
		Network:     NetworkHost,
		Interactive: true,
		TTY:         true,
		Remove:      true,
		Environment: make(map[string]string),
	}
}
