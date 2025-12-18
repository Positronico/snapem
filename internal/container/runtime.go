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

// NetworkMode defines network configuration
type NetworkMode string

const (
	// NetworkHost uses host networking
	NetworkHost NetworkMode = "host"

	// NetworkNone disables networking
	NetworkNone NetworkMode = "none"

	// NetworkBridge uses bridged networking (default)
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
