package container

import (
	"reflect"
	"testing"
)

// TestBuildArgs pins the exact `container run` argv we emit. When Apple's
// container CLI changes a flag (CLAUDE.md §4 captures the v0.9.0 reference),
// this test will fail and force a deliberate update rather than silently
// drifting.
func TestBuildArgs(t *testing.T) {
	r := &AppleRuntime{}

	cases := []struct {
		name string
		opts *RunOptions
		want []string
	}{
		{
			name: "minimal interactive run",
			opts: &RunOptions{
				Image:       "node:lts-slim",
				Command:     []string{"npm", "install"},
				WorkDir:     "/app",
				Interactive: true,
				TTY:         true,
				Remove:      true,
			},
			want: []string{
				"run", "--rm", "--interactive", "--tty",
				"--workdir", "/app",
				"node:lts-slim", "npm", "install",
			},
		},
		{
			name: "volume + port + env passthrough",
			opts: &RunOptions{
				Image:       "node:lts-slim",
				Command:     []string{"npm", "run", "dev"},
				WorkDir:     "/app",
				Remove:      true,
				Interactive: true,
				TTY:         true,
				Volumes: []VolumeMount{
					{HostPath: "/host/proj", ContainerPath: "/app"},
				},
				Ports: []PortMapping{
					{HostPort: "3000", ContainerPort: "3000"},
				},
				Environment: map[string]string{"NODE_ENV": "development"},
			},
			want: []string{
				"run", "--rm", "--interactive", "--tty",
				"--volume", "/host/proj:/app",
				"--workdir", "/app",
				"--publish", "3000:3000",
				"--env", "NODE_ENV=development",
				"node:lts-slim", "npm", "run", "dev",
			},
		},
		{
			name: "readonly volume rendered with :ro suffix",
			opts: &RunOptions{
				Image: "node:lts-slim",
				Volumes: []VolumeMount{
					{HostPath: "/host", ContainerPath: "/app", ReadOnly: true},
				},
				Command: []string{"node", "-v"},
			},
			want: []string{
				"run",
				"--volume", "/host:/app:ro",
				"node:lts-slim", "node", "-v",
			},
		},
		{
			name: "isolated network emits --network none",
			opts: &RunOptions{
				Image:   "node:lts-slim",
				Command: []string{"npm", "install"},
				Network: NetworkNone,
				Remove:  true,
			},
			want: []string{
				"run", "--rm",
				"--network", "none",
				"node:lts-slim", "npm", "install",
			},
		},
		{
			name: "host network emits nothing (default network)",
			opts: &RunOptions{
				Image:   "node:lts-slim",
				Command: []string{"npm", "install"},
				Network: NetworkHost,
				Remove:  true,
			},
			want: []string{
				"run", "--rm",
				"node:lts-slim", "npm", "install",
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := r.buildArgs(tc.opts)
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("buildArgs mismatch:\n  got:  %q\n  want: %q", got, tc.want)
			}
		})
	}
}
