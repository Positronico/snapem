package pkgmanager

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/positronico/snapem/internal/container"
)

// setFakeHome points HOME at a temp dir for the duration of the test.
func setFakeHome(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	return dir
}

func TestAddPrivateRegistryMount_FilePresent(t *testing.T) {
	home := setFakeHome(t)
	npmrc := filepath.Join(home, ".npmrc")
	if err := os.WriteFile(npmrc, []byte("registry=https://r.example.com/\n"), 0o600); err != nil {
		t.Fatalf("write npmrc: %v", err)
	}

	opts := &container.RunOptions{}
	if !AddPrivateRegistryMount(opts) {
		t.Fatal("expected mount to be added when ~/.npmrc exists")
	}
	if len(opts.Volumes) != 1 {
		t.Fatalf("expected 1 volume, got %d", len(opts.Volumes))
	}
	v := opts.Volumes[0]
	if v.HostPath != npmrc {
		t.Errorf("HostPath = %q, want %q", v.HostPath, npmrc)
	}
	if v.ContainerPath != "/root/.npmrc" {
		t.Errorf("ContainerPath = %q, want /root/.npmrc", v.ContainerPath)
	}
	if !v.ReadOnly {
		t.Error("expected ReadOnly=true")
	}
}

func TestAddPrivateRegistryMount_FileAbsent(t *testing.T) {
	setFakeHome(t) // no .npmrc inside
	opts := &container.RunOptions{}
	if AddPrivateRegistryMount(opts) {
		t.Error("expected no mount when ~/.npmrc does not exist")
	}
	if len(opts.Volumes) != 0 {
		t.Errorf("opts.Volumes should remain empty, got %v", opts.Volumes)
	}
}

func TestAddPrivateRegistryMount_NpmrcIsDirectory(t *testing.T) {
	home := setFakeHome(t)
	// Pathological case: ~/.npmrc exists but is a directory. Should be
	// treated the same as absent rather than mounted (mounting a dir
	// over /root/.npmrc would break the container).
	if err := os.Mkdir(filepath.Join(home, ".npmrc"), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	opts := &container.RunOptions{}
	if AddPrivateRegistryMount(opts) {
		t.Error("expected no mount when ~/.npmrc is a directory")
	}
}

func TestAddPrivateRegistryMount_AppendsRatherThanReplaces(t *testing.T) {
	home := setFakeHome(t)
	if err := os.WriteFile(filepath.Join(home, ".npmrc"), []byte(""), 0o600); err != nil {
		t.Fatalf("write npmrc: %v", err)
	}

	opts := &container.RunOptions{
		Volumes: []container.VolumeMount{
			{HostPath: "/some/project", ContainerPath: "/app"},
		},
	}
	AddPrivateRegistryMount(opts)
	if len(opts.Volumes) != 2 {
		t.Fatalf("expected 2 volumes after add, got %d", len(opts.Volumes))
	}
	if opts.Volumes[0].ContainerPath != "/app" {
		t.Errorf("existing /app mount got clobbered: %+v", opts.Volumes[0])
	}
}
