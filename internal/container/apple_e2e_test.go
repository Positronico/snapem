//go:build container_e2e

// Package container's apple_e2e_test.go drives a real Apple `container`
// runtime to verify the argv we generate actually maps to the behavior we
// promise (bind mounts writable from inside the container, --network none
// blocks outbound DNS, --rm tears the container down). Compile-gated by
// the `container_e2e` build tag so `go test ./...` stays hermetic.
//
// Run with:
//
//	make test-e2e
//	# or directly:
//	go test -tags container_e2e -run E2E ./internal/container/...
//
// The suite skips cleanly when `container system status` reports the
// service down, so a developer without a running runtime gets a clear
// "SKIP: ..." message rather than a confusing failure.

package container

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const e2eImage = "node:lts-slim"

func requireContainerService(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath(containerBinary); err != nil {
		t.Skip("SKIP: `container` CLI not installed on this host")
	}
	out, err := exec.Command(containerBinary, "system", "status").CombinedOutput()
	if err != nil || !strings.Contains(string(out), "apiserver is running") {
		t.Skipf("SKIP: container service not running\n%s", out)
	}
}

// TestE2E_BindMountIsWritable confirms that a host directory bind-mounted
// at /app round-trips a file write back to the host. Failure here means
// either --volume isn't being passed correctly or the runtime isn't
// honoring it. Either way, every `snapem install` is broken.
func TestE2E_BindMountIsWritable(t *testing.T) {
	requireContainerService(t)

	dir := t.TempDir()
	marker := filepath.Join(dir, "marker")

	r := NewAppleRuntime()
	if !r.IsAvailable() {
		t.Fatalf("container CLI looked up but IsAvailable() is false")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	if err := r.Run(ctx, &RunOptions{
		Image:   e2eImage,
		Command: []string{"sh", "-c", "echo container-side > /app/marker"},
		WorkDir: "/app",
		Remove:  true,
		Volumes: []VolumeMount{{HostPath: dir, ContainerPath: "/app"}},
	}); err != nil {
		t.Fatalf("Run: %v", err)
	}

	data, err := os.ReadFile(marker)
	if err != nil {
		t.Fatalf("expected marker file on host after container write: %v", err)
	}
	if got := strings.TrimSpace(string(data)); got != "container-side" {
		t.Errorf("marker content=%q, want %q", got, "container-side")
	}
}

// TestE2E_ReadOnlyVolumeRejectsWrite asserts that ReadOnly=true on a volume
// surfaces as a write rejection inside the container. Pins the P1 read-only
// mount feature — if Apple ever changes :ro semantics, this fails loudly.
func TestE2E_ReadOnlyVolumeRejectsWrite(t *testing.T) {
	requireContainerService(t)

	dir := t.TempDir()
	r := NewAppleRuntime()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	// We expect the container to exit non-zero because the touch fails.
	err := r.Run(ctx, &RunOptions{
		Image:   e2eImage,
		Command: []string{"sh", "-c", "touch /app/should-fail 2>&1; exit $?"},
		WorkDir: "/app",
		Remove:  true,
		Volumes: []VolumeMount{{HostPath: dir, ContainerPath: "/app", ReadOnly: true}},
	})
	if err == nil {
		t.Fatalf("expected non-zero exit when writing to read-only mount")
	}

	// And no file on the host either way.
	if _, statErr := os.Stat(filepath.Join(dir, "should-fail")); !os.IsNotExist(statErr) {
		t.Errorf("read-only mount should not have produced a file; stat err=%v", statErr)
	}
}

// TestE2E_NetworkNoneBlocksDNS confirms that NetworkMode=NetworkNone
// actually isolates the container. Without this, --no-network on snapem
// exec / install could silently allow egress and we'd never know.
func TestE2E_NetworkNoneBlocksDNS(t *testing.T) {
	requireContainerService(t)

	dir := t.TempDir()
	r := NewAppleRuntime()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	// node's dns.lookup uses getaddrinfo under the hood. With no network
	// attached we expect EAI_AGAIN or similar. Either way the process
	// exits non-zero, which is the contract we care about.
	err := r.Run(ctx, &RunOptions{
		Image:   e2eImage,
		Network: NetworkNone,
		Command: []string{"node", "-e", `require('dns').lookup('example.com', (e) => { process.exit(e ? 0 : 1) })`},
		Remove:  true,
		Volumes: []VolumeMount{{HostPath: dir, ContainerPath: "/app"}},
	})
	// Inverted exit: the node script intentionally exits 0 when DNS fails,
	// because that's the success criterion for this test. So err must be
	// nil here — if DNS succeeded against expectation, the script exits 1
	// and Run returns an error.
	if err != nil {
		t.Fatalf("DNS lookup with NetworkNone should have failed inside the container, but the script reported success: %v", err)
	}
}
