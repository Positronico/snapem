package ui

import (
	"testing"
)

// TestProgress_NonTTYIsSafe exercises the non-TTY code path (the test
// binary's stdout is not a TTY under `go test`). With animation
// disabled, every method should be a synchronous write-or-nop — no
// goroutine should start, and Stop should not block.
func TestProgress_NonTTYIsSafe(t *testing.T) {
	u := New(false, false, true) // useColor=true, but stdout still not a TTY
	prog := u.NewProgress()

	if prog.enabled {
		t.Fatal("Progress should not be enabled when stdout isn't a TTY")
	}

	prog.Add("socket")
	prog.Add("osv")
	prog.Done("socket")
	prog.Done("osv")
	prog.Stop()
}

// Adding the same scanner twice must not double-print or duplicate
// state.
func TestProgress_AddIdempotent(t *testing.T) {
	u := New(false, false, true)
	prog := u.NewProgress()

	prog.Add("socket")
	prog.Add("socket")
	prog.Add("socket")

	if got := len(prog.scanners); got != 1 {
		t.Errorf("expected 1 scanner after triple-Add, got %d", got)
	}
}

// Done for an unregistered scanner should be a no-op, not a panic.
func TestProgress_DoneForUnknownScanner(t *testing.T) {
	u := New(false, false, true)
	prog := u.NewProgress()
	prog.Done("never-added") // must not panic
}

// Stop without any Add must be safe to call.
func TestProgress_StopWithoutAdd(t *testing.T) {
	u := New(false, false, true)
	prog := u.NewProgress()
	prog.Stop() // no goroutine ever started; must return immediately
}

// Quiet mode disables animation regardless of TTY state.
func TestProgress_QuietDisablesAnimation(t *testing.T) {
	u := New(false, true, true) // quiet=true
	prog := u.NewProgress()
	if prog.enabled {
		t.Error("Progress should be disabled when ui is quiet")
	}
}
