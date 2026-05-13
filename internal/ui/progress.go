package ui

import (
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"golang.org/x/term"
)

// spinnerFrames cycles a braille spinner. Each frame is one column-width
// rune so cursor accounting stays simple. Universal in modern terminals
// (Terminal.app, iTerm2, Ghostty, Alacritty, Kitty, VS Code).
var spinnerFrames = []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}

// Progress renders an animated multi-line block of scanner statuses.
// One row per scanner, redrawn on a 100ms ticker until Stop().
//
// When the output isn't a TTY (CI, redirected stdout, --quiet), Progress
// degrades to the same per-event println the previous static UI used —
// no escape sequences, no flicker. Callers don't need to branch; just
// always Add/Done/Stop and the right thing happens.
//
// Progress is goroutine-safe.
type Progress struct {
	mu          sync.Mutex
	ui          *UI
	scanners    []string // insertion-ordered names
	state       map[string]progressState
	frame       int
	started     bool
	stopCh      chan struct{}
	doneCh      chan struct{}
	enabled     bool // animated; false for non-TTY / quiet
	linesShown  int  // count of rendered rows in the last redraw
}

type progressState struct {
	status string
	done   bool
}

// NewProgress returns a Progress bound to ui. The returned value is safe
// to use even when animations are disabled — every method becomes a
// targeted no-op or a single-line write that matches pre-spinner output.
func (u *UI) NewProgress() *Progress {
	enabled := !u.quiet && u.useColor && term.IsTerminal(int(os.Stdout.Fd()))
	return &Progress{
		ui:      u,
		state:   make(map[string]progressState),
		enabled: enabled,
	}
}

// Add registers a scanner row. Subsequent updates use the same name.
// Adding the same name twice is idempotent.
func (p *Progress) Add(name string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if _, exists := p.state[name]; exists {
		return
	}
	p.scanners = append(p.scanners, name)
	p.state[name] = progressState{status: "scanning..."}

	if !p.enabled {
		// Static fallback: print the "scanning..." line once, just as
		// the pre-spinner UI did.
		fmt.Fprintln(os.Stdout, "  "+IconScanning+" "+name+": "+StyleMuted.Render("scanning..."))
		return
	}

	if !p.started {
		p.started = true
		p.stopCh = make(chan struct{})
		p.doneCh = make(chan struct{})
		go p.loop()
	}
}

// Done marks the named scanner complete. Safe to call for an unknown
// name (no-op).
func (p *Progress) Done(name string) {
	p.mu.Lock()
	st, ok := p.state[name]
	if !ok {
		p.mu.Unlock()
		return
	}
	st.done = true
	st.status = "complete"
	p.state[name] = st
	p.mu.Unlock()

	if !p.enabled {
		fmt.Fprintln(os.Stdout, "  "+IconSuccess+" "+name+": complete")
	}
}

// Stop halts the redraw goroutine and renders the final state. After
// Stop, the cursor sits below the rendered block on its own line, ready
// for whatever the caller prints next.
func (p *Progress) Stop() {
	p.mu.Lock()
	started := p.started
	p.mu.Unlock()

	if !started {
		return
	}
	close(p.stopCh)
	<-p.doneCh
}

// loop runs the redraw ticker. Exits when stopCh closes.
func (p *Progress) loop() {
	t := time.NewTicker(100 * time.Millisecond)
	defer t.Stop()
	defer close(p.doneCh)

	for {
		select {
		case <-p.stopCh:
			p.redraw(true)
			return
		case <-t.C:
			p.redraw(false)
		}
	}
}

// redraw rewrites the block in place. final=true is the post-Stop
// render: no more cursor management, every row shown with its final
// icon (✓ or 🔍 depending on done state), cursor left on a fresh line.
func (p *Progress) redraw(final bool) {
	p.mu.Lock()
	defer p.mu.Unlock()

	var b strings.Builder

	// Move cursor up to the start of the previous block and clear each
	// line. Only after the first frame, so we don't clobber the line
	// the caller printed before us.
	if p.linesShown > 0 {
		fmt.Fprintf(&b, "\x1b[%dA", p.linesShown) // cursor up N lines
	}

	frame := spinnerFrames[p.frame%len(spinnerFrames)]
	for _, name := range p.scanners {
		st := p.state[name]
		// \x1b[2K clears the entire line; \r returns to column 0 before
		// we write the new content. Together they replace whatever was
		// on this row without flicker.
		b.WriteString("\r\x1b[2K")
		if st.done {
			b.WriteString("  " + IconSuccess + " " + name + ": complete\n")
		} else {
			b.WriteString("  " + StyleCyan.Render(frame) + " " + name + ": " +
				StyleMuted.Render(st.status) + "\n")
		}
	}

	os.Stdout.WriteString(b.String())
	p.linesShown = len(p.scanners)
	p.frame++

	_ = final // currently no different handling; reserved for future
}
