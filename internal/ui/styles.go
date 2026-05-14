package ui

import (
	"fmt"
	"os"
	"sort"

	"github.com/charmbracelet/lipgloss"
)

var (
	// Colors
	colorGreen   = lipgloss.Color("#22c55e")
	colorRed     = lipgloss.Color("#ef4444")
	colorYellow  = lipgloss.Color("#eab308")
	colorBlue    = lipgloss.Color("#3b82f6")
	colorCyan    = lipgloss.Color("#06b6d4")
	colorGray    = lipgloss.Color("#6b7280")
	colorMagenta = lipgloss.Color("#d946ef")

	// Styles
	StyleSuccess = lipgloss.NewStyle().Foreground(colorGreen).Bold(true)
	StyleError   = lipgloss.NewStyle().Foreground(colorRed).Bold(true)
	StyleWarning = lipgloss.NewStyle().Foreground(colorYellow).Bold(true)
	StyleInfo    = lipgloss.NewStyle().Foreground(colorBlue)
	StyleMuted   = lipgloss.NewStyle().Foreground(colorGray)
	StyleBold    = lipgloss.NewStyle().Bold(true)
	StyleCyan    = lipgloss.NewStyle().Foreground(colorCyan)

	// Severity styles
	StyleCritical = lipgloss.NewStyle().Foreground(colorRed).Bold(true)
	StyleHigh     = lipgloss.NewStyle().Foreground(colorRed)
	StyleMedium   = lipgloss.NewStyle().Foreground(colorYellow)
	StyleLow      = lipgloss.NewStyle().Foreground(colorGray)

	// Icons
	IconSuccess  = StyleSuccess.Render("✓")
	IconError    = StyleError.Render("✗")
	IconWarning  = StyleWarning.Render("!")
	IconInfo     = StyleInfo.Render("i")
	IconShield   = StyleCyan.Render("🛡")
	IconScanning = StyleCyan.Render("🔍")
	IconPackage  = StyleInfo.Render("📦")
	IconLock     = StyleMuted.Render("🔒")
)

// UI manages terminal output
type UI struct {
	verbose  bool
	quiet    bool
	useColor bool
}

// New creates a new UI instance
func New(verbose, quiet, useColor bool) *UI {
	return &UI{
		verbose:  verbose,
		quiet:    quiet,
		useColor: useColor,
	}
}

// Success prints a success message
func (u *UI) Success(msg string) {
	if u.quiet {
		return
	}
	if u.useColor {
		os.Stdout.WriteString(IconSuccess + " " + StyleSuccess.Render(msg) + "\n")
	} else {
		os.Stdout.WriteString("[OK] " + msg + "\n")
	}
}

// Error prints an error message
func (u *UI) Error(msg string) {
	if u.useColor {
		os.Stderr.WriteString(IconError + " " + StyleError.Render(msg) + "\n")
	} else {
		os.Stderr.WriteString("[ERROR] " + msg + "\n")
	}
}

// ScannerErrors renders a prominent block when one or more scanners
// failed during the run. Each line names the scanner and its error
// — the user needs to know their malware (or CVE, or hygiene) signal
// didn't actually run, even if other scanners said everything looked
// clean. Silent partial-success is the worst outcome.
func (u *UI) ScannerErrors(errs map[string]string) {
	if u.quiet || len(errs) == 0 {
		return
	}
	names := make([]string, 0, len(errs))
	for n := range errs {
		names = append(names, n)
	}
	sort.Strings(names)

	u.Warning("Some scanners failed to run; coverage is incomplete:")
	for _, n := range names {
		msg := truncateError(errs[n], 140)
		line := "  - " + n + ": " + msg
		if u.useColor {
			os.Stdout.WriteString(StyleWarning.Render(line) + "\n")
		} else {
			os.Stdout.WriteString(line + "\n")
		}
	}
}

// truncateError caps an error string at n bytes with an ellipsis so
// long stack-trace-y network errors don't dominate the scan output.
func truncateError(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-1] + "…"
}

// Warning prints a warning message
func (u *UI) Warning(msg string) {
	if u.quiet {
		return
	}
	if u.useColor {
		os.Stdout.WriteString(IconWarning + " " + StyleWarning.Render(msg) + "\n")
	} else {
		os.Stdout.WriteString("[WARN] " + msg + "\n")
	}
}

// Info prints an info message
func (u *UI) Info(msg string) {
	if u.quiet {
		return
	}
	if u.useColor {
		os.Stdout.WriteString(StyleInfo.Render(msg) + "\n")
	} else {
		os.Stdout.WriteString(msg + "\n")
	}
}

// Verbose prints a message only in verbose mode
func (u *UI) Verbose(msg string) {
	if !u.verbose {
		return
	}
	if u.useColor {
		os.Stdout.WriteString(StyleMuted.Render(msg) + "\n")
	} else {
		os.Stdout.WriteString(msg + "\n")
	}
}

// Print prints a plain message
func (u *UI) Print(msg string) {
	if u.quiet {
		return
	}
	os.Stdout.WriteString(msg + "\n")
}

// ScanningHeader prints the scanning header
func (u *UI) ScanningHeader() {
	if u.quiet {
		return
	}
	if u.useColor {
		os.Stdout.WriteString("\n" + IconShield + " " + StyleBold.Render("Security Scan") + "\n")
	} else {
		os.Stdout.WriteString("\n[SCAN] Security Scan\n")
	}
}

// ScannerStatus prints status for a specific scanner
func (u *UI) ScannerStatus(scanner string, status string, isRunning bool) {
	if u.quiet {
		return
	}
	prefix := "  "
	if isRunning {
		if u.useColor {
			os.Stdout.WriteString(prefix + IconScanning + " " + scanner + ": " + StyleMuted.Render(status) + "\n")
		} else {
			os.Stdout.WriteString(prefix + "[...] " + scanner + ": " + status + "\n")
		}
	} else {
		if u.useColor {
			os.Stdout.WriteString(prefix + IconSuccess + " " + scanner + ": " + status + "\n")
		} else {
			os.Stdout.WriteString(prefix + "[OK] " + scanner + ": " + status + "\n")
		}
	}
}

// PackageHeader prints a header for one package's findings block, e.g.
//
//	▶ lodash@4.17.20  (5 issues)
//
// followed by indented ThreatLine calls. Severity-tinted by the worst
// finding under the package so the eye lands on critical issues first.
func (u *UI) PackageHeader(pkg string, count int, worstSeverity string) {
	if u.quiet {
		return
	}
	style := severityStyle(worstSeverity)
	if u.useColor {
		os.Stdout.WriteString("\n  " + style.Render("▶") + " " + StyleBold.Render(pkg) + StyleMuted.Render(fmt.Sprintf("  (%d issue%s)", count, plural(count))) + "\n")
	} else {
		os.Stdout.WriteString("\n  > " + pkg + fmt.Sprintf("  (%d issue%s)\n", count, plural(count)))
	}
}

// ThreatLine prints one finding under a PackageHeader. id is shown when
// non-empty; fix and url emit additional indented lines when present.
func (u *UI) ThreatLine(severity, id, title, fix, url string) {
	if u.quiet {
		return
	}
	style := severityStyle(severity)

	prefix := "[" + severity + "]"
	header := title
	if id != "" {
		header = id + ": " + title
	}

	if u.useColor {
		os.Stdout.WriteString("    " + style.Render(prefix) + " " + header + "\n")
		if fix != "" {
			os.Stdout.WriteString("      " + StyleSuccess.Render("→ "+fix) + "\n")
		}
		if url != "" {
			os.Stdout.WriteString("      " + StyleMuted.Render(url) + "\n")
		}
	} else {
		os.Stdout.WriteString("    " + prefix + " " + header + "\n")
		if fix != "" {
			os.Stdout.WriteString("      -> " + fix + "\n")
		}
		if url != "" {
			os.Stdout.WriteString("      " + url + "\n")
		}
	}
}

func severityStyle(severity string) lipgloss.Style {
	switch severity {
	case "critical":
		return StyleCritical
	case "high":
		return StyleHigh
	case "medium":
		return StyleMedium
	default:
		return StyleLow
	}
}

func plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}

// ContainerHeader prints the container execution header
func (u *UI) ContainerHeader(cmd string) {
	if u.quiet {
		return
	}
	if u.useColor {
		os.Stdout.WriteString("\n" + IconLock + " " + StyleBold.Render("Container Execution") + "\n")
		os.Stdout.WriteString("  " + StyleMuted.Render(cmd) + "\n\n")
	} else {
		os.Stdout.WriteString("\n[CONTAINER] " + cmd + "\n\n")
	}
}
