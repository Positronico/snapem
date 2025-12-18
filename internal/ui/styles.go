package ui

import (
	"os"

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

// ThreatFound prints a threat message
func (u *UI) ThreatFound(severity, pkg, desc string) {
	if u.quiet {
		return
	}
	var style lipgloss.Style
	switch severity {
	case "critical":
		style = StyleCritical
	case "high":
		style = StyleHigh
	case "medium":
		style = StyleMedium
	default:
		style = StyleLow
	}

	if u.useColor {
		os.Stdout.WriteString("  " + style.Render("▶ "+severity) + " " + StyleBold.Render(pkg) + "\n")
		os.Stdout.WriteString("    " + StyleMuted.Render(desc) + "\n")
	} else {
		os.Stdout.WriteString("  [" + severity + "] " + pkg + "\n")
		os.Stdout.WriteString("    " + desc + "\n")
	}
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
