package pkgmanager

import (
	"reflect"
	"strings"
	"testing"
)

func TestShellQuote(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"lodash", "'lodash'"},
		{"", "''"},
		{"a b c", "'a b c'"},
		{`o'reilly`, `'o'\''reilly'`},
	}
	for _, tc := range cases {
		got := shellQuote(tc.in)
		if got != tc.want {
			t.Errorf("shellQuote(%q)=%q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestPNPM_InstallCommand(t *testing.T) {
	p := NewPNPM("")
	cmd := p.InstallCommand([]string{"lodash"}, false)

	if len(cmd) != 3 || cmd[0] != "sh" || cmd[1] != "-c" {
		t.Fatalf("expected sh -c wrapper, got %v", cmd)
	}
	if !strings.Contains(cmd[2], "corepack enable") {
		t.Errorf("install command should enable corepack: %q", cmd[2])
	}
	if !strings.Contains(cmd[2], "corepack pnpm install 'lodash'") {
		t.Errorf("install command should run corepack pnpm install with quoted args: %q", cmd[2])
	}
}

func TestPNPM_RunCommand(t *testing.T) {
	p := NewPNPM("")
	cmd := p.RunCommand("dev", []string{"--watch"})
	if len(cmd) != 3 || cmd[0] != "sh" || cmd[1] != "-c" {
		t.Fatalf("expected sh -c wrapper, got %v", cmd)
	}
	if !strings.Contains(cmd[2], "trap 'exit 0' INT TERM") {
		t.Errorf("run command should trap INT/TERM for clean Ctrl+C: %q", cmd[2])
	}
	if !strings.Contains(cmd[2], "corepack pnpm run 'dev' '--watch'") {
		t.Errorf("run command should pass through to pnpm run with quoted args: %q", cmd[2])
	}
}

func TestPNPM_InstallCommand_SaveDev(t *testing.T) {
	p := NewPNPM("")
	cmd := p.InstallCommand(nil, true)
	if !strings.Contains(cmd[2], "--save-dev") {
		t.Errorf("expected --save-dev in install: %q", cmd[2])
	}
}

func TestDetect_PrefersExplicit(t *testing.T) {
	images := map[string]string{"npm": "n", "bun": "b", "pnpm": "p"}
	if _, ok := Detect("/nonexistent", "pnpm", images).(*PNPM); !ok {
		t.Errorf("preferred=pnpm should return *PNPM")
	}
	if _, ok := Detect("/nonexistent", "bun", images).(*Bun); !ok {
		t.Errorf("preferred=bun should return *Bun")
	}
	if _, ok := Detect("/nonexistent", "npm", images).(*NPM); !ok {
		t.Errorf("preferred=npm should return *NPM")
	}
	if _, ok := Detect("/nonexistent", "", images).(*NPM); !ok {
		t.Errorf("default with no lockfile should be *NPM")
	}
}

func TestPNPM_ExecCommandPassthrough(t *testing.T) {
	p := NewPNPM("")
	got := p.ExecCommand([]string{"node", "-v"})
	want := []string{"node", "-v"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("ExecCommand passthrough: got %v, want %v", got, want)
	}
}
