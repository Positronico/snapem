package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRenderAgent_SkillHasFrontmatter(t *testing.T) {
	out, err := renderAgent("skill")
	if err != nil {
		t.Fatalf("renderAgent: %v", err)
	}
	if !strings.HasPrefix(out, "---\n") {
		t.Errorf("skill output should start with YAML frontmatter, got %q", out[:min(40, len(out))])
	}
	if !strings.Contains(out, "name: snapem\n") {
		t.Errorf("skill output should declare name: snapem")
	}
	if !strings.Contains(out, "description: ") {
		t.Errorf("skill output should carry a description")
	}
	// Body must still be present after the frontmatter.
	if !strings.Contains(out, "## Command translations") {
		t.Errorf("skill output is missing the body content")
	}
}

func TestRenderAgent_MarkdownHasNoFrontmatter(t *testing.T) {
	out, err := renderAgent("md")
	if err != nil {
		t.Fatalf("renderAgent: %v", err)
	}
	if strings.HasPrefix(out, "---") {
		t.Errorf("md output must not carry YAML frontmatter — would break AGENTS.md ingest")
	}
	if !strings.HasPrefix(out, "# Using snapem") {
		t.Errorf("md output should start with the body heading")
	}
}

func TestRenderAgent_RejectsUnknownFormat(t *testing.T) {
	_, err := renderAgent("toml")
	if err == nil {
		t.Fatal("renderAgent(\"toml\") should return an error")
	}
	if !strings.Contains(err.Error(), "toml") {
		t.Errorf("error should name the bad format: %v", err)
	}
}

func TestDefaultAgentPath(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatalf("UserHomeDir: %v", err)
	}

	if got, _ := defaultAgentPath("skill"); got != filepath.Join(home, ".claude", "skills", "snapem.md") {
		t.Errorf("skill default path = %q", got)
	}
	if got, _ := defaultAgentPath("md"); got != "AGENTS.md" {
		t.Errorf("md default path = %q, want AGENTS.md", got)
	}
}

// Critical safety property: install must refuse to overwrite an existing
// file unless --force. Users would otherwise lose any hand-edited
// instructions they'd layered on top.
func TestRunAgentInstall_RefusesOverwriteWithoutForce(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "snapem.md")
	if err := os.WriteFile(target, []byte("user's hand-written content"), 0o644); err != nil {
		t.Fatalf("seed: %v", err)
	}

	// Mimic the runAgentInstall flag state.
	prevFormat, prevOutput, prevForce := agentFormat, agentOutput, agentForce
	defer func() { agentFormat, agentOutput, agentForce = prevFormat, prevOutput, prevForce }()
	agentFormat = "md"
	agentOutput = target
	agentForce = false

	err := runAgentInstall(nil, nil)
	if err == nil {
		t.Fatal("expected refusal to overwrite without --force")
	}
	if !strings.Contains(err.Error(), "already exists") {
		t.Errorf("error should explain the file exists: %v", err)
	}

	// File must be untouched.
	got, _ := os.ReadFile(target)
	if string(got) != "user's hand-written content" {
		t.Errorf("file was overwritten despite refusal: %q", got)
	}

	// With --force, the install proceeds.
	agentForce = true
	if err := runAgentInstall(nil, nil); err != nil {
		t.Fatalf("install with --force: %v", err)
	}
	got, _ = os.ReadFile(target)
	if !strings.Contains(string(got), "Using snapem") {
		t.Errorf("expected template content after --force overwrite, got %q", got[:min(60, len(got))])
	}
}

func TestRunAgentInstall_WritesAndCreatesParentDir(t *testing.T) {
	dir := t.TempDir()
	nested := filepath.Join(dir, "deeply", "nested", "snapem.md")

	prevFormat, prevOutput, prevForce := agentFormat, agentOutput, agentForce
	defer func() { agentFormat, agentOutput, agentForce = prevFormat, prevOutput, prevForce }()
	agentFormat = "skill"
	agentOutput = nested
	agentForce = false

	if err := runAgentInstall(nil, nil); err != nil {
		t.Fatalf("install: %v", err)
	}
	data, err := os.ReadFile(nested)
	if err != nil {
		t.Fatalf("read written file: %v", err)
	}
	if !strings.HasPrefix(string(data), "---\nname: snapem\n") {
		t.Errorf("written file should carry skill frontmatter, got %q", data[:min(40, len(data))])
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
