package cli

import (
	_ "embed"
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/positronico/snapem/internal/errors"
)

// agentBody is the canonical instruction text for AI coding assistants.
// Kept as bare markdown so it can be wrapped in either skill frontmatter
// (Claude Code) or shipped as-is (AGENTS.md, CLAUDE.md, etc.).
//
//go:embed agent_template.md
var agentBody string

// Claude Code reads ~/.claude/skills/*.md and matches the YAML frontmatter
// description against the user's intent. The description has to be specific
// enough that the skill activates for "install lodash" but not for "edit
// the README".
const skillDescription = `When the user is working in a Node.js or TypeScript project where the snapem command is available, use snapem instead of npm/bun/pnpm/npx directly. snapem scans dependencies for malware and CVEs before installing and runs commands in an isolated container. Use for: install/run/exec/audit invocations. Translates npm install → snapem install, npm run → snapem run, npx → snapem exec --, node ... → snapem exec -- node, npm audit → snapem scan. Skip for editing files, reading code, or git operations.`

var agentCmd = &cobra.Command{
	Use:   "agent",
	Short: "Generate instructions for AI coding assistants (Claude Code, AGENTS.md tools)",
	Long: `Outputs an instruction file that teaches AI coding assistants to use snapem
instead of invoking npm/bun/pnpm directly.

Quickest path for a Claude Code user:

    snapem agent install

That writes ~/.claude/skills/snapem.md, which Claude Code loads
automatically and uses to choose snapem for install/run/exec/audit tasks
in projects where snapem is on PATH.

For other AI tools (Codex, Cursor, generic AGENTS.md), use --format=md
to emit plain markdown the tool can ingest.`,
}

var (
	agentFormat string
	agentOutput string
	agentForce  bool
)

var agentShowCmd = &cobra.Command{
	Use:   "show",
	Short: "Print the agent instructions to stdout",
	Long: `Print the rendered agent instructions. Default format is the Claude Code
skill format (with YAML frontmatter); use --format=md for plain markdown
suitable for AGENTS.md or CLAUDE.md.`,
	RunE: runAgentShow,
}

var agentInstallCmd = &cobra.Command{
	Use:   "install",
	Short: "Write the agent instructions to disk",
	Long: `Write the agent instructions to the conventional location for the chosen
format:

  --format=skill (default)  →  ~/.claude/skills/snapem.md
  --format=md               →  ./AGENTS.md

Refuses to overwrite an existing file unless --force is given. Use
--output to write to a different path.`,
	RunE: runAgentInstall,
}

func init() {
	agentShowCmd.Flags().StringVar(&agentFormat, "format", "skill", "output format: skill (Claude Code skill with frontmatter) or md (plain markdown)")

	agentInstallCmd.Flags().StringVar(&agentFormat, "format", "skill", "output format: skill or md")
	agentInstallCmd.Flags().StringVar(&agentOutput, "output", "", "write to this path instead of the conventional location")
	agentInstallCmd.Flags().BoolVar(&agentForce, "force", false, "overwrite an existing file at the target path")

	agentCmd.AddCommand(agentShowCmd)
	agentCmd.AddCommand(agentInstallCmd)
	rootCmd.AddCommand(agentCmd)
}

func runAgentShow(cmd *cobra.Command, args []string) error {
	content, err := renderAgent(agentFormat)
	if err != nil {
		return err
	}
	_, err = os.Stdout.WriteString(content)
	return err
}

func runAgentInstall(cmd *cobra.Command, args []string) error {
	content, err := renderAgent(agentFormat)
	if err != nil {
		return err
	}

	target := agentOutput
	if target == "" {
		target, err = defaultAgentPath(agentFormat)
		if err != nil {
			return err
		}
	}

	if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
		return errors.New(errors.ExitGeneralError, fmt.Sprintf("create parent dir: %v", err))
	}

	if _, statErr := os.Stat(target); statErr == nil && !agentForce {
		return errors.New(errors.ExitGeneralError, fmt.Sprintf(
			"%s already exists. Pass --force to overwrite, --output PATH to write elsewhere, or `snapem agent show` to print to stdout.",
			target))
	}

	if err := os.WriteFile(target, []byte(content), 0o644); err != nil {
		return errors.New(errors.ExitGeneralError, fmt.Sprintf("write %s: %v", target, err))
	}

	fmt.Fprintf(os.Stdout, "Wrote %s\n", target)
	fmt.Fprintf(os.Stdout, "Restart your AI assistant (or reload its context) to pick up the new file.\n")
	return nil
}

// renderAgent returns the instructions in the chosen format. Skill format
// wraps the body in Claude Code's YAML frontmatter; md format is the bare
// body, suitable for AGENTS.md or CLAUDE.md.
func renderAgent(format string) (string, error) {
	switch format {
	case "skill":
		return "---\nname: snapem\ndescription: " + skillDescription + "\n---\n\n" + agentBody, nil
	case "md":
		return agentBody, nil
	default:
		return "", errors.New(errors.ExitConfigError, fmt.Sprintf("unknown --format %q, want one of: skill, md", format))
	}
}

// defaultAgentPath returns the conventional install location for the given
// format. Skill goes user-global (~/.claude/skills/), md goes project-local
// (./AGENTS.md) because that's how the two conventions work.
func defaultAgentPath(format string) (string, error) {
	switch format {
	case "skill":
		home, err := os.UserHomeDir()
		if err != nil {
			return "", errors.New(errors.ExitGeneralError, fmt.Sprintf("resolve home dir: %v", err))
		}
		return filepath.Join(home, ".claude", "skills", "snapem.md"), nil
	case "md":
		return "AGENTS.md", nil
	default:
		return "", errors.New(errors.ExitConfigError, fmt.Sprintf("unknown --format %q", format))
	}
}
