package manifest

import (
	stderrors "errors"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/positronico/snapem/internal/errors"
)

// pnpmWorkspaceConfig is the subset of pnpm-workspace.yaml we read.
//
// Reference: https://pnpm.io/pnpm-workspace_yaml — only `packages`
// matters for member discovery; other keys (catalog, save-exact, etc.)
// are runtime/install config that doesn't change the dependency tree.
type pnpmWorkspaceConfig struct {
	Packages []string `yaml:"packages"`
}

// HasPnpmWorkspaceConfig reports whether pnpm-workspace.yaml exists.
func (p *Parser) HasPnpmWorkspaceConfig() bool {
	_, err := os.Stat(filepath.Join(p.projectDir, "pnpm-workspace.yaml"))
	return err == nil
}

// ParsePnpmWorkspaceConfig returns the workspace glob patterns declared
// in pnpm-workspace.yaml. Returns (nil, nil) when the file is absent.
func (p *Parser) ParsePnpmWorkspaceConfig() ([]string, error) {
	path := filepath.Join(p.projectDir, "pnpm-workspace.yaml")
	data, err := os.ReadFile(path)
	if err != nil {
		if stderrors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, errors.ManifestError("failed to read pnpm-workspace.yaml", err)
	}
	var cfg pnpmWorkspaceConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, errors.ManifestError("failed to parse pnpm-workspace.yaml", err)
	}
	return cfg.Packages, nil
}

// WorkspacePatterns returns the configured workspace glob patterns for
// this project. For pnpm it reads pnpm-workspace.yaml; for npm/bun/yarn
// it reads the `workspaces` field from package.json. Returns (nil, nil)
// when no workspace config is present.
func (p *Parser) WorkspacePatterns() ([]string, error) {
	if p.HasPnpmWorkspaceConfig() {
		return p.ParsePnpmWorkspaceConfig()
	}
	if !p.HasManifest() {
		return nil, nil
	}
	m, err := p.ParseManifest()
	if err != nil {
		return nil, err
	}
	return []string(m.Workspaces), nil
}

// IsWorkspace reports whether this project declares any workspaces.
func (p *Parser) IsWorkspace() (bool, error) {
	patterns, err := p.WorkspacePatterns()
	if err != nil {
		return false, err
	}
	return len(patterns) > 0, nil
}

// ResolveWorkspaceMembers returns absolute paths to each workspace
// member directory. Patterns support `*` (single path segment), exact
// paths, and `!`-prefixed exclusions (pnpm semantics; harmless for
// npm/bun/yarn where exclusions are not standard).
//
// `**` recursive globs are not supported — npm/bun/yarn don't define
// them, and pnpm's recursive form is rare enough to defer. Patterns
// containing `**` are skipped with no error so a future user-reported
// case can be fixed without breaking the common shape.
func (p *Parser) ResolveWorkspaceMembers() ([]string, error) {
	patterns, err := p.WorkspacePatterns()
	if err != nil {
		return nil, err
	}
	if len(patterns) == 0 {
		return nil, nil
	}

	var includes, excludes []string
	for _, pat := range patterns {
		pat = strings.TrimSpace(pat)
		if pat == "" {
			continue
		}
		if strings.HasPrefix(pat, "!") {
			excludes = append(excludes, strings.TrimPrefix(pat, "!"))
			continue
		}
		includes = append(includes, pat)
	}

	seen := make(map[string]struct{})
	var members []string

	for _, pat := range includes {
		if strings.Contains(pat, "**") {
			// Unsupported in MVP. See doc comment.
			continue
		}
		matches, err := filepath.Glob(filepath.Join(p.projectDir, pat))
		if err != nil {
			// filepath.Glob only errors on malformed pattern syntax.
			// Skip the bad pattern rather than failing the whole resolve.
			continue
		}
		for _, m := range matches {
			info, err := os.Stat(m)
			if err != nil || !info.IsDir() {
				continue
			}
			// Must have a package.json to be a workspace member.
			if _, err := os.Stat(filepath.Join(m, "package.json")); err != nil {
				continue
			}
			abs, err := filepath.Abs(m)
			if err != nil {
				continue
			}
			if matchesAny(abs, p.projectDir, excludes) {
				continue
			}
			if _, ok := seen[abs]; ok {
				continue
			}
			seen[abs] = struct{}{}
			members = append(members, abs)
		}
	}

	sort.Strings(members)
	return members, nil
}

// matchesAny reports whether absPath matches any of the exclude
// patterns when interpreted relative to projectDir.
func matchesAny(absPath, projectDir string, excludes []string) bool {
	rel, err := filepath.Rel(projectDir, absPath)
	if err != nil {
		return false
	}
	for _, pat := range excludes {
		if ok, _ := filepath.Match(pat, rel); ok {
			return true
		}
	}
	return false
}

// GetWorkspaceDirectDeps returns the union of direct dependencies
// declared in the root package.json and every workspace member's
// package.json. Used by `snapem upgrade` so findings on workspace
// member dependencies are correctly classified as direct.
//
// In a monorepo the root package.json typically has no `dependencies`
// at all (just `workspaces` and shared devDeps); without this expanded
// view every workspace finding would be misclassified as transitive.
//
// Non-workspace projects get the same result as GetDirectDependencies.
func (p *Parser) GetWorkspaceDirectDeps(includeDev bool) ([]Package, error) {
	root, err := p.GetDirectDependencies(includeDev)
	if err != nil {
		return nil, err
	}

	members, err := p.ResolveWorkspaceMembers()
	if err != nil {
		return nil, err
	}
	if len(members) == 0 {
		return root, nil
	}

	// Dedup by (name, version) — workspace members frequently share
	// devDeps with the root, and emitting duplicates would just bloat
	// the directIndex without changing classification.
	type key struct{ name, version string }
	seen := make(map[key]struct{}, len(root))
	out := make([]Package, 0, len(root))
	for _, d := range root {
		k := key{d.Name, d.Version}
		if _, ok := seen[k]; ok {
			continue
		}
		seen[k] = struct{}{}
		out = append(out, d)
	}

	for _, dir := range members {
		mp := NewParser(dir)
		deps, err := mp.GetDirectDependencies(includeDev)
		if err != nil {
			// A member with an unparseable package.json shouldn't sink
			// the whole upgrade. Skip; the user will see the underlying
			// scan still pick up the lockfile-resolved versions.
			continue
		}
		for _, d := range deps {
			k := key{d.Name, d.Version}
			if _, ok := seen[k]; ok {
				continue
			}
			seen[k] = struct{}{}
			out = append(out, d)
		}
	}

	return out, nil
}
