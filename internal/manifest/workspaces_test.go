package manifest

import (
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"testing"
)

// writeJSON writes data at path/name with parent directories created.
func writeJSON(t *testing.T, dir, name, body string) {
	t.Helper()
	full := filepath.Join(dir, name)
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(full, []byte(body), 0o644); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
}

func TestWorkspaceList_UnmarshalArrayForm(t *testing.T) {
	dir := t.TempDir()
	writeJSON(t, dir, "package.json", `{
  "name": "root",
  "workspaces": ["packages/*", "apps/web"]
}`)
	p := NewParser(dir)
	m, err := p.ParseManifest()
	if err != nil {
		t.Fatalf("ParseManifest: %v", err)
	}
	want := []string{"packages/*", "apps/web"}
	if !reflect.DeepEqual([]string(m.Workspaces), want) {
		t.Errorf("Workspaces = %v, want %v", m.Workspaces, want)
	}
}

func TestWorkspaceList_UnmarshalYarnObjectForm(t *testing.T) {
	dir := t.TempDir()
	writeJSON(t, dir, "package.json", `{
  "name": "root",
  "workspaces": {
    "packages": ["packages/*"],
    "nohoist": ["**/react-native"]
  }
}`)
	p := NewParser(dir)
	m, err := p.ParseManifest()
	if err != nil {
		t.Fatalf("ParseManifest: %v", err)
	}
	want := []string{"packages/*"}
	if !reflect.DeepEqual([]string(m.Workspaces), want) {
		t.Errorf("Workspaces = %v, want %v (nohoist must be discarded)", m.Workspaces, want)
	}
}

func TestWorkspaceList_UnmarshalAbsent(t *testing.T) {
	dir := t.TempDir()
	writeJSON(t, dir, "package.json", `{"name": "root"}`)
	p := NewParser(dir)
	m, err := p.ParseManifest()
	if err != nil {
		t.Fatalf("ParseManifest: %v", err)
	}
	if len(m.Workspaces) != 0 {
		t.Errorf("Workspaces should be empty, got %v", m.Workspaces)
	}
}

func TestParsePnpmWorkspaceConfig(t *testing.T) {
	dir := t.TempDir()
	writeJSON(t, dir, "pnpm-workspace.yaml", `packages:
  - 'packages/*'
  - 'apps/*'
  - '!packages/excluded'
`)
	p := NewParser(dir)
	if !p.HasPnpmWorkspaceConfig() {
		t.Fatal("HasPnpmWorkspaceConfig=false, want true")
	}
	got, err := p.ParsePnpmWorkspaceConfig()
	if err != nil {
		t.Fatalf("ParsePnpmWorkspaceConfig: %v", err)
	}
	want := []string{"packages/*", "apps/*", "!packages/excluded"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestParsePnpmWorkspaceConfig_Absent(t *testing.T) {
	p := NewParser(t.TempDir())
	got, err := p.ParsePnpmWorkspaceConfig()
	if err != nil {
		t.Errorf("absent file should not error: %v", err)
	}
	if got != nil {
		t.Errorf("expected nil, got %v", got)
	}
}

func TestWorkspacePatterns_PnpmTakesPrecedence(t *testing.T) {
	// If both pnpm-workspace.yaml and package.json's workspaces field
	// exist, pnpm-workspace.yaml wins — that's what pnpm itself does.
	dir := t.TempDir()
	writeJSON(t, dir, "package.json", `{"workspaces": ["from-package-json/*"]}`)
	writeJSON(t, dir, "pnpm-workspace.yaml", `packages:
  - 'from-yaml/*'
`)
	p := NewParser(dir)
	got, err := p.WorkspacePatterns()
	if err != nil {
		t.Fatalf("WorkspacePatterns: %v", err)
	}
	if !reflect.DeepEqual(got, []string{"from-yaml/*"}) {
		t.Errorf("got %v, want pnpm yaml to win", got)
	}
}

func TestIsWorkspace(t *testing.T) {
	t.Run("non-workspace", func(t *testing.T) {
		dir := t.TempDir()
		writeJSON(t, dir, "package.json", `{"name": "solo"}`)
		p := NewParser(dir)
		is, err := p.IsWorkspace()
		if err != nil {
			t.Fatalf("IsWorkspace: %v", err)
		}
		if is {
			t.Error("solo package wrongly reported as workspace")
		}
	})

	t.Run("workspace root", func(t *testing.T) {
		dir := t.TempDir()
		writeJSON(t, dir, "package.json", `{"workspaces": ["packages/*"]}`)
		p := NewParser(dir)
		is, err := p.IsWorkspace()
		if err != nil {
			t.Fatalf("IsWorkspace: %v", err)
		}
		if !is {
			t.Error("workspace root not detected")
		}
	})
}

func TestResolveWorkspaceMembers_GlobExpansion(t *testing.T) {
	dir := t.TempDir()
	writeJSON(t, dir, "package.json", `{"workspaces": ["packages/*"]}`)
	writeJSON(t, dir, "packages/a/package.json", `{"name": "a"}`)
	writeJSON(t, dir, "packages/b/package.json", `{"name": "b"}`)
	// A directory under packages/ without a package.json should be skipped.
	if err := os.MkdirAll(filepath.Join(dir, "packages/not-a-pkg"), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	p := NewParser(dir)
	members, err := p.ResolveWorkspaceMembers()
	if err != nil {
		t.Fatalf("ResolveWorkspaceMembers: %v", err)
	}
	if len(members) != 2 {
		t.Fatalf("expected 2 members, got %d: %v", len(members), members)
	}
	sort.Strings(members)
	expectA, _ := filepath.Abs(filepath.Join(dir, "packages/a"))
	expectB, _ := filepath.Abs(filepath.Join(dir, "packages/b"))
	if members[0] != expectA || members[1] != expectB {
		t.Errorf("members = %v, want [%s %s]", members, expectA, expectB)
	}
}

func TestResolveWorkspaceMembers_ExactPath(t *testing.T) {
	dir := t.TempDir()
	writeJSON(t, dir, "package.json", `{"workspaces": ["apps/web", "shared/utils"]}`)
	writeJSON(t, dir, "apps/web/package.json", `{"name": "web"}`)
	writeJSON(t, dir, "shared/utils/package.json", `{"name": "utils"}`)

	p := NewParser(dir)
	members, err := p.ResolveWorkspaceMembers()
	if err != nil {
		t.Fatalf("ResolveWorkspaceMembers: %v", err)
	}
	if len(members) != 2 {
		t.Errorf("expected 2 members, got %d: %v", len(members), members)
	}
}

func TestResolveWorkspaceMembers_PnpmExclusion(t *testing.T) {
	dir := t.TempDir()
	writeJSON(t, dir, "pnpm-workspace.yaml", `packages:
  - 'packages/*'
  - '!packages/legacy'
`)
	writeJSON(t, dir, "packages/keep/package.json", `{"name": "keep"}`)
	writeJSON(t, dir, "packages/legacy/package.json", `{"name": "legacy"}`)

	p := NewParser(dir)
	members, err := p.ResolveWorkspaceMembers()
	if err != nil {
		t.Fatalf("ResolveWorkspaceMembers: %v", err)
	}
	if len(members) != 1 {
		t.Fatalf("expected 1 member after exclusion, got %d: %v", len(members), members)
	}
	if filepath.Base(members[0]) != "keep" {
		t.Errorf("wrong member kept: %v", members[0])
	}
}

func TestResolveWorkspaceMembers_DoubleStarSkipped(t *testing.T) {
	dir := t.TempDir()
	writeJSON(t, dir, "package.json", `{"workspaces": ["packages/**"]}`)
	writeJSON(t, dir, "packages/a/package.json", `{"name": "a"}`)

	p := NewParser(dir)
	members, err := p.ResolveWorkspaceMembers()
	if err != nil {
		t.Fatalf("ResolveWorkspaceMembers: %v", err)
	}
	// `**` is documented as unsupported. We skip it silently; caller
	// gets no members instead of a parse error.
	if len(members) != 0 {
		t.Errorf("expected 0 members for ** pattern, got %v", members)
	}
}

func TestResolveWorkspaceMembers_DedupesAcrossPatterns(t *testing.T) {
	dir := t.TempDir()
	writeJSON(t, dir, "package.json", `{"workspaces": ["packages/*", "packages/a"]}`)
	writeJSON(t, dir, "packages/a/package.json", `{"name": "a"}`)

	p := NewParser(dir)
	members, err := p.ResolveWorkspaceMembers()
	if err != nil {
		t.Fatalf("ResolveWorkspaceMembers: %v", err)
	}
	if len(members) != 1 {
		t.Errorf("expected 1 member after dedup, got %d: %v", len(members), members)
	}
}

func TestResolveWorkspaceMembers_NonWorkspace(t *testing.T) {
	dir := t.TempDir()
	writeJSON(t, dir, "package.json", `{"name": "solo"}`)
	p := NewParser(dir)
	members, err := p.ResolveWorkspaceMembers()
	if err != nil {
		t.Fatalf("ResolveWorkspaceMembers: %v", err)
	}
	if members != nil {
		t.Errorf("non-workspace should return nil, got %v", members)
	}
}

func TestGetWorkspaceDirectDeps_UnionsRootAndMembers(t *testing.T) {
	dir := t.TempDir()
	// Root: only devDeps + workspaces field; common monorepo shape.
	writeJSON(t, dir, "package.json", `{
  "name": "root",
  "workspaces": ["packages/*"],
  "devDependencies": { "typescript": "5.0.0" }
}`)
	writeJSON(t, dir, "packages/api/package.json", `{
  "name": "api",
  "dependencies": { "express": "^4.18.0", "lodash": "4.17.20" }
}`)
	writeJSON(t, dir, "packages/web/package.json", `{
  "name": "web",
  "dependencies": { "react": "18.2.0", "lodash": "4.17.20" }
}`)

	p := NewParser(dir)
	deps, err := p.GetWorkspaceDirectDeps(true)
	if err != nil {
		t.Fatalf("GetWorkspaceDirectDeps: %v", err)
	}

	got := make(map[string]string)
	for _, d := range deps {
		got[d.Name] = d.Version
	}
	want := map[string]string{
		"typescript": "5.0.0",
		"express":    "4.18.0", // cleanVersion strips ^
		"lodash":     "4.17.20",
		"react":      "18.2.0",
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestGetWorkspaceDirectDeps_ExcludesDevWhenAsked(t *testing.T) {
	dir := t.TempDir()
	writeJSON(t, dir, "package.json", `{
  "workspaces": ["packages/*"],
  "devDependencies": { "typescript": "5.0.0" }
}`)
	writeJSON(t, dir, "packages/api/package.json", `{
  "dependencies": { "express": "4.18.2" },
  "devDependencies": { "jest": "29.0.0" }
}`)

	p := NewParser(dir)
	deps, err := p.GetWorkspaceDirectDeps(false)
	if err != nil {
		t.Fatalf("GetWorkspaceDirectDeps: %v", err)
	}
	got := make(map[string]string)
	for _, d := range deps {
		got[d.Name] = d.Version
	}
	if _, ok := got["typescript"]; ok {
		t.Errorf("typescript (devDep) should not appear when includeDev=false")
	}
	if _, ok := got["jest"]; ok {
		t.Errorf("jest (member devDep) should not appear when includeDev=false")
	}
	if got["express"] != "4.18.2" {
		t.Errorf("express should be included, got %v", got)
	}
}

func TestGetWorkspaceDirectDeps_NonWorkspaceMatchesGetDirectDeps(t *testing.T) {
	dir := t.TempDir()
	writeJSON(t, dir, "package.json", `{
  "dependencies": { "express": "4.18.2" }
}`)
	p := NewParser(dir)
	got, err := p.GetWorkspaceDirectDeps(true)
	if err != nil {
		t.Fatalf("GetWorkspaceDirectDeps: %v", err)
	}
	if len(got) != 1 || got[0].Name != "express" {
		t.Errorf("non-workspace fallback broken, got %v", got)
	}
}

func TestGetWorkspaceDirectDeps_SkipsUnparseableMember(t *testing.T) {
	// A workspace member with malformed JSON shouldn't sink the upgrade.
	dir := t.TempDir()
	writeJSON(t, dir, "package.json", `{"workspaces": ["packages/*"]}`)
	writeJSON(t, dir, "packages/good/package.json", `{"dependencies": {"lodash": "4.17.20"}}`)
	writeJSON(t, dir, "packages/bad/package.json", `{ this is not json`)

	p := NewParser(dir)
	deps, err := p.GetWorkspaceDirectDeps(true)
	if err != nil {
		t.Fatalf("GetWorkspaceDirectDeps must not fail on bad member: %v", err)
	}
	got := make(map[string]string)
	for _, d := range deps {
		got[d.Name] = d.Version
	}
	if got["lodash"] != "4.17.20" {
		t.Errorf("good member's deps lost: %v", got)
	}
}
