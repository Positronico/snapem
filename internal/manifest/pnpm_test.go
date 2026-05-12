package manifest

import (
	"os"
	"path/filepath"
	"sort"
	"testing"
)

const pnpmV9Fixture = `lockfileVersion: '9.0'

settings:
  autoInstallPeers: true

importers:
  .:
    dependencies:
      lodash:
        specifier: ^4.17.21
        version: 4.17.21

snapshots:
  lodash@4.17.21: {}
  '@types/node@20.10.0': {}
  '@babel/core@7.24.0': {}
  react@18.2.0(redux@5.0.0):
    dependencies:
      redux: 5.0.0
  redux@5.0.0: {}
`

const pnpmV8Fixture = `lockfileVersion: '6.0'

packages:
  /lodash/4.17.21:
    resolution: {integrity: sha512-x}
  /@types/node/20.10.0:
    resolution: {integrity: sha512-y}
  /@babel/core/7.24.0:
    resolution: {integrity: sha512-z}
`

func writeFile(t *testing.T, dir, name, contents string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(contents), 0o644); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
}

func TestParsePnpmLockfile_V9(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "pnpm-lock.yaml", pnpmV9Fixture)

	p := NewParser(dir)
	if !p.HasPnpmLockfile() {
		t.Fatal("HasPnpmLockfile=false, expected true")
	}

	pkgs, err := p.ParsePnpmLockfile()
	if err != nil {
		t.Fatalf("ParsePnpmLockfile: %v", err)
	}
	sort.Slice(pkgs, func(i, j int) bool { return pkgs[i].Name < pkgs[j].Name })

	want := []Package{
		{Name: "@babel/core", Version: "7.24.0", Ecosystem: "npm"},
		{Name: "@types/node", Version: "20.10.0", Ecosystem: "npm"},
		{Name: "lodash", Version: "4.17.21", Ecosystem: "npm"},
		{Name: "react", Version: "18.2.0", Ecosystem: "npm"},
		{Name: "redux", Version: "5.0.0", Ecosystem: "npm"},
	}
	if len(pkgs) != len(want) {
		t.Fatalf("got %d packages, want %d: %+v", len(pkgs), len(want), pkgs)
	}
	for i, p := range pkgs {
		if p != want[i] {
			t.Errorf("pkg[%d]=%+v, want %+v", i, p, want[i])
		}
	}
}

func TestParsePnpmLockfile_V8FallsBackToPackages(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "pnpm-lock.yaml", pnpmV8Fixture)

	p := NewParser(dir)
	pkgs, err := p.ParsePnpmLockfile()
	if err != nil {
		t.Fatalf("ParsePnpmLockfile: %v", err)
	}
	if len(pkgs) != 3 {
		t.Fatalf("got %d packages from v8 fixture, want 3: %+v", len(pkgs), pkgs)
	}
}

func TestParsePnpmLockfile_MissingFile(t *testing.T) {
	p := NewParser(t.TempDir())
	pkgs, err := p.ParsePnpmLockfile()
	if err != nil {
		t.Errorf("missing file should not error: %v", err)
	}
	if pkgs != nil {
		t.Errorf("expected nil, got %v", pkgs)
	}
}

func TestSplitPnpmKey(t *testing.T) {
	cases := []struct {
		in              string
		name, version   string
		ok              bool
	}{
		// v9+ format
		{"lodash@4.17.21", "lodash", "4.17.21", true},
		{"@types/node@20.10.0", "@types/node", "20.10.0", true},
		{"react@18.2.0(redux@5.0.0)", "react", "18.2.0", true},
		{"@scope/pkg@1.0.0(peer@2.0.0)", "@scope/pkg", "1.0.0", true},

		// v6-v8 format
		{"/lodash/4.17.21", "lodash", "4.17.21", true},
		{"/@types/node/20.10.0", "@types/node", "20.10.0", true},
		{"/@babel/core/7.24.0", "@babel/core", "7.24.0", true},

		// Non-registry protocols
		{"my-pkg@workspace:packages/foo", "", "", false},
		{"my-pkg@link:../foo", "", "", false},
		{"my-pkg@file:./local.tgz", "", "", false},

		// Degenerate
		{"", "", "", false},
		{"no-at", "", "", false},
		{"/incomplete/", "", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			n, v, ok := splitPnpmKey(tc.in)
			if ok != tc.ok || n != tc.name || v != tc.version {
				t.Errorf("splitPnpmKey(%q)=(%q,%q,%v), want (%q,%q,%v)",
					tc.in, n, v, ok, tc.name, tc.version, tc.ok)
			}
		})
	}
}
