package manifest

import (
	"os"
	"path/filepath"
	"sort"
	"testing"
)

// Fixture modelled on a real bun 1.2 bun.lock for a small project that
// pulls lodash, @types/node, an in-repo workspace package, and a linked
// local fork. The full bun layout has many more fields per tuple; we only
// read the first element so the rest is just realistic noise.
const bunLockFixture = `{
  "lockfileVersion": 1,
  "workspaces": {
    "": {
      "name": "smoke",
      "dependencies": {
        "lodash": "^4.17.21",
        "@types/node": "20.10.0"
      }
    }
  },
  "packages": {
    "lodash": [
      "lodash@4.17.21",
      "registry+https://registry.npmjs.org/",
      {},
      "sha512-aaaaaa"
    ],
    "@types/node": [
      "@types/node@20.10.0",
      "registry+https://registry.npmjs.org/",
      {},
      "sha512-bbbbbb"
    ],
    "@babel/core": [
      "@babel/core@7.24.0",
      "registry+https://registry.npmjs.org/",
      {},
      "sha512-cccccc"
    ],
    "my-workspace-pkg": [
      "my-workspace-pkg@workspace:packages/internal",
      "workspace"
    ],
    "my-fork": [
      "my-fork@link:../forks/my-fork",
      "link"
    ],
    "lodash-duplicated-at-different-path": [
      "lodash@4.17.21",
      "registry+https://registry.npmjs.org/",
      {},
      "sha512-aaaaaa"
    ]
  }
}`

func writeBunLock(t *testing.T, dir, contents string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, "bun.lock"), []byte(contents), 0o644); err != nil {
		t.Fatalf("write bun.lock: %v", err)
	}
}

func TestParseBunLockfile(t *testing.T) {
	dir := t.TempDir()
	writeBunLock(t, dir, bunLockFixture)

	p := NewParser(dir)
	if !p.HasBunTextLockfile() {
		t.Fatalf("HasBunTextLockfile() = false, expected true")
	}

	pkgs, err := p.ParseBunLockfile()
	if err != nil {
		t.Fatalf("ParseBunLockfile: %v", err)
	}

	// Sort for deterministic comparison.
	sort.Slice(pkgs, func(i, j int) bool { return pkgs[i].Name < pkgs[j].Name })

	want := []Package{
		{Name: "@babel/core", Version: "7.24.0", Ecosystem: "npm"},
		{Name: "@types/node", Version: "20.10.0", Ecosystem: "npm"},
		{Name: "lodash", Version: "4.17.21", Ecosystem: "npm"},
	}
	if len(pkgs) != len(want) {
		t.Fatalf("got %d packages, want %d: %+v", len(pkgs), len(want), pkgs)
	}
	for i, p := range pkgs {
		if p != want[i] {
			t.Errorf("pkg[%d] = %+v, want %+v", i, p, want[i])
		}
	}
}

func TestParseBunLockfile_NoFile(t *testing.T) {
	p := NewParser(t.TempDir())
	pkgs, err := p.ParseBunLockfile()
	if err != nil {
		t.Errorf("missing file should not error: %v", err)
	}
	if pkgs != nil {
		t.Errorf("expected nil, got %v", pkgs)
	}
}

func TestParseBunLockfile_Malformed(t *testing.T) {
	dir := t.TempDir()
	writeBunLock(t, dir, "{ not json")

	p := NewParser(dir)
	_, err := p.ParseBunLockfile()
	if err == nil {
		t.Errorf("expected parse error, got nil")
	}
}

func TestSplitBunPackageSpec(t *testing.T) {
	cases := []struct {
		in              string
		name, version   string
		ok              bool
	}{
		{"lodash@4.17.21", "lodash", "4.17.21", true},
		{"@types/node@20.10.0", "@types/node", "20.10.0", true},
		{"@scope/pkg@1.0.0-beta.1", "@scope/pkg", "1.0.0-beta.1", true},

		// Non-registry protocols — skipped.
		{"my-pkg@workspace:packages/foo", "", "", false},
		{"my-pkg@link:../foo", "", "", false},
		{"my-pkg@file:./local.tgz", "", "", false},
		{"my-pkg@git+ssh://x", "", "", false},

		// Degenerate inputs.
		{"", "", "", false},
		{"no-at-symbol", "", "", false},
		{"@only-scope", "", "", false},
		{"foo@", "", "", false},
	}

	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			n, v, ok := splitBunPackageSpec(tc.in)
			if ok != tc.ok || n != tc.name || v != tc.version {
				t.Errorf("got (%q,%q,%v), want (%q,%q,%v)",
					n, v, ok, tc.name, tc.version, tc.ok)
			}
		})
	}
}
