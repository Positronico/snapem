package manifest

import (
	"errors"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// pnpmLockfile is the subset of pnpm-lock.yaml fields we need.
// pnpm v9+ writes the resolved tree under `snapshots`. Older versions
// (v6-v8) used `packages` with slightly different key formats; we
// support both.
type pnpmLockfile struct {
	LockfileVersion any                       `yaml:"lockfileVersion"`
	Snapshots       map[string]map[string]any `yaml:"snapshots"`
	Packages        map[string]map[string]any `yaml:"packages"`
}

// HasPnpmLockfile reports whether pnpm-lock.yaml exists in the project.
func (p *Parser) HasPnpmLockfile() bool {
	_, err := os.Stat(filepath.Join(p.projectDir, "pnpm-lock.yaml"))
	return err == nil
}

// ParsePnpmLockfile returns every (name, version) tuple referenced in
// pnpm-lock.yaml. Peer-dependency suffixes like
// "react@18.2.0(some-peer@1.0.0)" are stripped to "react@18.2.0".
// Returns (nil, nil) if no pnpm-lock.yaml exists.
func (p *Parser) ParsePnpmLockfile() ([]Package, error) {
	path := filepath.Join(p.projectDir, "pnpm-lock.yaml")
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}

	var lock pnpmLockfile
	if err := yaml.Unmarshal(data, &lock); err != nil {
		return nil, err
	}

	// Prefer snapshots (pnpm v9+); fall back to packages (v6-v8).
	keys := lock.Snapshots
	if len(keys) == 0 {
		keys = lock.Packages
	}

	seen := make(map[string]struct{}, len(keys))
	out := make([]Package, 0, len(keys))
	for key := range keys {
		name, version, ok := splitPnpmKey(key)
		if !ok {
			continue
		}
		coord := name + "@" + version
		if _, dup := seen[coord]; dup {
			continue
		}
		seen[coord] = struct{}{}
		out = append(out, Package{
			Name:      name,
			Version:   version,
			Ecosystem: "npm",
		})
	}
	return out, nil
}

// splitPnpmKey parses pnpm's snapshot/packages key into (name, version).
// Handles:
//
//   - v9+ snapshots: "lodash@4.17.21" or "@types/node@20.10.0"
//   - v9+ with peer suffix: "react@18.2.0(some-peer@1.0.0)"
//   - v6-v8 packages: "/lodash/4.17.21" or "/@types/node/20.10.0"
//
// Returns ok=false for keys we can't make sense of (workspace refs,
// link: protocols, etc.).
func splitPnpmKey(key string) (name, version string, ok bool) {
	// Strip a trailing "(peer@x.y)" qualifier if present.
	if i := strings.IndexByte(key, '('); i >= 0 {
		key = key[:i]
	}

	// v6-v8 leading-slash form: "/lodash/4.17.21".
	if strings.HasPrefix(key, "/") {
		rest := key[1:]
		// Scoped packages: "@types/node/20.10.0" - find the last '/'.
		idx := strings.LastIndex(rest, "/")
		if idx <= 0 || idx == len(rest)-1 {
			return "", "", false
		}
		return rest[:idx], rest[idx+1:], true
	}

	// v9+ "name@version" form. Same scoped-aware logic as parsePackageArg.
	if strings.HasPrefix(key, "@") {
		rest := key[1:]
		for i := len(rest) - 1; i >= 0; i-- {
			if rest[i] == '@' {
				idx := i + 1
				name, version = key[:idx], key[idx+1:]
				return validatePnpmVersion(name, version)
			}
		}
		return "", "", false
	}
	for i := len(key) - 1; i >= 0; i-- {
		if key[i] == '@' {
			name, version = key[:i], key[i+1:]
			return validatePnpmVersion(name, version)
		}
	}
	return "", "", false
}

// validatePnpmVersion rejects non-registry version specs that pnpm uses for
// local file/link/git references.
func validatePnpmVersion(name, version string) (string, string, bool) {
	if name == "" || version == "" {
		return "", "", false
	}
	if strings.Contains(version, ":") {
		return "", "", false
	}
	return name, version, true
}
