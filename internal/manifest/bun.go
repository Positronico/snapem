package manifest

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
)

// bunLockfile mirrors the subset of bun.lock fields we need. Bun writes
// `packages` as a map whose values are heterogeneous tuples — the first
// element is always a string of the form `<name>@<version>` (or
// `<name>@<protocol>:<rest>` for non-registry installs). We treat
// everything else as opaque.
type bunLockfile struct {
	LockfileVersion int                          `json:"lockfileVersion"`
	Packages        map[string][]json.RawMessage `json:"packages"`
}

// HasBunTextLockfile reports whether a bun.lock (text) exists in the
// project directory. This is the format bun 1.1+ supports and 1.2+
// defaults to.
func (p *Parser) HasBunTextLockfile() bool {
	_, err := os.Stat(filepath.Join(p.projectDir, "bun.lock"))
	return err == nil
}

// ParseBunLockfile reads bun.lock and returns every (name, version) tuple
// referenced by its `packages` map. Workspace, link, and other
// non-registry protocols are silently skipped because we can't scan
// them. Returns (nil, nil) if no bun.lock exists.
func (p *Parser) ParseBunLockfile() ([]Package, error) {
	path := filepath.Join(p.projectDir, "bun.lock")
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}

	var lock bunLockfile
	if err := json.Unmarshal(data, &lock); err != nil {
		return nil, err
	}

	seen := make(map[string]struct{}, len(lock.Packages))
	out := make([]Package, 0, len(lock.Packages))
	for _, tuple := range lock.Packages {
		if len(tuple) == 0 {
			continue
		}
		var spec string
		if err := json.Unmarshal(tuple[0], &spec); err != nil {
			continue
		}
		name, version, ok := splitBunPackageSpec(spec)
		if !ok {
			continue
		}
		key := name + "@" + version
		if _, dup := seen[key]; dup {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, Package{
			Name:      name,
			Version:   version,
			Ecosystem: "npm",
		})
	}
	return out, nil
}

// splitBunPackageSpec parses bun's `name@version` tuple element. Returns
// ok=false for non-registry installs (workspace:, link:, file:, etc.)
// since those aren't scannable via Socket/OSV.
func splitBunPackageSpec(spec string) (name, version string, ok bool) {
	// Scoped packages start with '@', so we find the LAST '@' as the
	// version separator (same logic as parsePackageArg in cli/install.go).
	at := strings.LastIndex(spec, "@")
	if at <= 0 {
		// Either no '@' (just a bare name, unusual) or starts with '@'
		// and has no second '@'. Either way we can't extract a version.
		return "", "", false
	}
	name = spec[:at]
	version = spec[at+1:]

	// Skip non-registry protocols: bun writes things like
	// "my-pkg@workspace:packages/foo" or "x@link:../x" for local refs.
	if strings.Contains(version, ":") {
		return "", "", false
	}
	if name == "" || version == "" {
		return "", "", false
	}
	return name, version, true
}
