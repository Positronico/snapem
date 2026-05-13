package manifest

import (
	"bufio"
	"errors"
	"os"
	"path/filepath"
	"strings"
)

// HasYarnLockfile reports whether yarn.lock exists in the project.
func (p *Parser) HasYarnLockfile() bool {
	_, err := os.Stat(filepath.Join(p.projectDir, "yarn.lock"))
	return err == nil
}

// ParseYarnLockfile reads yarn.lock and returns every (name, version)
// tuple referenced in it.
//
// Format: yarn v1 emits blocks of the form
//
//	"name@^x.y.z", "name@~x.y.z":
//	  version "x.y.z"
//	  resolved "..."
//	  integrity "..."
//	  dependencies:
//	    ...
//
// We scan for block headers (lines that don't start with whitespace and
// end with `:`) and the immediate `version "..."` lines beneath them.
// yarn Berry (v2+) writes a YAML-ish format that this parser does NOT
// fully handle; the common case (single resolved version per package
// spec) still works because the leading-header convention is similar.
//
// Returns (nil, nil) when no yarn.lock exists.
func (p *Parser) ParseYarnLockfile() ([]Package, error) {
	path := filepath.Join(p.projectDir, "yarn.lock")
	f, err := os.Open(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	defer f.Close()

	seen := make(map[string]struct{})
	var out []Package
	var pendingName string

	scanner := bufio.NewScanner(f)
	// yarn.lock entries can have long dependency lists; bump the buffer.
	scanner.Buffer(make([]byte, 1024*1024), 4*1024*1024)
	for scanner.Scan() {
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)

		// Skip blanks and comments.
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			pendingName = ""
			continue
		}

		// Block headers are flush-left and end with ':'. Indented lines
		// are body content.
		isIndented := len(line) > 0 && (line[0] == ' ' || line[0] == '\t')

		if !isIndented && strings.HasSuffix(trimmed, ":") {
			// One block can have multiple package specs separated by ", ".
			// They all resolve to the same version, so we only need the
			// first one to extract the name.
			header := strings.TrimSuffix(trimmed, ":")
			first := strings.SplitN(header, ",", 2)[0]
			first = strings.TrimSpace(first)
			first = strings.Trim(first, `"`)
			pendingName = packageNameFromYarnSpec(first)
			continue
		}

		// Inside a block — look for the version line.
		if isIndented && pendingName != "" {
			if v, ok := versionFromYarnLine(trimmed); ok {
				key := pendingName + "@" + v
				if _, dup := seen[key]; !dup {
					seen[key] = struct{}{}
					out = append(out, Package{
						Name:      pendingName,
						Version:   v,
						Ecosystem: "npm",
					})
				}
				pendingName = "" // consumed
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

// packageNameFromYarnSpec strips the version range from a yarn block-header
// spec. yarn v1: "lodash@^4.17.21". Scoped: "@types/node@20.10.0".
// Berry: same shape but spec may have "npm:" protocol prefix —
// "react@npm:18.2.0"; we strip it.
func packageNameFromYarnSpec(spec string) string {
	// Scoped packages: name starts with '@'; find the SECOND '@' as the
	// version separator. Same convention as everywhere else in the
	// codebase (see splitListEntry in internal/config).
	if strings.HasPrefix(spec, "@") {
		rest := spec[1:]
		i := strings.IndexByte(rest, '@')
		if i < 0 {
			return ""
		}
		return spec[:i+1]
	}
	if i := strings.IndexByte(spec, '@'); i > 0 {
		return spec[:i]
	}
	return ""
}

// versionFromYarnLine extracts the value of a `version "x.y.z"` line.
func versionFromYarnLine(line string) (string, bool) {
	const prefix = "version "
	if !strings.HasPrefix(line, prefix) {
		return "", false
	}
	val := strings.TrimSpace(strings.TrimPrefix(line, prefix))
	// yarn v1 quotes the version; Berry sometimes doesn't.
	val = strings.Trim(val, `"`)
	if val == "" {
		return "", false
	}
	return val, true
}
