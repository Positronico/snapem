package manifest

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"

	"github.com/positronico/snapem/internal/errors"
)

// Package represents a dependency package
type Package struct {
	Name      string `json:"name"`
	Version   string `json:"version"`
	Ecosystem string `json:"ecosystem"`
}

// PURL returns the Package URL for this package
func (p *Package) PURL() string {
	return "pkg:" + p.Ecosystem + "/" + p.Name + "@" + p.Version
}

// Manifest represents a parsed package.json
type Manifest struct {
	Name            string            `json:"name"`
	Version         string            `json:"version"`
	Scripts         map[string]string `json:"scripts"`
	Dependencies    map[string]string `json:"dependencies"`
	DevDependencies map[string]string `json:"devDependencies"`
}

// PackageLock represents a parsed package-lock.json
type PackageLock struct {
	Name            string                    `json:"name"`
	Version         string                    `json:"version"`
	LockfileVersion int                       `json:"lockfileVersion"`
	Packages        map[string]PackageLockPkg `json:"packages"`
}

// PackageLockPkg represents a package in the lockfile
type PackageLockPkg struct {
	Version   string `json:"version"`
	Resolved  string `json:"resolved"`
	Integrity string `json:"integrity"`
	Dev       bool   `json:"dev"`
}

// Parser handles manifest file parsing
type Parser struct {
	projectDir string
}

// NewParser creates a new manifest parser for the given directory
func NewParser(projectDir string) *Parser {
	return &Parser{
		projectDir: projectDir,
	}
}

// ParseManifest reads and parses package.json
func (p *Parser) ParseManifest() (*Manifest, error) {
	path := filepath.Join(p.projectDir, "package.json")
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, errors.ManifestError("failed to read package.json", err)
	}

	var manifest Manifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		return nil, errors.ManifestError("failed to parse package.json", err)
	}

	return &manifest, nil
}

// ParseLockfile reads and parses package-lock.json
func (p *Parser) ParseLockfile() (*PackageLock, error) {
	path := filepath.Join(p.projectDir, "package-lock.json")
	data, err := os.ReadFile(path)
	if err != nil {
		// Lockfile might not exist, which is okay
		return nil, nil
	}

	var lockfile PackageLock
	if err := json.Unmarshal(data, &lockfile); err != nil {
		return nil, errors.ManifestError("failed to parse package-lock.json", err)
	}

	return &lockfile, nil
}

// HasLockfile returns true if a lockfile exists
func (p *Parser) HasLockfile() bool {
	_, err := os.Stat(filepath.Join(p.projectDir, "package-lock.json"))
	return err == nil
}

// HasBunLockfile returns true if a bun.lockb exists
func (p *Parser) HasBunLockfile() bool {
	_, err := os.Stat(filepath.Join(p.projectDir, "bun.lockb"))
	return err == nil
}

// GetDependencies extracts every dependency from whichever lockfile this
// project uses, falling back to package.json's declared (possibly ranged)
// versions when no lockfile is available.
//
// Preference order:
//  1. bun.lock (text, bun 1.1+)
//  2. package-lock.json (npm v7+, LockfileVersion >= 2)
//  3. package.json — top-level only; transitive deps are not visible
//
// Bun's legacy bun.lockb is binary and not parseable here; if it's the
// only artifact we have, the caller still gets a result but only from
// package.json, and Notes is populated so the CLI can warn the user.
func (p *Parser) GetDependencies(includeDev bool) ([]Package, error) {
	pkgs, _, err := p.GetDependenciesWithNotes(includeDev)
	return pkgs, err
}

// GetDependenciesWithNotes is GetDependencies plus advisory messages that
// the caller should surface to the user (e.g. "you have only bun.lockb,
// transitive scanning unavailable"). Notes are non-fatal.
func (p *Parser) GetDependenciesWithNotes(includeDev bool) ([]Package, []string, error) {
	var notes []string

	// 1) Prefer bun.lock when present — it carries the full resolved tree.
	if p.HasBunTextLockfile() {
		pkgs, err := p.ParseBunLockfile()
		if err != nil {
			return nil, notes, err
		}
		return pkgs, notes, nil
	}

	// 2) pnpm-lock.yaml — same idea.
	if p.HasPnpmLockfile() {
		pkgs, err := p.ParsePnpmLockfile()
		if err != nil {
			return nil, notes, err
		}
		return pkgs, notes, nil
	}

	// 3) npm lockfile v2+ — the well-trodden path.
	lockfile, _ := p.ParseLockfile() // Ignore error, lockfile is optional
	if lockfile != nil && lockfile.LockfileVersion >= 2 {
		var pkgs []Package
		for pkgPath, pkgInfo := range lockfile.Packages {
			if pkgPath == "" {
				continue
			}
			if pkgInfo.Dev && !includeDev {
				continue
			}
			name := extractPackageName(pkgPath)
			if name == "" || pkgInfo.Version == "" {
				continue
			}
			pkgs = append(pkgs, Package{
				Name:      name,
				Version:   pkgInfo.Version,
				Ecosystem: "npm",
			})
		}
		return pkgs, notes, nil
	}

	// 3) Fallback. Warn the user if we suspect we're missing transitive
	// data they would expect to be scanned.
	manifest, err := p.ParseManifest()
	if err != nil {
		return nil, notes, err
	}
	if p.HasBunLockfile() {
		notes = append(notes,
			"Only bun.lockb (binary) found. Transitive scanning is unavailable. "+
				"Run `bun install --save-text-lockfile` (bun 1.1+) or upgrade to bun 1.2+ "+
				"to emit bun.lock and get full coverage.")
	} else if !p.HasLockfile() {
		notes = append(notes,
			"No lockfile found. Scanning declared dependencies only; "+
				"transitive packages will not be checked.")
	}

	var pkgs []Package
	for name, version := range manifest.Dependencies {
		pkgs = append(pkgs, Package{
			Name:      name,
			Version:   cleanVersion(version),
			Ecosystem: "npm",
		})
	}
	if includeDev {
		for name, version := range manifest.DevDependencies {
			pkgs = append(pkgs, Package{
				Name:      name,
				Version:   cleanVersion(version),
				Ecosystem: "npm",
			})
		}
	}
	return pkgs, notes, nil
}

// GetDirectDependencies returns only direct dependencies from package.json
func (p *Parser) GetDirectDependencies(includeDev bool) ([]Package, error) {
	manifest, err := p.ParseManifest()
	if err != nil {
		return nil, err
	}

	var packages []Package

	for name, version := range manifest.Dependencies {
		packages = append(packages, Package{
			Name:      name,
			Version:   cleanVersion(version),
			Ecosystem: "npm",
		})
	}

	if includeDev {
		for name, version := range manifest.DevDependencies {
			packages = append(packages, Package{
				Name:      name,
				Version:   cleanVersion(version),
				Ecosystem: "npm",
			})
		}
	}

	return packages, nil
}

// cleanVersion removes version prefixes like ^ and ~
func cleanVersion(version string) string {
	if len(version) == 0 {
		return version
	}
	// Remove common prefixes
	for _, prefix := range []string{"^", "~", ">=", "<=", ">", "<", "="} {
		if len(version) > len(prefix) && version[:len(prefix)] == prefix {
			return version[len(prefix):]
		}
	}
	return version
}

// DetectPackageManager determines which package manager to use
func (p *Parser) DetectPackageManager() string {
	// Check for bun.lockb first
	if p.HasBunLockfile() {
		return "bun"
	}
	// Default to npm
	return "npm"
}

// HasManifest returns true if package.json exists
func (p *Parser) HasManifest() bool {
	_, err := os.Stat(filepath.Join(p.projectDir, "package.json"))
	return err == nil
}

// extractPackageName extracts the package name from a lockfile path.
// Handles both scoped (@scope/name) and unscoped (name) packages,
// including nested dependencies.
// Examples:
//   - "node_modules/lodash" -> "lodash"
//   - "node_modules/@babel/core" -> "@babel/core"
//   - "node_modules/express/node_modules/debug" -> "debug"
//   - "node_modules/@babel/core/node_modules/@types/node" -> "@types/node"
func extractPackageName(pkgPath string) string {
	const prefix = "node_modules/"

	// Find the last occurrence of "node_modules/" to handle nested deps
	lastIdx := strings.LastIndex(pkgPath, prefix)
	if lastIdx == -1 {
		// Unexpected format, fall back to basename
		return filepath.Base(pkgPath)
	}

	// Extract everything after the last "node_modules/"
	return pkgPath[lastIdx+len(prefix):]
}
