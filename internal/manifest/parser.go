package manifest

import (
	"encoding/json"
	"os"
	"path/filepath"

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

// GetDependencies extracts all dependencies from manifest and lockfile
func (p *Parser) GetDependencies(includeDev bool) ([]Package, error) {
	manifest, err := p.ParseManifest()
	if err != nil {
		return nil, err
	}

	lockfile, _ := p.ParseLockfile() // Ignore error, lockfile is optional

	var packages []Package

	// If we have a lockfile, use exact versions from it
	if lockfile != nil && lockfile.LockfileVersion >= 2 {
		for pkgPath, pkgInfo := range lockfile.Packages {
			// Skip root package
			if pkgPath == "" {
				continue
			}
			// Skip dev dependencies if not included
			if pkgInfo.Dev && !includeDev {
				continue
			}
			// Extract package name from path (e.g., "node_modules/lodash" -> "lodash")
			name := filepath.Base(pkgPath)
			if name == "" || pkgInfo.Version == "" {
				continue
			}
			packages = append(packages, Package{
				Name:      name,
				Version:   pkgInfo.Version,
				Ecosystem: "npm",
			})
		}
	} else {
		// Fall back to manifest versions (may include ranges)
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
	}

	return packages, nil
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
