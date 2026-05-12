// Package cache persists scan results so repeat invocations don't re-query
// OSV / Socket for packages that haven't changed. Keyed by
// (scanner, ecosystem, name, version) with a TTL from configuration.
//
// The cache is intentionally per-package rather than per-scan-batch: a user
// who runs `snapem scan` and then `snapem install lodash` should reuse all
// the cached records for the unchanged dependencies and only fetch lodash.
package cache

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/positronico/snapem/internal/types"
)

// schemaVersion is bumped whenever the Finding shape or this Entry layout
// changes. Old files with a different schemaVersion are treated as a miss
// rather than failing the read.
//
// History:
//
//	1 — initial cache shape (v0.3.0)
//	2 — Finding gained FixedVersions field; old entries returning without
//	    it would make `snapem upgrade` show "no fix info" for 24h after a
//	    user upgrades snapem, so we invalidate on bump (v0.4.0+)
const schemaVersion = 2

// Entry is what we persist per (scanner, ecosystem, name, version) tuple.
type Entry struct {
	SchemaVersion int             `json:"schema_version"`
	Scanner       string          `json:"scanner"`
	Ecosystem     string          `json:"ecosystem"`
	Package       string          `json:"package"`
	Version       string          `json:"version"`
	CachedAt      time.Time       `json:"cached_at"`
	Findings      []types.Finding `json:"findings"`
}

// Store reads and writes scanner findings keyed by package coordinates.
// Implementations are safe for sequential use from a single CLI invocation
// but do not lock against concurrent processes — last-write-wins is fine
// because the value is derived from upstream APIs that we re-query freely.
type Store interface {
	// Get returns the entry for the tuple if one exists and is younger than
	// maxAge. Cache misses, expired entries, and unreadable files all
	// return (nil, nil) — the caller fetches fresh.
	Get(scanner, ecosystem, name, version string, maxAge time.Duration) (*Entry, error)

	// Put writes the entry. Errors are returned but typically logged and
	// ignored by callers — a failed write degrades performance, not
	// correctness.
	Put(entry *Entry) error
}

// FileStore stores one JSON file per cache entry under Dir. Filenames are
// sha256 hashes of the key so we don't have to escape package names like
// "@scope/name" for the filesystem.
type FileStore struct {
	Dir string
}

// NewFileStore returns a FileStore rooted at dir, creating it if missing.
func NewFileStore(dir string) (*FileStore, error) {
	if dir == "" {
		return nil, errors.New("cache: directory must not be empty")
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("cache: create dir: %w", err)
	}
	return &FileStore{Dir: dir}, nil
}

func (s *FileStore) path(scanner, ecosystem, name, version string) string {
	key := scanner + "|" + ecosystem + "|" + name + "|" + version
	sum := sha256.Sum256([]byte(key))
	return filepath.Join(s.Dir, hex.EncodeToString(sum[:])+".json")
}

// Get implements Store.
func (s *FileStore) Get(scanner, ecosystem, name, version string, maxAge time.Duration) (*Entry, error) {
	p := s.path(scanner, ecosystem, name, version)
	data, err := os.ReadFile(p)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, nil // unreadable -> treat as miss, don't bubble
	}
	var e Entry
	if err := json.Unmarshal(data, &e); err != nil {
		// Corrupt file: treat as miss. The next Put will overwrite.
		return nil, nil
	}
	if e.SchemaVersion != schemaVersion {
		return nil, nil
	}
	if maxAge > 0 && time.Since(e.CachedAt) > maxAge {
		return nil, nil
	}
	return &e, nil
}

// Stats reports the number of cache entries and total bytes used by them.
// Stale-on-disk files that don't parse are still counted.
type Stats struct {
	Entries int
	Bytes   int64
}

// Stat walks the cache directory and returns aggregate counts.
func (s *FileStore) Stat() (Stats, error) {
	var out Stats
	entries, err := os.ReadDir(s.Dir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return out, nil
		}
		return out, err
	}
	for _, e := range entries {
		if e.IsDir() || filepath.Ext(e.Name()) != ".json" {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		out.Entries++
		out.Bytes += info.Size()
	}
	return out, nil
}

// Clear deletes every cache entry under the store directory. The directory
// itself is left in place so subsequent Put calls don't need to recreate it.
func (s *FileStore) Clear() (int, error) {
	entries, err := os.ReadDir(s.Dir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return 0, nil
		}
		return 0, err
	}
	deleted := 0
	for _, e := range entries {
		if e.IsDir() || filepath.Ext(e.Name()) != ".json" {
			continue
		}
		if err := os.Remove(filepath.Join(s.Dir, e.Name())); err == nil {
			deleted++
		}
	}
	return deleted, nil
}

// Put implements Store via atomic temp-file + rename.
func (s *FileStore) Put(entry *Entry) error {
	if entry == nil {
		return errors.New("cache: nil entry")
	}
	entry.SchemaVersion = schemaVersion
	if entry.CachedAt.IsZero() {
		entry.CachedAt = time.Now().UTC()
	}
	if entry.Findings == nil {
		entry.Findings = []types.Finding{}
	}

	p := s.path(entry.Scanner, entry.Ecosystem, entry.Package, entry.Version)
	tmp, err := os.CreateTemp(s.Dir, "snapem-cache-*.tmp")
	if err != nil {
		return fmt.Errorf("cache: create temp: %w", err)
	}
	cleanup := func() {
		tmp.Close()
		os.Remove(tmp.Name())
	}

	if err := json.NewEncoder(tmp).Encode(entry); err != nil {
		cleanup()
		return fmt.Errorf("cache: encode: %w", err)
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmp.Name())
		return fmt.Errorf("cache: close temp: %w", err)
	}
	if err := os.Rename(tmp.Name(), p); err != nil {
		os.Remove(tmp.Name())
		return fmt.Errorf("cache: rename: %w", err)
	}
	return nil
}
