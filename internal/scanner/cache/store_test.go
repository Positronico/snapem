package cache

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/positronico/snapem/internal/types"
)

func tempStore(t *testing.T) *FileStore {
	t.Helper()
	dir := t.TempDir()
	s, err := NewFileStore(dir)
	if err != nil {
		t.Fatalf("NewFileStore: %v", err)
	}
	return s
}

func TestFileStore_PutAndGet(t *testing.T) {
	s := tempStore(t)

	entry := &Entry{
		Scanner:   "Google OSV",
		Ecosystem: "npm",
		Package:   "lodash",
		Version:   "4.17.21",
		Findings: []types.Finding{
			{Package: "lodash", Version: "4.17.21", ID: "GHSA-foo"},
		},
	}
	if err := s.Put(entry); err != nil {
		t.Fatalf("Put: %v", err)
	}

	got, err := s.Get("Google OSV", "npm", "lodash", "4.17.21", time.Hour)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got == nil {
		t.Fatal("expected cache hit, got nil")
	}
	if len(got.Findings) != 1 || got.Findings[0].ID != "GHSA-foo" {
		t.Errorf("findings not roundtripped: %+v", got.Findings)
	}
	if got.CachedAt.IsZero() {
		t.Errorf("CachedAt should be populated on Put")
	}
}

func TestFileStore_MissReturnsNilNoError(t *testing.T) {
	s := tempStore(t)

	got, err := s.Get("Google OSV", "npm", "missing", "1.0.0", time.Hour)
	if err != nil {
		t.Fatalf("unexpected error on miss: %v", err)
	}
	if got != nil {
		t.Errorf("expected nil on miss, got %+v", got)
	}
}

func TestFileStore_TTLExpiry(t *testing.T) {
	s := tempStore(t)

	old := &Entry{
		Scanner:   "x",
		Ecosystem: "npm",
		Package:   "p",
		Version:   "1",
		CachedAt:  time.Now().Add(-2 * time.Hour),
	}
	if err := s.Put(old); err != nil {
		t.Fatalf("Put: %v", err)
	}

	got, err := s.Get("x", "npm", "p", "1", time.Hour)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got != nil {
		t.Errorf("entry older than maxAge should miss, got %+v", got)
	}

	// Same entry with a generous maxAge hits.
	got, _ = s.Get("x", "npm", "p", "1", 24*time.Hour)
	if got == nil {
		t.Errorf("entry within maxAge should hit")
	}
}

func TestFileStore_CorruptFileMissesGracefully(t *testing.T) {
	s := tempStore(t)
	// Compute the on-disk path the way the store does and drop garbage there.
	p := s.path("x", "npm", "p", "1")
	if err := os.WriteFile(p, []byte("not json"), 0o644); err != nil {
		t.Fatalf("seed: %v", err)
	}

	got, err := s.Get("x", "npm", "p", "1", time.Hour)
	if err != nil {
		t.Fatalf("Get on corrupt file should not error: %v", err)
	}
	if got != nil {
		t.Errorf("Get on corrupt file should miss, got %+v", got)
	}
}

func TestFileStore_SchemaMismatchTreatedAsMiss(t *testing.T) {
	s := tempStore(t)

	entry := &Entry{
		Scanner:   "x",
		Ecosystem: "npm",
		Package:   "p",
		Version:   "1",
	}
	if err := s.Put(entry); err != nil {
		t.Fatalf("Put: %v", err)
	}

	// Hand-edit the file to a fake schema version.
	p := s.path("x", "npm", "p", "1")
	data, err := os.ReadFile(p)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	munged := []byte(string(data))
	// Crude string surgery is fine — we just want a non-matching number.
	for i := 0; i < len(munged)-2; i++ {
		if munged[i] == '"' && i+2 < len(munged) && munged[i+1] == 's' && string(munged[i:i+15]) == `"schema_version` {
			// Replace the digit after the colon with 9.
			for j := i + 15; j < len(munged); j++ {
				if munged[j] >= '0' && munged[j] <= '9' {
					munged[j] = '9'
					break
				}
			}
			break
		}
	}
	if err := os.WriteFile(p, munged, 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}

	got, _ := s.Get("x", "npm", "p", "1", time.Hour)
	if got != nil {
		t.Errorf("schema mismatch should miss, got %+v", got)
	}
}

func TestFileStore_KeyIsolation(t *testing.T) {
	s := tempStore(t)

	for _, e := range []Entry{
		{Scanner: "a", Ecosystem: "npm", Package: "p", Version: "1"},
		{Scanner: "b", Ecosystem: "npm", Package: "p", Version: "1"}, // different scanner
		{Scanner: "a", Ecosystem: "npm", Package: "p", Version: "2"}, // different version
	} {
		entry := e
		if err := s.Put(&entry); err != nil {
			t.Fatalf("Put: %v", err)
		}
	}

	files, err := filepath.Glob(filepath.Join(s.Dir, "*.json"))
	if err != nil {
		t.Fatalf("glob: %v", err)
	}
	if len(files) != 3 {
		t.Errorf("expected 3 distinct files, got %d", len(files))
	}
}
