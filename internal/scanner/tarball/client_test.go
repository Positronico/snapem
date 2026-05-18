package tarball

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/positronico/snapem/internal/config"
	"github.com/positronico/snapem/internal/manifest"
	"github.com/positronico/snapem/internal/types"
)

// makeTarball builds an in-memory .tgz with the given paths as
// zero-byte regular files. Paths are prefixed with "package/" exactly
// as npm publishes them.
func makeTarball(t *testing.T, paths []string) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for _, p := range paths {
		hdr := &tar.Header{
			Name:     "package/" + p,
			Mode:     0o644,
			Size:     0,
			Typeflag: tar.TypeReg,
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatalf("tar header: %v", err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("tar close: %v", err)
	}
	if err := gz.Close(); err != nil {
		t.Fatalf("gzip close: %v", err)
	}
	return buf.Bytes()
}

// fakeRegistry serves /<name>/<version> JSON and /<name>/-/<file>.tgz
// tarball bytes. The handler dispatches on path suffix.
type fakeRegistry struct {
	mu       sync.Mutex
	versions map[string]versionDoc
	tarballs map[string][]byte
	calls    map[string]int
}

type versionDoc struct {
	Main    string          `json:"main,omitempty"`
	Module  string          `json:"module,omitempty"`
	Types   string          `json:"types,omitempty"`
	Typings string          `json:"typings,omitempty"`
	Bin     json.RawMessage `json:"bin,omitempty"`
	Files   []string        `json:"files,omitempty"`
	Dist    struct {
		Tarball string `json:"tarball"`
	} `json:"dist"`
}

func newFakeRegistry() *fakeRegistry {
	return &fakeRegistry{
		versions: map[string]versionDoc{},
		tarballs: map[string][]byte{},
		calls:    map[string]int{},
	}
}

func (f *fakeRegistry) handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.EscapedPath()
		f.mu.Lock()
		f.calls[path]++
		if tgz, ok := f.tarballs[path]; ok {
			f.mu.Unlock()
			w.Header().Set("Content-Type", "application/octet-stream")
			_, _ = w.Write(tgz)
			return
		}
		doc, ok := f.versions[path]
		f.mu.Unlock()
		if !ok {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(doc)
	})
}

func newClient(t *testing.T, fr *fakeRegistry) (*Client, *httptest.Server) {
	t.Helper()
	srv := httptest.NewServer(fr.handler())
	t.Cleanup(srv.Close)
	c := NewClient(config.TarballConfig{Enabled: true, Timeout: 3 * time.Second})
	c.baseURL = srv.URL
	return c, srv
}

// register sets up a registry version doc plus its tarball at the
// canonical URL under the test server.
func (f *fakeRegistry) register(srvURL, name, version string, doc versionDoc, paths []string, tgz []byte) {
	verPath := "/" + name + "/" + version
	tgzPath := "/" + name + "/-/" + name + "-" + version + ".tgz"
	doc.Dist.Tarball = srvURL + tgzPath
	f.versions[verPath] = doc
	if tgz == nil {
		// Built lazily below in the helper if not supplied
		f.tarballs[tgzPath] = []byte{}
	} else {
		f.tarballs[tgzPath] = tgz
	}
}

// registerWithPaths is the high-level fixture: builds the tarball from
// paths and stitches everything together. Returns nothing — tests
// fetch via Scan.
func registerWithPaths(t *testing.T, fr *fakeRegistry, srvURL, name, version string, files []string, paths []string, extras ...func(*versionDoc)) {
	t.Helper()
	tgz := makeTarball(t, paths)
	doc := versionDoc{Files: files}
	for _, fn := range extras {
		fn(&doc)
	}
	fr.register(srvURL, name, version, doc, paths, tgz)
}

func TestScan_FlagsRootFileOutsideFilesField(t *testing.T) {
	// Mirror of the structural pattern: files: ["dist","src"] but the
	// tarball ships an extra root JS file. The scanner emits one
	// finding listing it.
	fr := newFakeRegistry()
	c, srv := newClient(t, fr)
	registerWithPaths(t, fr, srv.URL, "p", "1.0.0",
		[]string{"dist", "src"},
		[]string{"package.json", "README.md", "dist/index.js", "src/a.ts", "router_init.js"},
	)

	res, err := c.Scan(context.Background(), []manifest.Package{{Name: "p", Version: "1.0.0", Ecosystem: "npm"}})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(res.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d (%+v)", len(res.Findings), res.Findings)
	}
	f := res.Findings[0]
	if f.Severity != types.SeverityMedium {
		t.Errorf("Severity = %v, want medium", f.Severity)
	}
	if !strings.Contains(f.Description, "router_init.js") {
		t.Errorf("description should name the undeclared file, got %q", f.Description)
	}
}

func TestScan_CleanTarballNoFinding(t *testing.T) {
	fr := newFakeRegistry()
	c, srv := newClient(t, fr)
	registerWithPaths(t, fr, srv.URL, "clean", "1.0.0",
		[]string{"dist"},
		[]string{"package.json", "README.md", "LICENSE", "dist/index.js", "dist/sub/x.js"},
	)
	res, _ := c.Scan(context.Background(), []manifest.Package{{Name: "clean", Version: "1.0.0", Ecosystem: "npm"}})
	if len(res.Findings) != 0 {
		t.Errorf("expected no findings, got %d: %+v", len(res.Findings), res.Findings)
	}
}

func TestScan_AlwaysIncludedFilesIgnored(t *testing.T) {
	// Tarball ships README.md / LICENSE.txt / CHANGELOG.md / HISTORY /
	// NOTICE.md none of which are in `files`. None should be flagged.
	fr := newFakeRegistry()
	c, srv := newClient(t, fr)
	registerWithPaths(t, fr, srv.URL, "p", "1.0.0",
		[]string{"dist"},
		[]string{
			"package.json",
			"README.md",
			"LICENSE.txt",
			"LICENCE",
			"CHANGELOG.md",
			"HISTORY",
			"NOTICE.md",
			"dist/index.js",
		},
	)
	res, _ := c.Scan(context.Background(), []manifest.Package{{Name: "p", Version: "1.0.0", Ecosystem: "npm"}})
	if len(res.Findings) != 0 {
		t.Errorf("always-included docs should not flag, got %+v", res.Findings)
	}
}

func TestScan_MainAndBinPathsAlwaysIncluded(t *testing.T) {
	fr := newFakeRegistry()
	c, srv := newClient(t, fr)
	registerWithPaths(t, fr, srv.URL, "p", "1.0.0",
		[]string{"dist"},
		[]string{"package.json", "main.js", "bin/cli.js", "dist/x.js"},
		func(d *versionDoc) {
			d.Main = "main.js"
			d.Bin = json.RawMessage(`{"p":"bin/cli.js"}`)
		},
	)
	res, _ := c.Scan(context.Background(), []manifest.Package{{Name: "p", Version: "1.0.0", Ecosystem: "npm"}})
	if len(res.Findings) != 0 {
		t.Errorf("main + bin entries should not flag, got %+v", res.Findings)
	}
}

func TestScan_NoFilesFieldSkips(t *testing.T) {
	// No files field → no claim to audit. Skip entirely, even if the
	// tarball ships odd content.
	fr := newFakeRegistry()
	c, srv := newClient(t, fr)
	registerWithPaths(t, fr, srv.URL, "p", "1.0.0",
		nil,
		[]string{"package.json", "weird.js"},
	)
	res, _ := c.Scan(context.Background(), []manifest.Package{{Name: "p", Version: "1.0.0", Ecosystem: "npm"}})
	if len(res.Findings) != 0 {
		t.Errorf("missing files field should skip audit, got %+v", res.Findings)
	}
}

func TestScan_DoubleStarPatternsDisableAudit(t *testing.T) {
	// `files` contains a `**` glob — we can't faithfully match those,
	// so we skip the audit rather than emit a noisy false positive.
	fr := newFakeRegistry()
	c, srv := newClient(t, fr)
	registerWithPaths(t, fr, srv.URL, "p", "1.0.0",
		[]string{"**/*.d.ts", "dist"},
		[]string{"package.json", "weird.js", "dist/index.js"},
	)
	res, _ := c.Scan(context.Background(), []manifest.Package{{Name: "p", Version: "1.0.0", Ecosystem: "npm"}})
	if len(res.Findings) != 0 {
		t.Errorf("`**` patterns should disable audit, got %+v", res.Findings)
	}
}

func TestScan_NegationPatternsDisableAudit(t *testing.T) {
	fr := newFakeRegistry()
	c, srv := newClient(t, fr)
	registerWithPaths(t, fr, srv.URL, "p", "1.0.0",
		[]string{"dist", "!dist/internal"},
		[]string{"package.json", "weird.js", "dist/index.js"},
	)
	res, _ := c.Scan(context.Background(), []manifest.Package{{Name: "p", Version: "1.0.0", Ecosystem: "npm"}})
	if len(res.Findings) != 0 {
		t.Errorf("`!` negations should disable audit, got %+v", res.Findings)
	}
}

func TestScan_SimpleGlobPatternsRecognized(t *testing.T) {
	// Root-level *.js glob matches all root .js — nothing flagged.
	fr := newFakeRegistry()
	c, srv := newClient(t, fr)
	registerWithPaths(t, fr, srv.URL, "p", "1.0.0",
		[]string{"*.js"},
		[]string{"package.json", "a.js", "b.js", "c.js"},
	)
	res, _ := c.Scan(context.Background(), []manifest.Package{{Name: "p", Version: "1.0.0", Ecosystem: "npm"}})
	if len(res.Findings) != 0 {
		t.Errorf("simple glob should cover matching files, got %+v", res.Findings)
	}
}

func TestScan_MultipleOffendersListedTruncated(t *testing.T) {
	// 7 undeclared files. Description should list 5 and indicate the
	// rest with an "…and 2 more" marker.
	fr := newFakeRegistry()
	c, srv := newClient(t, fr)
	registerWithPaths(t, fr, srv.URL, "p", "1.0.0",
		[]string{"dist"},
		[]string{
			"package.json", "dist/index.js",
			"a.js", "b.js", "c.js", "d.js", "e.js", "f.js", "g.js",
		},
	)
	res, _ := c.Scan(context.Background(), []manifest.Package{{Name: "p", Version: "1.0.0", Ecosystem: "npm"}})
	if len(res.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(res.Findings))
	}
	if !strings.Contains(res.Findings[0].Description, "and 2 more") {
		t.Errorf("expected truncation marker, got %q", res.Findings[0].Description)
	}
}

func TestScan_DedupesPackages(t *testing.T) {
	fr := newFakeRegistry()
	c, srv := newClient(t, fr)
	registerWithPaths(t, fr, srv.URL, "dup", "1.0.0",
		[]string{"dist"},
		[]string{"package.json", "rogue.js", "dist/x.js"},
	)
	pkgs := []manifest.Package{
		{Name: "dup", Version: "1.0.0", Ecosystem: "npm"},
		{Name: "dup", Version: "1.0.0", Ecosystem: "npm"},
		{Name: "dup", Version: "1.0.0", Ecosystem: "npm"},
	}
	res, _ := c.Scan(context.Background(), pkgs)
	if len(res.Findings) != 1 {
		t.Errorf("expected 1 finding after dedup, got %d", len(res.Findings))
	}
}

func TestScan_RegistryMissSilent(t *testing.T) {
	fr := newFakeRegistry()
	c, _ := newClient(t, fr)
	res, err := c.Scan(context.Background(), []manifest.Package{{Name: "absent", Version: "9.9.9", Ecosystem: "npm"}})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(res.Findings) != 0 {
		t.Errorf("expected silent skip on 404, got %d findings", len(res.Findings))
	}
}

func TestScan_TarballDownloadFailureSilent(t *testing.T) {
	// Version doc points at a non-existent tarball path → download
	// 404s → audit silently skips (don't fail the scan).
	fr := newFakeRegistry()
	c, srv := newClient(t, fr)
	fr.versions["/p/1.0.0"] = versionDoc{
		Files: []string{"dist"},
		Dist: struct {
			Tarball string `json:"tarball"`
		}{Tarball: srv.URL + "/missing.tgz"},
	}
	res, _ := c.Scan(context.Background(), []manifest.Package{{Name: "p", Version: "1.0.0", Ecosystem: "npm"}})
	if len(res.Findings) != 0 {
		t.Errorf("tarball 404 should be silent, got %+v", res.Findings)
	}
}

func TestScan_ContextCancellationSurfaces(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-time.After(2 * time.Second):
		}
		fmt.Fprint(w, `{}`)
	}))
	defer srv.Close()
	c := NewClient(config.TarballConfig{Enabled: true, Timeout: 5 * time.Second})
	c.baseURL = srv.URL

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := c.Scan(ctx, []manifest.Package{{Name: "p", Version: "1", Ecosystem: "npm"}})
	if err == nil {
		t.Error("expected ctx.Err() from canceled Scan, got nil")
	}
}

func TestIsAvailable_HonorsEnabledFlag(t *testing.T) {
	if !NewClient(config.TarballConfig{Enabled: true}).IsAvailable() {
		t.Error("enabled=true should be available")
	}
	if NewClient(config.TarballConfig{Enabled: false}).IsAvailable() {
		t.Error("enabled=false should not be available")
	}
}

func TestNormalizePath_Cases(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"foo/bar", "foo/bar"},
		{"./foo/bar", "foo/bar"},
		{"/foo/bar", "foo/bar"},
		{"foo\\bar", "foo/bar"},
	}
	for _, tc := range cases {
		if got := normalizePath(tc.in); got != tc.want {
			t.Errorf("normalizePath(%q)=%q, want %q", tc.in, got, tc.want)
		}
	}
}
