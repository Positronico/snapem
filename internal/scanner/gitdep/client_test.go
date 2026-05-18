package gitdep

import (
	"context"
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

// fakeRegistry stubs the npm registry's /<name>/<version> endpoint.
type fakeRegistry struct {
	mu        sync.Mutex
	responses map[string]string
	calls     map[string]int
}

func newFakeRegistry() *fakeRegistry {
	return &fakeRegistry{
		responses: map[string]string{},
		calls:     map[string]int{},
	}
}

func (f *fakeRegistry) handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.EscapedPath()
		f.mu.Lock()
		f.calls[path]++
		body, ok := f.responses[path]
		f.mu.Unlock()
		if !ok {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, body)
	})
}

func (f *fakeRegistry) callCount(path string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls[path]
}

func newClient(t *testing.T, fr *fakeRegistry) *Client {
	t.Helper()
	srv := httptest.NewServer(fr.handler())
	t.Cleanup(srv.Close)
	c := NewClient(config.GitDepConfig{Enabled: true, Timeout: 3 * time.Second})
	c.baseURL = srv.URL
	return c
}

func TestClassifySpec_FlagsGitURLs(t *testing.T) {
	cases := []struct {
		in    string
		flags bool
		desc  string
	}{
		// Flagged
		{"git+https://github.com/owner/repo.git", true, "git+https"},
		{"git+ssh://git@github.com/owner/repo.git", true, "git+ssh"},
		{"git://github.com/owner/repo.git", true, "git://"},
		{"github:owner/repo", true, "github shortcut"},
		{"github:owner/repo#abcdef0", true, "github shortcut with sha"},
		{"gitlab:owner/repo", true, "gitlab shortcut"},
		{"bitbucket:owner/repo", true, "bitbucket shortcut"},
		{"gist:abcdef123456", true, "gist shortcut"},
		{"ssh://git@host/repo.git", true, "raw ssh"},
		{"https://example.com/pkg.tgz", true, "tarball over https"},
		{"http://example.com/pkg.tgz", true, "tarball over http"},
		{"file:../local-pkg", true, "file path"},
		{"owner/repo", true, "bare owner/repo GitHub short-form"},
		{"owner/repo#main", true, "bare owner/repo with ref"},

		// NOT flagged — these are normal registry refs
		{"^1.0.0", false, "caret range"},
		{"~1.2.3", false, "tilde range"},
		{"1.2.3", false, "exact"},
		{"1.x", false, "x-range"},
		{">=1.0.0 <2.0.0", false, "compound range"},
		{"*", false, "wildcard"},
		{"latest", false, "dist-tag"},
		{"next", false, "dist-tag with letters"},
		{"npm:lodash@^4.17.0", false, "alias to registry"},
		{"workspace:*", false, "workspace protocol"},
		{"@scope/name", false, "scoped package name (not a slash-shortcut)"},
	}
	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			got := classifySpec(tc.in) != ""
			if got != tc.flags {
				t.Errorf("classifySpec(%q) flagged=%v, want %v", tc.in, got, tc.flags)
			}
		})
	}
}

func TestScan_FlagsGitURLInDependencies(t *testing.T) {
	fr := newFakeRegistry()
	fr.responses["/p/1.0.0"] = `{
		"dependencies": {"good":"^1.0.0"},
		"optionalDependencies": {"hidden-setup":"github:attacker/repo#deadbeef"}
	}`

	c := newClient(t, fr)
	res, err := c.Scan(context.Background(), []manifest.Package{
		{Name: "p", Version: "1.0.0", Ecosystem: "npm"},
	})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(res.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(res.Findings))
	}
	f := res.Findings[0]
	if f.Severity != types.SeverityHigh {
		t.Errorf("Severity = %v, want high", f.Severity)
	}
	if !strings.Contains(f.Description, "hidden-setup") {
		t.Errorf("description should name the offending dep, got %q", f.Description)
	}
	if !strings.Contains(f.Description, "optionalDependencies") {
		t.Errorf("description should name the dep section, got %q", f.Description)
	}
}

func TestScan_CleanPackageNoFinding(t *testing.T) {
	fr := newFakeRegistry()
	fr.responses["/clean/1.0.0"] = `{
		"dependencies":{"a":"^1","b":"~2.3.0","c":"1.x"},
		"optionalDependencies":{"d":"*"},
		"peerDependencies":{"e":">=1 <2"}
	}`
	c := newClient(t, fr)
	res, _ := c.Scan(context.Background(), []manifest.Package{
		{Name: "clean", Version: "1.0.0", Ecosystem: "npm"},
	})
	if len(res.Findings) != 0 {
		t.Errorf("clean registry refs should produce no findings, got %d: %+v", len(res.Findings), res.Findings)
	}
}

func TestScan_MultipleOffendersListedTruncated(t *testing.T) {
	// Construct a package with 7 git-URL deps. Description should
	// list 5 of them plus an "…and N more" line.
	fr := newFakeRegistry()
	fr.responses["/many/1"] = `{
		"dependencies":{
			"a":"github:x/a","b":"github:x/b","c":"github:x/c",
			"d":"github:x/d","e":"github:x/e","f":"github:x/f","g":"github:x/g"
		}
	}`
	c := newClient(t, fr)
	res, _ := c.Scan(context.Background(), []manifest.Package{
		{Name: "many", Version: "1", Ecosystem: "npm"},
	})
	if len(res.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(res.Findings))
	}
	desc := res.Findings[0].Description
	if !strings.Contains(desc, "and 2 more") {
		t.Errorf("description should note the truncated count, got %q", desc)
	}
}

func TestScan_DedupesPackages(t *testing.T) {
	fr := newFakeRegistry()
	fr.responses["/dup/1.0.0"] = `{"dependencies":{"x":"github:a/b"}}`
	c := newClient(t, fr)
	pkgs := []manifest.Package{
		{Name: "dup", Version: "1.0.0", Ecosystem: "npm"},
		{Name: "dup", Version: "1.0.0", Ecosystem: "npm"},
		{Name: "dup", Version: "1.0.0", Ecosystem: "npm"},
	}
	res, _ := c.Scan(context.Background(), pkgs)
	if len(res.Findings) != 1 {
		t.Errorf("expected 1 finding after dedup, got %d", len(res.Findings))
	}
	if got := fr.callCount("/dup/1.0.0"); got != 1 {
		t.Errorf("expected 1 backend call after dedup, got %d", got)
	}
}

func TestScan_RegistryMissSilent(t *testing.T) {
	fr := newFakeRegistry()
	c := newClient(t, fr)
	res, err := c.Scan(context.Background(), []manifest.Package{
		{Name: "absent", Version: "9.9.9", Ecosystem: "npm"},
	})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(res.Findings) != 0 {
		t.Errorf("expected silent skip on 404, got %d findings", len(res.Findings))
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

	c := NewClient(config.GitDepConfig{Enabled: true, Timeout: 5 * time.Second})
	c.baseURL = srv.URL

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := c.Scan(ctx, []manifest.Package{{Name: "p", Version: "1", Ecosystem: "npm"}})
	if err == nil {
		t.Error("expected ctx.Err() from canceled Scan, got nil")
	}
}

func TestIsAvailable_HonorsEnabledFlag(t *testing.T) {
	if !NewClient(config.GitDepConfig{Enabled: true}).IsAvailable() {
		t.Error("enabled=true should be available")
	}
	if NewClient(config.GitDepConfig{Enabled: false}).IsAvailable() {
		t.Error("enabled=false should not be available")
	}
}

func TestScan_EmptyInputReturnsEmptyResult(t *testing.T) {
	c := NewClient(config.GitDepConfig{Enabled: true})
	res, err := c.Scan(context.Background(), nil)
	if err != nil {
		t.Fatalf("Scan(nil): %v", err)
	}
	if len(res.Findings) != 0 {
		t.Errorf("expected no findings for empty input, got %d", len(res.Findings))
	}
}
