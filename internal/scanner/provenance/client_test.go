package provenance

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/positronico/snapem/internal/config"
	"github.com/positronico/snapem/internal/manifest"
	"github.com/positronico/snapem/internal/types"
)

// fakeRegistry stubs the npm registry + attestations endpoints.
type fakeRegistry struct {
	// versions maps "/<name>/<version>" → JSON body
	versions map[string]string
	// attestations maps "/-/npm/v1/attestations/<name>@<version>" → JSON body
	attestations map[string]string
	// versionCode/attestationCode override default 200 for the matched path
	versionCode    int
	attestationCode int
	// counters for verifying request shaping
	versionCalls    map[string]int
	attestationCalls map[string]int
}

func newFakeRegistry() *fakeRegistry {
	return &fakeRegistry{
		versions:         map[string]string{},
		attestations:     map[string]string{},
		versionCalls:     map[string]int{},
		attestationCalls: map[string]int{},
	}
}

func (f *fakeRegistry) handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.EscapedPath()
		if strings.HasPrefix(path, "/-/npm/v1/attestations/") {
			f.attestationCalls[path]++
			body, ok := f.attestations[path]
			if !ok {
				http.Error(w, "not found", http.StatusNotFound)
				return
			}
			code := f.attestationCode
			if code == 0 {
				code = http.StatusOK
			}
			w.WriteHeader(code)
			fmt.Fprint(w, body)
			return
		}
		f.versionCalls[path]++
		body, ok := f.versions[path]
		if !ok {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		code := f.versionCode
		if code == 0 {
			code = http.StatusOK
		}
		w.WriteHeader(code)
		fmt.Fprint(w, body)
	})
}

// buildBundle builds the deps.dev-equivalent attestations response.
// subjectPurl can be empty to omit the subject (anomaly path).
func buildBundle(t *testing.T, subjectPurl, repo, ref, workflow, builder string) string {
	t.Helper()
	payload := map[string]any{
		"predicateType": slsaPredicate,
		"predicate": map[string]any{
			"buildDefinition": map[string]any{
				"externalParameters": map[string]any{
					"workflow": map[string]any{
						"ref":        ref,
						"repository": repo,
						"path":       workflow,
					},
				},
			},
			"runDetails": map[string]any{
				"builder": map[string]any{"id": builder},
			},
		},
	}
	if subjectPurl != "" {
		payload["subject"] = []map[string]any{{"name": subjectPurl}}
	} else {
		payload["subject"] = []map[string]any{}
	}
	pj, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	encoded := base64.StdEncoding.EncodeToString(pj)
	bundle := map[string]any{
		"attestations": []map[string]any{
			{
				"predicateType": "https://github.com/npm/attestation/tree/main/specs/publish/v0.1",
				"bundle": map[string]any{
					"dsseEnvelope": map[string]any{
						"payload":     "e30=", // empty {} just to fill the slot
						"payloadType": "application/vnd.in-toto+json",
					},
				},
			},
			{
				"predicateType": slsaPredicate,
				"bundle": map[string]any{
					"dsseEnvelope": map[string]any{
						"payload":     encoded,
						"payloadType": "application/vnd.in-toto+json",
					},
				},
			},
		},
	}
	b, err := json.Marshal(bundle)
	if err != nil {
		t.Fatalf("marshal bundle: %v", err)
	}
	return string(b)
}

func setupClient(t *testing.T, fr *fakeRegistry, warnMissing bool) *Client {
	t.Helper()
	srv := httptest.NewServer(fr.handler())
	t.Cleanup(srv.Close)
	c := NewClient(config.ProvenanceConfig{
		Enabled:     true,
		Timeout:     3 * time.Second,
		WarnMissing: warnMissing,
	})
	c.baseURL = srv.URL
	// Rewrite the attestation URL too so it points at our test server.
	// We do this by storing absolute URLs in version metadata that
	// reference srv.URL.
	return c
}

// versionBodyWithAttestation builds the version metadata where dist.attestations.url
// points at the test server's attestation path.
func versionBodyWithAttestation(serverURL, name, version string) string {
	return fmt.Sprintf(`{"dist":{"attestations":{"url":"%s/-/npm/v1/attestations/%s@%s"}}}`,
		serverURL, name, version)
}

func versionBodyWithoutAttestation() string {
	return `{"dist":{"shasum":"abc"}}`
}

func TestScan_HealthyProvenanceNoFinding(t *testing.T) {
	fr := newFakeRegistry()
	srv := httptest.NewServer(fr.handler())
	defer srv.Close()
	fr.versions["/sigstore/3.0.0"] = versionBodyWithAttestation(srv.URL, "sigstore", "3.0.0")
	fr.attestations["/-/npm/v1/attestations/sigstore@3.0.0"] = buildBundle(t,
		"pkg:npm/sigstore@3.0.0",
		"https://github.com/sigstore/sigstore-js",
		"refs/heads/main", ".github/workflows/release.yml",
		"https://github.com/actions/runner/github-hosted",
	)

	c := NewClient(config.ProvenanceConfig{Enabled: true, Timeout: 3 * time.Second})
	c.baseURL = srv.URL

	res, err := c.Scan(context.Background(), []manifest.Package{
		{Name: "sigstore", Version: "3.0.0", Ecosystem: "npm"},
	})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(res.Findings) != 0 {
		t.Errorf("expected no findings for healthy provenance, got %d: %v", len(res.Findings), res.Findings)
	}
}

func TestScan_SubjectMismatchEmitsMedium(t *testing.T) {
	// Attestation declares "pkg:npm/other@1.0.0" but we're scanning
	// "pkg:npm/sigstore@3.0.0" — attestation-confusion shape.
	fr := newFakeRegistry()
	srv := httptest.NewServer(fr.handler())
	defer srv.Close()
	fr.versions["/sigstore/3.0.0"] = versionBodyWithAttestation(srv.URL, "sigstore", "3.0.0")
	fr.attestations["/-/npm/v1/attestations/sigstore@3.0.0"] = buildBundle(t,
		"pkg:npm/other@1.0.0", // mismatch
		"https://github.com/attacker/fake", "refs/heads/main",
		".github/workflows/release.yml",
		"https://github.com/actions/runner/github-hosted",
	)

	c := NewClient(config.ProvenanceConfig{Enabled: true, Timeout: 3 * time.Second})
	c.baseURL = srv.URL

	res, err := c.Scan(context.Background(), []manifest.Package{
		{Name: "sigstore", Version: "3.0.0", Ecosystem: "npm"},
	})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(res.Findings) != 1 {
		t.Fatalf("expected 1 finding for subject mismatch, got %d", len(res.Findings))
	}
	f := res.Findings[0]
	if f.Severity != types.SeverityMedium {
		t.Errorf("Severity = %v, want medium", f.Severity)
	}
	if !strings.Contains(f.Title, "subject mismatch") {
		t.Errorf("Title should mention subject mismatch, got %q", f.Title)
	}
	if !strings.Contains(f.Description, "pkg:npm/other@1.0.0") {
		t.Errorf("Description should name the offending subject, got %q", f.Description)
	}
}

func TestScan_NoProvenance_WarnMissingFalse_NoFinding(t *testing.T) {
	fr := newFakeRegistry()
	srv := httptest.NewServer(fr.handler())
	defer srv.Close()
	fr.versions["/lodash/4.17.21"] = versionBodyWithoutAttestation()

	c := NewClient(config.ProvenanceConfig{
		Enabled: true, Timeout: 3 * time.Second, WarnMissing: false,
	})
	c.baseURL = srv.URL

	res, err := c.Scan(context.Background(), []manifest.Package{
		{Name: "lodash", Version: "4.17.21", Ecosystem: "npm"},
	})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(res.Findings) != 0 {
		t.Errorf("warn_missing=false should suppress findings on no provenance, got %d", len(res.Findings))
	}
}

func TestScan_NoProvenance_WarnMissingTrue_EmitsLow(t *testing.T) {
	fr := newFakeRegistry()
	srv := httptest.NewServer(fr.handler())
	defer srv.Close()
	fr.versions["/lodash/4.17.21"] = versionBodyWithoutAttestation()

	c := NewClient(config.ProvenanceConfig{
		Enabled: true, Timeout: 3 * time.Second, WarnMissing: true,
	})
	c.baseURL = srv.URL

	res, err := c.Scan(context.Background(), []manifest.Package{
		{Name: "lodash", Version: "4.17.21", Ecosystem: "npm"},
	})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(res.Findings) != 1 {
		t.Fatalf("expected 1 finding for missing provenance with warn_missing=true, got %d", len(res.Findings))
	}
	if res.Findings[0].Severity != types.SeverityLow {
		t.Errorf("Severity = %v, want low", res.Findings[0].Severity)
	}
}

func TestScan_AttestationURLAdvertisedButUnreachableEmitsLow(t *testing.T) {
	// Version metadata says there's an attestation at /404-path, but
	// the attestations endpoint returns 404. That's an anomaly — npm
	// promised provenance and we couldn't get it. Surface as low.
	fr := newFakeRegistry()
	srv := httptest.NewServer(fr.handler())
	defer srv.Close()
	fr.versions["/pkg/1.0.0"] = versionBodyWithAttestation(srv.URL, "pkg", "1.0.0")
	// No attestations entry → 404 from /-/npm/v1/attestations/pkg@1.0.0

	c := NewClient(config.ProvenanceConfig{Enabled: true, Timeout: 3 * time.Second})
	c.baseURL = srv.URL

	res, err := c.Scan(context.Background(), []manifest.Package{
		{Name: "pkg", Version: "1.0.0", Ecosystem: "npm"},
	})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(res.Findings) != 1 {
		t.Fatalf("expected 1 finding for unreachable attestation, got %d", len(res.Findings))
	}
	if !strings.Contains(res.Findings[0].Title, "unreadable") {
		t.Errorf("Title should mention unreadable, got %q", res.Findings[0].Title)
	}
}

func TestScan_VersionNotFoundDoesNotEmit(t *testing.T) {
	// Registry returns 404 for an unknown package. Not a provenance
	// problem — another scanner is better positioned to surface this.
	fr := newFakeRegistry()
	srv := httptest.NewServer(fr.handler())
	defer srv.Close()
	// No entry for /unknown/9.9.9

	c := NewClient(config.ProvenanceConfig{Enabled: true, Timeout: 3 * time.Second, WarnMissing: true})
	c.baseURL = srv.URL

	res, err := c.Scan(context.Background(), []manifest.Package{
		{Name: "unknown", Version: "9.9.9", Ecosystem: "npm"},
	})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(res.Findings) != 0 {
		t.Errorf("expected silent skip on registry 404 even with warn_missing=true, got %d findings", len(res.Findings))
	}
}

func TestScan_OnlyNpmPublishAttestationNoSLSA(t *testing.T) {
	// Bundle has the npm publish attestation but no SLSA provenance.
	// That can happen for older publish flows. Treat the same as
	// "advertised but unreadable" since we can't recover build inputs.
	fr := newFakeRegistry()
	srv := httptest.NewServer(fr.handler())
	defer srv.Close()
	fr.versions["/pkg/1.0.0"] = versionBodyWithAttestation(srv.URL, "pkg", "1.0.0")
	fr.attestations["/-/npm/v1/attestations/pkg@1.0.0"] = `{
        "attestations": [{
            "predicateType": "https://github.com/npm/attestation/tree/main/specs/publish/v0.1",
            "bundle": {"dsseEnvelope": {"payload": "e30=", "payloadType": "x"}}
        }]
    }`

	c := NewClient(config.ProvenanceConfig{Enabled: true, Timeout: 3 * time.Second})
	c.baseURL = srv.URL

	res, err := c.Scan(context.Background(), []manifest.Package{
		{Name: "pkg", Version: "1.0.0", Ecosystem: "npm"},
	})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(res.Findings) != 1 {
		t.Fatalf("expected 1 finding when SLSA attestation absent, got %d", len(res.Findings))
	}
}

func TestScan_DedupesPackages(t *testing.T) {
	// Three duplicate inputs should hit the registry once.
	fr := newFakeRegistry()
	srv := httptest.NewServer(fr.handler())
	defer srv.Close()
	fr.versions["/dup/1.0.0"] = versionBodyWithoutAttestation()

	c := NewClient(config.ProvenanceConfig{Enabled: true, Timeout: 3 * time.Second, WarnMissing: true})
	c.baseURL = srv.URL

	pkgs := []manifest.Package{
		{Name: "dup", Version: "1.0.0", Ecosystem: "npm"},
		{Name: "dup", Version: "1.0.0", Ecosystem: "npm"},
		{Name: "dup", Version: "1.0.0", Ecosystem: "npm"},
	}
	res, err := c.Scan(context.Background(), pkgs)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(res.Findings) != 1 {
		t.Errorf("expected 1 finding after dedup, got %d", len(res.Findings))
	}
	if fr.versionCalls["/dup/1.0.0"] != 1 {
		t.Errorf("expected 1 version call after dedup, got %d", fr.versionCalls["/dup/1.0.0"])
	}
}

func TestScan_ContextCancellationSurfaces(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-time.After(2 * time.Second):
		}
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `{}`)
	}))
	defer srv.Close()

	c := NewClient(config.ProvenanceConfig{Enabled: true, Timeout: 5 * time.Second})
	c.baseURL = srv.URL

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // pre-canceled

	_, err := c.Scan(ctx, []manifest.Package{{Name: "p", Version: "1", Ecosystem: "npm"}})
	if err == nil {
		t.Error("expected ctx.Err() from canceled Scan, got nil")
	}
}

func TestScan_EmptyInputReturnsEmptyResult(t *testing.T) {
	c := NewClient(config.ProvenanceConfig{Enabled: true})
	res, err := c.Scan(context.Background(), nil)
	if err != nil {
		t.Fatalf("Scan(nil): %v", err)
	}
	if len(res.Findings) != 0 {
		t.Errorf("expected no findings for empty input, got %d", len(res.Findings))
	}
}

func TestIsAvailable_HonorsEnabledFlag(t *testing.T) {
	if !NewClient(config.ProvenanceConfig{Enabled: true}).IsAvailable() {
		t.Error("enabled=true should be available")
	}
	if NewClient(config.ProvenanceConfig{Enabled: false}).IsAvailable() {
		t.Error("enabled=false should not be available")
	}
}

func TestStatementForPackage_ParsesBuildInputs(t *testing.T) {
	fr := newFakeRegistry()
	srv := httptest.NewServer(fr.handler())
	defer srv.Close()
	fr.versions["/sigstore/3.0.0"] = versionBodyWithAttestation(srv.URL, "sigstore", "3.0.0")
	fr.attestations["/-/npm/v1/attestations/sigstore@3.0.0"] = buildBundle(t,
		"pkg:npm/sigstore@3.0.0",
		"https://github.com/sigstore/sigstore-js",
		"refs/heads/main", ".github/workflows/release.yml",
		"https://github.com/actions/runner/github-hosted",
	)

	c := NewClient(config.ProvenanceConfig{Enabled: true, Timeout: 3 * time.Second})
	c.baseURL = srv.URL

	stmt, ok := c.StatementForPackage(context.Background(), manifest.Package{
		Name: "sigstore", Version: "3.0.0", Ecosystem: "npm",
	})
	if !ok {
		t.Fatal("StatementForPackage returned ok=false on a healthy package")
	}
	if stmt.Repository != "https://github.com/sigstore/sigstore-js" {
		t.Errorf("Repository = %q", stmt.Repository)
	}
	if stmt.Ref != "refs/heads/main" {
		t.Errorf("Ref = %q", stmt.Ref)
	}
	if !stmt.SubjectOK {
		t.Error("SubjectOK should be true for matching PURL")
	}
	if got := stmt.Short(); got != "github.com/sigstore/sigstore-js@main" {
		t.Errorf("Short() = %q, want github.com/sigstore/sigstore-js@main", got)
	}
}

func TestStatementForPackage_NoneReturnsFalse(t *testing.T) {
	fr := newFakeRegistry()
	srv := httptest.NewServer(fr.handler())
	defer srv.Close()
	fr.versions["/lodash/4.17.21"] = versionBodyWithoutAttestation()

	c := NewClient(config.ProvenanceConfig{Enabled: true, Timeout: 3 * time.Second})
	c.baseURL = srv.URL

	_, ok := c.StatementForPackage(context.Background(), manifest.Package{
		Name: "lodash", Version: "4.17.21", Ecosystem: "npm",
	})
	if ok {
		t.Error("expected ok=false when no attestations present")
	}
}

func TestStatement_Short_HandlesEdgeCases(t *testing.T) {
	cases := []struct {
		repo, ref, want string
	}{
		{"https://github.com/x/y", "refs/heads/main", "github.com/x/y@main"},
		{"https://github.com/x/y", "refs/tags/v1.2.3", "github.com/x/y@v1.2.3"},
		{"https://github.com/x/y", "", "github.com/x/y"},
		{"https://gitlab.com/g/r", "refs/heads/dev", "gitlab.com/g/r@dev"},
	}
	for _, tc := range cases {
		s := &Statement{Repository: tc.repo, Ref: tc.ref}
		if got := s.Short(); got != tc.want {
			t.Errorf("Short(%q, %q) = %q, want %q", tc.repo, tc.ref, got, tc.want)
		}
	}
}
