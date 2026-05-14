package metadata

import (
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

// fakeDepsdev stubs the /v3/systems/npm/packages/<name>/versions/<v>
// endpoint. responses maps escaped paths → JSON body. calls tracks
// per-path hit counts for dedup verification.
//
// The handler is hit concurrently by the scanner's worker pool, so
// every map access is mu-guarded.
type fakeDepsdev struct {
	mu        sync.Mutex
	responses map[string]string
	statusFor map[string]int
	calls     map[string]int
}

func newFakeDepsdev() *fakeDepsdev {
	return &fakeDepsdev{
		responses: map[string]string{},
		statusFor: map[string]int{},
		calls:     map[string]int{},
	}
}

func (f *fakeDepsdev) handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.EscapedPath()
		f.mu.Lock()
		f.calls[path]++
		body, ok := f.responses[path]
		code := f.statusFor[path]
		f.mu.Unlock()
		if !ok {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		if code == 0 {
			code = http.StatusOK
		}
		w.WriteHeader(code)
		fmt.Fprint(w, body)
	})
}

// callCount returns the per-path call count safely from a test
// goroutine.
func (f *fakeDepsdev) callCount(path string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls[path]
}

// body builds a deps.dev versions response. isDeprecated/reason and
// licenses are all optional via pointers/empty values.
func body(t *testing.T, isDeprecated bool, reason string, licenses ...string) string {
	t.Helper()
	d := map[string]any{
		"isDeprecated":     isDeprecated,
		"deprecatedReason": reason,
		"licenses":         licenses,
	}
	b, err := json.Marshal(d)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return string(b)
}

func newClient(t *testing.T, fr *fakeDepsdev, warnLicense bool) *Client {
	t.Helper()
	srv := httptest.NewServer(fr.handler())
	t.Cleanup(srv.Close)
	c := NewClient(config.MetadataConfig{
		Enabled:            true,
		Timeout:            3 * time.Second,
		WarnUnknownLicense: warnLicense,
	})
	c.baseURL = srv.URL + "/v3"
	return c
}

func TestScan_DeprecatedEmitsMedium(t *testing.T) {
	fr := newFakeDepsdev()
	fr.responses["/v3/systems/npm/packages/request/versions/2.88.2"] =
		body(t, true, "request has been deprecated, see https://github.com/request/request/issues/3142", "Apache-2.0")

	c := newClient(t, fr, false)
	res, err := c.Scan(context.Background(), []manifest.Package{
		{Name: "request", Version: "2.88.2", Ecosystem: "npm"},
	})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(res.Findings) != 1 {
		t.Fatalf("expected 1 finding for deprecated package, got %d", len(res.Findings))
	}
	f := res.Findings[0]
	if f.Severity != types.SeverityMedium {
		t.Errorf("Severity = %v, want medium", f.Severity)
	}
	if f.Type != types.FindingTypeQuality {
		t.Errorf("Type = %v, want quality", f.Type)
	}
	if !strings.Contains(f.Description, "request has been deprecated") {
		t.Errorf("Description should include the deprecation reason, got %q", f.Description)
	}
	if len(f.References) == 0 || !strings.Contains(f.References[0], "npmjs.com") {
		t.Errorf("References should link to npmjs, got %v", f.References)
	}
}

func TestScan_DeprecatedNoReasonFallback(t *testing.T) {
	// isDeprecated=true but no reason string. Should still emit with
	// a generic description rather than a colon-terminated one.
	fr := newFakeDepsdev()
	fr.responses["/v3/systems/npm/packages/p/versions/1"] = body(t, true, "")

	c := newClient(t, fr, false)
	res, _ := c.Scan(context.Background(), []manifest.Package{
		{Name: "p", Version: "1", Ecosystem: "npm"},
	})
	if len(res.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(res.Findings))
	}
	desc := res.Findings[0].Description
	if strings.HasSuffix(desc, ":") || strings.HasSuffix(desc, ": ") {
		t.Errorf("description should not end with empty colon, got %q", desc)
	}
}

func TestScan_NotDeprecatedNoFinding(t *testing.T) {
	fr := newFakeDepsdev()
	fr.responses["/v3/systems/npm/packages/sigstore/versions/3.0.0"] =
		body(t, false, "", "Apache-2.0")

	c := newClient(t, fr, false)
	res, _ := c.Scan(context.Background(), []manifest.Package{
		{Name: "sigstore", Version: "3.0.0", Ecosystem: "npm"},
	})
	if len(res.Findings) != 0 {
		t.Errorf("expected no findings for healthy package, got %d", len(res.Findings))
	}
}

func TestScan_UnknownLicenseEmitsOnlyWhenWarnLicenseTrue(t *testing.T) {
	cases := []struct {
		licenses []string
		want     bool
		desc     string
	}{
		{[]string{}, true, "empty licenses array → unknown"},
		{[]string{"non-standard"}, true, "deps.dev's literal 'non-standard'"},
		{[]string{"unknown"}, true, "explicit 'unknown'"},
		{[]string{""}, true, "single empty entry"},
		{[]string{"MIT"}, false, "valid SPDX → not unknown"},
		{[]string{"Apache-2.0", "MIT"}, false, "multi-license → at least one valid"},
		{[]string{"non-standard", "MIT"}, false, "mix with one valid → not unknown"},
	}
	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			fr := newFakeDepsdev()
			b, _ := json.Marshal(map[string]any{
				"isDeprecated": false,
				"licenses":     tc.licenses,
			})
			fr.responses["/v3/systems/npm/packages/p/versions/1"] = string(b)

			// warn_unknown_license=true
			c := newClient(t, fr, true)
			res, _ := c.Scan(context.Background(), []manifest.Package{
				{Name: "p", Version: "1", Ecosystem: "npm"},
			})
			gotFinding := len(res.Findings) == 1
			if gotFinding != tc.want {
				t.Errorf("warn_license=true: gotFinding=%v, want=%v (licenses=%v)", gotFinding, tc.want, tc.licenses)
			}
			if gotFinding {
				if res.Findings[0].Type != types.FindingTypeLicense {
					t.Errorf("Type = %v, want license", res.Findings[0].Type)
				}
				if res.Findings[0].Severity != types.SeverityLow {
					t.Errorf("Severity = %v, want low", res.Findings[0].Severity)
				}
			}
		})
	}
}

func TestScan_UnknownLicenseSuppressedByDefault(t *testing.T) {
	fr := newFakeDepsdev()
	fr.responses["/v3/systems/npm/packages/lodash/versions/4.17.21"] =
		body(t, false, "", "non-standard")

	c := newClient(t, fr, false) // warn_unknown_license=false
	res, _ := c.Scan(context.Background(), []manifest.Package{
		{Name: "lodash", Version: "4.17.21", Ecosystem: "npm"},
	})
	if len(res.Findings) != 0 {
		t.Errorf("default config should suppress unknown-license findings, got %d", len(res.Findings))
	}
}

func TestScan_DeprecatedPlusUnknownLicenseEmitsTwo(t *testing.T) {
	// Package is both deprecated AND has no license. With
	// warn_license=true we should get two findings.
	fr := newFakeDepsdev()
	fr.responses["/v3/systems/npm/packages/old/versions/0.1.0"] =
		body(t, true, "abandoned in 2018")

	c := newClient(t, fr, true)
	res, _ := c.Scan(context.Background(), []manifest.Package{
		{Name: "old", Version: "0.1.0", Ecosystem: "npm"},
	})
	if len(res.Findings) != 2 {
		t.Fatalf("expected 2 findings (deprecated + unknown-license), got %d", len(res.Findings))
	}

	// Findings are sorted by package, then title.
	titles := []string{res.Findings[0].Title, res.Findings[1].Title}
	hasDeprecation := false
	hasLicense := false
	for _, ti := range titles {
		if strings.Contains(ti, "Deprecated") {
			hasDeprecation = true
		}
		if strings.Contains(ti, "license") || strings.Contains(ti, "License") {
			hasLicense = true
		}
	}
	if !hasDeprecation || !hasLicense {
		t.Errorf("expected one deprecation + one license finding, got titles %v", titles)
	}
}

func TestScan_PackageNotInDepsdevSilentlySkipped(t *testing.T) {
	fr := newFakeDepsdev()
	// No entry → 404 from fake backend

	c := newClient(t, fr, true)
	res, err := c.Scan(context.Background(), []manifest.Package{
		{Name: "unknown", Version: "9.9.9", Ecosystem: "npm"},
	})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(res.Findings) != 0 {
		t.Errorf("expected silent skip on registry 404, got %d findings", len(res.Findings))
	}
}

func TestScan_DedupesPackages(t *testing.T) {
	fr := newFakeDepsdev()
	fr.responses["/v3/systems/npm/packages/dup/versions/1.0.0"] = body(t, true, "abandoned")

	c := newClient(t, fr, false)
	pkgs := []manifest.Package{
		{Name: "dup", Version: "1.0.0", Ecosystem: "npm"},
		{Name: "dup", Version: "1.0.0", Ecosystem: "npm"},
		{Name: "dup", Version: "1.0.0", Ecosystem: "npm"},
	}
	res, _ := c.Scan(context.Background(), pkgs)
	if len(res.Findings) != 1 {
		t.Errorf("expected 1 finding after dedup, got %d", len(res.Findings))
	}
	if got := fr.callCount("/v3/systems/npm/packages/dup/versions/1.0.0"); got != 1 {
		t.Errorf("expected 1 backend call after dedup, got %d", got)
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

	c := NewClient(config.MetadataConfig{Enabled: true, Timeout: 5 * time.Second})
	c.baseURL = srv.URL + "/v3"

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := c.Scan(ctx, []manifest.Package{{Name: "p", Version: "1", Ecosystem: "npm"}})
	if err == nil {
		t.Error("expected ctx.Err() from canceled Scan, got nil")
	}
}

func TestScan_EmptyInputReturnsEmptyResult(t *testing.T) {
	c := NewClient(config.MetadataConfig{Enabled: true})
	res, err := c.Scan(context.Background(), nil)
	if err != nil {
		t.Fatalf("Scan(nil): %v", err)
	}
	if len(res.Findings) != 0 {
		t.Errorf("expected no findings for empty input, got %d", len(res.Findings))
	}
}

func TestIsAvailable_HonorsEnabledFlag(t *testing.T) {
	if !NewClient(config.MetadataConfig{Enabled: true}).IsAvailable() {
		t.Error("enabled=true should be available")
	}
	if NewClient(config.MetadataConfig{Enabled: false}).IsAvailable() {
		t.Error("enabled=false should not be available")
	}
}

func TestScan_MultiPackageMixedResults(t *testing.T) {
	// One deprecated, one healthy, one unknown — verify findings are
	// sorted by package and only the deprecated one emits (with
	// warn_license=false).
	fr := newFakeDepsdev()
	fr.responses["/v3/systems/npm/packages/abandoned/versions/1.0.0"] =
		body(t, true, "moved to fork-of-abandoned")
	fr.responses["/v3/systems/npm/packages/healthy/versions/1.0.0"] =
		body(t, false, "", "MIT")
	// "unknown" returns 404 → skip

	c := newClient(t, fr, false)
	res, _ := c.Scan(context.Background(), []manifest.Package{
		{Name: "healthy", Version: "1.0.0", Ecosystem: "npm"},
		{Name: "unknown", Version: "9.9.9", Ecosystem: "npm"},
		{Name: "abandoned", Version: "1.0.0", Ecosystem: "npm"},
	})
	if len(res.Findings) != 1 {
		t.Fatalf("expected 1 finding (only abandoned), got %d", len(res.Findings))
	}
	if res.Findings[0].Package != "abandoned" {
		t.Errorf("expected the abandoned package's finding, got %v", res.Findings[0])
	}
}

func TestIsUnknownLicense_Cases(t *testing.T) {
	// Direct unit test of the helper since it's load-bearing for the
	// license-finding behavior and worth pinning independently of the
	// HTTP roundtrip.
	cases := []struct {
		in   []string
		want bool
	}{
		{nil, true},
		{[]string{}, true},
		{[]string{""}, true},
		{[]string{"  "}, true},
		{[]string{"non-standard"}, true},
		{[]string{"NON-STANDARD"}, true}, // case insensitive
		{[]string{"unknown"}, true},
		{[]string{"MIT"}, false},
		{[]string{"Apache-2.0"}, false},
		{[]string{"non-standard", "MIT"}, false},
		{[]string{"MIT", "GPL-3.0-or-later"}, false},
	}
	for _, tc := range cases {
		if got := isUnknownLicense(tc.in); got != tc.want {
			t.Errorf("isUnknownLicense(%v) = %v, want %v", tc.in, got, tc.want)
		}
	}
}
