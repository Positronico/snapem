package scorecard

import (
	"context"
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

// fakeBackend wires httptest paths so the client thinks it's hitting
// real deps.dev. Each path knob is set by individual tests.
type fakeBackend struct {
	versionResp map[string]string // path → JSON body
	projectResp map[string]string // path → JSON body
	versionCode int               // status for version endpoint (default 200)
	projectCode int               // status for project endpoint (default 200)
}

func (f *fakeBackend) handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Match on the escaped form so test keys keep the %2F that
		// deps.dev wants (it treats the repo id as a single path
		// segment via url.PathEscape).
		path := r.URL.EscapedPath()
		if strings.Contains(path, "/versions/") {
			body, ok := f.versionResp[path]
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
			return
		}
		if strings.HasPrefix(path, "/v3/projects/") {
			body, ok := f.projectResp[path]
			if !ok {
				http.Error(w, "not found", http.StatusNotFound)
				return
			}
			code := f.projectCode
			if code == 0 {
				code = http.StatusOK
			}
			w.WriteHeader(code)
			fmt.Fprint(w, body)
			return
		}
		http.Error(w, "unexpected path: "+path, http.StatusBadRequest)
	})
}

func newTestClient(t *testing.T, fb *fakeBackend, threshold float64) *Client {
	t.Helper()
	srv := httptest.NewServer(fb.handler())
	t.Cleanup(srv.Close)
	c := NewClient(config.ScorecardConfig{
		Enabled:   true,
		Timeout:   3 * time.Second,
		Threshold: threshold,
	})
	c.baseURL = srv.URL + "/v3"
	return c
}

// versionBody builds the deps.dev versions-endpoint JSON for a package
// with the given source repo. Pass repoID="" to omit SOURCE_REPO.
func versionBody(t *testing.T, repoID string) string {
	t.Helper()
	type rp struct {
		ProjectKey struct {
			ID string `json:"id"`
		} `json:"projectKey"`
		RelationType string `json:"relationType"`
	}
	body := struct {
		RelatedProjects []rp `json:"relatedProjects"`
	}{}
	if repoID != "" {
		var r rp
		r.ProjectKey.ID = repoID
		r.RelationType = "SOURCE_REPO"
		body.RelatedProjects = append(body.RelatedProjects, r)
	}
	b, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return string(b)
}

// projectBody builds the deps.dev projects-endpoint JSON with a given
// overall score. Pass overall<0 to omit the scorecard block (i.e.
// project exists but has no Scorecard data).
func projectBody(t *testing.T, overall float64, weakest ...string) string {
	t.Helper()
	if overall < 0 {
		return `{}`
	}
	type check struct {
		Name   string  `json:"name"`
		Score  float64 `json:"score"`
		Reason string  `json:"reason"`
	}
	var checks []check
	for i, name := range weakest {
		checks = append(checks, check{Name: name, Score: float64(i)})
	}
	// Pad with a few high-scoring checks so the "weakest" calculation
	// has something to sort against.
	for i := 0; i < 3; i++ {
		checks = append(checks, check{Name: fmt.Sprintf("Filler-%d", i), Score: 10})
	}
	body := map[string]any{
		"scorecard": map[string]any{
			"overallScore": overall,
			"checks":       checks,
		},
	}
	b, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return string(b)
}

func TestScan_HighScoreEmitsNothing(t *testing.T) {
	fb := &fakeBackend{
		versionResp: map[string]string{
			"/v3/systems/npm/packages/lodash/versions/4.17.21": versionBody(t, "github.com/lodash/lodash"),
		},
		projectResp: map[string]string{
			"/v3/projects/github.com%2Flodash%2Flodash": projectBody(t, 7.4, "Maintained"),
		},
	}
	c := newTestClient(t, fb, 5.0)
	result, err := c.Scan(context.Background(), []manifest.Package{
		{Name: "lodash", Version: "4.17.21", Ecosystem: "npm"},
	})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(result.Findings) != 0 {
		t.Errorf("expected no findings for score 7.4 ≥ threshold 5.0, got %d", len(result.Findings))
	}
}

func TestScan_LowScoreEmitsFinding(t *testing.T) {
	fb := &fakeBackend{
		versionResp: map[string]string{
			"/v3/systems/npm/packages/abandoned/versions/1.0.0": versionBody(t, "github.com/ghost/abandoned"),
		},
		projectResp: map[string]string{
			"/v3/projects/github.com%2Fghost%2Fabandoned": projectBody(t, 1.5,
				"Maintained", "Code-Review"),
		},
	}
	c := newTestClient(t, fb, 5.0)
	result, err := c.Scan(context.Background(), []manifest.Package{
		{Name: "abandoned", Version: "1.0.0", Ecosystem: "npm"},
	})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(result.Findings) != 1 {
		t.Fatalf("expected 1 finding for score 1.5, got %d", len(result.Findings))
	}
	f := result.Findings[0]
	if f.Type != types.FindingTypeQuality {
		t.Errorf("Type = %v, want quality", f.Type)
	}
	if f.Severity != types.SeverityHigh {
		t.Errorf("Severity = %v, want high (score < 2)", f.Severity)
	}
	if !strings.Contains(f.Description, "Maintained 0/10") {
		t.Errorf("description should name the weakest check, got %q", f.Description)
	}
	if len(f.References) == 0 || !strings.Contains(f.References[0], "deps.dev") {
		t.Errorf("References should link to deps.dev, got %v", f.References)
	}
}

func TestScan_SeverityFromScore(t *testing.T) {
	cases := []struct {
		score    float64
		wantSev  types.Severity
		wantEmit bool
	}{
		{0.5, types.SeverityHigh, true},   // < 2
		{1.99, types.SeverityHigh, true},  // < 2
		{2.0, types.SeverityMedium, true}, // < 4
		{3.9, types.SeverityMedium, true},
		{4.0, types.SeverityLow, true}, // < threshold (5)
		{4.9, types.SeverityLow, true},
		{5.0, "", false}, // == threshold → no emit
		{8.5, "", false},
	}
	for _, tc := range cases {
		t.Run(fmt.Sprintf("score_%.1f", tc.score), func(t *testing.T) {
			fb := &fakeBackend{
				versionResp: map[string]string{
					"/v3/systems/npm/packages/p/versions/1": versionBody(t, "github.com/x/y"),
				},
				projectResp: map[string]string{
					"/v3/projects/github.com%2Fx%2Fy": projectBody(t, tc.score, "Maintained"),
				},
			}
			c := newTestClient(t, fb, 5.0)
			res, err := c.Scan(context.Background(), []manifest.Package{
				{Name: "p", Version: "1", Ecosystem: "npm"},
			})
			if err != nil {
				t.Fatalf("Scan: %v", err)
			}
			if tc.wantEmit {
				if len(res.Findings) != 1 {
					t.Fatalf("expected 1 finding, got %d", len(res.Findings))
				}
				if res.Findings[0].Severity != tc.wantSev {
					t.Errorf("Severity = %v, want %v", res.Findings[0].Severity, tc.wantSev)
				}
			} else if len(res.Findings) != 0 {
				t.Errorf("expected no findings for score %v ≥ threshold, got %d", tc.score, len(res.Findings))
			}
		})
	}
}

func TestScan_NoSourceRepoSkipped(t *testing.T) {
	// Package exists in deps.dev but has no SOURCE_REPO link. Common
	// for packages whose maintainers didn't fill in the repository
	// field in package.json. Should silently skip rather than emit a
	// "no data" finding.
	fb := &fakeBackend{
		versionResp: map[string]string{
			"/v3/systems/npm/packages/no-repo/versions/1.0.0": versionBody(t, ""),
		},
	}
	c := newTestClient(t, fb, 5.0)
	res, err := c.Scan(context.Background(), []manifest.Package{
		{Name: "no-repo", Version: "1.0.0", Ecosystem: "npm"},
	})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(res.Findings) != 0 {
		t.Errorf("expected silent skip for no-source-repo package, got %d findings", len(res.Findings))
	}
}

func TestScan_NonGithubRepoSkipped(t *testing.T) {
	// Scorecard only covers GitHub. GitLab / Bitbucket repos should
	// skip silently.
	fb := &fakeBackend{
		versionResp: map[string]string{
			"/v3/systems/npm/packages/gitlab-pkg/versions/1.0.0": versionBody(t, "gitlab.com/foo/bar"),
		},
	}
	c := newTestClient(t, fb, 5.0)
	res, err := c.Scan(context.Background(), []manifest.Package{
		{Name: "gitlab-pkg", Version: "1.0.0", Ecosystem: "npm"},
	})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(res.Findings) != 0 {
		t.Errorf("expected silent skip for GitLab repo, got %d findings", len(res.Findings))
	}
}

func TestScan_ProjectsEndpointNotFoundSkipped(t *testing.T) {
	// deps.dev knows the package + source repo but Scorecard hasn't
	// run on the repo yet (the common case for less-popular packages).
	// Should silently skip.
	fb := &fakeBackend{
		versionResp: map[string]string{
			"/v3/systems/npm/packages/unknown-to-scorecard/versions/1.0.0": versionBody(t, "github.com/foo/bar"),
		},
		// No projectResp entry → 404 from the projects endpoint.
	}
	c := newTestClient(t, fb, 5.0)
	res, err := c.Scan(context.Background(), []manifest.Package{
		{Name: "unknown-to-scorecard", Version: "1.0.0", Ecosystem: "npm"},
	})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(res.Findings) != 0 {
		t.Errorf("expected silent skip on Scorecard 404, got %d findings", len(res.Findings))
	}
}

func TestScan_ProjectExistsButNoScorecard(t *testing.T) {
	// /projects returns 200 with the project metadata but no scorecard
	// block. Happens when deps.dev has the repo but Scorecard analysis
	// is missing. Silent skip — same as 404.
	fb := &fakeBackend{
		versionResp: map[string]string{
			"/v3/systems/npm/packages/p/versions/1": versionBody(t, "github.com/x/y"),
		},
		projectResp: map[string]string{
			"/v3/projects/github.com%2Fx%2Fy": projectBody(t, -1), // no scorecard
		},
	}
	c := newTestClient(t, fb, 5.0)
	res, err := c.Scan(context.Background(), []manifest.Package{
		{Name: "p", Version: "1", Ecosystem: "npm"},
	})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(res.Findings) != 0 {
		t.Errorf("expected silent skip when scorecard block absent, got %d", len(res.Findings))
	}
}

func TestScan_DedupesPackages(t *testing.T) {
	// In a monorepo, the same (name, version) commonly appears across
	// multiple workspace members. The scanner should hit the upstream
	// only once per unique tuple — verifying this directly is awkward
	// without instrumentation; the proxy is that we get one finding
	// instead of N duplicates when the score is low.
	fb := &fakeBackend{
		versionResp: map[string]string{
			"/v3/systems/npm/packages/dup/versions/1.0.0": versionBody(t, "github.com/x/y"),
		},
		projectResp: map[string]string{
			"/v3/projects/github.com%2Fx%2Fy": projectBody(t, 1.0, "Maintained"),
		},
	}
	c := newTestClient(t, fb, 5.0)
	res, err := c.Scan(context.Background(), []manifest.Package{
		{Name: "dup", Version: "1.0.0", Ecosystem: "npm"},
		{Name: "dup", Version: "1.0.0", Ecosystem: "npm"},
		{Name: "dup", Version: "1.0.0", Ecosystem: "npm"},
	})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(res.Findings) != 1 {
		t.Errorf("expected 1 finding after dedup, got %d", len(res.Findings))
	}
}

func TestScan_ContextCancellation(t *testing.T) {
	// Slow backend; cancel context immediately. Scan should return
	// ctx.Err() rather than hang or panic.
	fb := &fakeBackend{
		versionResp: map[string]string{},
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-time.After(2 * time.Second):
		}
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `{}`)
	}))
	defer srv.Close()

	_ = fb
	c := NewClient(config.ScorecardConfig{
		Enabled: true, Timeout: 5 * time.Second, Threshold: 5,
	})
	c.baseURL = srv.URL + "/v3"

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // pre-canceled

	_, err := c.Scan(ctx, []manifest.Package{
		{Name: "p", Version: "1", Ecosystem: "npm"},
	})
	if err == nil {
		t.Error("expected ctx.Err() to surface from canceled Scan, got nil")
	}
}

func TestScan_EmptyInputReturnsEmptyResult(t *testing.T) {
	c := NewClient(config.ScorecardConfig{Enabled: true, Threshold: 5})
	res, err := c.Scan(context.Background(), nil)
	if err != nil {
		t.Fatalf("Scan(nil): %v", err)
	}
	if len(res.Findings) != 0 {
		t.Errorf("expected no findings for empty input, got %d", len(res.Findings))
	}
}

func TestIsAvailable_HonorsEnabledFlag(t *testing.T) {
	on := NewClient(config.ScorecardConfig{Enabled: true})
	if !on.IsAvailable() {
		t.Error("enabled=true should be available")
	}
	off := NewClient(config.ScorecardConfig{Enabled: false})
	if off.IsAvailable() {
		t.Error("enabled=false should not be available")
	}
}
