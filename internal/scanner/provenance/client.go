// Package provenance implements a scanner that surfaces npm package
// provenance attestations.
//
// When a publisher runs `npm publish --provenance` from a trusted
// builder (today: GitHub Actions, GitLab Pipelines), npm stores a
// Sigstore-signed SLSA provenance attestation alongside the tarball.
// The attestation binds the published tarball to (source repository,
// git ref, build workflow path, builder identity) — a different kind
// of supply-chain signal from "is there a known CVE" (OSV) or
// "did Socket flag this as malware" (Socket).
//
// What this release does
//
// snapem fetches the per-version metadata from the npm registry,
// detects the presence/absence of provenance, and — when present —
// downloads the attestation bundle, decodes the DSSE envelope's
// payload (base64 JSON), and recovers the build inputs.
//
// It also checks that the attestation's `subject` PURL matches the
// package snapem is scanning. A subject mismatch is a real red flag:
// it means a published tarball is shipping attestations for a
// different name@version, which is the shape of a confusion attack.
//
// What this release does NOT do (yet)
//
// Cryptographic verification of the Sigstore bundle (Fulcio cert
// chain, rekor inclusion proof, signature over the DSSE envelope) is
// a planned follow-up.
//
// Posture: valid provenance is NOT a positive safety signal
//
// Provenance attestations were once the strongest pre-disclosure
// signal in this stack. They no longer are. A compromised CI pipeline
// produces *valid* attestations — the signing identity is the real
// builder, the subject PURL is the real package, the Sigstore bundle
// verifies cryptographically — because the builder is doing exactly
// what the predicate claims, just with poisoned inputs the predicate
// can't see. SLSA verifies process integrity, not source integrity.
//
// Consequence for this scanner: a healthy provenance result means
// "nothing here is wrong" and nothing more. Do NOT treat it as
// evidence the package is safe. Treat it as evidence the package is
// not exhibiting the *naïve token-theft* failure mode (an attacker
// who skipped --provenance because they didn't have a way to run the
// real workflow). For richer signals, defer to behavioral scanners
// (Socket) and the structural scanners in the gitdep and tarball
// packages — those don't rely on the publishing pipeline being
// trustworthy.
//
// Subject-PURL mismatch and "attestation present but unreadable"
// remain genuine anomalies and are still emitted as findings.
package provenance

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/hashicorp/go-retryablehttp"

	"github.com/positronico/snapem/internal/config"
	"github.com/positronico/snapem/internal/manifest"
	"github.com/positronico/snapem/internal/types"
)

const (
	registryBase = "https://registry.npmjs.org"

	// slsaPredicate is the predicateType in npm's SLSA provenance
	// attestation. There's also an "npm publish" attestation whose
	// predicateType is npm-specific; we care about the SLSA one
	// because it carries the build-input claim.
	slsaPredicate = "https://slsa.dev/provenance/v1"

	// concurrency bounds parallel registry/attestation lookups.
	// The npm registry is generous; we stay polite.
	concurrency = 8
)

// Client is the provenance scanner. Satisfies the parent package's
// Scanner interface via Name / IsAvailable / Scan.
type Client struct {
	httpClient  *http.Client
	timeout     time.Duration
	warnMissing bool
	enabled     bool
	baseURL     string // overrideable in tests
}

// NewClient returns a configured provenance client.
func NewClient(cfg config.ProvenanceConfig) *Client {
	retry := retryablehttp.NewClient()
	retry.RetryMax = 3
	retry.Logger = nil
	retry.CheckRetry = retryOn429
	retry.Backoff = retryablehttp.DefaultBackoff

	return &Client{
		httpClient:  retry.StandardClient(),
		timeout:     cfg.Timeout,
		warnMissing: cfg.WarnMissing,
		enabled:     cfg.Enabled,
		baseURL:     registryBase,
	}
}

func retryOn429(ctx context.Context, resp *http.Response, err error) (bool, error) {
	if resp != nil && resp.StatusCode == http.StatusTooManyRequests {
		return true, nil
	}
	return retryablehttp.DefaultRetryPolicy(ctx, resp, err)
}

// Name returns "provenance".
func (c *Client) Name() string { return "provenance" }

// IsAvailable mirrors the config toggle. The npm registry is public,
// so there's no credential check.
func (c *Client) IsAvailable() bool { return c.enabled }

// versionMetadata is the subset of the npm registry's
// /<name>/<version> response we need. dist.attestations is present
// when the publisher used --provenance.
type versionMetadata struct {
	Dist struct {
		Attestations *attestationsRef `json:"attestations"`
	} `json:"dist"`
}

type attestationsRef struct {
	URL string `json:"url"`
}

// attestationsResponse is what npm returns from
// /-/npm/v1/attestations/<name>@<version>.
type attestationsResponse struct {
	Attestations []attestation `json:"attestations"`
}

type attestation struct {
	PredicateType string `json:"predicateType"`
	Bundle        struct {
		DSSEEnvelope struct {
			// Payload is a base64-encoded JSON document (the
			// in-toto statement). Signatures are present but we
			// don't verify them in this release.
			Payload     string `json:"payload"`
			PayloadType string `json:"payloadType"`
		} `json:"dsseEnvelope"`
	} `json:"bundle"`
}

// slsaStatement is the in-toto statement we decode from the DSSE
// envelope payload. Only the fields we need to display or verify.
type slsaStatement struct {
	PredicateType string `json:"predicateType"`
	Subject       []struct {
		Name string `json:"name"` // e.g. "pkg:npm/lodash@4.17.21"
	} `json:"subject"`
	Predicate struct {
		BuildDefinition struct {
			ExternalParameters struct {
				Workflow struct {
					Ref        string `json:"ref"`
					Repository string `json:"repository"`
					Path       string `json:"path"`
				} `json:"workflow"`
			} `json:"externalParameters"`
		} `json:"buildDefinition"`
		RunDetails struct {
			Builder struct {
				ID string `json:"id"`
			} `json:"builder"`
		} `json:"runDetails"`
	} `json:"predicate"`
}

// Scan returns findings for any provenance anomaly: subject-PURL
// mismatch always emits, missing provenance emits when
// cfg.WarnMissing is true. Healthy provenance produces no finding
// (positive signal is surfaced via the standard verbose path; we
// don't spam scan output with "all good" rows).
func (c *Client) Scan(ctx context.Context, packages []manifest.Package) (*types.ScanResult, error) {
	result := &types.ScanResult{Scanner: c.Name(), Findings: []types.Finding{}}
	if len(packages) == 0 {
		return result, nil
	}

	// Dedupe (name, version).
	seen := make(map[string]struct{}, len(packages))
	deduped := make([]manifest.Package, 0, len(packages))
	for _, p := range packages {
		key := p.Name + "@" + p.Version
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		deduped = append(deduped, p)
	}

	jobs := make(chan manifest.Package)
	var (
		mu       sync.Mutex
		findings []types.Finding
		wg       sync.WaitGroup
	)

	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for p := range jobs {
				select {
				case <-ctx.Done():
					return
				default:
				}
				if f, ok := c.scanOne(ctx, p); ok {
					mu.Lock()
					findings = append(findings, f)
					mu.Unlock()
				}
			}
		}()
	}

	for _, p := range deduped {
		select {
		case <-ctx.Done():
			close(jobs)
			wg.Wait()
			return nil, ctx.Err()
		case jobs <- p:
		}
	}
	close(jobs)
	wg.Wait()

	if err := ctx.Err(); err != nil {
		return nil, err
	}

	sort.Slice(findings, func(i, j int) bool {
		return findings[i].Package < findings[j].Package
	})
	result.Findings = findings
	return result, nil
}

// scanOne runs the per-package flow and returns (finding, true) when
// something should be surfaced.
func (c *Client) scanOne(ctx context.Context, pkg manifest.Package) (types.Finding, bool) {
	meta, ok := c.fetchVersion(ctx, pkg)
	if !ok {
		// Couldn't reach the registry or package not found. Don't
		// emit — this isn't an attestation problem, just a network
		// or naming issue another scanner is better positioned to
		// surface.
		return types.Finding{}, false
	}

	if meta.Dist.Attestations == nil || meta.Dist.Attestations.URL == "" {
		if !c.warnMissing {
			return types.Finding{}, false
		}
		return types.Finding{
			Type:     types.FindingTypeQuality,
			Severity: types.SeverityLow,
			Package:  pkg.Name,
			Version:  pkg.Version,
			Title:    "No npm provenance attestation",
			Description: "Package was not published with `npm publish --provenance`. " +
				"Without it, the source repo and builder cannot be verified.",
		}, true
	}

	stmt, ok := c.fetchSLSA(ctx, meta.Dist.Attestations.URL)
	if !ok {
		// Provenance was advertised but we couldn't fetch/decode it.
		// That's a real anomaly — surface it.
		return types.Finding{
			Type:        types.FindingTypeQuality,
			Severity:    types.SeverityLow,
			Package:     pkg.Name,
			Version:     pkg.Version,
			Title:       "Provenance attestation present but unreadable",
			Description: "npm registry advertised a provenance URL but the bundle could not be fetched or decoded.",
		}, true
	}

	// Subject-PURL match. The attestation says "I'm for X" — confirm
	// X is the package npm just served us. A mismatch is the shape
	// of an attestation-confusion attack.
	expected := "pkg:npm/" + pkg.Name + "@" + pkg.Version
	matched := false
	for _, sub := range stmt.Subject {
		if equalPURL(sub.Name, expected) {
			matched = true
			break
		}
	}
	if !matched {
		gotList := make([]string, 0, len(stmt.Subject))
		for _, sub := range stmt.Subject {
			gotList = append(gotList, sub.Name)
		}
		return types.Finding{
			Type:     types.FindingTypeQuality,
			Severity: types.SeverityMedium,
			Package:  pkg.Name,
			Version:  pkg.Version,
			Title:    "Provenance subject mismatch",
			Description: fmt.Sprintf("Attestation declares subject %v but package served as %s. "+
				"This is the shape of an attestation-confusion attack.",
				gotList, expected),
		}, true
	}

	// Healthy provenance — no finding emitted. Note this is the
	// absence of an *attestation* anomaly only; it does not certify
	// the package is benign. A compromised CI pipeline produces
	// cryptographically valid attestations for malicious tarballs
	// because SLSA verifies process integrity, not source integrity.
	// See the package header comment.
	return types.Finding{}, false
}

// equalPURL compares two PURLs case-sensitively. PURLs are RFC-style
// scheme-host-path lowercase-by-convention but we don't enforce since
// npm package names are case-sensitive in the registry already.
func equalPURL(a, b string) bool { return a == b }

// fetchVersion grabs <name>/<version> from the npm registry. Returns
// (nil, false) for 404s and transport errors alike — the caller
// distinguishes by interpreting the boolean.
func (c *Client) fetchVersion(ctx context.Context, pkg manifest.Package) (*versionMetadata, bool) {
	u := c.baseURL + "/" + url.PathEscape(pkg.Name) + "/" + url.PathEscape(pkg.Version)
	var v versionMetadata
	if !c.getJSON(ctx, u, &v) {
		return nil, false
	}
	return &v, true
}

// fetchSLSA pulls the attestations bundle and returns the SLSA
// statement. Returns ok=false if no SLSA attestation is present, the
// payload doesn't decode, or the HTTP call fails.
func (c *Client) fetchSLSA(ctx context.Context, attestationsURL string) (*slsaStatement, bool) {
	var resp attestationsResponse
	if !c.getJSON(ctx, attestationsURL, &resp) {
		return nil, false
	}
	for _, a := range resp.Attestations {
		if a.PredicateType != slsaPredicate {
			continue
		}
		payload, err := base64.StdEncoding.DecodeString(a.Bundle.DSSEEnvelope.Payload)
		if err != nil {
			continue
		}
		var stmt slsaStatement
		if err := json.Unmarshal(payload, &stmt); err != nil {
			continue
		}
		return &stmt, true
	}
	return nil, false
}

// getJSON is the shared GET-and-decode used by both endpoints.
func (c *Client) getJSON(ctx context.Context, fullURL string, out any) bool {
	if c.timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, c.timeout)
		defer cancel()
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, fullURL, nil)
	if err != nil {
		return false
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "snapem")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		_, _ = io.Copy(io.Discard, resp.Body)
		return false
	}
	if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
		return false
	}
	return true
}

// StatementForPackage exposes the parsed SLSA statement for a single
// package without going through Scan. Intended for the verbose
// summary that lists "✓ pkg has provenance from <repo>@<ref>". The
// scanner output is restricted to findings (anomalies); positive
// signal goes through this side channel.
//
// Returns (nil, false) when the package has no provenance, the
// attestation can't be fetched, or any decode error.
func (c *Client) StatementForPackage(ctx context.Context, pkg manifest.Package) (*Statement, bool) {
	meta, ok := c.fetchVersion(ctx, pkg)
	if !ok || meta.Dist.Attestations == nil {
		return nil, false
	}
	stmt, ok := c.fetchSLSA(ctx, meta.Dist.Attestations.URL)
	if !ok {
		return nil, false
	}
	return &Statement{
		Repository: stmt.Predicate.BuildDefinition.ExternalParameters.Workflow.Repository,
		Ref:        stmt.Predicate.BuildDefinition.ExternalParameters.Workflow.Ref,
		Workflow:   stmt.Predicate.BuildDefinition.ExternalParameters.Workflow.Path,
		Builder:    stmt.Predicate.RunDetails.Builder.ID,
		SubjectOK:  hasSubject(stmt, pkg),
	}, true
}

// Statement is the user-facing summary of a provenance attestation.
// Hides the in-toto/SLSA layering so callers can render without
// knowing the spec.
type Statement struct {
	Repository string // e.g. "https://github.com/sigstore/sigstore-js"
	Ref        string // e.g. "refs/heads/main"
	Workflow   string // e.g. ".github/workflows/release.yml"
	Builder    string // e.g. "https://github.com/actions/runner/github-hosted"
	SubjectOK  bool   // whether the attestation's subject matches this package
}

// Short returns a one-line "<repo>@<short-ref>" rendering for the
// scan progress UI.
func (s *Statement) Short() string {
	repo := strings.TrimPrefix(s.Repository, "https://")
	ref := strings.TrimPrefix(s.Ref, "refs/heads/")
	ref = strings.TrimPrefix(ref, "refs/tags/")
	if ref == "" {
		return repo
	}
	return repo + "@" + ref
}

func hasSubject(stmt *slsaStatement, pkg manifest.Package) bool {
	expected := "pkg:npm/" + pkg.Name + "@" + pkg.Version
	for _, sub := range stmt.Subject {
		if equalPURL(sub.Name, expected) {
			return true
		}
	}
	return false
}
