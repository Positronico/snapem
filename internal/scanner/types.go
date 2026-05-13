package scanner

import (
	"context"

	"github.com/positronico/snapem/internal/manifest"
	"github.com/positronico/snapem/internal/types"
)

// Re-export types from the types package for convenience
type (
	ScanResult       = types.ScanResult
	Finding          = types.Finding
	FindingType      = types.FindingType
	Severity         = types.Severity
	AggregatedResult = types.AggregatedResult
)

// Re-export constants
const (
	FindingTypeMalware    = types.FindingTypeMalware
	FindingTypeCVE        = types.FindingTypeCVE
	FindingTypeTyposquat  = types.FindingTypeTyposquat
	FindingTypeLicense    = types.FindingTypeLicense
	FindingTypeMaintainer = types.FindingTypeMaintainer
	FindingTypeQuality    = types.FindingTypeQuality

	SeverityCritical = types.SeverityCritical
	SeverityHigh     = types.SeverityHigh
	SeverityMedium   = types.SeverityMedium
	SeverityLow      = types.SeverityLow
	SeverityInfo     = types.SeverityInfo
)

// Re-export functions
var SeverityOrder = types.SeverityOrder

// Scanner is the contract every security scanner implements. The
// orchestrator races every available scanner against the same input
// and aggregates their findings.
//
// Implementations must:
//   - Honor context cancellation in long-running batch calls. The
//     orchestrator cancels stragglers when one scanner fails fast.
//   - Dedupe (name, version) before any upstream API call and chunk
//     batches to the upstream's per-request limit (OSV: 1000 per
//     /v1/querybatch; Socket: 200 conservative).
//   - Return all findings in a single *ScanResult; the orchestrator
//     aggregates across scanners but does not combine per-scanner
//     results internally.
//   - Be safe to call from goroutines — the orchestrator parallelizes.
//
// Tests in this package mock concrete scanners via httptest.Server.
// See internal/scanner/osv/client.go and internal/scanner/socket/
// client.go for reference implementations.
type Scanner interface {
	// Name returns the scanner's stable identifier (e.g. "osv",
	// "socket"). Used in cache keys, log lines, and the UI progress
	// callback — changing it is a breaking change.
	Name() string

	// Scan analyzes the given packages and returns every finding
	// matched against any of them. May return findings for fewer
	// packages than requested when not all packages had matches.
	// Returning (nil, nil) means "no findings"; returning a non-nil
	// error means the entire scan failed and no findings should be
	// trusted from this scanner.
	Scan(ctx context.Context, packages []manifest.Package) (*types.ScanResult, error)

	// IsAvailable reports whether this scanner can be used in the
	// current configuration (credentials present, network reachable,
	// feature flag enabled). Unavailable scanners are skipped by the
	// orchestrator without erroring.
	IsAvailable() bool
}
