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

// Scanner defines the interface for security scanners
type Scanner interface {
	// Name returns the scanner identifier
	Name() string

	// Scan analyzes packages and returns findings
	Scan(ctx context.Context, packages []manifest.Package) (*types.ScanResult, error)

	// IsAvailable checks if the scanner can be used
	IsAvailable() bool
}
