package scanner

import (
	"context"
	"sync"
	"time"

	"github.com/positronico/snapem/internal/config"
	"github.com/positronico/snapem/internal/manifest"
	"github.com/positronico/snapem/internal/scanner/osv"
	"github.com/positronico/snapem/internal/scanner/socket"
)

// Orchestrator coordinates multiple security scanners
type Orchestrator struct {
	scanners []Scanner
	config   *config.Config
}

// NewOrchestrator creates a new scanner orchestrator
func NewOrchestrator(cfg *config.Config) *Orchestrator {
	o := &Orchestrator{
		config: cfg,
	}

	// Add enabled scanners
	if cfg.Scanning.Socket.Enabled {
		o.scanners = append(o.scanners, socket.NewClient(cfg.Scanning.Socket))
	}
	if cfg.Scanning.OSV.Enabled {
		o.scanners = append(o.scanners, osv.NewClient(cfg.Scanning.OSV))
	}

	return o
}

// Scan runs all configured scanners concurrently
func (o *Orchestrator) Scan(ctx context.Context, packages []manifest.Package) (*AggregatedResult, error) {
	start := time.Now()

	if len(packages) == 0 {
		return &AggregatedResult{
			Results:       []*ScanResult{},
			TotalPackages: 0,
			TotalFindings: 0,
			Duration:      time.Since(start),
		}, nil
	}

	// Filter out allowlisted packages
	filteredPackages := o.filterAllowlisted(packages)

	// Run scanners concurrently
	var wg sync.WaitGroup
	resultsChan := make(chan *ScanResult, len(o.scanners))
	errChan := make(chan error, len(o.scanners))

	for _, s := range o.scanners {
		if !s.IsAvailable() {
			continue
		}
		wg.Add(1)
		go func(scanner Scanner) {
			defer wg.Done()
			result, err := scanner.Scan(ctx, filteredPackages)
			if err != nil {
				errChan <- err
				return
			}
			resultsChan <- result
		}(s)
	}

	// Wait for all scanners to complete
	go func() {
		wg.Wait()
		close(resultsChan)
		close(errChan)
	}()

	// Collect results
	var results []*ScanResult
	var firstErr error

	for {
		select {
		case result, ok := <-resultsChan:
			if !ok {
				resultsChan = nil
			} else {
				results = append(results, result)
			}
		case err, ok := <-errChan:
			if !ok {
				errChan = nil
			} else if firstErr == nil {
				firstErr = err
			}
		}

		if resultsChan == nil && errChan == nil {
			break
		}
	}

	// If all scanners failed, return error
	if len(results) == 0 && firstErr != nil {
		return nil, firstErr
	}

	// Aggregate results
	aggregated := o.aggregate(results)
	aggregated.TotalPackages = len(filteredPackages)
	aggregated.Duration = time.Since(start)

	// Filter out blocklisted packages (add findings for them)
	for _, pkg := range packages {
		if o.config.IsPackageBlocklisted(pkg.Name) {
			aggregated.Results = append(aggregated.Results, &ScanResult{
				Scanner:  "policy",
				Packages: 1,
				Findings: []Finding{
					{
						Package:     pkg.Name,
						Version:     pkg.Version,
						Type:        FindingTypeMalware,
						Severity:    SeverityCritical,
						Title:       "Blocklisted package",
						Description: "This package is in your blocklist",
					},
				},
			})
			aggregated.HasMalware = true
			aggregated.TotalFindings++
		}
	}

	return aggregated, nil
}

// ScanWithProgress runs scanners and reports progress via callback
func (o *Orchestrator) ScanWithProgress(ctx context.Context, packages []manifest.Package, onProgress func(scanner string, done bool)) (*AggregatedResult, error) {
	start := time.Now()

	if len(packages) == 0 {
		return &AggregatedResult{
			Results:       []*ScanResult{},
			TotalPackages: 0,
			TotalFindings: 0,
			Duration:      time.Since(start),
		}, nil
	}

	filteredPackages := o.filterAllowlisted(packages)

	var wg sync.WaitGroup
	resultsChan := make(chan *ScanResult, len(o.scanners))
	errChan := make(chan error, len(o.scanners))

	for _, s := range o.scanners {
		if !s.IsAvailable() {
			continue
		}
		wg.Add(1)
		go func(scanner Scanner) {
			defer wg.Done()
			if onProgress != nil {
				onProgress(scanner.Name(), false)
			}
			result, err := scanner.Scan(ctx, filteredPackages)
			if onProgress != nil {
				onProgress(scanner.Name(), true)
			}
			if err != nil {
				errChan <- err
				return
			}
			resultsChan <- result
		}(s)
	}

	go func() {
		wg.Wait()
		close(resultsChan)
		close(errChan)
	}()

	var results []*ScanResult
	var firstErr error

	for {
		select {
		case result, ok := <-resultsChan:
			if !ok {
				resultsChan = nil
			} else {
				results = append(results, result)
			}
		case err, ok := <-errChan:
			if !ok {
				errChan = nil
			} else if firstErr == nil {
				firstErr = err
			}
		}

		if resultsChan == nil && errChan == nil {
			break
		}
	}

	if len(results) == 0 && firstErr != nil {
		return nil, firstErr
	}

	aggregated := o.aggregate(results)
	aggregated.TotalPackages = len(filteredPackages)
	aggregated.Duration = time.Since(start)

	return aggregated, nil
}

func (o *Orchestrator) filterAllowlisted(packages []manifest.Package) []manifest.Package {
	var filtered []manifest.Package
	for _, pkg := range packages {
		if !o.config.IsPackageAllowlisted(pkg.Name) {
			filtered = append(filtered, pkg)
		}
	}
	return filtered
}

func (o *Orchestrator) aggregate(results []*ScanResult) *AggregatedResult {
	aggregated := &AggregatedResult{
		Results: results,
	}

	for _, result := range results {
		for _, finding := range result.Findings {
			aggregated.TotalFindings++

			if finding.Type == FindingTypeMalware || finding.Type == FindingTypeTyposquat {
				aggregated.HasMalware = true
			}

			switch finding.Severity {
			case SeverityCritical:
				aggregated.HasCritical = true
			case SeverityHigh:
				aggregated.HasHigh = true
			}
		}
	}

	return aggregated
}

// HasSocketScanner returns true if Socket scanner is enabled
func (o *Orchestrator) HasSocketScanner() bool {
	for _, s := range o.scanners {
		if s.Name() == "Socket.dev" && s.IsAvailable() {
			return true
		}
	}
	return false
}

// AvailableScanners returns names of available scanners
func (o *Orchestrator) AvailableScanners() []string {
	var names []string
	for _, s := range o.scanners {
		if s.IsAvailable() {
			names = append(names, s.Name())
		}
	}
	return names
}
