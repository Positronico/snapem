# snapem TODO

## Completed

### Core Features
- [x] CLI with Cobra (install, run, exec, scan, config, version)
- [x] Configuration system with Viper (file + env vars)
- [x] Package.json manifest parsing
- [x] Dependency extraction for scanning
- [x] OSV API integration for CVE detection
- [x] Socket.dev API integration for malware detection
- [x] Concurrent scanning with orchestrator
- [x] Apple container runtime integration
- [x] Volume mounting (project dir → /app)
- [x] Network modes (host, none)
- [x] Port publishing with auto-detection
- [x] Signal handling for clean Ctrl+C
- [x] Policy enforcement (block/warn/ignore)
- [x] Verbose and quiet modes
- [x] npm package manager support
- [x] bun package manager support

### Testing (Manual)
- [x] Security scanning with vulnerable packages (lodash@4.17.20)
- [x] Install blocking on CVEs found
- [x] Dev server with port forwarding
- [x] Build scripts execution
- [x] Exec arbitrary commands
- [x] Configuration display
- [x] Network isolation (--network none)
- [x] Homebrew installation

### Distribution
- [x] GoReleaser setup (.goreleaser.yaml)
- [x] GitHub Actions release workflow
- [x] Homebrew tap (Positronico/homebrew-tap)
- [x] Formula update script (scripts/update-formula.sh)
- [x] Shell completions (bash/zsh/fish via Cobra)

### Documentation
- [x] README with beginner-friendly explanations
- [x] Security policies documentation
- [x] Shell completions instructions
- [x] Full configuration reference
- [x] Troubleshooting guide
- [x] Release workflow documentation (WORKFLOW.md)

## High Priority

### Testing & Validation
- [x] Mock HTTP responses for Socket.dev and OSV APIs (orchestrator, chunking, enrichment)
- [x] Policy enforcement tests (each finding type × severity × policy action)
- [x] Configuration validation tests
- [x] CVSS parser tests (table-driven with real vectors)
- [ ] Manifest parser fixtures for v1 lockfiles (existing tests cover v2 paths only)
- [x] Package argument parsing edge cases (`parsePackageArg`)
- [ ] End-to-end test against `container` runtime (gated behind a build tag)

### Security Scanner
- [x] **OSV finding enrichment** — fetch /v1/vulns/{id} after batch query so titles, severities, and references populate
- [x] **Batch chunking + dedup** — respect OSV's 1000/req cap; Socket conservative 200/req; dedupe (name, version) across nested node_modules paths
- [x] **Remediation surfacing** — pull `affected[].ranges[].events.fixed` and render "Fixed in X.Y.Z" in install/scan output

- [x] **Scan result caching**
  - File-based cache under `os.UserCacheDir()/snapem/`, one JSON per (scanner, ecosystem, name, version)
  - TTL from `scanning.cache.ttl`; schema-versioned so future shape changes invalidate cleanly
  - Per-scanner decorator so dedup at the orchestrator and chunking at the client both still apply to the miss set
  - Misconfigured cache directory degrades to no-cache rather than failing the scan
  - `snapem cache info` / `snapem cache clear` subcommands

- [x] **Rate limiting**
  - Custom CheckRetry on both clients adds 429 to the retry-able statuses
  - Backoff honors `Retry-After` header (via go-retryablehttp DefaultBackoff)
  - ErrorHandler surfaces a clean "rate limit exceeded after N attempts" when retries exhaust, instead of the opaque "giving up" wrap

### Bugs fixed this iteration (kept here so they don't recur silently)
- [x] Blocklist was silently ignored on install/scan (ScanWithProgress diverged from Scan)
- [x] Defaults disagreed across viper SetDefault, the YAML template, and Load
- [x] Fake CVSS parser replaced with a real v3 base-score implementation
- [x] `snapem scan` did not apply the full policy table (only blocked on malware + critical CVE)
- [x] `--no-color` flag was sign-inverted via viper binding
- [x] `--package-manager pnpm` and `--include garbage` silently fell back to defaults
- [x] NPM_TOKEN removed from default container environment passthrough
- [x] Container CLI flag generation pinned with a golden test

## Medium Priority

### User Experience
- [ ] **Progress indicators**
  - Add spinner during API calls
  - Show progress bar for large scans

- [ ] **Better scan output**
  - Show remediation suggestions for CVEs
  - Link to vulnerability details
  - Group findings by package

### Configuration
- [ ] **Project-level overrides**
  - Support `.snapemrc` file
  - Support `snapem` key in package.json

- [ ] **Per-package policies**
  - Allow different policies per package
  - Version-specific exceptions

## Low Priority

### Additional Features
- [ ] **SBOM generation** (CycloneDX, SPDX)
- [ ] **CI/CD integration** (GitHub Actions, GitLab CI)
- [ ] **SARIF output format**
- [ ] **Audit logging**

### Package Manager Support
- [ ] **pnpm support**
- [ ] **yarn support**

### Performance
- [ ] **Incremental scanning** (only scan changed packages)
- [ ] **Background scanning daemon**

## Technical Debt
- [ ] Add godoc comments to exported functions
- [ ] Implement structured logging (slog)
- [ ] Add context cancellation throughout
- [ ] Metrics (scan duration, cache hit rates)

## Documentation
- [ ] Security best practices guide
- [ ] Contributing guide

## Ideas for Future
- [ ] VS Code extension
- [ ] Pre-commit hook
- [ ] Dependency update suggestions
- [ ] Private registry support
- [ ] Offline mode with cached vulnerability data
- [ ] Policy as code (Rego/OPA)
