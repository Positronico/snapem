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

## High Priority

### Testing & Validation
- [ ] **Automated tests**
  - Mock HTTP responses for Socket.dev and OSV APIs
  - Test concurrent scanning behavior
  - Test policy enforcement logic
  - Test cache functionality

- [ ] **Unit tests**
  - Manifest parser (package.json, package-lock.json)
  - Configuration loading and validation
  - Error handling and exit codes
  - Package argument parsing (name@version)

### Security Scanner
- [ ] **Scan result caching**
  - Implement file-based cache in `~/.cache/snapem/`
  - Cache key based on package name + version
  - Respect TTL from configuration
  - Invalidate cache on config changes

- [ ] **Rate limiting**
  - Handle Socket.dev rate limits gracefully
  - Exponential backoff for retries

## Medium Priority

### Distribution
- [x] **GoReleaser setup**
  - Create `.goreleaser.yaml`
  - Configure for darwin/arm64 (macOS Silicon)
  - Set up GitHub Actions for releases

- [ ] **Homebrew formula**
  - Create tap repository
  - Write formula with container dependency
  - Test installation flow

- [ ] **Shell completions**
  - Generate bash/zsh/fish completions
  - Add to install instructions

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
- [ ] Detailed configuration reference
- [ ] Security best practices guide
- [ ] Troubleshooting guide
- [ ] Contributing guide

## Ideas for Future
- [ ] VS Code extension
- [ ] Pre-commit hook
- [ ] Dependency update suggestions
- [ ] Private registry support
- [ ] Offline mode with cached vulnerability data
- [ ] Policy as code (Rego/OPA)
