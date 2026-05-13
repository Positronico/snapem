# snapem TODO

Forward-looking only. Shipped work lives in [CHANGELOG.md](CHANGELOG.md).

Items are ordered by priority within each tier. Anything in **Out of scope** has been deliberately declined — open an issue with new context if you think it should come back.

---

## P1 — known correctness or trust gaps

Nothing currently open. All previous P1 items shipped to `main` as part of the post-v0.3.0 batch (build-tag E2E suite, `--read-only` flag on `exec`/`run`, `snapem doctor`). See [CHANGELOG.md](CHANGELOG.md) `Unreleased` section.

## P2 — features in scope, not yet built

- [x] **yarn.lock parsing.** Shipped v0.6.0. yarn v1 fully supported; Berry's YAML-ish dialect covered for the common case (single resolved version per spec). corepack-driven yarn Manager in the container.
- [x] **SARIF output format.** Shipped v0.6.0. `snapem scan --format sarif` emits SARIF v2.1.0 with one Run per scanner, deduped Rules, severity→level mapping.
- [x] **CI/CD recipe docs.** Shipped v0.6.0. README "CI/CD Integration" section with GitHub Actions + GitLab CI snippets.
- [x] **Per-package policy actions.** Shipped v0.6.0. `scanning.policy.packages: { name: { malware?, cve? } }` with partial-fallback to global for unset keys.
- [x] **`snapem upgrade`** — shipped v0.5.0. Per-package target version that resolves all findings, stays in current major by default, `--major` opts into cross-major bumps.
- [x] **Workspace / monorepo support.** `snapem upgrade` and the scan fallback path union workspace member `package.json` deps with root for direct-vs-transitive classification (npm/bun/yarn `workspaces`, pnpm `pnpm-workspace.yaml`). Scan via lockfile was already workspace-aware. `**` glob deferred.

## P3 — polish and internal quality

- [x] **Progress indicators.** Animated braille spinner per scanner during fan-out (`scan`, `install`, `upgrade`), 100ms multi-line redraw. Non-TTY/quiet fallback to the prior static lines.
- [ ] **macOS code signing / notarization.** Not blocking for the brew-first install path: Homebrew downloads via `curl` from a shell, so the bottle binary doesn't get the `com.apple.quarantine` xattr and runs without a Gatekeeper prompt. Becomes important if users download tarballs directly from the GitHub releases page in a browser, if we ship a `.pkg` installer, or if a corporate macOS fleet enforces "signed binaries only". Needs an Apple Developer account + signing cert (owner action) before this can be automated. **Blocked on user when prioritized.**
- [x] **Godoc on exported APIs.** Scanner interface, Orchestrator, manifest.Parser/Package/Manifest documented. cache.Store was already covered.
- [ ] **Structured logging (slog).** Replace ad-hoc `fmt.Fprintln(os.Stderr, ...)` calls with `slog`. Lets verbose mode produce machine-parseable output.
- [ ] **Context cancellation audit.** Ctrl+C should propagate cleanly through every blocking operation. Most paths use `ctx` already; we haven't formally verified every fan-out goroutine respects cancel.
- [ ] **Scan duration / cache hit metrics.** Verbose-mode summary line: "scanned 482 packages (379 cached, 103 fresh) in 0.6s".
- [x] **Security best practices guide.** Shipped as SECURITY.md — threat model, prevents/doesn't-prevent table, policy choice guidance, operational hardening.
- [x] **Contributing guide.** Shipped as CONTRIBUTING.md — project layout, the loop, how to add a scanner / package manager / lockfile parser, E2E test run instructions.

## P4 — small-scope helpers worth doing eventually

- [ ] **Pre-commit hook helper.** `snapem install pre-commit-hook` drops in a `.git/hooks/pre-commit` that runs `snapem scan`. Lightweight, useful.
- [ ] **Manifest parser for npm v1 lockfile** (npm 6). Niche in 2026 but a one-screen function.
- [x] **Private registry support.** `~/.npmrc` auto-mounted read-only at `/root/.npmrc` when present (npm/yarn/pnpm compatible). `container.mount_npmrc: false` opts out. Credential-exposure tradeoff documented in SECURITY.md.
- [ ] **Audit log file.** `~/.local/share/snapem/audit.log` records every `--force` / `--skip-scan` invocation with timestamp and package list. Helps post-incident review.

## P5 — larger features that need design discussion before code

- [ ] **SBOM generation** (CycloneDX, SPDX). Output the dependency tree in either format. Important for compliance use cases but the spec is non-trivial.
- [ ] **Offline mode.** Local mirror of the OSV database (downloadable as a zip from osv.dev). Lets snapem work air-gapped at the cost of staleness.
- [ ] **Dependency update suggestions.** Beyond `Remediation`, suggest the next minor or major that resolves multiple findings. Needs semver-aware logic.

## Out of scope (declined for now)

These came up during analysis but aren't going to ship. Open an issue if you disagree.

- **VS Code extension.** Separate project; not part of the CLI.
- **Background scanning daemon.** A persistent process doesn't fit the "drop-in for npm" model.
- **Incremental scanning.** Dedup + cache already give us this for free at much lower complexity.
- **Policy as code (OPA / Rego).** YAML policy + per-package overrides cover the realistic delta; OPA is heavy for the value.

---

## Notes on E2E coverage

What's verified live against real APIs and runtime:
- ✅ OSV `/v1/querybatch` + `/v1/vulns/{id}` enrichment against real CVEs (lodash, minimist, axios fixtures).
- ✅ Socket.dev `/v0/purl` with a real token (any account with `SOCKET_API_TOKEN` env set).
- ✅ Cache miss → hit timing (10× differential demonstrated on a 4-package project).
- ✅ Grouped output with advisory URLs against multi-package vulnerable fixtures.
- ✅ Apple `container` runtime against CLI v0.9.0: `snapem exec` (basic command), `snapem install` (full npm install path, host-owned files via bind mount), `snapem run <script>` (Ctrl+C-safe via trap wrapper), `snapem install` blocking on critical CVE before container starts, `--no-network` returning EAI_AGAIN for outbound DNS.

What's pinned by unit tests but not exercised against the live runtime:
- bun and pnpm install command shape (parsers tested against fixtures; the actual `corepack pnpm install` and `bun install` round-trips have not been driven from a session with those tools installed).
