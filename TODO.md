# snapem TODO

Forward-looking only. Shipped work lives in [CHANGELOG.md](CHANGELOG.md).

Items are ordered by priority within each tier. Anything in **Out of scope** has been deliberately declined — open an issue with new context if you think it should come back.

---

## P1 — known correctness or trust gaps

These are things we *claim* the product does but haven't fully proven, or where the current behavior could surprise a user in a security-relevant way.

- [ ] **Automated E2E test against Apple `container` runtime.** Build-tag gated (`//go:build container_e2e`) so it doesn't run in CI unless the service is up. Boots a container, mounts a real fixture project, runs `npm install`, asserts the install succeeded and the container was removed. Manual smoke pass was completed during v0.3.0 prep (install, run-script, exec, `--no-network` isolation all verified live); this item tracks turning that into a repeatable script.
- [ ] **`snapem doctor` subcommand.** Inspects the runtime: `container system status`, presence of `SOCKET_API_TOKEN`, cache directory writable, network reachability of OSV and Socket. Prints a checklist so new users diagnose their own setup.
- [ ] **Read-only project mount option.** `snapem exec` and `snapem run` currently mount the project read-write. A `--read-only` flag (or `container.readonly: true` in config) would let users opt into a stronger isolation posture for scripts that shouldn't write back. Volume option goes from `path:/app` to `path:/app:ro`.

## P2 — features in scope, not yet built

- [ ] **yarn.lock parsing.** Round out the four major npm-compatible package managers. yarn.lock has a custom textual format — `github.com/replicatedhq/yaml` or a hand-rolled parser. yarn v1 differs from Berry (v2+); cover at least v1 since it's still widespread.
- [ ] **SARIF output format.** Map scanner findings to SARIF v2.1.0 so CI tools (GitHub code scanning, etc.) ingest snapem results directly. Add `snapem scan --format sarif`.
- [ ] **CI/CD recipe docs.** README section with copy-paste GitHub Actions / GitLab CI snippets. Likely paired with the SARIF item.
- [ ] **Per-package policy actions.** Today policy is global by severity. Some users want `lodash` warnings to be informational while `axios` issues block. Schema sketch: `policy.packages: { "axios": { cve: { high: "block" } } }` overrides.
- [ ] **`snapem upgrade`.** Read findings, propose `npm install <name>@<fixed-version>` for each, optionally apply. Uses the `Remediation` field already populated by OSV enrichment. Major UX win.
- [ ] **Workspace / monorepo support.** Detect npm/pnpm/bun workspaces and scan each member's dependency tree. Currently only the root is scanned.

## P3 — polish and internal quality

- [ ] **Progress indicators.** Spinner during OSV/Socket fan-out. Cache hits make most scans fast now, but a 1500-dep cold scan still takes a few seconds.
- [ ] **macOS code signing / notarization.** Not blocking for the brew-first install path: Homebrew downloads via `curl` from a shell, so the bottle binary doesn't get the `com.apple.quarantine` xattr and runs without a Gatekeeper prompt. Becomes important if users download tarballs directly from the GitHub releases page in a browser, if we ship a `.pkg` installer, or if a corporate macOS fleet enforces "signed binaries only". Needs an Apple Developer account + signing cert (owner action) before this can be automated. **Blocked on user when prioritized.**
- [ ] **Godoc on exported APIs.** `internal/scanner.Scanner`, `internal/scanner/cache.Store`, `internal/manifest.Parser` are the highest-value ones.
- [ ] **Structured logging (slog).** Replace ad-hoc `fmt.Fprintln(os.Stderr, ...)` calls with `slog`. Lets verbose mode produce machine-parseable output.
- [ ] **Context cancellation audit.** Ctrl+C should propagate cleanly through every blocking operation. Most paths use `ctx` already; we haven't formally verified every fan-out goroutine respects cancel.
- [ ] **Scan duration / cache hit metrics.** Verbose-mode summary line: "scanned 482 packages (379 cached, 103 fresh) in 0.6s".
- [ ] **Security best practices guide.** Document threat model, what isolation does and doesn't cover, how to choose a policy.
- [ ] **Contributing guide.** Project layout, how to add a scanner / package manager / lockfile parser.

## P4 — small-scope helpers worth doing eventually

- [ ] **Pre-commit hook helper.** `snapem install pre-commit-hook` drops in a `.git/hooks/pre-commit` that runs `snapem scan`. Lightweight, useful.
- [ ] **Manifest parser for npm v1 lockfile** (npm 6). Niche in 2026 but a one-screen function.
- [ ] **Private registry support.** Forward `~/.npmrc` into the container as read-only, or honor `NPM_CONFIG_REGISTRY` from config. Currently impossible to install from a private registry inside the sandbox.
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
