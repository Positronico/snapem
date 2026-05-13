# Changelog

All notable changes to snapem. Versions follow [SemVer](https://semver.org).

## v0.8.0 — 2026-05-12

### Added
- Animated spinner during scanner fan-out (`snapem scan`, `install`, `upgrade`). Multi-line redraw with braille spinner frames at 100ms. Non-TTY / `--quiet` / piped output falls back to the prior static `scanning... → complete` lines — no flicker, no escape sequences leaking into CI logs.
- Private registry support. New `container.mount_npmrc` config (**default `false`**, opt-in). When set to `true`, snapem bind-mounts `~/.npmrc` read-only at `/root/.npmrc` so installs from private registries (GitHub Packages, Verdaccio, npm Enterprise, etc.) work. A yellow warning prints on every install/run/exec/upgrade while the mount is active so the credential exposure is never silent. Credential-exposure tradeoff documented in SECURITY.md.
- `SECURITY.md` — threat model, what isolation does and doesn't cover, how to choose a policy. Concrete table of attacks snapem prevents vs. accepts.
- `CONTRIBUTING.md` — project layout, the loop, how to add a scanner / package manager / lockfile parser, how to run E2E tests.

### Changed
- Godoc passes on `internal/scanner.Scanner`, `internal/scanner.Orchestrator`, `internal/manifest.Parser`, `internal/manifest.Package`, `internal/manifest.Manifest`. Cache.Store was already documented; left as-is.

## v0.7.0 — 2026-05-12

### Added
- Workspace / monorepo support. `snapem upgrade` now reads each workspace member's `package.json` (npm/bun/yarn `workspaces` field; pnpm `pnpm-workspace.yaml`) and classifies findings on member-declared dependencies as direct, not transitive — so a lodash CVE in `packages/api/package.json` is now auto-fixable from the root. `scan` was already workspace-aware via the lockfile; the no-lockfile fallback now also unions member deps. Glob support: `packages/*` and exact paths; `**` patterns are silently skipped (rare, deferred). pnpm `!`-exclusions honored.

## v0.6.0 — 2026-05-12

### Added
- yarn.lock parsing (v1 fully supported; Berry's YAML-ish dialect covered for the common case). `Yarn` Manager runs via corepack inside `node:lts-slim` (same pattern as PNPM). `--package-manager yarn` and auto-detection from `yarn.lock` both work.
- `snapem scan --format sarif` emits SARIF v2.1.0 with one Run per scanner, deduped Rules keyed by advisory ID, and severity mapped to SARIF level. Ready for `github/codeql-action/upload-sarif@v3` ingest and GitLab's SAST report.
- `snapem scan --format` flag (text/json/sarif). `--json` kept as a backward-compatible shorthand for `--format json`.
- Per-package policy overrides: `scanning.policy.packages: { lodash: { cve: { high: warn } } }` overrides global policy for a specific package. Partial overrides fall back to global for unset keys; no override = global behavior preserved.
- README "CI/CD Integration" section with GitHub Actions + GitLab CI snippets paired with the SARIF support.

## v0.5.0 — 2026-05-12

### Added
- `snapem upgrade` subcommand. Scans the current dependency tree, groups findings by package, picks a per-package upgrade target that resolves every finding for that package (lowest version within the current major by default; `--major` opts into cross-major bumps), and applies the install through the container after confirmation. `--dry-run` prints the plan only; `--yes` skips the prompt. Transitive dependencies are reported but not auto-fixed.
- `Finding.FixedVersions []string` — structured form of the `Fixed in X, Y, Z` remediation. Used by `snapem upgrade` to pick a target version programmatically. Cache `schemaVersion` bumped 1 → 2 so older entries refetch and pick up the new field.

### Changed
- Agent template (`snapem agent install`) now recommends `snapem upgrade` as the primary remediation path when scan blocks, with `snapem install <pkg>@<version>` as the surgical fallback. Updates the install location for users who reinstall the skill (`snapem agent install --force`).

## v0.4.0 — 2026-05-12

### Added
- `snapem agent` subcommand. `snapem agent install` writes an instruction file that teaches AI coding assistants (Claude Code, AGENTS.md-aware tools) to use snapem instead of invoking npm/bun/pnpm directly — including how to surface block-severity findings with their `Fixed in X.Y.Z` remediation instead of bypassing them. Default writes a Claude Code skill at `~/.claude/skills/snapem.md`; `--format=md` writes `./AGENTS.md` in plain markdown. Refuses to overwrite existing files without `--force`.
- `snapem doctor` subcommand. Inspects the runtime environment (container CLI, service status, `SOCKET_API_TOKEN`, cache directory, OSV/Socket reachability) and prints a checklist. Exits non-zero only on blocking issues; missing token surfaces as a warning.
- `--read-only` flag on `snapem exec` and `snapem run`. Mounts the project at `/app` with `:ro` so untrusted scripts can't write back to your source. Not added to `install` (npm needs to write `node_modules` and `package-lock.json`).
- Build-tag-gated E2E test suite for the Apple container runtime (`make test-e2e`). Three cases: bind-mount writability, read-only volume rejection, `--network none` blocking DNS. Skips cleanly when the container service is down.

## v0.3.0 — 2026-05-12

### Added
- `snapem cache info` and `snapem cache clear` subcommands. File-based scan cache (one JSON per `(scanner, ecosystem, name, version)` under `os.UserCacheDir()/snapem/`, schema-versioned, TTL from `scanning.cache.ttl`).
- `bun.lock` (text) parsing for full transitive scanning on Bun 1.1+ projects. Clear warning emitted when only the binary `bun.lockb` is present.
- pnpm support: `pnpm-lock.yaml` parser (v9+ `snapshots` and v6–v8 `packages` shapes), pnpm `Manager` that runs via corepack inside `node:lts-slim`, `--package-manager pnpm`.
- Version-aware allowlist and blocklist: entries accept `name` (all versions) or `name@version` (exact). Name-only allowlist used to exempt every future release forever — a real security regression.
- Scan output groups findings by package, sorts by severity within, and prints a canonical advisory URL (GHSA / NVD) plus a `Fixed in X.Y.Z` line per finding.
- OSV findings are now enriched via `/v1/vulns/{id}` (was only IDs from `/querybatch`), so titles, descriptions, references, and severities populate.
- `--package-manager`, `--include`, and `container.network` config values are validated up front instead of silently falling back to defaults.

### Changed
- `EvaluatePolicy` is the single decision path for both `install` and `scan`. Previously `scan` only blocked on malware + critical CVE and silently exited 0 for high/medium even when policy said block.
- OSV and Socket batch requests are deduplicated and chunked (OSV 1000/req per spec, Socket 200/req conservative).
- Both scanners retry 429 with `Retry-After` honored; retry exhaustion produces "rate limit exceeded after N attempts" instead of opaque "giving up".
- Default `container.environment` no longer forwards `NPM_TOKEN` — a malicious install script would otherwise see the publish token.
- CI: bumped `actions/checkout` v4 → v6, `actions/setup-go` v5 → v6, `goreleaser/goreleaser-action` v6 → v7; pinned goreleaser CLI to `~> v2`.

### Fixed
- Blocklist was silently ignored on `install` and `scan` (`ScanWithProgress` was a 95%-duplicate of `Scan` and dropped the blocklist injection).
- CVSS parser replaced — the previous implementation counted substring occurrences via a buggy hand-rolled `contains()` and produced scores unrelated to the spec. Now a real CVSS v3 base-score calculator, with `database_specific.severity` preferred when GHSA published it.
- Configuration defaults disagreed across three places (viper SetDefault, the YAML template, post-load fallback). Single source of truth in `config.Defaults()` now, locked by a test.
- `--no-color` was sign-inverted via viper binding. Now resolved by a `useColor(cfg, flag)` helper with a truth-table test.
- CLI errors exited silently — `rootCmd` had `SilenceErrors=true` and `main.go` discarded the returned error. Now printed, with the typed `SnapemError` exit code propagated.

### Testing
- 7 packages covered (up from 1). Network-using code uses `httptest` mocks; no test hits live APIs.
- Apple `container` CLI argument generation pinned with a golden test so a flag rename surfaces as a deterministic failure.
- Live runtime smoke against `container` CLI v0.9.0 covering: `exec`, `install` (host-owned bind-mount writes), `run <script>`, pre-install threat blocking, and `--no-network` egress isolation (verified by EAI_AGAIN on outbound DNS).

## v0.1.2 — 2025-12-19

Earlier releases predate this changelog. See `git log v0.1.2` and prior tags for history.
