# Contributing to snapem

Thanks for taking an interest. snapem is a small focused tool, so changes that fit the goal — security-first, drop-in for `npm`, macOS-first — land quickly. Changes that broaden the scope are usually a hard sell; please open an issue to discuss first.

## Before you start

- Read [CLAUDE.md](CLAUDE.md). It's the operating manual: how the codebase is laid out, what the container CLI actually does (it's not Docker), and which bug categories cause regressions.
- Read [SECURITY.md](SECURITY.md). If your change touches scanning, isolation, or policy evaluation, the threat model in there is load-bearing.
- Build and test locally: `make build && make test`. If those don't pass on a clean checkout, file an issue with your `uname -a` and `go version`.

## Project layout

```
cmd/snapem/             # entry point, version ldflags
internal/cli/           # cobra commands
internal/config/        # viper-backed config
internal/manifest/      # package.json + lockfile parsers
internal/scanner/       # orchestrator + Scanner interface
  scanner/osv/          # Google OSV client (CVEs)
  scanner/socket/       # Socket.dev client (malware, typosquats)
  scanner/scorecard/    # OSSF Scorecard via deps.dev (maintainer hygiene)
  scanner/provenance/   # npm SLSA provenance attestations
  scanner/metadata/     # deps.dev package metadata (deprecation, license)
internal/container/     # Apple container CLI wrapper
internal/pkgmanager/    # npm / bun / pnpm / yarn command-builders
internal/types/         # shared scanner data types
internal/errors/        # typed errors with exit codes
internal/ui/            # lipgloss-styled output + prompts
scripts/                # release helpers (homebrew tap, etc.)
.github/workflows/      # release.yml (goreleaser on tag)
```

No `pkg/` — public surface stays inside `internal/` unless there's a clear reason for an external API.

## The loop

For any non-trivial change:

1. **Plan.** Break the change into discrete commits you'd want to revert independently.
2. **Test-first when fixing a bug.** Write the failing Go test first. Confirm it fails. Then write the fix. Confirm it passes. Non-negotiable for the bug categories listed in CLAUDE.md §8.
3. **Build clean.** `make build`, `go vet ./...`, `make test` (which uses `-race`).
4. **Manual smoke when behavior is user-facing.** See CLAUDE.md §6 for the fixture-free smoke recipe.
5. **Commit.** Conventional subject (`fix:`, `feat:`, `refactor:`, `test:`, `docs:`, `chore:`). One feature per commit is the norm; combined commits are OK when shared-file diffs would force tedious hunk-by-hunk splits without revert-clean payoff.
6. **PR with a real description.** Use the same shape as the merged PRs on this repo: summary bullets, test plan, optional "Not in this PR" section for scoped-out work.

## Adding a new scanner

A scanner is anything that maps `(package name, version) → []Finding`. The interface is in [`internal/scanner/scanner.go`](internal/scanner/scanner.go) (`Scanner`). Concrete examples: [`internal/scanner/osv/client.go`](internal/scanner/osv/client.go), [`internal/scanner/socket/client.go`](internal/scanner/socket/client.go).

Required:
- Implement `Scanner.Name()`, `Scanner.Scan(ctx, packages) (*ScanResult, error)`.
- Honor `context.Cancel`. The orchestrator races scanners and cancels stragglers.
- Return all findings in a single `*ScanResult` — the orchestrator aggregates.
- Dedupe `(name, version)` before sending, and chunk large batches if the upstream API has a per-request cap (OSV: 1000 per `/v1/querybatch`; Socket: 200 conservative; deps.dev and the npm registry don't expose a batch endpoint so per-package calls are bounded by a worker pool — see `scorecard/client.go` for the pattern).
- Mock with `httptest.Server` for tests. Never hit the live API in CI.

Optional:
- Cache hit support: integrate with [`internal/scanner/cache.Store`](internal/scanner/cache/) so repeat scans of the same package don't re-call upstream. Bump `schemaVersion` if your finding shape changes.

Then register the scanner in [`internal/scanner/orchestrator.go`](internal/scanner/orchestrator.go) and add a config toggle in [`internal/config/config.go`](internal/config/config.go).

## Adding a new package manager

There are four today: npm, bun, pnpm, yarn — all in [`internal/pkgmanager/manager.go`](internal/pkgmanager/manager.go). The `Manager` interface is small:

```go
type Manager interface {
    Name() string
    InstallCommand(packages []string, saveDev bool) []string
    RunCommand(script string, args []string) []string
    ExecCommand(command []string) []string
    Image() string
}
```

The npm and bun managers run the binary directly. pnpm and yarn run via corepack inside `node:lts-slim` so we don't need a separate image per manager. Follow whichever pattern fits.

Update `pkgmanager.Detect()` to recognize the new lockfile and the `--package-manager` enum validator in [`internal/cli/root.go`](internal/cli/root.go).

## Adding a new lockfile parser

Lockfiles live in [`internal/manifest/`](internal/manifest/). Each parser is one file:

- [`parser.go`](internal/manifest/parser.go) — package-lock.json (npm v2+)
- [`bun.go`](internal/manifest/bun.go) — bun.lock (text format, bun 1.1+)
- [`pnpm.go`](internal/manifest/pnpm.go) — pnpm-lock.yaml (v9 + v6–v8 fallback)
- [`yarn.go`](internal/manifest/yarn.go) — yarn.lock (v1 + Berry common-case)

Each exposes `Has<X>Lockfile() bool` and `Parse<X>Lockfile() ([]Package, error)`. Update the preference chain in `GetDependenciesWithNotes` if the new format should take priority over an existing one.

Workspace-aware support is in [`workspaces.go`](internal/manifest/workspaces.go); the scan path uses the lockfile (workspace-aware by design) and the upgrade classifier uses `GetWorkspaceDirectDeps`.

## Tests

`make test` runs `go test -race -short ./...`. Treat warnings from `go vet` and `golangci-lint` as errors during cleanup PRs.

The full E2E suite runs against the real Apple `container` runtime:

```bash
make test-e2e   # requires `container system start` to have succeeded
```

It covers bind-mount writability, `--read-only` rejection, and `--network none` egress isolation. CI doesn't run this (the runner is Linux), so test locally before any change to [`internal/container/apple.go`](internal/container/apple.go).

## Release process

See [WORKFLOW.md](WORKFLOW.md). Only repo maintainers cut releases; if you're not sure whether your change should ship in the next release, ask in the PR.

## License and copyright

snapem is MIT-licensed. By contributing you agree that your changes ship under the same license.
