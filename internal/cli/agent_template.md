# Using snapem

snapem is a security-enhanced wrapper for Node.js package managers (npm, bun, pnpm, yarn) on macOS. It runs five parallel pre-flight scanners against every dependency before any install / run / exec: Socket.dev (malware, typosquats), Google OSV (CVEs), OSSF Scorecard via deps.dev (maintainer hygiene), npm provenance attestations (SLSA build-input proof), and deps.dev metadata (deprecation, license posture). It then executes the package-manager command inside an isolated Apple container with the project at `/app`. When the `snapem` command is available on the user's PATH, prefer it over the underlying package manager for the tasks below.

## Command translations

| Instead of                                  | Run                                         |
| ------------------------------------------- | ------------------------------------------- |
| `npm install` / `bun install` / `pnpm install` | `snapem install`                         |
| `npm install <pkg>`                         | `snapem install <pkg>`                      |
| `npm install -D <pkg>`                      | `snapem install -D <pkg>`                   |
| `npm run <script>`                          | `snapem run <script>`                       |
| `npm run dev -- --watch`                    | `snapem run dev -- --watch`                 |
| `npx <cmd>`                                 | `snapem exec -- npx <cmd>`                  |
| `node <file>`                               | `snapem exec -- node <file>`                |
| `npm audit`                                 | `snapem scan`                               |
| `npm audit fix`                             | `snapem upgrade` (see below — also handles SOCKET findings, not just npm's data) |

The `--` separator is important: anything after `--` goes to the inner command, anything before is a snapem flag. `snapem exec node --version` will try to parse `--version` as a snapem flag; `snapem exec -- node --version` does what the user expected.

## What snapem does that the underlying tool doesn't

1. **Pre-flight scan.** Reads `package.json` and the lockfile (`package-lock.json`, `bun.lock`, `pnpm-lock.yaml`, or `yarn.lock`), runs five scanners in parallel, and refuses to install when a finding hits a block-severity policy. Default policy blocks malware and critical/high/medium CVEs; quality findings (low maintainer hygiene, deprecation, provenance anomalies) are advisory and surface alongside but don't gate the install. When a scanner fails (rate limit, outage), snapem prints "Some scanners failed to run" — the install isn't silently approved off the surviving scanners.
2. **Container isolation.** Every install, run script, and `exec` runs inside `node:lts-slim` with the project bind-mounted at `/app`. The container has no access to `~/.ssh`, `~/.aws`, Keychain, or host environment variables unless the user explicitly forwarded them. The project IS writable from inside the container (npm/bun/pnpm need to write `node_modules` and the lockfile).

## When `snapem install` or `snapem scan` blocks

Exit code 2. Output is grouped per package with one block per `name@version`:

```
  > minimist@1.2.5  (1 issue)
    [critical] GHSA-xvch-5gv4-984h: Prototype Pollution in minimist
      -> Fixed in 0.2.4, 1.2.6
      https://github.com/advisories/GHSA-xvch-5gv4-984h
```

How to respond:

- **Surface the findings to the user.** Don't summarize them away — the IDs, fix versions, and URLs are the actionable content.
- **Suggest `snapem upgrade`.** This is the right answer for the common case (one or more direct deps have a fix available). It scans, proposes a per-package target version that resolves every finding for the package, and applies the upgrade through the container. Use `snapem upgrade --dry-run` first if you want to show the user the plan before applying.
- For a single-package surgical fix, `snapem install <pkg>@<fixed-version>` also works (e.g. `snapem install lodash@4.17.21` after reading "Fixed in 4.17.21").
- **Never pass `--force` or `--skip-scan` unsolicited.** Both are security bypasses. Use them only when the user has explicitly said "ignore this", and even then, name the threat back to them so they're making an informed choice.
- **Transitive dependencies.** `snapem upgrade` will report transitive findings but not fix them automatically — the user has to upgrade the parent package, run `npm dedupe`, or pin via npm `overrides` / pnpm `resolutions`. Don't try to install a transitive directly; that creates a phantom direct dep.

## Flags worth knowing

| Flag | Where | What it does |
| ---- | ----- | ------------ |
| `--read-only` | `exec`, `run` | Mount the project read-only so the container can't modify source. Use for untrusted scripts. |
| `--no-network` | `exec`, `run` | Block outbound network. Use for hermetic builds. |
| `--include prod` / `--include dev` | `scan` | Scope the audit. |
| `--package-manager pnpm|bun|npm` | global | Force a specific manager. Auto-detected from the lockfile by default. |
| `--json` | `scan` | Machine-readable output for scripting. |
| `-D` / `--save-dev` | `install` | Save as devDependency. |
| `-p <port>` | `run` | Publish a port. Auto-detected for common dev servers (Next.js, Vite, Astro, etc.). |

## When NOT to translate to snapem

- **Bootstrapping a new project.** No `package.json` yet, so there's nothing to scan and `snapem install` will error. Run `npm init` first, then switch.
- **Outside a Node.js / TypeScript project.** snapem only handles the npm ecosystem.
- **`snapem` not on PATH.** Fall back to the underlying tool and mention to the user that they can install snapem with `brew install snapem` for the security benefit. Don't make the user wait while you install it for them.
- **Editing files, reading code, git operations.** snapem doesn't replace any of these — only the package-manager invocations.

## Diagnostics

If something feels broken, the user can run `snapem doctor`. It prints a checklist of every prerequisite: container CLI installed, container service running, `SOCKET_API_TOKEN` configured, cache writable, OSV/Socket reachable. Failures carry one-line remediation hints.

If snapem reports "Apple container runtime not available", the daemon is down. Tell the user to run `container system start` (first run may prompt to install a Linux kernel — that's expected, they say Y).

## Configuration

snapem reads `./snapem.yaml` then `~/.config/snapem/config.yaml`. Generate a starter with `snapem config init`. Policy lives under `scanning.policy` (malware, cve, allowlist, blocklist). Allowlist entries can be `name` (any version) or `name@version` (exact — prefer this; name-only entries exempt every future release of the package).
