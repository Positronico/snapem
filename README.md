```
  █████████                                  ██
 ███░░░░░███                                ███
░███    ░░░  ████████    ██████   ████████ ░░░   ██████  █████████████
░░█████████ ░░███░░███  ░░░░░███ ░░███░░███     ███░░███░░███░░███░░███
 ░░░░░░░░███ ░███ ░███   ███████  ░███ ░███    ░███████  ░███ ░███ ░███
 ███    ░███ ░███ ░███  ███░░███  ░███ ░███    ░███░░░   ░███ ░███ ░███
░░█████████  ████ █████░░████████ ░███████     ░░██████  █████░███ █████
 ░░░░░░░░░  ░░░░ ░░░░░  ░░░░░░░░  ░███░░░       ░░░░░░  ░░░░░ ░░░ ░░░░░
                                  ░███
                                  █████
                                 ░░░░░
```

# snapem - Secure npm for macOS

**A safer way to install npm packages.** snapem scans your dependencies for security issues before installing them, and runs everything in an isolated container so malicious code can't access your files.

## Why Use snapem?

When you run `npm install`, packages can execute code on your computer immediately. A malicious package could:

- 📁 Read your SSH keys and upload them somewhere
- 🔑 Steal credentials from environment variables
- 📤 Send your source code to a remote server
- 💻 Install a backdoor on your system

This isn't theoretical — supply chain attacks happen regularly. In 2024 alone, thousands of malicious packages were detected on npm.

**snapem protects you by:**

1. **Scanning first** — Checks packages against security databases before installing
2. **Running in isolation** — Uses macOS containers so packages can't access your real files
3. **Blocking known threats** — Stops installation if malware or critical vulnerabilities are found

## Installation

### Option 1: Homebrew (Recommended)

```bash
brew tap Positronico/tap
brew install snapem
```

### Option 2: From Source

```bash
git clone https://github.com/Positronico/snapem.git
cd snapem
make build
sudo cp bin/snapem /usr/local/bin/
```

### Prerequisites

snapem requires Apple's container runtime (CLI v0.9.0 or newer):

```bash
# Install the container CLI
brew install container

# Start the container service (first time only)
container system start
# When prompted to install the Linux kernel, type Y
```

Verify it's working:
```bash
container run --rm node:lts-slim node --version
```

The first run pulls `node:lts-slim` (~250 MB extracted on Apple Silicon)
and starts the container service; subsequent runs are immediate.

## Quick Start

Use snapem exactly like you would use npm:

```bash
cd my-project

# Instead of: npm install
snapem install

# Instead of: npm run dev
snapem run dev

# Instead of: npm run build
snapem run build
```

That's it! snapem scans your packages, then runs everything safely in a container.

## Setting Up Security Scanning

snapem uses seven security data sources:

| Service | What it detects | API Key Required? |
|---------|----------------|-------------------|
| [Socket.dev](https://socket.dev) | Malware, suspicious code, typosquatting | Yes (free tier available) |
| [Google OSV](https://osv.dev) | Known vulnerabilities (CVEs) | No |
| [OSSF Scorecard](https://github.com/ossf/scorecard) via [deps.dev](https://deps.dev) | Maintainer hygiene (recent activity, code review, signed releases, dangerous workflows, etc.) | No |
| npm provenance attestations | SLSA-format proof of "this tarball was built from `<repo>@<ref>` by `<builder>`" — detects attestation-confusion attacks and (optionally) flags packages with no provenance. **Note**: valid provenance is *not* a positive safety signal; a compromised CI pipeline produces valid attestations for malicious tarballs. SLSA verifies process integrity, not source integrity. | No |
| Package metadata via [deps.dev](https://deps.dev) | Maintainer-marked deprecation (npm `npm deprecate`); optionally license posture | No |
| gitdep | Published packages whose `dependencies` / `optionalDependencies` / `peerDependencies` reference git URLs, raw tarballs, file paths, or GitHub-shortcut refs. Those bypass every other scanner and trigger a `prepare` lifecycle hook at install time. | No |
| tarball audit | Each package's tarball is downloaded and its contents are checked against the `files` whitelist declared in the package's own package.json (plus always-included docs and declared entry points). A mismatch is the shape of a tampered or surprise-content publish. | No |

Each scanner adds an independent angle. A bad-news package commonly trips multiple scanners — e.g. `request@2.88.2` shows up as deprecated, low maintainer hygiene, AND a known SSRF CVE in a single scan pass. Findings from quality scanners (Scorecard, metadata, provenance, gitdep, tarball) are advisory by default; the malware/CVE scanners block per the configured policy.

Tunables:
- `scanning.scorecard.threshold` (default `5.0`) — Scorecard score below which a finding fires
- `scanning.provenance.warn_missing` (default `false`) — also flag packages without any provenance
- `scanning.metadata.warn_unknown_license` (default `false`) — emit a low advisory for unknown / non-standard licenses
- `scanning.tarball.enabled` (default `true`) — disable in bandwidth-constrained CI to skip the per-package tarball download

### Getting a Socket.dev API Key (Recommended)

Without a Socket.dev key, snapem can only detect *known* vulnerabilities. With it, you also get protection against *new* malware that hasn't been reported yet.

1. Go to [socket.dev](https://socket.dev) and create a free account
2. Navigate to **Settings** → **API Tokens**
3. Click **Create Token** and copy it
4. Add to your shell profile (`~/.zshrc` or `~/.bashrc`):

```bash
export SOCKET_API_TOKEN="your-token-here"
```

5. Reload your shell: `source ~/.zshrc`

> **Without a token:** snapem will warn you and ask you to type `unsecure` to continue. You'll still get CVE scanning, just not malware detection.

## AI Assistant Integration

If you use Claude Code (or another AI coding assistant), one extra command teaches it to use snapem instead of running `npm` / `bun` / `pnpm` directly.

### Claude Code

```bash
snapem agent install
```

That writes `~/.claude/skills/snapem.md`. Claude Code picks it up automatically — restart any running session (or open a new one) and Claude will translate `npm install lodash` → `snapem install lodash`, `npm run dev` → `snapem run dev`, `npx prisma migrate` → `snapem exec -- npx prisma migrate`, and `npm audit` → `snapem scan` in projects where the `snapem` command is on PATH. It will also surface block-severity findings (with the `Fixed in X.Y.Z` remediation) instead of silently bypassing them.

### Other tools (Codex, Cursor, generic `AGENTS.md`)

```bash
snapem agent install --format=md
```

Writes `./AGENTS.md` in plain markdown, which most AGENTS.md-aware tools ingest automatically.

### Preview without installing

```bash
snapem agent show               # Claude Code skill format (with frontmatter)
snapem agent show --format=md   # plain markdown
```

Refuses to overwrite an existing file by default. Pass `--force` if you've customized your skill and want to start fresh, or `--output PATH` to write somewhere else (e.g., a project-local `CLAUDE.md`).

## Commands Reference

### `snapem install` — Install Packages

Scans dependencies, then installs them in a container.

```bash
snapem install                  # Install all from package.json
snapem install lodash           # Install a specific package
snapem install -D jest          # Install as dev dependency
snapem install --skip-scan      # Skip scanning (not recommended)
snapem install --no-container   # Run on host (not recommended)
snapem install --force          # Continue even if threats found
```

**Private registries.** Off by default. To install from a private registry (GitHub Packages, npm Enterprise, Verdaccio, etc.), set `container.mount_npmrc: true` in `snapem.yaml`. snapem will bind-mount `~/.npmrc` read-only into the container at `/root/.npmrc` and **print a yellow warning on every command** while the mount is active — a malicious install script in any dependency can read those auth tokens, same exposure as bare `npm install`. Read [SECURITY.md](SECURITY.md) before flipping the knob, and prefer enabling it only in the specific projects that need it.

### `snapem run` — Run Scripts

Runs npm scripts inside a container.

```bash
snapem run dev                  # Run dev server
snapem run build                # Run build script
snapem run test                 # Run tests
snapem run test -- --watch      # Pass arguments after --
```

**Port forwarding:** For dev servers, snapem automatically detects and exposes the right port:

```bash
snapem run dev                  # Auto-detects port (e.g., 3000)
snapem run dev -p 8080          # Use custom port
snapem run dev -p 8080:3000     # Map 8080 on host to 3000 in container
snapem run dev --no-ports       # Disable auto port detection
snapem run build --no-network   # Run without network access
```

### `snapem exec` — Run Any Command

Execute arbitrary commands in the container.

```bash
snapem exec -- node index.js
snapem exec -- npx prisma migrate
snapem exec -- sh -c "ls -la"
```

> **Important:** Use `--` before your command to separate snapem flags from command arguments.

### `snapem upgrade` — Apply Remediations Automatically

Scans, proposes a per-package version bump that resolves every finding for that package, and applies it through the container after confirmation.

```bash
snapem upgrade              # propose + confirm + apply
snapem upgrade --dry-run    # propose + exit
snapem upgrade --yes        # apply without prompting
snapem upgrade --major      # allow major-version bumps when no in-major fix exists
```

By default, upgrades stay within the package's current major version. Transitive dependencies (not in `package.json` directly) are reported but not auto-fixed — upgrade the parent dependency, run `npm dedupe`, or pin via npm `overrides` / pnpm `resolutions`.

**Workspaces / monorepos.** snapem reads each member's `package.json` (npm/bun/yarn `workspaces`, pnpm's `pnpm-workspace.yaml`) when deciding whether a finding is direct or transitive — so a CVE on a dependency declared in `packages/api/package.json` is auto-fixable from the workspace root.

### `snapem scan` — Security Scan Only

Scan without installing — useful for auditing existing projects.

```bash
snapem scan                     # Scan all dependencies
snapem scan --json              # Output as JSON
snapem scan --include prod      # Only production deps
snapem scan --include dev       # Only dev deps
```

### `snapem config` — Manage Configuration

```bash
snapem config show              # Display current settings
snapem config init              # Create a config file
```

### `snapem version` — Show Version

```bash
snapem version                  # Show version info
```

### `snapem doctor` — Diagnose Your Setup

```bash
snapem doctor                   # Checklist of container CLI, service, token, etc.
```

### `snapem cache` — Inspect or Clear the Scan Cache

```bash
snapem cache info               # Path, TTL, entry count, total bytes
snapem cache clear              # Delete every cached scan result
```

### `snapem agent` — Generate AI Assistant Instructions

See [AI Assistant Integration](#ai-assistant-integration) above.

```bash
snapem agent install            # ~/.claude/skills/snapem.md (Claude Code)
snapem agent install --format=md  # ./AGENTS.md
snapem agent show               # Print to stdout instead of writing
```

## Understanding Security Policies

When snapem finds a security issue, it takes an action based on your policy settings. There are three possible actions:

| Action | What happens |
|--------|-------------|
| `block` | Stop installation, show error, ask for confirmation to continue |
| `warn` | Show warning, continue with installation |
| `ignore` | Don't show anything, continue silently |

### Default Policies

| Threat Type | Default Action | Why |
|-------------|---------------|-----|
| Malware | `block` | Known malicious code should never be installed |
| Critical CVE | `block` | Severe vulnerabilities with known exploits |
| High CVE | `block` | Serious vulnerabilities that should be fixed |
| Medium CVE | `block` | Moderate risk, worth reviewing |
| Low CVE | `warn` | Minor issues, shown but don't stop installation |

### Customizing Policies

Create a `snapem.yaml` file in your project:

```yaml
scanning:
  policy:
    # What to do when malware is detected
    malware: block    # block, warn, or ignore

    # What to do for each CVE severity level
    cve:
      critical: block
      high: block
      medium: warn    # Changed: just warn for medium
      low: ignore     # Changed: ignore low severity

    # Can users bypass blocks with --force?
    allow_override: true

    # Always trust these packages (skip scanning). Entries may be a bare
    # name (every version is trusted — use with care) or "name@version"
    # to pin a specific release that you've reviewed.
    allowlist:
      - lodash@4.17.21        # only this exact version
      - express               # every version (less safe)
      - "@types/node@20.10.0"

    # Always block these packages
    blocklist:
      - malicious-package
      - left-pad@1.3.0        # only this release

    # Per-package policy overrides. Set only the keys you want to
    # override; everything else falls back to the global policy.
    packages:
      lodash:
        cve:
          high: warn          # we've reviewed every lodash release we use
      some-other-pkg:
        malware: warn         # treat malware finding as warning, not block
```

### When You Hit a Block

If snapem blocks an installation, you have options:

```bash
# Option 1: Force continue (use with caution!)
snapem install --force

# Option 2: Add to allowlist in snapem.yaml
# (if you've reviewed the package and trust it)

# Option 3: Fix the issue
# Update to a patched version of the package
```

## CI/CD Integration

`snapem scan` runs in CI without the container runtime; the scan itself is just HTTP queries against OSV, Socket, deps.dev, and the npm registry. Pin the version with `brew install positronico/tap/snapem` (or use the released tarball) and call `snapem scan` in your pipeline.

### GitHub Actions

Fail the build on findings, and (optionally) upload the SARIF report to GitHub code scanning so findings appear inline on the PR:

```yaml
name: dependency scan
on: [push, pull_request]

jobs:
  scan:
    runs-on: macos-latest
    permissions:
      security-events: write   # required for code-scanning upload
      contents: read
    steps:
      - uses: actions/checkout@v6

      - name: Install snapem
        run: brew install positronico/tap/snapem

      - name: Run snapem scan
        env:
          SOCKET_API_TOKEN: ${{ secrets.SOCKET_API_TOKEN }}
        run: snapem scan --format sarif > snapem.sarif
        # snapem exits non-zero on block-severity findings; this fails
        # the job. If you'd rather report-only, add `|| true`.

      - name: Upload SARIF to code scanning
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: snapem.sarif
```

Without a `SOCKET_API_TOKEN` secret, malware scanning is disabled but CVE scanning via OSV still runs.

### GitLab CI

```yaml
snapem_scan:
  image: macos-latest   # or any runner with snapem on PATH
  script:
    - brew install positronico/tap/snapem
    - snapem scan --format sarif > snapem.sarif
  artifacts:
    when: always
    reports:
      sast: snapem.sarif
  variables:
    SOCKET_API_TOKEN: $SOCKET_API_TOKEN   # define in CI/CD settings
```

### Just fail the build, no SARIF

For pipelines that only want a pass/fail gate:

```bash
snapem scan --quiet || exit 1
```

`snapem scan` exits 2 when findings hit block-severity policy.

## Shell Completions

Enable tab completion for faster command entry.

### Zsh (default on macOS)

```bash
# Add to ~/.zshrc
source <(snapem completion zsh)
```

Or install to completions directory:
```bash
snapem completion zsh > "${fpath[1]}/_snapem"
```

### Bash

```bash
# Add to ~/.bashrc
source <(snapem completion bash)
```

### Fish

```bash
snapem completion fish > ~/.config/fish/completions/snapem.fish
```

After adding, restart your shell or run `source ~/.zshrc` (or equivalent).

## Configuration File

snapem looks for configuration in:
1. `./snapem.yaml` (project directory)
2. `~/.config/snapem/config.yaml` (user home)

### Full Configuration Reference

```yaml
# Which package manager to use
package_manager:
  preferred: auto    # auto, npm, or bun

# Security scanning settings
scanning:
  enabled: true      # Set to false to disable all scanning

  # Socket.dev (malware detection)
  socket:
    enabled: true
    timeout: 30s

  # Google OSV (CVE database)
  osv:
    enabled: true
    timeout: 30s

  # Cache scan results to speed up repeated installs
  cache:
    enabled: true
    ttl: 24h         # How long to cache results

  # Security policies (see "Understanding Security Policies" above)
  policy:
    malware: block
    cve:
      critical: block
      high: block
      medium: block
      low: warn
    allow_override: false
    allowlist: []
    blocklist: []

# Container settings
container:
  enabled: true      # Set to false to run on host
  image:
    npm: node:lts-slim
    bun: oven/bun:latest
  network: host      # host (normal) or none (isolated)

# Output settings
ui:
  color: true        # Colored terminal output
  verbose: false     # Extra debug info
  quiet: false       # Minimal output
```

### Environment Variables

Any setting can be overridden with environment variables:

```bash
export SOCKET_API_TOKEN="your-token"           # Required for malware scanning
export SNAPEM_SCANNING_ENABLED=false           # Disable scanning
export SNAPEM_CONTAINER_NETWORK=none           # No network in container
export SNAPEM_PACKAGE_MANAGER_PREFERRED=bun    # Use bun instead of npm
```

## Global Flags

These flags work with any command:

| Flag | Short | Description |
|------|-------|-------------|
| `--config FILE` | | Use a specific config file |
| `--verbose` | `-v` | Show detailed output |
| `--quiet` | `-q` | Show only errors |
| `--no-color` | | Disable colored output |
| `--package-manager` | | Force `npm`, `bun`, `pnpm`, or `yarn` |
| `--help` | `-h` | Show help for any command |

## Troubleshooting

### "Apple container runtime not available"

The container CLI isn't installed or running:

```bash
brew install container
container system start
```

### "XPC connection error"

The container service isn't running:

```bash
container system start
container system status   # Should show "apiserver is running"
```

### "No SOCKET_API_TOKEN set"

You have two options:
1. Set up a token (see [Setting Up Security Scanning](#setting-up-security-scanning))
2. Type `unsecure` when prompted to continue without malware scanning

### Commands with flags aren't working

Use `--` to separate snapem flags from your command:

```bash
# Wrong — snapem thinks --version is its flag
snapem exec node --version

# Correct — everything after -- goes to the container
snapem exec -- node --version
```

### First run is slow

The first run pulls the container image (~250 MB extracted on Apple Silicon for `node:lts-slim`) and starts the container service. Subsequent runs use cached images and start in a few seconds.

### Port not accessible

Make sure the port is being published:

```bash
# Check what port was detected
snapem run dev -v

# Manually specify the port
snapem run dev -p 3000
```

## How It Works

### The Security Scan

```
┌──────────────────────────────────────────────────────────────┐
│  1. Read package.json and lockfile (workspace-aware)         │
│  2. Extract all package names and versions; dedupe           │
│  3. Query seven security sources in parallel:                │
│     ├── Socket.dev    → malware, typosquats, suspicious      │
│     ├── Google OSV    → known CVEs                           │
│     ├── OSSF Scorecard→ maintainer hygiene (via deps.dev)    │
│     ├── npm provenance→ SLSA build-input attestations        │
│     ├── deps.dev meta → deprecation, license posture         │
│     ├── gitdep        → git/URL/path dependency specifiers   │
│     └── tarball       → tarball vs `files` field audit       │
│  4. Apply your security policy (global + per-package)        │
│  5. Block or warn based on findings; surface scanner failures│
└──────────────────────────────────────────────────────────────┘
```

### The Container

When you run `snapem install`, it actually runs:

```bash
container run \
  --rm \
  --volume "$(pwd):/app" \
  --workdir "/app" \
  node:lts-slim \
  npm install
```

This means:
- ✅ Your project files are available at `/app`
- ❌ No access to `~/.ssh`, `~/.aws`, or other sensitive directories
- ❌ No access to macOS Keychain
- ✅ Container is deleted after the command finishes
- ✅ Uses Apple's fast hardware virtualization

## What snapem Protects Against

| Threat | Protection |
|--------|-----------|
| Malicious install scripts | ✅ Container isolation |
| Typosquatting (e.g., `loddash`) | ✅ Socket.dev detection |
| Known CVEs | ✅ Google OSV scanning |
| Abandoned / unmaintained dependencies | ✅ OSSF Scorecard via deps.dev |
| Attestation-confusion (`pkg:X` provenance shipped under `pkg:Y`) | ✅ npm provenance subject-PURL check |
| Maintainer-declared deprecation | ✅ deps.dev metadata (`isDeprecated` flag) |
| Dependency that bypasses the registry (git URL, raw tarball, file path) | ✅ gitdep scanner |
| Tarball ships files outside the package's own `files` whitelist | ✅ tarball-audit scanner |
| Data exfiltration | ✅ Optional network isolation (`--no-network`) |
| Host credential theft (SSH, AWS, Keychain) | ✅ Not mounted into the container |

## What snapem Does NOT Protect Against

- **Your project directory.** It's mounted read-write at `/app` so npm can write `node_modules`. A malicious package can read and modify your source.
- **Environment variables you forward.** Anything you list under `container.environment` in `snapem.yaml` is visible to every package in the install — don't put registry tokens (`NPM_TOKEN`, etc.) there unless you trust the entire dependency tree.
- Vulnerabilities in your own code
- Runtime attacks in production
- Compromised npm registry
- Social engineering attacks

## License

MIT — See [LICENSE](LICENSE)

## Credits

- [Apple Containerization](https://github.com/apple/containerization) — Native container runtime
- [Socket.dev](https://socket.dev) — Supply chain security (malware, typosquats)
- [Google OSV](https://osv.dev) — Vulnerability database (CVEs)
- [OSSF Scorecard](https://github.com/ossf/scorecard) — Maintainer hygiene scoring
- [deps.dev](https://deps.dev) — Package metadata + Scorecard delivery API
- [Sigstore](https://www.sigstore.dev/) / npm provenance — SLSA build-input attestations
- [Cobra](https://github.com/spf13/cobra) — CLI framework
