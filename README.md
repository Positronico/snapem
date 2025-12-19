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

snapem requires Apple's container runtime:

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

snapem uses two security services:

| Service | What it detects | API Key Required? |
|---------|----------------|-------------------|
| [Socket.dev](https://socket.dev) | Malware, suspicious code, typosquatting | Yes (free tier available) |
| [Google OSV](https://osv.dev) | Known vulnerabilities (CVEs) | No |

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

    # Always trust these packages (skip scanning)
    allowlist:
      - lodash
      - express

    # Always block these packages
    blocklist:
      - malicious-package
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
| `--package-manager` | | Force npm or bun |
| `--help` | `-h` | Show help for any command |

## Troubleshooting

### "Apple container runtime not available"

The container CLI isn't installed or running:

```bash
brew install --cask container
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

The first run downloads container images (~50MB). Subsequent runs use cached images and start instantly.

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
┌─────────────────────────────────────────────────────────┐
│  1. Read package.json and lockfile                      │
│  2. Extract all package names and versions              │
│  3. Query security APIs (in parallel):                  │
│     ├── Socket.dev → malware, typosquats, suspicious    │
│     └── Google OSV → known CVEs                         │
│  4. Apply your security policy                          │
│  5. Block or warn based on findings                     │
└─────────────────────────────────────────────────────────┘
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
| Data exfiltration | ✅ Optional network isolation |
| Credential theft | ✅ No access to host credentials |

## What snapem Does NOT Protect Against

- Vulnerabilities in your own code
- Runtime attacks in production
- Compromised npm registry
- Social engineering attacks

## License

MIT — See [LICENSE](LICENSE)

## Credits

- [Apple Containerization](https://github.com/apple/containerization) — Native container runtime
- [Socket.dev](https://socket.dev) — Supply chain security
- [Google OSV](https://osv.dev) — Vulnerability database
- [Cobra](https://github.com/spf13/cobra) — CLI framework
