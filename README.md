# snapem

**Secure npm/bun wrapper for macOS Silicon** - A Zero-Trust Development Environment that scans dependencies for malware and vulnerabilities before running them in isolated Apple containers.

## The Problem

Modern web development relies heavily on third-party packages. A single malicious package can gain full access to your file system, SSH keys, and environment variables immediately upon installation via `postinstall` scripts.

## The Solution

snapem provides defense-in-depth through three layers:

1. **Pre-Flight Scanning** - Automatic behavioral analysis using [Socket.dev](https://socket.dev) (malware detection) and [Google OSV](https://osv.dev) (CVE database)
2. **Execution Isolation** - All npm/bun commands run inside ephemeral Apple containers using the native Virtualization.framework
3. **Network Segregation** - Optional network isolation to prevent data exfiltration during builds

## Prerequisites

### System Requirements

- **macOS Sequoia 15.5+** on Apple Silicon (M1/M2/M3/M4)
- **Xcode Command Line Tools** (for building from source)

Check your macOS version:
```bash
sw_vers
# ProductName:        macOS
# ProductVersion:     15.5
```

### 1. Install Apple Container CLI

The Apple Container CLI provides native Linux container support using the Virtualization.framework.

```bash
# Install via Homebrew
brew install --cask container

# Start the container system service
container system start
```

On first run, it will prompt to install the Linux kernel:
```
No default kernel configured.
Install the recommended default kernel? [Y/n]: Y
```

Verify the installation:
```bash
container system status
# apiserver is running
```

Test that containers work:
```bash
container run --rm node:lts-slim node --version
# v24.12.0
```

### 2. Configure Socket.dev API (Recommended)

Socket.dev provides behavioral analysis for detecting malicious packages, typosquats, and supply chain attacks. This is **highly recommended** for full protection.

#### Create a Free Account

1. Go to [https://socket.dev](https://socket.dev)
2. Click "Sign Up" and create a free account
3. Verify your email address

#### Generate an API Token

1. Log in to your Socket.dev dashboard
2. Navigate to **Settings** → **API Tokens**
3. Click **"Create Token"**
4. Give it a name (e.g., "snapem-local")
5. Copy the generated token

#### Configure the Token

Add to your shell profile (`~/.zshrc` or `~/.bashrc`):

```bash
# Socket.dev API token for snapem malware detection
export SOCKET_API_TOKEN="your-token-here"
```

Then reload your shell:
```bash
source ~/.zshrc
```

Verify it's set:
```bash
echo $SOCKET_API_TOKEN
```

> **Note:** Without a Socket.dev token, snapem will still work but will only scan for known CVEs (via Google OSV). Malware detection will be disabled, and you'll need to type `unsecure` when prompted.

### 3. Install snapem

#### From Source (Recommended)

```bash
git clone https://github.com/positronico/snapem.git
cd snapem
make build

# Install to your PATH
sudo cp bin/snapem /usr/local/bin/

# Or add to your PATH
export PATH="$PATH:$(pwd)/bin"
```

#### Using Go

```bash
go install github.com/positronico/snapem/cmd/snapem@latest
```

### Verify Installation

```bash
snapem version
# snapem v1.0.0
#   commit: abc123
#   built:  2024-01-01T00:00:00Z
#   go:     go1.22.0
#   os:     darwin/arm64
```

## Quick Start

```bash
# Navigate to your Node.js project
cd my-project

# Install dependencies (scans first, then runs in container)
snapem install

# Run dev server in container (port auto-detected and published)
snapem run dev
# → Server available at http://localhost:3000

# Execute any command in container
snapem exec -- node index.js

# Run standalone security scan
snapem scan
```

## Usage

### Installing Dependencies

```bash
# Install all dependencies from package.json
snapem install

# Install specific packages
snapem install lodash axios

# Install as devDependency
snapem install -D jest

# Skip security scanning (not recommended)
snapem install --skip-scan

# Run without container (not recommended)
snapem install --no-container
```

### Running Scripts

```bash
# Run npm scripts in container
snapem run dev
snapem run build
snapem run test

# Pass arguments to scripts
snapem run test -- --watch

# Run without network access (high security)
snapem run build --no-network
```

### Port Publishing (Dev Servers)

When running dev servers (`dev`, `start`, `serve` scripts), snapem **automatically detects and publishes** the appropriate port based on your framework:

```bash
# Auto-detects port from your dependencies (e.g., 3000 for Express/Next.js)
snapem run dev
# ℹ Auto-detected port 3000 (use -p to override, --no-ports to disable)

# Override with a custom port
snapem run dev -p 8080

# Map container port to different host port
snapem run dev -p 8080:3000

# Expose multiple ports
snapem run dev -p 3000 -p 9229

# Disable auto port detection
snapem run dev --no-ports
```

**Supported frameworks and their default ports:**

| Framework | Default Port |
|-----------|--------------|
| Next.js, Remix, Nuxt, Express, Fastify | 3000 |
| Vite, SvelteKit | 5173 |
| Vue CLI, Webpack Dev Server | 8080 |
| Angular | 4200 |
| Astro | 4321 |
| Gatsby | 8000 |
| Parcel | 1234 |

snapem also parses your npm scripts for explicit `--port` or `PORT=` configurations.

### Executing Commands

```bash
# Run any command in container
snapem exec -- node script.js
snapem exec -- npx prisma migrate
snapem exec -- sh -c "ls -la"

# Use custom container image
snapem exec --image node:20 -- node --version
```

> **Important:** Use `--` to separate snapem flags from the command arguments, especially when your command has flags starting with `-` or `--`.

### Security Scanning

```bash
# Scan all dependencies
snapem scan

# Output as JSON
snapem scan --json

# Scan only production dependencies
snapem scan --include prod
```

## Configuration

Create a `snapem.yaml` in your project or `~/.config/snapem/config.yaml`:

```bash
snapem config init
```

View current configuration:
```bash
snapem config show
```

### Configuration Options

```yaml
# Package manager: auto, npm, bun
package_manager:
  preferred: auto

# Security scanning
scanning:
  enabled: true

  socket:
    enabled: true
    timeout: 30s

  osv:
    enabled: true
    timeout: 30s

  cache:
    enabled: true
    ttl: 24h

  policy:
    malware: block      # block, warn, ignore
    cve:
      critical: block
      high: warn
      medium: warn
      low: ignore
    allow_override: true
    allowlist: []       # Trusted packages to skip scanning
    blocklist: []       # Packages to always block

# Container settings
container:
  enabled: true
  image:
    npm: node:lts-slim
    bun: oven/bun:latest
  network: host         # host, none
```

### Environment Variables

```bash
# Socket.dev API token (required for malware detection)
export SOCKET_API_TOKEN="your-token-here"

# Override any config option
export SNAPEM_SCANNING_ENABLED=false
export SNAPEM_CONTAINER_NETWORK=none
```

## How It Works

### Security Scan Flow

```
1. Parse package.json and lockfile
2. Extract all dependencies with versions
3. Concurrent API calls:
   ├─ Socket.dev: Check for malware, typosquats, suspicious behavior
   └─ Google OSV: Check for known CVEs
4. Apply security policy:
   ├─ Block: Stop and show error
   ├─ Warn: Show warning, continue
   └─ Ignore: Silent continue
5. If blocked, prompt for 'force' override
```

### Container Execution

```bash
# What snapem actually runs:
container run \
  --rm \
  --volume "$(pwd):/app" \
  --workdir "/app" \
  node:lts-slim \
  npm install
```

The container:
- Mounts only your project directory at `/app`
- Has no access to `~/.ssh`, `~/.aws`, or macOS Keychain
- Is destroyed immediately after the command finishes
- Uses hardware-accelerated virtualization (fast!)

## Security Considerations

### What snapem protects against

- Malicious `postinstall` scripts accessing your filesystem
- Typosquatting attacks (e.g., `loddash` instead of `lodash`)
- Known CVEs in dependencies
- Supply chain attacks during installation

### What snapem does NOT protect against

- Vulnerabilities in your own code
- Runtime attacks in production
- Social engineering
- Compromised registries (npm itself)

### Recommended Workflow

1. Always use `snapem install` instead of `npm install`
2. Always use `snapem run` instead of `npm run`
3. Set `SOCKET_API_TOKEN` for malware detection
4. Review security warnings before overriding
5. Use `--no-network` for builds that don't need network access

## Troubleshooting

### "Apple container runtime not available"

Install and start the container CLI:
```bash
brew install --cask container
container system start
```

If prompted for kernel installation, type `Y`.

### "XPC connection error: Connection invalid"

The container system service is not running:
```bash
container system start
container system status  # Should show "apiserver is running"
```

### "No SOCKET_API_TOKEN set"

Either:
1. Set the token: `export SOCKET_API_TOKEN="your-token"` (see [Configure Socket.dev API](#2-configure-socketdev-api-recommended))
2. Type `unsecure` when prompted to continue without malware scanning

### Commands with flags not working

Use `--` to separate snapem flags from command arguments:
```bash
# Wrong - snapem interprets --version as its own flag
snapem exec node --version

# Correct - everything after -- goes to the container
snapem exec -- node --version
```

### Slow first run

The first run downloads the container image (~50MB for node:lts-slim). Subsequent runs use the cached image and start in sub-seconds.

### Container networking issues

On macOS Sequoia 15.x, containers have network access by default. If you experience issues:
```bash
# Check if DNS is working inside container
snapem exec -- ping -c 1 google.com
```

## Development

```bash
# Build
make build

# Run tests
make test

# Format code
make fmt

# Build release binary
make build-release

# Clean
make clean
```

## License

MIT

## Credits

- [Apple Containerization](https://github.com/apple/containerization) - Native container runtime
- [Socket.dev](https://socket.dev) - Supply chain security
- [Google OSV](https://osv.dev) - Vulnerability database
- [Cobra](https://github.com/spf13/cobra) - CLI framework
- [Viper](https://github.com/spf13/viper) - Configuration
- [Lipgloss](https://github.com/charmbracelet/lipgloss) - Terminal styling
