# Security model

This document describes what snapem protects against, what it doesn't, and how to think about its threat model when configuring policies.

If you find a security issue in snapem itself (not in a package snapem scanned), please open a GitHub issue with the label `security` rather than a public PR.

## Threat model

snapem exists because `npm install` runs arbitrary code on your machine with your user's permissions. A malicious package can read `~/.ssh`, exfiltrate `NPM_TOKEN`, write to `~/.bash_profile`, query the Keychain, and reach anywhere on your filesystem and the network — all before any of *your* code runs. Lifecycle hooks like `postinstall` are the most common delivery vector, but `require()`-time code in a transitive dependency works just as well.

snapem narrows that surface in two ways:

1. **Pre-flight scanning.** Every dependency is checked against seven data sources *before* the package manager is invoked: Socket.dev (malware, typosquats, install-script analysis), Google OSV (CVEs), OSSF Scorecard via deps.dev (maintainer hygiene), npm provenance attestations (SLSA-format binding of tarball → source repo + builder), deps.dev package metadata (maintainer-marked deprecation, license posture), gitdep (out-of-registry dependency specifiers in published packages — git URLs, raw tarballs, file paths, GitHub shortcuts), and tarball (audits tarball contents against the package's own `files` whitelist for surprise-content publishes). Configurable per-severity policies (`block` / `warn` / `ignore`) decide whether to proceed. Quality findings (Scorecard, provenance, metadata, gitdep, tarball) are advisory by default — they surface signal that no other scanner sees, but won't gate an install. Malware and CVE findings block per policy.
2. **Container isolation.** The install/run/exec actually happens inside Apple's native `container` runtime. Lifecycle scripts run in a Linux VM with no access to your home directory, your Keychain, your shell environment, or the host network beyond what you allow.

## What snapem prevents

These are concrete attacker capabilities that snapem blocks or detects on a default-policy install:

| Attack | How snapem stops it |
|---|---|
| Maintainer-declared deprecation | The metadata scanner reads deps.dev's `isDeprecated` flag, set when the publisher ran `npm deprecate`. Surfaces as a medium finding with the publisher's reason in the description. |
| Attestation-confusion attack | A malicious republish ships another package's provenance attestation. snapem's provenance scanner verifies that the SLSA statement's `subject` PURL matches the package npm just served — a mismatch fires a medium-severity finding. |
| Abandoned-but-still-popular dependency | OSSF Scorecard's `Maintained` check surfaces packages with no recent commits. Default threshold 5.0/10 catches the common "last touched 4 years ago" case before a malicious fork of the package starts circulating. |
| Postinstall reading `~/.ssh/id_rsa` | The container has no bind-mount of `~/.ssh`; the malicious read returns ENOENT. |
| `process.env.NPM_TOKEN` exfiltration | `NPM_TOKEN` is explicitly stripped from the forwarded environment (`container.environment` default). |
| `keytar` / Keychain probe | The container is a Linux VM. The macOS Keychain API does not exist there. |
| Typosquat (`lodahs` for `lodash`) | Socket.dev flags as `typosquat`; default policy blocks at `high`. |
| Known CVE in a transitive dep | OSV returns the advisory; default policy blocks at `high`+. |
| `--network none` for `snapem run` | Outbound DNS fails (`EAI_AGAIN`). A reverse-shell payload from a build script can't dial home. |
| Editing `~/.bash_profile` for persistence | No mount; the write hits a Linux filesystem that's destroyed when the container exits. |
| Dependency that bypasses the registry (git URL, raw tarball, file path in published deps) | gitdep scanner flags any `dependencies` / `optionalDependencies` / `peerDependencies` entry that's not a registry version spec. Default severity high; advisory. The `prepare` lifecycle hook fires unconditionally on git-URL installs, which is why this is a real install-time-execution risk. |
| Tarball ships files outside the package's own `files` whitelist | tarball scanner downloads each version's tarball and verifies its contents match the `files` field declared in the package's own `package.json` (plus always-included docs and declared entry points). Default severity medium; advisory. Catches the "publishing pipeline produced bytes the manifest doesn't admit to" failure mode independent of any threat database. |

## What snapem does NOT prevent

Be honest about the gaps. snapem is **defense in depth**, not a silver bullet.

| Gap | Mitigation outside snapem |
|---|---|
| **Code you write that calls into a compromised package** | snapem can't stop you from `import`-ing a malicious package and then `eval`-ing its output yourself. The container only isolates the install/build step. |
| **Attacks via the lockfile itself** (`overrides`, `resolutions`) | snapem reads the lockfile but doesn't audit overrides for substitution attacks. Treat untrusted lockfile diffs as untrusted code. |
| **A scanner missing a finding** | Both Socket.dev and OSV have lag between an incident and an advisory being published. snapem caches scan results — clear the cache (`snapem cache clear`) when you suspect freshness matters. |
| **Compromised-CI provenance** | A more important gap than forgery: a compromised CI pipeline produces *cryptographically valid* SLSA attestations for malicious tarballs, because SLSA verifies process integrity, not source integrity. The signature chain, builder identity, subject PURL, and predicate all check out — they just describe a build that was fed poisoned inputs (e.g. via a poisoned Actions cache). snapem's provenance scanner does NOT treat valid attestations as a positive safety signal for this reason; it still emits findings on subject-PURL mismatch and missing/unreadable bundles. The structural scanners (gitdep, tarball) and behavioral upstreams (Socket) are the load-bearing layers against this class. |
| **Forged provenance attestations** | snapem's provenance scanner currently parses the SLSA statement but does not yet verify the Sigstore signature chain. A motivated attacker without OIDC access could craft a fake bundle; until cryptographic verification ships, provenance is a weak signal against bespoke forgery. Less important than the compromised-CI case above. |
| **Compromised registry** (npmjs.com itself serving a different tarball) | snapem doesn't verify package integrity beyond what the package manager does. If npmjs.com is compromised, you need out-of-band verification (sigstore, OIDC-signed provenance). |
| **Container escape** | A bug in Apple's `container` runtime would defeat isolation. Apple's container shares the macOS hypervisor with Docker Desktop and Lima; no known escapes as of v0.9.0, but it's not zero risk. |
| **Attacks via your editor** (VS Code extensions, IntelliJ plugins) | Out of scope. snapem only intercepts the package-manager CLI. |
| **Data left in the project directory** | The project dir is bind-mounted. A build script can still write to `./node_modules/<pkg>/postscript.sh` and trick a later non-snapem command into running it. Use `--read-only` for exec/run when you don't need writes. |
| **Registry tokens in `~/.npmrc`** when opt-in is on | snapem's default is `container.mount_npmrc: false` — credentials are withheld from the container, and private-registry installs fail with 401/403 until you explicitly flip the knob. When you do flip it to `true`, `~/.npmrc` is bind-mounted read-only at `/root/.npmrc` and snapem prints a yellow warning on every install/run/exec/upgrade so the exposure is never silent. A malicious post-install script can still read the mounted npmrc — same exposure as `npm install` directly. Treat the opt-in as a deliberate tradeoff per-project, not a global setting. |
| **Network egress to allowed hosts** | Default network mode forwards DNS so `npm install` can reach the registry. A finding that already passed the scan can still phone home during install via the registry-allowed network path. Set `container.network: none` for the strictest posture and accept that some installs will fail. |

## Choosing a policy

Default policy errs on the side of safety: malware blocks, CVEs of `high`+ block, `medium` warns, `low` is informational. That's the right starting point for most users. Override per-severity in `snapem.yaml`:

```yaml
scanning:
  policy:
    malware: block   # block | warn | ignore
    cve:
      critical: block
      high: block
      medium: warn
      low: ignore
```

### When to relax

- **You're triaging a known finding.** Use `--force` on a single command, or add the specific `name@version` to `scanning.allowlist`. Avoid name-only allowlist entries unless you really mean "all current and future versions of this package are trusted." Version-pinned allowlist is the security best practice.
- **A package is universally trusted in your org.** Use a per-package override (`scanning.policy.packages.<name>.cve.<severity>: warn`) rather than relaxing global policy. Keeps the blast radius scoped to that one package.

### When to tighten

- **CI / production-grade workflows.** Set `scanning.policy.cve.medium: block` and require a human to allowlist before any medium-severity install lands.
- **Air-gapped or offline-by-default.** Set `container.network: none`. Many installs will fail (they need the registry); the ones that succeed are pure local resolves and known safe.

## Operational hardening

Beyond policy, three habits that materially raise your security floor:

1. **Don't `--force` past a block without an allowlist entry.** `--force` skips the policy check but leaves no audit trail. An allowlist entry with a comment is reviewable.
2. **Keep `SOCKET_API_TOKEN` set in your shell.** The unauthenticated fallback (`unsecure` prompt) works but is rate-limited and returns a strict subset of findings. The free Socket.dev tier is enough for individual use.
3. **Run `snapem upgrade` regularly.** A finding that was `medium` last week may be `critical` today if exploitation was published. The upgrade picker prefers in-major bumps and only crosses majors with `--major`, so the cost is low.

## Reporting issues

For issues in snapem itself (the CLI, the container wrapper, the scanner orchestrator): open a GitHub issue. If the issue would allow bypassing the policy check or container isolation, mark it `security` and please don't include exploitation details in the public issue body — a brief reproducer is enough.

For issues in packages snapem scanned but didn't catch: the right path is to report to Socket.dev or OSV directly, since fixing snapem won't help other tools without their data improving. snapem will pick up the new advisory on the next cache miss.
