# Release Workflow

This document describes the process for releasing a new version of snapem.

## Prerequisites

- All changes committed and pushed to `main`
- GoReleaser installed locally (for testing): `brew install goreleaser`
- `gh` CLI authenticated with GitHub

## Release Steps

### 1. Determine Version Number

Follow semantic versioning (MAJOR.MINOR.PATCH):
- PATCH: Bug fixes, minor changes
- MINOR: New features, backward compatible
- MAJOR: Breaking changes

### 2. Create and Push Tag

```bash
git tag v<VERSION>
git push origin v<VERSION>
```

Example:
```bash
git tag v0.2.0
git push origin v0.2.0
```

### 3. Wait for GitHub Actions

The release workflow will automatically:
- Build binaries for darwin/arm64 and darwin/amd64
- Create GitHub release with changelog
- Upload archives and checksums

Monitor progress:
```bash
gh run watch
```

Or check status:
```bash
gh run list --limit 1
```

Wait until status shows `completed` and `success`.

### 4. Update Homebrew Formula

Once the release is complete, update the formula with new checksums:

```bash
./scripts/update-formula.sh v<VERSION>
```

Example:
```bash
./scripts/update-formula.sh v0.2.0
```

### 5. Commit and Push Formula

```bash
git add Formula/snapem.rb
git commit -m "Update formula to v<VERSION>"
git push
```

### 6. Verify Release

Check the GitHub release page:
```bash
gh release view v<VERSION>
```

Test Homebrew installation (optional):
```bash
brew untap Positronico/snapem 2>/dev/null
brew tap Positronico/snapem
brew install snapem
snapem version
```

## Quick Reference

Complete release in one session:

```bash
VERSION="0.2.0"

# Tag and push
git tag v$VERSION && git push origin v$VERSION

# Wait for release
gh run watch

# Update formula
./scripts/update-formula.sh v$VERSION

# Commit formula
git add Formula/snapem.rb && git commit -m "Update formula to v$VERSION" && git push

# Verify
gh release view v$VERSION
```

## Troubleshooting

### Release workflow failed
Check logs: `gh run view --log-failed`

### Formula update script fails
Ensure the release is published and checksums.txt exists:
```bash
curl -sL "https://github.com/Positronico/snapem/releases/download/v<VERSION>/checksums.txt"
```

### Need to re-release same version
Delete the tag and release first:
```bash
gh release delete v<VERSION> --yes
git tag -d v<VERSION>
git push origin :refs/tags/v<VERSION>
```

Then start from step 2.
