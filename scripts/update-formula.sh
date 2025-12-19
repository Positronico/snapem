#!/bin/bash
set -e

# Update Homebrew formula with new version and checksums
# Usage: ./scripts/update-formula.sh v0.2.0

if [ -z "$1" ]; then
  echo "Usage: $0 <version>"
  echo "Example: $0 v0.2.0"
  exit 1
fi

VERSION="${1#v}"  # Strip 'v' prefix if present
REPO="Positronico/snapem"
FORMULA="Formula/snapem.rb"

echo "Updating formula to version $VERSION..."

# Fetch checksums.txt from release
CHECKSUMS_URL="https://github.com/$REPO/releases/download/v$VERSION/checksums.txt"
echo "Fetching checksums from $CHECKSUMS_URL"

CHECKSUMS=$(curl -sL "$CHECKSUMS_URL")

if [ -z "$CHECKSUMS" ]; then
  echo "Error: Could not fetch checksums. Is the release published?"
  exit 1
fi

# Parse SHA256 for each arch
SHA_ARM64=$(echo "$CHECKSUMS" | grep "darwin_arm64" | awk '{print $1}')
SHA_AMD64=$(echo "$CHECKSUMS" | grep "darwin_amd64" | awk '{print $1}')

if [ -z "$SHA_ARM64" ] || [ -z "$SHA_AMD64" ]; then
  echo "Error: Could not parse checksums"
  echo "Checksums content:"
  echo "$CHECKSUMS"
  exit 1
fi

echo "  arm64: $SHA_ARM64"
echo "  amd64: $SHA_AMD64"

# Update version
sed -i '' "s/version \"[^\"]*\"/version \"$VERSION\"/" "$FORMULA"

# Update arm64 sha256 (the first sha256 in the file, after on_arm)
# Using a more targeted approach with awk
awk -v sha="$SHA_ARM64" '
  /on_arm do/ { in_arm=1 }
  in_arm && /sha256/ { sub(/"[a-f0-9]{64}"/, "\"" sha "\""); in_arm=0 }
  { print }
' "$FORMULA" > "$FORMULA.tmp" && mv "$FORMULA.tmp" "$FORMULA"

# Update amd64 sha256 (after on_intel)
awk -v sha="$SHA_AMD64" '
  /on_intel do/ { in_intel=1 }
  in_intel && /sha256/ { sub(/"[a-f0-9]{64}"/, "\"" sha "\""); in_intel=0 }
  { print }
' "$FORMULA" > "$FORMULA.tmp" && mv "$FORMULA.tmp" "$FORMULA"

echo "Formula updated successfully!"
echo ""
echo "Next steps:"
echo "  git add Formula/snapem.rb"
echo "  git commit -m \"Update formula to v$VERSION\""
echo "  git push"
