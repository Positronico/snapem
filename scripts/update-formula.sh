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
TAP_REPO="git@github.com:Positronico/homebrew-tap.git"
TAP_DIR="${HOME}/.homebrew-tap"
FORMULA_NAME="snapem.rb"

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

# Clone or pull homebrew-tap repo
echo ""
echo "Updating homebrew-tap repository..."

if [ -d "$TAP_DIR" ]; then
  echo "  Pulling latest changes..."
  git -C "$TAP_DIR" pull --quiet
else
  echo "  Cloning repository..."
  git clone --quiet "$TAP_REPO" "$TAP_DIR"
fi

# Ensure Formula directory exists
mkdir -p "$TAP_DIR/Formula"

FORMULA_PATH="$TAP_DIR/Formula/$FORMULA_NAME"

# Create formula if it doesn't exist
if [ ! -f "$FORMULA_PATH" ]; then
  echo "  Creating new formula..."
  cat > "$FORMULA_PATH" << 'FORMULA'
class Snapem < Formula
  desc "Zero-Trust npm/bun CLI for macOS Silicon"
  homepage "https://github.com/Positronico/snapem"
  version "0.0.0"
  license "MIT"

  on_macos do
    on_arm do
      url "https://github.com/Positronico/snapem/releases/download/v#{version}/snapem_#{version}_darwin_arm64.tar.gz"
      sha256 "0000000000000000000000000000000000000000000000000000000000000000"
    end
    on_intel do
      url "https://github.com/Positronico/snapem/releases/download/v#{version}/snapem_#{version}_darwin_amd64.tar.gz"
      sha256 "0000000000000000000000000000000000000000000000000000000000000000"
    end
  end

  def install
    bin.install "snapem"
  end

  def caveats
    <<~EOS
      snapem requires Apple's container CLI for isolation features.
      Install it with: brew install --cask container
    EOS
  end

  test do
    system "#{bin}/snapem", "version"
  end
end
FORMULA
fi

# Update version
sed -i '' "s/version \"[^\"]*\"/version \"$VERSION\"/" "$FORMULA_PATH"

# Update arm64 sha256
awk -v sha="$SHA_ARM64" '
  /on_arm do/ { in_arm=1 }
  in_arm && /sha256/ { sub(/"[a-f0-9]{64}"/, "\"" sha "\""); in_arm=0 }
  { print }
' "$FORMULA_PATH" > "$FORMULA_PATH.tmp" && mv "$FORMULA_PATH.tmp" "$FORMULA_PATH"

# Update amd64 sha256
awk -v sha="$SHA_AMD64" '
  /on_intel do/ { in_intel=1 }
  in_intel && /sha256/ { sub(/"[a-f0-9]{64}"/, "\"" sha "\""); in_intel=0 }
  { print }
' "$FORMULA_PATH" > "$FORMULA_PATH.tmp" && mv "$FORMULA_PATH.tmp" "$FORMULA_PATH"

# Commit and push
echo ""
echo "Committing and pushing to homebrew-tap..."
git -C "$TAP_DIR" add Formula/$FORMULA_NAME
git -C "$TAP_DIR" commit -m "Update snapem to v$VERSION"
git -C "$TAP_DIR" push

echo ""
echo "Formula updated and pushed successfully!"
echo ""
echo "Users can now install with:"
echo "  brew tap Positronico/tap"
echo "  brew install snapem"
