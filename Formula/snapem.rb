class Snapem < Formula
  desc "Zero-Trust npm/bun CLI for macOS Silicon"
  homepage "https://github.com/Positronico/snapem"
  version "0.1.1"
  license "MIT"

  on_macos do
    on_arm do
      url "https://github.com/Positronico/snapem/releases/download/v#{version}/snapem_#{version}_darwin_arm64.tar.gz"
      sha256 "d72d3e47e00010c18aa0cab316f5812defc468e8f1143e5beb396916d2b3feea"
    end
    on_intel do
      url "https://github.com/Positronico/snapem/releases/download/v#{version}/snapem_#{version}_darwin_amd64.tar.gz"
      sha256 "3ba1793d062dc41f2d362563a8b8120e9cc66e995b99b3704bf962bbfd58d06b"
    end
  end

  depends_on :macos
  depends_on cask: "container"

  def install
    bin.install "snapem"
  end

  test do
    system "#{bin}/snapem", "version"
  end
end
