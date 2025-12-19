class Snapem < Formula
  desc "Zero-Trust npm/bun CLI for macOS Silicon"
  homepage "https://github.com/Positronico/snapem"
  version "0.1.0"
  license "MIT"

  on_macos do
    on_arm do
      url "https://github.com/Positronico/snapem/releases/download/v#{version}/snapem_#{version}_darwin_arm64.tar.gz"
      sha256 "2e88690bb71d803000bd71a9b33451a97876b30dfe1333e25bdcee26b320891a"
    end
    on_intel do
      url "https://github.com/Positronico/snapem/releases/download/v#{version}/snapem_#{version}_darwin_amd64.tar.gz"
      sha256 "ab589aa3cdd157f7efa7671a1c57736e43247551b859ed32985df78d16117e40"
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
