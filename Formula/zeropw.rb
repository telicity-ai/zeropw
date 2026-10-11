class Zeropw < Formula
  desc "Use HTTP APIs and SSH without giving agents original credentials"
  homepage "https://github.com/telicity-ai/zeropw"
  version "0.1.0"
  license "MIT"

  on_macos do
    on_arm do
      url "https://github.com/telicity-ai/zeropw/releases/download/v0.1.0/zeropw-v0.1.0-aarch64-apple-darwin.tar.gz"
      sha256 "0c35232b800b60dae0c5975239c736caedf262bde4a4cc293287c0ec2b3d3d0e"
    end
  end
  on_linux do
    on_arm do
      url "https://github.com/telicity-ai/zeropw/releases/download/v0.1.0/zeropw-v0.1.0-aarch64-unknown-linux-gnu.tar.gz"
      sha256 "ce010ae6749f82fe5da81fd0450def5ffebae9c950e5e6bd82d6699789eb565a"
    end
  end
  depends_on arch: :arm64

  head "https://github.com/telicity-ai/zeropw.git", branch: "main"
  depends_on "rust" => :build if build.head?
  depends_on "openssl@3" if build.head?

  def install
    if build.head?
      ENV["OPENSSL_DIR"] = Formula["openssl@3"].opt_prefix
      system "cargo", "build", "--locked", "--release", "--manifest-path", "rust/Cargo.toml", "--bins"
      %w[zeropw-admin zeropw-agent zeropw_session zeropw-demo zeropw-democli].each do |name|
        bin.install "rust/target/release/#{name}"
      end
      doc.install "README.md", "GUIDE.md", "LICENSE"
    else
      %w[zeropw-admin zeropw-agent zeropw_session zeropw-demo zeropw-democli].each do |name|
        bin.install name
      end
      doc.install "README.md", "LICENSE", "THIRD_PARTY_LICENSES.md"
    end
  end

  test do
    ENV["TMPDIR"] = testpath.to_s
    assert_match "ZeroPW agent", shell_output("#{bin}/zeropw-agent --help")
    assert_match "ZeroPW administrator", shell_output("#{bin}/zeropw-admin --help")
    assert_path_exists bin/"zeropw_session"
    system bin/"zeropw-demo"
  end
end
