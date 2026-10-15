class Zeropw < Formula
  desc "Use HTTP APIs and SSH without giving agents original credentials"
  homepage "https://github.com/telicity-ai/zeropw"
  version "0.1.0"
  license "MIT"

  on_macos do
    on_arm do
      url "https://github.com/telicity-ai/zeropw/releases/download/v0.1.0/zeropw-v0.1.0-aarch64-apple-darwin.tar.gz"
      sha256 "7f7218e467f2f913e73bbc20785caeb96bc9f63a916fdca4e217abcdd37deef9"
    end
  end
  on_linux do
    on_arm do
      url "https://github.com/telicity-ai/zeropw/releases/download/v0.1.0/zeropw-v0.1.0-aarch64-unknown-linux-gnu.tar.gz"
      sha256 "c8c48db2dab796790248115cc74b366c5be7ecba3bb9c40db9b308697297ac75"
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
