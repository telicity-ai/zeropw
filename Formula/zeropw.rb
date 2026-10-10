class Zeropw < Formula
  desc "Use HTTP APIs and SSH without giving agents original credentials"
  homepage "https://github.com/telicity-ai/zeropw"
  license "MIT"
  head "https://github.com/telicity-ai/zeropw.git", branch: "main"

  depends_on "rust" => :build

  def install
    system "cargo", "build", "--locked", "--release", "--manifest-path", "rust/Cargo.toml", "--bins"
    %w[zeropw-admin zeropw-agent zeropw_session zeropw-demo zeropw-democli].each do |name|
      bin.install "rust/target/release/#{name}"
    end
    doc.install "README.md", "GUIDE.md", "LICENSE"
  end

  test do
    assert_match "ZeroPW agent", shell_output("#{bin}/zeropw-agent --help")
    assert_match "ZeroPW administrator", shell_output("#{bin}/zeropw-admin --help")
    assert_path_exists bin/"zeropw_session"
    system bin/"zeropw-demo"
  end
end
