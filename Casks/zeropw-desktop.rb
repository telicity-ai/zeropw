cask "zeropw-desktop" do
  version "0.2.0"
  sha256 "3a4315bfd1b17e41294a46c754581a9373750d61e77f3717de310b4dc481c77e"

  url "https://github.com/telicity-ai/zeropw/releases/download/v#{version}/zeropw-desktop-v#{version}-aarch64-apple-darwin.dmg"
  name "ZeroPW"
  desc "Administrator app for agent-safe API and SSH credentials"
  homepage "https://github.com/telicity-ai/zeropw"

  depends_on arch: :arm64

  app "ZeroPW.app"

  # The vault, device keys and settings live in ~/Library/Application Support/ZeroPW.
  # Neither uninstall nor zap may touch that folder: removing it destroys the vault.
  zap trash: [
    "~/Library/Caches/ai.telicity.zeropw",
    "~/Library/HTTPStorages/ai.telicity.zeropw",
    "~/Library/Preferences/ai.telicity.zeropw.plist",
    "~/Library/Saved Application State/ai.telicity.zeropw.savedState",
    "~/Library/WebKit/ai.telicity.zeropw",
  ]

  caveats <<~EOS
    ZeroPW is an ad hoc signed preview. It is not notarized, and its interface is Korean only.

    The first time, open ZeroPW from /Applications. When macOS says that Apple could not
    verify ZeroPW, close the dialog with Done. Within about an hour, open System Settings >
    Privacy & Security, click Open Anyway next to the message about ZeroPW and confirm.
    Do not install with --no-quarantine, remove the quarantine attribute or turn Gatekeeper off.

    Closing the window does not quit the app. Quit it with Cmd+Q before
    brew upgrade --cask or brew uninstall --cask.

    The vault stays in ~/Library/Application Support/ZeroPW: uninstalling, even with --zap,
    does not remove it. The app runs its own bundled zeropw-admin; the zeropw formula
    installs the command-line tools separately.
  EOS
end
