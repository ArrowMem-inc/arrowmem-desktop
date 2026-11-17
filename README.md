# arrowmem-desktop

Tauri v2 app for the ArrowBridge home machine.
Nothing here runs the real companion or llama-server yet; `src-tauri/binaries/` holds placeholders.

Release 0.1.1 does not include the Arrowmesh daemon; it arrives in a later release.

Build (needs Rust via rustup, Linux needs webkit2gtk-4.1 dev packages):

    sh scripts/make-placeholders.sh
    cd src-tauri && cargo build        # or: cargo tauri build --debug  (needs tauri-cli)

Release build (the package): a release build without the feature is a Tauri dev build and embeds the build folder path in the binary.
Always pass the release feature, then run makepkg (`scripts/build-clean-pkg.sh` does all of it):

    cd src-tauri && cargo build --release --locked --features custom-protocol

Window text is placeholder and uncleared. No key is ever printed or placed in the webview.
