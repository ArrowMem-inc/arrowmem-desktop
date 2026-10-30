# arrowmem-desktop

Tauri v2 app for the ArrowBridge home machine.
Nothing here runs the real companion or llama-server yet; `src-tauri/binaries/` holds placeholders.

Build (needs Rust via rustup, Linux needs webkit2gtk-4.1 dev packages):

    sh scripts/make-placeholders.sh
    cd src-tauri && cargo build        # or: cargo tauri build --debug  (needs tauri-cli)

Window text is placeholder and uncleared. No key is ever printed or placed in the webview.
