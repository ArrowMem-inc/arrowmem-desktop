// Every app command is listed so the capability files decide which window may call which (Tauri v2 app manifest):
// a command not granted to a window's capability is refused for that window.
const COMMANDS: &[&str] = &[
    "status_view", "retry_firewall", "pair_state", "pair_confirm", "pair_cancel", "open_pairing",
    "uninstall_texts", "uninstall", "status_texts", "home_view", "restart_service", "model_options", "model_download", "model_choose", "mesh_call", "mesh_export",
];

fn main() {
    tauri_build::try_build(
        tauri_build::Attributes::new().app_manifest(tauri_build::AppManifest::new().commands(COMMANDS)),
    )
    .expect("tauri build failed");
}
