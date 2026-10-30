pub mod autostart;
#[cfg(unix)]
pub mod desktop;
pub mod firstrun;
pub mod paircode;
pub mod mesh;
pub mod models;
pub mod modelpick;
pub mod supervisor;
#[cfg(unix)]
pub mod userunit;
#[cfg(unix)]
pub mod linuxrun;
#[cfg(unix)]
pub mod firewall;
#[cfg(unix)]
pub mod apikey;
#[cfg(unix)]
pub mod pairing;
#[cfg(unix)]
pub mod uninstall;

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tauri::menu::{MenuBuilder, MenuItemBuilder};
use tauri::tray::TrayIconBuilder;
use tauri::{Manager, WindowEvent};

use supervisor::{free_port, locate_companion, locate_llama, LlamaLauncher, RealLauncher, Supervisor};

#[cfg(unix)]
static SIGNALLED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
#[cfg(unix)]
extern "C" fn on_signal(_: libc::c_int) {
    SIGNALLED.store(true, std::sync::atomic::Ordering::SeqCst);
}

fn companion_port() -> u16 {
    std::env::var("ARROWMEM_COMPANION_PORT").ok().and_then(|v| v.parse().ok()).unwrap_or(8788)
}

/// Choose the model (a file the person picked from this computer, else the saved or automatic approved pick), guard memory, and build the llama-server launcher.
/// Blocking (a sha256 over the file), runs on its own thread, never on the tick thread. On Linux nothing is downloaded here any more: the picker
/// offers the download, and with no model file the launcher still exists, so the model service unit is written and idles quietly until the file is there.
fn prepare_llama(dir: &std::path::Path, port: u16, key_file: Option<std::path::PathBuf>) -> Result<(LlamaLauncher, models::Model), firstrun::ModelState> {
    use firstrun::ModelState;
    let (binary, variant) = locate_llama().ok_or_else(|| ModelState::Unavailable("llama-server not found".into()))?;
    let mf = models::load_manifest();
    let settings_dir = dir.parent().unwrap_or(dir);
    let settings = firstrun::load_settings(settings_dir);
    #[cfg(target_os = "linux")]
    let (mut l, entry) = {
        let ram = models::total_ram_bytes().ok_or_else(|| ModelState::Unavailable("cannot read total RAM".into()))?;
        let custom = settings.custom_model_path.as_deref().map(std::path::PathBuf::from).filter(|p| modelpick::is_gguf(p));
        if let Some(cp) = custom {
            let size = cp.metadata().map(|m| m.len()).unwrap_or(0);
            // A model the person chose from the files already on this computer is their own file: it is not checked against our manifest (it is not in it), only that it is a GGUF.
            (LlamaLauncher::unchecked(binary, cp, port), models::Model::synthetic("custom", size))
        } else {
            let entry = firstrun::choose(&mf.models, settings.model_pick.as_deref(), ram).ok_or(ModelState::NoApprovedFit)?.clone();
            match models::presence(&entry, dir) {
                // Not (completely) on this computer yet: the launcher points at a file that does not exist, so the unit is written and idles quietly (ConditionPathExists)
                // and a half-downloaded split model is never started.
                models::Presence::Missing => (LlamaLauncher::unchecked(binary, dir.join(format!("{}.missing", entry.main_name())), port), entry),
                models::Presence::Verified(path) => (LlamaLauncher::new(binary, path, &entry, port).map_err(ModelState::Unavailable)?, entry),
                // A file that is there but does not match the pinned size and sha256 is NEVER handed to llama.cpp's parser: nothing is written, nothing is started.
                models::Presence::Mismatch => return Err(ModelState::Unavailable(format!("{}: the model file does not match the manifest", entry.id))),
            }
        }
    };
    #[cfg(not(target_os = "linux"))]
    let (mut l, entry) = {
        let (entry, path) = firstrun::prepare(&mf, settings_dir, dir, models::total_ram_bytes(), &firstrun::available_ram_bytes)?;
        (LlamaLauncher::new(binary, path, &entry, port).map_err(ModelState::Unavailable)?, entry)
    };
    l.idle_seconds = settings.idle_seconds();
    l.variant = variant.map(str::to_string);
    l.key_file = key_file;
    if variant == Some("vulkan") {
        l.cpu_fallback = l.binary.parent().map(|d| d.join("llama-server-cpu")).filter(|p| p.exists());
    }
    Ok((l, entry))
}

/// Where llama-server's API key file lives (the same rule run() uses).
#[cfg(unix)]
fn key_file_path() -> Option<std::path::PathBuf> {
    let home = std::env::var("HOME").ok()?;
    Some(uninstall::state_dir(std::env::var("ARROWBRIDGE_STATE_DIR").ok().as_deref(), std::env::var("XDG_STATE_HOME").ok().as_deref(), &home).join("llama-api-key"))
}

/// Linux: (re)build the launcher for the current choice and bring the model service in line: used at start and when the person chooses another model or a
/// download finishes. A model file that is not there yet is not an error: the unit idles. Blocking; always on a thread of its own.
#[cfg(target_os = "linux")]
fn bring_up_model(handle: &tauri::AppHandle) {
    let Some(info) = handle.try_state::<Info>() else { return };
    let r = match info.model_dir.clone() {
        Some(d) => prepare_llama(&d, info.llama_port, key_file_path()),
        None => Err(firstrun::ModelState::Unavailable("no app data dir".into())),
    };
    match r {
        Ok((l, entry)) => {
            *info.llama_variant.lock().unwrap() = l.variant.clone();
            *info.model_tier.lock().unwrap() = Some(entry.tier);
            // Memory once more, immediately before a launch; a file that is not there is not launched, so there is nothing to guard.
            if l.model.exists() {
                if let Err(st) = firstrun::guard(&entry, firstrun::available_ram_bytes()) {
                    *info.note.lock().unwrap() = model_state_note(&st);
                    return;
                }
            }
            let data_dir = info.model_dir.as_ref().and_then(|d| d.parent().map(|p| p.to_path_buf())).unwrap_or_default();
            let note = linux_sync(&l, handle, &data_dir);
            *info.note.lock().unwrap() = note;
        }
        Err(e) => *info.note.lock().unwrap() = model_state_note(&e),
    }
}

/// Placeholder status words for a model state (uncleared copy, the real words are written separately).
fn model_state_note(s: &firstrun::ModelState) -> String {
    use firstrun::ModelState::*;
    match s {
        Preparing => firstrun::status_line("note_preparing", firstrun::locale_is_fr()),
        Ready { id } => {
            let (t, e) = firstrun::tiers_for(id);
            firstrun::ready_note(t, e, firstrun::locale_is_fr())
        }
        RefusedLowMemory { .. } | RefusedMemoryUnknown { .. } | NoApprovedFit => {
            firstrun::refusal_text(s, firstrun::locale_is_fr()).unwrap_or_default()
        }
        Unavailable(_) => firstrun::status_line("note_unavailable", firstrun::locale_is_fr()),
    }
}

/// Linux: install or refresh both user units; the returned text is a placeholder status note (uncleared copy).
#[cfg(target_os = "linux")]
fn linux_sync(l: &LlamaLauncher, app: &tauri::AppHandle, data_dir: &std::path::Path) -> String {
    let (Some(home), Some(companion)) = (std::env::var_os("HOME"), locate_companion()) else {
        return firstrun::status_line("note_unavailable", firstrun::locale_is_fr());
    };
    let home = std::path::PathBuf::from(home);
    let xdg = std::env::var("XDG_CONFIG_HOME").ok();
    let dir = userunit::unit_dir(xdg.as_deref(), &home.to_string_lossy());
    let state = uninstall::state_dir(
        std::env::var("ARROWBRIDGE_STATE_DIR").ok().as_deref(),
        std::env::var("XDG_STATE_HOME").ok().as_deref(),
        &home.to_string_lossy(),
    );
    let p = linuxrun::Paths { companion_bin: &companion, state_dir: &state, llama_bin: &l.binary, model: &l.model, llama_port: l.port, idle_seconds: l.idle_seconds };
    let ifaces = linuxrun::list_ipv4();
    let default_if = linuxrun::default_iface(std::path::Path::new("/proc/net/route"));
    // The same interface supplies the bind address and the firewall network.
    let lan = linuxrun::pick_lan(&ifaces, default_if.as_deref()).map(|i| (i.ip, i.mask));
    *app.state::<Info>().lan.lock().unwrap() = lan;
    *app.state::<Info>().data_dir.lock().unwrap() = Some(data_dir.to_path_buf());
    *app.state::<Info>().fallback.lock().unwrap() = match (l.variant.as_deref(), &l.cpu_fallback) {
        (Some("vulkan"), Some(cpu)) => Some(linuxrun::Fallback::new(linuxrun::LlamaPlan {
            port: l.port, cpu_bin: cpu.clone(), model: l.model.clone(), idle_seconds: l.idle_seconds, state_dir: state.clone(),
        })),
        _ => None,
    };
    match linuxrun::sync(std::path::Path::new("/usr/bin/systemctl"), &dir, &p, lan.map(|(ip, _)| ip)) {
        Ok(linuxrun::LanState::Lan(_)) => {
            // End of the first install: the one elevated prompt (firewall), then the pair window.
            let fi = pairing::first_install(data_dir, lan, std::path::Path::new("/usr/bin/pkexec"), std::path::Path::new(firewall::HELPER_PATH));
            if fi.open_pair_window {
                open_window(app, "main", "home.html");
            }
            firstrun::status_line("note_services", firstrun::locale_is_fr())
        }
        Ok(linuxrun::LanState::NoPrivateAddress) => firstrun::status_line("note_services_no_address", firstrun::locale_is_fr()),
        Err(_) => firstrun::status_line("note_unavailable", firstrun::locale_is_fr()),
    }
}

/// Shared with the windows: the LAN address in use (if any) and the model status note.
struct Info {
    lan: Mutex<Option<(std::net::Ipv4Addr, std::net::Ipv4Addr)>>,
    data_dir: Mutex<Option<std::path::PathBuf>>,
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    model_dir: Option<std::path::PathBuf>,
    llama_port: u16,
    llama_variant: Arc<Mutex<Option<String>>>,
    /// Tier of the model that was chosen to run; None until chosen.
    model_tier: Mutex<Option<u32>>,
    /// Set when the Vulkan llama unit is running; switches to the CPU build once if it fails.
    fallback: Mutex<Option<linuxrun::Fallback>>,
    note: Arc<Mutex<String>>,
    /// Silent self-heal of the companion unit: the down card shows only when restarts truly fail.
    heal: Mutex<linuxrun::Heal>,
    /// The picker's last scan of this computer for model files (rescanned when older than a minute); paths live only here and in the settings file.
    found: Mutex<Option<(Instant, Vec<modelpick::Found>)>>,
    /// The approved model being downloaded now (one at a time).
    dl: Mutex<Option<String>>,
    /// A model choice is being applied (the checksum and the unit restart take a while).
    applying: Mutex<bool>,
    /// Models whose sha256 has been checked (see models::Proofs).
    proofs: Arc<Mutex<models::Proofs>>,
}

/// The home window's whole view: the pairing block (None without a private address) and the three status rows.
#[tauri::command]
fn home_view(info: tauri::State<Info>) -> pairing::HomeView {
    let lan = (*info.lan.lock().unwrap()).map(|(ip, _)| ip);
    let note = info.note.lock().unwrap().clone();
    let v = pairing::status_view(pairing::COMPANION_PORT, info.llama_port, llama_key().as_deref(), lan, &note, std::path::Path::new(firewall::HELPER_PATH), info.llama_variant.lock().unwrap().clone(), info.fallback.lock().unwrap().as_ref().is_some_and(|f| f.switched));
    let pair = lan.and_then(|ip| pairing::pair_view(ip, &pairing::device_name()).ok());
    let answers = v.paired.is_some(); // status_view already asked the companion: one request, not two
    let step = info.heal.lock().unwrap().step(answers, std::time::Instant::now());
    #[cfg(target_os = "linux")]
    if step == linuxrun::HealStep::Attempt {
        // Silent: reset a failed unit and restart both, off the window's thread. The window says "restarting" until it answers or three tries fail.
        std::thread::spawn(|| { let _ = linuxrun::recover(std::path::Path::new("/usr/bin/systemctl")); });
    }
    let service = match step { linuxrun::HealStep::Up => "up", linuxrun::HealStep::Failed => "down", _ => "recovering" };
    pairing::HomeView { service, rows: pairing::home_rows(&v), model: v.model, helper_missing: v.helper_missing, pair }
}

/// The window's Restart button after the companion went down (a failed unit after an upgrade): reset and restart both units. True when the companion unit is running again.
#[tauri::command]
fn restart_service(info: tauri::State<Info>) -> bool {
    info.heal.lock().unwrap().reset();
    #[cfg(target_os = "linux")]
    { return linuxrun::recover(std::path::Path::new("/usr/bin/systemctl")); }
    #[allow(unreachable_code)]
    false
}


/// The picker's rows: the approved models with what fits and what is installed, and the models already on this computer. Read only.
#[tauri::command]
async fn model_options(app: tauri::AppHandle) -> Vec<modelpick::ModelOption> {
    // On a worker, never the main thread: the scan reads the disk (a slow mount must not freeze the window or the tray).
    tauri::async_runtime::spawn_blocking(move || model_options_blocking(&app)).await.unwrap_or_default()
}

fn model_options_blocking(app: &tauri::AppHandle) -> Vec<modelpick::ModelOption> {
    let info = app.state::<Info>();
    let mf = models::load_manifest();
    let ram = models::total_ram_bytes().unwrap_or(0);
    let Some(dir) = info.model_dir.clone() else { return Vec::new() };
    let found = found_models(&info, &dir);
    let settings = firstrun::load_settings(dir.parent().unwrap_or(&dir));
    let chosen = match settings.custom_model_path.as_deref().map(std::path::Path::new).filter(|p| modelpick::is_gguf(p)) {
        Some(p) => Some(modelpick::id_of(p)),
        None => firstrun::choose(&mf.models, settings.model_pick.as_deref(), ram).map(|m| m.id.clone()),
    };
    let downloading = info.dl.lock().unwrap().clone().and_then(|id| {
        let m = mf.models.iter().find(|m| m.id == id)?;
        Some((id, models::bytes_so_far(m, &dir)))
    });
    let on_disk = |m: &models::Model| models::installed_cheap(m, &dir);
    // "Installed" means downloaded AND hash-checked. A model that is present but unproven is checked once on a worker (never in this poll) and reads "checking" meanwhile.
    let installed = |m: &models::Model| {
        if !on_disk(m) { return false; }
        if info.proofs.lock().unwrap().is_proven(m, &dir) { return true; }
        if info.proofs.lock().unwrap().begin(&m.id) {
            let (proofs, m, dir) = (info.proofs.clone(), m.clone(), dir.clone());
            std::thread::spawn(move || {
                if models::verified(&m, &dir.join(m.main_name())) { proofs.lock().unwrap().mark(&m, &dir); }
                proofs.lock().unwrap().end(&m.id);
            });
        }
        false
    };
    modelpick::options(&modelpick::Facts { manifest: &mf, ram, free_disk: modelpick::free_bytes(&dir), installed: &installed, on_disk: &on_disk, downloading, found: &found, chosen })
}

/// The scan result, rescanned when older than a minute. Never the owner's own model folder (that holds our approved downloads).
fn found_models(info: &Info, model_dir: &std::path::Path) -> Vec<modelpick::Found> {
    let mut g = info.found.lock().unwrap();
    if let Some((t, v)) = g.as_ref() {
        if t.elapsed() < Duration::from_secs(60) { return v.clone(); }
    }
    let home = std::env::var_os("HOME").map(std::path::PathBuf::from).unwrap_or_default();
    let v = modelpick::scan(&home, &[model_dir.to_path_buf()]);
    *g = Some((Instant::now(), v.clone()));
    v
}

/// Download one APPROVED model by its manifest id: the pinned host, size and sha256 of models::download, one at a time, only when it fits this computer and the disk.
#[tauri::command]
fn model_download(id: String, info: tauri::State<Info>, app: tauri::AppHandle) -> Result<(), String> {
    let mf = models::load_manifest();
    let m = mf.models.iter().find(|m| m.id == id && m.approved).ok_or("not an approved model")?.clone();
    let dir = info.model_dir.clone().ok_or("no model folder")?;
    let ram = models::total_ram_bytes().ok_or("cannot read memory")?;
    if !models::fits(&m, ram) { return Err("does not fit".into()); }
    if modelpick::free_bytes(&dir).map(|d| d < m.size_bytes + (1 << 30)).unwrap_or(true) { return Err("no disk".into()); }
    {
        let mut g = info.dl.lock().unwrap();
        if g.is_some() { return Err("busy".into()); }
        *g = Some(m.id.clone());
    }
    std::thread::spawn(move || {
        let ok = models::download(&mf, &m.url(), &dir).is_ok();
        // download() checked every file's size and sha256 before giving it its final name: that is a proof.
        if ok { if let Some(i) = app.try_state::<Info>() { i.proofs.lock().unwrap().mark(&m, &dir); } }
        if let Some(i) = app.try_state::<Info>() { *i.dl.lock().unwrap() = None; }
        // The model this computer would use anyway (no other choice saved) starts at once when its file lands; any other waits for "Use this".
        #[cfg(target_os = "linux")]
        if ok {
            let settings = firstrun::load_settings(dir.parent().unwrap_or(&dir));
            let would_use = settings.custom_model_path.is_none()
                && models::total_ram_bytes().and_then(|ram| firstrun::choose(&mf.models, settings.model_pick.as_deref(), ram).map(|c| c.id == m.id)).unwrap_or(false);
            if would_use { bring_up_model(&app); }
        }
        let _ = ok;
    });
    Ok(())
}

/// Use a model: an approved one that is installed (its sha256 is checked now, before anything is saved), or one found on this computer (by the opaque id the scan
/// handed out; a path never comes from the page). The choice is saved and the model service is brought in line. Runs on a worker (hashing a large file takes a while).
#[tauri::command]
async fn model_choose(id: String, app: tauri::AppHandle) -> Result<(), String> {
    tauri::async_runtime::spawn_blocking(move || model_choose_blocking(&id, &app)).await.map_err(|e| e.to_string())?
}

fn model_choose_blocking(id: &str, app: &tauri::AppHandle) -> Result<(), String> {
    let info = app.state::<Info>();
    let mf = models::load_manifest();
    let dir = info.model_dir.clone().ok_or("no model folder")?;
    let settings_dir = dir.parent().unwrap_or(&dir).to_path_buf();
    let ram = models::total_ram_bytes().ok_or("cannot read memory")?;
    {
        let mut a = info.applying.lock().unwrap();
        if *a { return Err("busy".into()); }
        *a = true;
    }
    let saved = if let Some(m) = mf.models.iter().find(|m| m.id == id) {
        // An approved model must match its pinned size AND sha256 before it is saved or ever started (the full hash, not the cheap size look).
        if !m.approved || !models::installed_cheap(m, &dir) { Err("not installed".to_string()) }
        else if !models::verified(m, &dir.join(m.main_name())) { Err("does not match the manifest".to_string()) }
        else {
            info.proofs.lock().unwrap().mark(m, &dir);
            firstrun::save_pick(&settings_dir, &mf.models, id, ram)
        }
    } else {
        let found = found_models(&info, &dir);
        match found.iter().find(|f| f.id == id) {
            // The unit file can only carry a plain path: refuse here rather than save a choice the unit cannot follow.
            Some(f) if modelpick::is_gguf(&f.path) && userunit::safe_path(&f.path).is_ok() => firstrun::save_custom(&settings_dir, &f.path),
            _ => Err("not a model on this computer".to_string()),
        }
    };
    if let Err(e) = saved {
        *info.applying.lock().unwrap() = false;
        return Err(e);
    }
    #[cfg(target_os = "linux")]
    {
        let handle = app.clone();
        std::thread::spawn(move || {
            bring_up_model(&handle);
            if let Some(i) = handle.try_state::<Info>() { *i.applying.lock().unwrap() = false; }
        });
    }
    #[cfg(not(target_os = "linux"))]
    { *info.applying.lock().unwrap() = false; }
    Ok(())
}

/// The pair window polls this about once a second while it is open.
#[tauri::command]
fn pair_state() -> pairing::PairState {
    pairing::fetch_pair_state(pairing::COMPANION_PORT)
}

/// The pair window's Connect: the six digits the owner typed go to the companion's /pair-confirm on loopback.
/// The code is validated in pairing:: and is never logged or kept.
#[tauri::command]
fn pair_confirm(handshake_id: String, code: String) -> pairing::ConfirmResult {
    pairing::confirm_if_revealed(pairing::COMPANION_PORT, &handshake_id, &code)
}

/// The pair window's Not me: the companion's /pair-cancel.
#[tauri::command]
fn pair_cancel() -> bool {
    pairing::cancel_pairing(pairing::COMPANION_PORT)
}

/// The pair window's "open pairing" action (the companion's owner route; the window then lasts its own timeout).
#[tauri::command]
fn open_pairing() -> Result<(), String> {
    match pairing::open_pairing(pairing::COMPANION_PORT) {
        pairing::OpenResult::Opened => Ok(()),
        pairing::OpenResult::PhoneLimit => Err("phone_limit".into()),
        pairing::OpenResult::Failed => Err("failed".into()),
    }
}

/// llama-server's API key, read from its 0600 file in the state dir. None when absent or not safely stored.
fn llama_key() -> Option<String> {
    let home = std::env::var("HOME").ok()?;
    let dir = uninstall::state_dir(std::env::var("ARROWBRIDGE_STATE_DIR").ok().as_deref(), std::env::var("XDG_STATE_HOME").ok().as_deref(), &home);
    apikey::read_key(&dir)
}

#[tauri::command]
fn status_view(info: tauri::State<Info>) -> pairing::StatusView {
    let lan = (*info.lan.lock().unwrap()).map(|(ip, _)| ip);
    let note = info.note.lock().unwrap().clone();
    let mut v = pairing::status_view(pairing::COMPANION_PORT, info.llama_port, llama_key().as_deref(), lan, &note, std::path::Path::new(firewall::HELPER_PATH), info.llama_variant.lock().unwrap().clone(), info.fallback.lock().unwrap().as_ref().is_some_and(|f| f.switched));
    let e4b = models::load_manifest().models.iter().find(|m| m.id.contains("E4B")).map(|m| m.tier);
    v.slowness = firstrun::slowness_kind(*info.model_tier.lock().unwrap(), e4b).map(|k| k.as_str().to_string());
    v
}

/// The status window's words (both languages) and the untranslated firewall command with this network filled in.
#[tauri::command]
fn status_texts(info: tauri::State<Info>) -> (pairing::StatusTexts, Option<String>) {
    let cidr = (*info.lan.lock().unwrap()).and_then(|(ip, mask)| firewall::cidr_from(ip, mask).ok());
    pairing::status_texts(cidr.as_deref())
}

/// The status window's retry button: ask for the firewall rule again. Returns a machine state, not words.
#[tauri::command]
fn retry_firewall(info: tauri::State<Info>) -> Result<String, String> {
    let lan = *info.lan.lock().unwrap();
    let dir = info.data_dir.lock().unwrap().clone().ok_or("not ready")?;
    let r = pairing::retry_firewall(&dir, lan, std::path::Path::new("/usr/bin/pkexec"), std::path::Path::new(firewall::HELPER_PATH))?;
    Ok(match r {
        firewall::FwOutcome::Done => "done".into(),
        firewall::FwOutcome::NoFirewall => "no_firewall".into(),
        firewall::FwOutcome::HelperMissing => "helper_not_installed".into(),
        firewall::FwOutcome::Failed(c) => format!("failed_{c}"),
    })
}

#[cfg(target_os = "linux")]
fn uninstall_dirs(info: &Info) -> Result<(std::path::PathBuf, std::path::PathBuf, std::path::PathBuf), String> {
    let home = std::path::PathBuf::from(std::env::var_os("HOME").ok_or("HOME missing")?);
    let state = uninstall::state_dir(
        std::env::var("ARROWBRIDGE_STATE_DIR").ok().as_deref(),
        std::env::var("XDG_STATE_HOME").ok().as_deref(),
        &home.to_string_lossy(),
    );
    Ok((home, state, info.model_dir.clone().ok_or("no model folder")?))
}

/// The confirm window's words, both languages, with the real folders substituted.
#[tauri::command]
fn uninstall_texts(info: tauri::State<Info>) -> Result<uninstall::AllStrings, String> {
    let _ = &info;
    #[cfg(target_os = "linux")]
    {
        let (_, state, models) = uninstall_dirs(&info)?;
        return Ok(uninstall::texts(&state, &models));
    }
    #[allow(unreachable_code)]
    Err("uninstall is Linux only".into())
}

/// Uninstall. `purge` is the checkbox (off by default in the window). Reports every step.
#[tauri::command]
async fn uninstall(purge: bool, info: tauri::State<'_, Info>) -> Result<uninstall::Report, String> {
    let _ = (&info, purge);
    #[cfg(target_os = "linux")]
    {
        let (home, state, models) = uninstall_dirs(&info)?;
        let xdg_cfg = std::env::var("XDG_CONFIG_HOME").ok();
        let units = userunit::unit_dir(xdg_cfg.as_deref(), &home.to_string_lossy());
        let (apps, icons) = desktop::data_dirs(std::env::var("XDG_DATA_HOME").ok().as_deref(), &home.to_string_lossy());
        let auto = autostart::autostart_dir();
        let xdg_state = std::env::var_os("XDG_STATE_HOME").map(std::path::PathBuf::from);
        let plan = uninstall::Plan {
            ctl: std::path::Path::new("/usr/bin/systemctl"),
            unit_dir: &units,
            pkexec: std::path::Path::new("/usr/bin/pkexec"),
            helper: std::path::Path::new(firewall::HELPER_PATH),
            autostart_dir: auto.as_deref(),
            apps_dir: &apps,
            icons_dir: &icons,
            state_dir: &state,
            model_dir: &models,
            home: &home,
            xdg_state: xdg_state.as_deref(),
        };
        return Ok(uninstall::run(&plan, purge));
    }
    #[allow(unreachable_code)]
    Err("uninstall is Linux only".into())
}

/// True when the autostart entry started the app: it goes to the tray and shows no window.
fn started_in_background(args: &[String]) -> bool {
    args.iter().skip(1).any(|a| a == "--background")
}

/// The Arrowmesh screens' only way to the daemon (see mesh.rs). The reply is data for any HTTP status; a transport or local refusal is a short code.
#[tauri::command]
fn mesh_call(method: String, path: String, body: Option<serde_json::Value>) -> Result<mesh::MeshReply, String> {
    let t = mesh::target_from_env().map_err(str::to_string)?;
    mesh::call(&t, &method, &path, body.as_ref()).map_err(str::to_string)
}

/// What the window learns about an export: a status word, never the bytes. "cancelled" = the dialog was closed (nothing was requested or written).
#[derive(serde::Serialize)]
struct ExportReply {
    outcome: &'static str,
    status: u16,
}

/// Vault export. A native save dialog first (no default folder, only a dated placeholder file name); on a chosen path
/// this side asks the daemon for the sealed export and writes the bytes to that path. The bytes never reach the window.
/// Async so the blocking dialog does not run on the main thread.
#[tauri::command]
async fn mesh_export(app: tauri::AppHandle) -> Result<ExportReply, String> {
    use mesh::dlg::DialogExt;
    let (y, m, d) = mesh::civil_from_unix(std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|x| x.as_secs()).unwrap_or(0));
    let chosen = app.dialog().file().set_file_name(mesh::export_filename(y, m, d)).blocking_save_file();
    let Some(fp) = chosen else { return Ok(ExportReply { outcome: "cancelled", status: 0 }) };
    let path = fp.into_path().map_err(|_| "bad_path".to_string())?;
    let t = mesh::target_from_env().map_err(str::to_string)?;
    let (status, bytes) = mesh::call_export(&t).map_err(str::to_string)?;
    if status != 200 {
        return Ok(ExportReply { outcome: "refused", status });
    }
    mesh::write_export(&path, &bytes).map_err(|_| "write_failed".to_string())?;
    Ok(ExportReply { outcome: "written", status })
}

fn open_window(app: &tauri::AppHandle, label: &str, page: &str) {
    if let Some(w) = app.get_webview_window(label) {
        let _ = w.show();
        let _ = w.set_focus();
        return;
    }
    let _ = tauri::WebviewWindowBuilder::new(app, label, tauri::WebviewUrl::App(page.into()))
        .title("ArrowMem")
        .inner_size(if label == "mesh" { 1280.0 } else if label == "main" { 720.0 } else { 420.0 }, if label == "mesh" { 740.0 } else if label == "main" { 700.0 } else { 520.0 })
        .build();
}

pub fn run() {
    let llama_port = if cfg!(target_os = "linux") { linuxrun::LLAMA_PORT } else { free_port().unwrap_or(18080) };
    let llama_sup: Arc<Mutex<Option<Supervisor<LlamaLauncher>>>> = Arc::new(Mutex::new(None));
    let llama_note: Arc<Mutex<String>> = Arc::new(Mutex::new("Model: preparing".into()));
    // Linux: the companion and llama-server run as systemd user units, not as children (linuxrun).
    // Where llama-server's API key lives. Linux: the units' install rotates it (linuxrun::sync). Elsewhere the
    // children are started here, so a fresh key is made now: llama-server reads the file, the companion child gets
    // the key in its environment.
    #[cfg(unix)]
    let key_dir: Option<std::path::PathBuf> = std::env::var("HOME").ok().map(|h| {
        uninstall::state_dir(std::env::var("ARROWBRIDGE_STATE_DIR").ok().as_deref(), std::env::var("XDG_STATE_HOME").ok().as_deref(), &h)
    });
    #[cfg(not(unix))]
    let key_dir: Option<std::path::PathBuf> = None;
    #[cfg(not(target_os = "linux"))]
    #[cfg(unix)]
    let child_key: Option<String> = key_dir.as_ref().and_then(|d| apikey::rotate(d).ok().and_then(|_| apikey::read_key(d)));
    #[cfg(any(target_os = "linux", not(unix)))]
    let child_key: Option<String> = None;
    let key_file: Option<std::path::PathBuf> = key_dir.as_ref().map(|d| d.join("llama-api-key"));
    let sup: Arc<Mutex<Option<Supervisor<RealLauncher>>>> = Arc::new(Mutex::new(locate_companion().filter(|_| cfg!(not(target_os = "linux"))).map(|binary| {
        Supervisor::new(RealLauncher {
            binary,
            port: companion_port(),
            upstream_url: Some(format!("http://127.0.0.1:{llama_port}")),
            upstream_key: child_key.clone(),
        })
    })));
    #[cfg_attr(target_os = "linux", allow(unused_variables))]
    let llama_setup = llama_sup.clone();
    let llama_exit = llama_sup.clone();
    let (note_setup, note_tick, note_status) = (llama_note.clone(), llama_note.clone(), llama_note.clone());
    let llama_variant: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
    let variant_setup = llama_variant.clone();
    let sup_setup = sup.clone();
    let sup_exit = sup.clone();

    let app = tauri::Builder::default()
        .plugin(mesh::dlg_init())
        .invoke_handler(tauri::generate_handler![home_view, restart_service, model_options, model_download, model_choose, status_view, retry_firewall, pair_state, pair_confirm, pair_cancel, open_pairing, uninstall_texts, uninstall, status_texts, mesh_call, mesh_export])
        .setup(move |app| {
            #[cfg(target_os = "linux")]
            if std::env::var_os("ARROWMEM_NO_AUTOSTART").is_none() {
                if let (Some(dir), Ok(exe)) = (autostart::autostart_dir(), std::env::current_exe()) {
                    let _ = autostart::write_autostart(&dir, &exe.to_string_lossy());
                }
            }
            // First run from an AppImage: put a launcher entry and icon in the user's XDG data dir (no root).
            #[cfg(target_os = "linux")]
            if let (Some(appimage), Some(home)) = (std::env::var_os("APPIMAGE"), std::env::var_os("HOME")) {
                let (apps, icons) = desktop::data_dirs(std::env::var("XDG_DATA_HOME").ok().as_deref(), &home.to_string_lossy());
                let _ = desktop::install_launcher(&apps, &icons, &appimage.to_string_lossy());
            }
            let fr = firstrun::locale_is_fr();
            let status_item = MenuItemBuilder::with_id("status", firstrun::status_line("tray_initial", fr)).enabled(false).build(app)?;
            let open = MenuItemBuilder::with_id("open", firstrun::status_line("tray_open", fr)).build(app)?;
            let uninstall_item = MenuItemBuilder::with_id("uninstall", if fr { uninstall::strings().fr.menu_uninstall } else { uninstall::strings().en.menu_uninstall }).build(app)?;
            let quit = MenuItemBuilder::with_id("quit", firstrun::status_line("tray_quit", fr)).build(app)?;
            let status_win = MenuItemBuilder::with_id("status_win", firstrun::status_line("tray_status_window", fr)).build(app)?;
            let pair_item = MenuItemBuilder::with_id("pair", firstrun::status_line("tray_pair", fr)).build(app)?;
            // UNCLEARED placeholder label, verbatim from the approved render (DES_ARROWMESH_RENDER_2026-10-29).
            let mesh_item = MenuItemBuilder::with_id("mesh", "[CA] app name").build(app)?;
            let menu = MenuBuilder::new(app).items(&[&status_item, &open, &pair_item, &mesh_item, &status_win, &uninstall_item, &quit]).build()?;
            let mut tray = TrayIconBuilder::new().menu(&menu).tooltip("ArrowMem").on_menu_event(
                |app, ev| match ev.id().as_ref() {
                    "open" | "pair" => open_window(app, "main", "home.html"),
                    "mesh" => open_window(app, "mesh", "mesh-chat.html"),
                    "status_win" => open_window(app, "status", "status.html"),
                    "uninstall" => open_window(app, "uninstall", "uninstall.html"),
                    "quit" => app.exit(0),
                    _ => {}
                },
            );
            if let Some(icon) = app.default_window_icon() {
                tray = tray.icon(icon.clone());
            }
            tray.build(app)?;

            // SIGTERM/SIGINT must stop the companion too, so route them through the normal exit path.
            #[cfg(unix)]
            unsafe {
                libc::signal(libc::SIGTERM, on_signal as *const () as libc::sighandler_t);
                libc::signal(libc::SIGINT, on_signal as *const () as libc::sighandler_t);
            }
            let model_dir = std::env::var_os("ARROWMEM_MODEL_DIR")
                .map(std::path::PathBuf::from)
                .or_else(|| app.path().app_data_dir().ok().map(|d| d.join("models")));
            // The model server's loopback port: chosen once from an unusual range and kept, never a fixed 8080 that another program may hold.
            #[cfg(target_os = "linux")]
            let llama_port = model_dir.as_ref().map(|d| linuxrun::pick_llama_port(d.parent().unwrap_or(d), std::path::Path::new("/usr/bin/systemctl"))).unwrap_or(linuxrun::LLAMA_PORT);
            app.manage(Info { lan: Mutex::new(None), data_dir: Mutex::new(None), model_dir: model_dir.clone(), llama_port, llama_variant: llama_variant.clone(), model_tier: Mutex::new(None), fallback: Mutex::new(None), note: note_status.clone(), heal: Mutex::new(linuxrun::Heal::default()), found: Mutex::new(None), dl: Mutex::new(None), applying: Mutex::new(false), proofs: Arc::new(Mutex::new(models::Proofs::default())) });
            // The window asks for Info at once, so it opens only after Info is managed. Started by hand: show the home window; by the autostart entry: the tray only.
            if !started_in_background(&std::env::args().collect::<Vec<_>>()) {
                open_window(app.handle(), "main", "home.html");
            }
            let handle_info = app.handle().clone();
            #[cfg(target_os = "linux")]
            let handle_model = app.handle().clone();
            #[cfg(target_os = "linux")]
            {
                let _ = (&model_dir, &key_file, &variant_setup, &note_setup, &handle_info);
                std::thread::spawn(move || bring_up_model(&handle_model));
            }
            #[cfg(not(target_os = "linux"))]
            std::thread::spawn(move || {
                let r = match model_dir {
                    Some(d) => prepare_llama(&d, llama_port, key_file.clone()),
                    None => Err(firstrun::ModelState::Unavailable("no app data dir".into())),
                };
                match r {
                    Ok((l, entry)) => {
                        *variant_setup.lock().unwrap() = l.variant.clone();
                        if let Some(i) = handle_info.try_state::<Info>() { *i.model_tier.lock().unwrap() = Some(entry.tier); }
                        if let Err(st) = firstrun::guard(&entry, firstrun::available_ram_bytes()) {
                            *note_setup.lock().unwrap() = model_state_note(&st);
                            return;
                        }
                        *llama_setup.lock().unwrap() = Some(Supervisor::new(l).with_grace(300_000));
                        *note_setup.lock().unwrap() = firstrun::status_line("note_starting", firstrun::locale_is_fr());
                    }
                    Err(e) => *note_setup.lock().unwrap() = model_state_note(&e),
                }
            });
            let handle = app.handle().clone();
            let sup = sup_setup.clone();
            let llama_tick = llama_sup.clone();
            let t0 = Instant::now();
            let mut tray_tick: u32 = 0;
            std::thread::spawn(move || loop {
                #[cfg(unix)]
                if SIGNALLED.load(std::sync::atomic::Ordering::SeqCst) {
                    handle.exit(0);
                    return;
                }
                #[cfg(target_os = "linux")]
                let label = {
                    let _ = &sup;
                    // A Vulkan llama unit that fails is switched to the CPU build, once per app start.
                    if let (Some(info), Some(home)) = (handle.try_state::<Info>(), std::env::var_os("HOME")) {
                        let dir = userunit::unit_dir(std::env::var("XDG_CONFIG_HOME").ok().as_deref(), &home.to_string_lossy());
                        if let Some(f) = info.fallback.lock().unwrap().as_mut() {
                            let _ = f.step(std::path::Path::new("/usr/bin/systemctl"), &dir, &mut info.llama_variant.lock().unwrap());
                        }
                    }
                    let (b, l) = linuxrun::health(std::path::Path::new("/usr/bin/systemctl"));
                    // Placeholder labels, uncleared copy.
                    format!("companion {}, model {}", if b { "active" } else { "inactive" }, if l { "active" } else { "inactive" })
                };
                #[cfg(not(target_os = "linux"))]
                let label = {
                    let mut g = sup.lock().unwrap();
                    match g.as_mut() {
                        Some(s) => s.tick(t0.elapsed().as_millis() as u64).label(),
                        None => "Companion not found".to_string(),
                    }
                };
                if let Some(s) = llama_tick.lock().unwrap().as_mut() {
                    *note_tick.lock().unwrap() = format!("Model: {}", s.tick(t0.elapsed().as_millis() as u64).label());
                }
                let _ = &label;
                // The tray status line is the paired state; unknown keeps the line as it was. Asked every tenth second, not every second: each loopback request leaves a
                // TIME-WAIT socket on the companion port, and a restart of the companion cannot bind while many exist (it binds without SO_REUSEADDR).
                tray_tick = tray_tick.wrapping_add(1);
                if tray_tick % 5 == 1 { match pairing::fetch_paired(pairing::COMPANION_PORT) {
                    Some(true) => { let _ = status_item.set_text(firstrun::status_line("tray_paired", firstrun::locale_is_fr())); }
                    Some(false) => { let _ = status_item.set_text(firstrun::status_line("tray_unpaired", firstrun::locale_is_fr())); }
                    None => {}
                } }
                for _ in 0..10 {
                    #[cfg(unix)]
                    if SIGNALLED.load(std::sync::atomic::Ordering::SeqCst) {
                        break;
                    }
                    std::thread::sleep(Duration::from_millis(200));
                }
            });
            Ok(())
        })
        .on_window_event(|w, ev| {
            // Closing the window hides it; the tray keeps the app and the companion running.
            if let WindowEvent::CloseRequested { api, .. } = ev {
                api.prevent_close();
                let _ = w.hide();
            }
        })
        .build(tauri::generate_context!())
        .expect("error while building ArrowMem Desktop");

    app.run(move |_h, ev| {
        if let tauri::RunEvent::Exit = ev {
            if let Some(s) = sup_exit.lock().unwrap().as_mut() {
                s.stop();
            }
            if let Some(s) = llama_exit.lock().unwrap().as_mut() {
                s.stop();
            }
        }
    });
}

#[cfg(test)]
mod home_tests {
    use super::started_in_background;

    #[test]
    fn only_the_background_flag_hides_the_home_window() {
        let a = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        assert!(started_in_background(&a(&["arrowmem-desktop", "--background"])));
        assert!(!started_in_background(&a(&["arrowmem-desktop"])));
        assert!(!started_in_background(&a(&["--background"]))); // the program name slot is never a flag
        assert!(!started_in_background(&a(&["arrowmem-desktop", "--backgroundx", "background"])));
    }
}
