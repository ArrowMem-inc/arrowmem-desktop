//! Release 11, S3: first-run model choice, the memory guard, and the saved size pick. Thresholds come from
//! manifest data (desktop_min_ram_gb, headroom_gb); nothing here names a model or a RAM figure.
//! GPU VRAM is not read: the pick is RAM only (the first cut on the plan's list).
//! Needed from a human-run step: a 26B Q8_0 manifest entry (for 64 GB and up). A sha256 has to be read from a
//! downloaded file by hand; none is invented here, so that tier is absent and 64 GB machines get 26B Q4_0 once
//! that entry is approved.

use crate::models::{self, Manifest, Model};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

const GIB: u64 = 1024 * 1024 * 1024;

const STATUS_RAW: &str = include_str!("../strings/status.json");

/// The model-refusal line from strings/status.json, in French when `fr`, else English. None for a state that
/// carries no refusal text.
pub fn refusal_text(s: &ModelState, fr: bool) -> Option<String> {
    let key = match s {
        ModelState::RefusedLowMemory { .. } => "low_memory",
        ModelState::RefusedMemoryUnknown { .. } => "memory_unknown",
        ModelState::NoApprovedFit => "no_fit",
        _ => return None,
    };
    let v: serde_json::Value = serde_json::from_str(STATUS_RAW).expect("strings/status.json is part of the build");
    v[if fr { "fr" } else { "en" }][key].as_str().map(str::to_string)
}

/// Any line of strings/status.json by key (English, or French when `fr`). Empty if the key is missing.
pub fn status_line(key: &str, fr: bool) -> String {
    let v: serde_json::Value = serde_json::from_str(STATUS_RAW).expect("strings/status.json is part of the build");
    v[if fr { "fr" } else { "en" }][key].as_str().unwrap_or_default().to_string()
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Slowness { Specific, Generic }

impl Slowness {
    pub fn as_str(self) -> &'static str { match self { Slowness::Specific => "specific", Slowness::Generic => "generic" } }
}

/// The slowness line to show. Specific only when the running model's tier is above E4B's; the generic line when
/// either tier cannot be told; nothing for E4B or smaller.
pub fn slowness_kind(running_tier: Option<u32>, e4b_tier: Option<u32>) -> Option<Slowness> {
    match above_e4b(running_tier, e4b_tier) {
        Some(true) => Some(Slowness::Specific),
        Some(false) => None,
        None => Some(Slowness::Generic),
    }
}

/// The one tier comparison: Some(true) when the running tier is above E4B's, Some(false) at or below, None when
/// either cannot be told.
pub fn above_e4b(running_tier: Option<u32>, e4b_tier: Option<u32>) -> Option<bool> {
    Some(running_tier? > e4b_tier?)
}

/// "Model ready: Standard|Larger" (FR likewise); the plain "Model ready." when the tier cannot be told. Never
/// carries a model name or id.
pub fn ready_note(running_tier: Option<u32>, e4b_tier: Option<u32>, fr: bool) -> String {
    match above_e4b(running_tier, e4b_tier) {
        Some(above) => status_line("note_ready_size", fr).replace("{size}", &status_line(if above { "size_larger" } else { "size_standard" }, fr)),
        None => status_line("note_ready", fr),
    }
}

/// Tier of the manifest entry `id`, and of E4B (the entry whose id contains "E4B").
pub fn tiers_for(id: &str) -> (Option<u32>, Option<u32>) {
    let mf = crate::models::load_manifest();
    (mf.models.iter().find(|m| m.id == id).map(|m| m.tier), mf.models.iter().find(|m| m.id.contains("E4B")).map(|m| m.tier))
}

/// French when the first of LC_ALL, LC_MESSAGES, LANG that is set starts with "fr" (the same rule the windows
/// apply to navigator.language).
pub fn locale_is_fr() -> bool {
    ["LC_ALL", "LC_MESSAGES", "LANG"].iter().filter_map(|k| std::env::var(k).ok()).find(|v| !v.is_empty())
        .is_some_and(|v| v.to_lowercase().starts_with("fr"))
}

/// What the status window reads. A state, not words: the words for each are written separately.
#[derive(Debug, Clone, PartialEq)]
pub enum ModelState {
    Preparing,
    Ready { id: String },
    /// Free RAM was below the file plus headroom; nothing was loaded.
    RefusedLowMemory { id: String, need_bytes: u64, available_bytes: u64 },
    /// Free RAM could not be read, so the guard refuses (could-not-check is not fine).
    RefusedMemoryUnknown { id: String },
    NoApprovedFit,
    Unavailable(String),
}

/// Largest approved entry that fits `ram_bytes` (the manifest's own thresholds). Unapproved entries are never
/// chosen, however much RAM there is.
pub fn auto_pick(models: &[Model], ram_bytes: u64) -> Option<&Model> {
    models::select(models, ram_bytes)
}

/// The user's pick, valid only if it is an approved entry that fits.
pub fn valid_pick<'a>(models: &'a [Model], id: &str, ram_bytes: u64) -> Option<&'a Model> {
    models.iter().find(|m| m.id == id && m.approved && models::fits(m, ram_bytes))
}

/// Approved entries smaller (lower tier) than `current`, largest first: what Settings offers as "next size down".
pub fn sizes_down<'a>(models: &'a [Model], current: &Model, ram_bytes: u64) -> Vec<&'a Model> {
    let mut v: Vec<&Model> = models.iter().filter(|m| m.approved && m.tier < current.tier && models::fits(m, ram_bytes)).collect();
    v.sort_by_key(|m| std::cmp::Reverse(m.tier));
    v
}

/// Saved choice, or auto pick when none / invalid.
pub fn choose<'a>(models: &'a [Model], saved: Option<&str>, ram_bytes: u64) -> Option<&'a Model> {
    saved.and_then(|id| valid_pick(models, id, ram_bytes)).or_else(|| auto_pick(models, ram_bytes))
}

/// Memory guard, before EVERY llama load. `available` is None when it could not be read.
pub fn guard(m: &Model, available: Option<u64>) -> Result<(), ModelState> {
    let need = m.size_bytes + m.headroom_gb * GIB;
    match available {
        None => Err(ModelState::RefusedMemoryUnknown { id: m.id.clone() }),
        Some(a) if a < need => Err(ModelState::RefusedLowMemory { id: m.id.clone(), need_bytes: need, available_bytes: a }),
        Some(_) => Ok(()),
    }
}

/// Reuse a file at the target path only if it matches the pinned size and sha256; any other file is ignored
/// (and replaced by the download), never loaded. Returns the verified path.
pub fn ensure_model(manifest: &Manifest, m: &Model, dir: &Path) -> Result<PathBuf, String> {
    models::download(manifest, &m.url(), dir).map_err(|e| format!("{}: {e:?}", m.id))
}

pub fn parse_meminfo_available(s: &str) -> Option<u64> {
    let line = s.lines().find(|l| l.starts_with("MemAvailable:"))?;
    let kb: u64 = line.split_whitespace().nth(1)?.parse().ok()?;
    Some(kb * 1024)
}

/// macOS `vm_stat`: free + inactive + speculative pages.
pub fn parse_vm_stat_available(s: &str) -> Option<u64> {
    let first = s.lines().next()?;
    let page: u64 = first.split("page size of ").nth(1)?.split_whitespace().next()?.parse().ok()?;
    let pages = |key: &str| -> Option<u64> {
        let l = s.lines().find(|l| l.starts_with(key))?;
        l.split(':').nth(1)?.trim().trim_end_matches('.').parse().ok()
    };
    Some((pages("Pages free")? + pages("Pages inactive")? + pages("Pages speculative").unwrap_or(0)) * page)
}

pub fn available_ram_bytes() -> Option<u64> {
    #[cfg(target_os = "linux")]
    {
        return parse_meminfo_available(&std::fs::read_to_string("/proc/meminfo").ok()?);
    }
    #[cfg(target_os = "macos")]
    {
        let out = std::process::Command::new("/usr/bin/vm_stat").output().ok()?;
        return parse_vm_stat_available(&String::from_utf8_lossy(&out.stdout));
    }
    #[allow(unreachable_code)]
    None
}

/// The user's saved size pick (settings.json in the app data dir).
#[derive(Debug, Default, Serialize, Deserialize, PartialEq)]
pub struct Settings {
    pub model_pick: Option<String>,
    /// Seconds of idleness before llama-server unloads the model. None or 0 = the default. The UI comes later.
    #[serde(default)]
    pub idle_seconds: Option<u32>,
    /// A model file already on this computer, chosen in the picker (never typed by the page: the app hands out an opaque id and keeps the path here).
    #[serde(default)]
    pub custom_model_path: Option<String>,
    /// The loopback port of the model server, chosen once (a free one from an unusual range) and kept so the unit text stays the same.
    #[serde(default)]
    pub llama_port: Option<u16>,
}

pub const DEFAULT_IDLE_SECONDS: u32 = 600;
pub const MIN_IDLE_SECONDS: u32 = 60;
pub const MAX_IDLE_SECONDS: u32 = 86_400;

impl Settings {
    pub fn idle_seconds(&self) -> u32 {
        match self.idle_seconds {
            Some(n) if n > 0 => n.clamp(MIN_IDLE_SECONDS, MAX_IDLE_SECONDS),
            _ => DEFAULT_IDLE_SECONDS,
        }
    }
}

pub fn load_settings(dir: &Path) -> Settings {
    std::fs::read_to_string(dir.join("settings.json")).ok().and_then(|s| serde_json::from_str(&s).ok()).unwrap_or_default()
}

/// Save a pick, refusing anything that is not an approved entry that fits this machine.
pub fn save_pick(dir: &Path, models: &[Model], id: &str, ram_bytes: u64) -> Result<(), String> {
    if valid_pick(models, id, ram_bytes).is_none() {
        return Err(format!("not an approved model that fits: {id}"));
    }
    std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
    let s = serde_json::to_string(&Settings { model_pick: Some(id.to_string()), custom_model_path: None, ..load_settings(dir) }).map_err(|e| e.to_string())?;
    std::fs::write(dir.join("settings.json"), s).map_err(|e| e.to_string())
}

/// The picker chose a model file that is already on this computer. The caller has checked it is a GGUF file; the path stays in this settings file only.
pub fn save_custom(dir: &Path, path: &Path) -> Result<(), String> {
    std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
    let s = serde_json::to_string(&Settings { custom_model_path: Some(path.to_string_lossy().into_owned()), ..load_settings(dir) }).map_err(|e| e.to_string())?;
    std::fs::write(dir.join("settings.json"), s).map_err(|e| e.to_string())
}

/// First run end to end: choose, guard, ensure the verified file. Returns the entry and path, or the state to
/// show. Blocking (download); never call on a UI thread.
pub fn prepare(manifest: &Manifest, settings_dir: &Path, model_dir: &Path, ram: Option<u64>, available: &dyn Fn() -> Option<u64>) -> Result<(Model, PathBuf), ModelState> {
    let ram = ram.ok_or_else(|| ModelState::Unavailable("cannot read total RAM".into()))?;
    let saved = load_settings(settings_dir).model_pick;
    let entry = choose(&manifest.models, saved.as_deref(), ram).ok_or(ModelState::NoApprovedFit)?.clone();
    guard(&entry, available())?;
    let path = ensure_model(manifest, &entry, model_dir).map_err(ModelState::Unavailable)?;
    // A download takes long enough for memory to change: read it again, fresh, just before the caller launches.
    guard(&entry, available())?;
    Ok((entry, path))
}

/// Settings.idle_seconds, clamped to 60..=86400; 0 or absent is 600. (Doc for the readers of the file.)
#[cfg(test)]
mod idle_tests {
    use super::*;

    #[test]
    fn idle_seconds_defaults_to_600_and_is_bounded() {
        assert_eq!(Settings::default().idle_seconds(), 600);
        for (v, want) in [(Some(0), 600), (Some(1), 60), (Some(59), 60), (Some(60), 60), (Some(61), 61), (Some(120), 120), (Some(86_400), 86_400), (Some(86_401), 86_400), (Some(u32::MAX), 86_400), (None, 600)] {
            assert_eq!(Settings { model_pick: None, idle_seconds: v, custom_model_path: None, llama_port: None }.idle_seconds(), want, "{v:?}");
        }
        let s: Settings = serde_json::from_str(r#"{"model_pick":"x"}"#).unwrap();
        assert_eq!(s.idle_seconds(), 600, "an old settings file has no idle field");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn gb(n: u64) -> u64 { n * GIB }
    /// The desktop tier table as manifest data. 12B and 26B are unapproved, as today.
    fn table(approve_big: bool) -> Vec<Model> {
        let mut v = models::load_manifest().models;
        for m in v.iter_mut() {
            if m.id.contains("12B") || m.id.contains("26B") { m.approved = approve_big; }
        }
        v
    }
    fn pick_id(v: &[Model], ram: u64) -> Option<String> { auto_pick(v, ram).map(|m| m.id.clone()) }

    #[test]
    fn real_manifest_has_not_approved_the_big_tiers() {
        for m in models::load_manifest().models {
            if m.id.contains("12B") || m.id.contains("26B") { assert!(!m.approved, "{}", m.id); }
        }
    }

    #[test]
    fn today_the_pick_caps_at_e4b_even_with_huge_ram() {
        let v = table(false);
        for g in [8u64, 16, 24, 32, 64, 128] {
            assert_eq!(pick_id(&v, gb(g)).as_deref(), Some("gemma-4-E4B-it-q4_0"), "{g} GB");
        }
    }

    #[test]
    fn once_approved_the_table_follows_manifest_thresholds() {
        let v = table(true);
        assert_eq!(pick_id(&v, gb(8)).as_deref(), Some("gemma-4-E4B-it-q4_0"));
        assert_eq!(pick_id(&v, gb(16)).as_deref(), Some("gemma-4-12B-it-q4_0"));
        assert_eq!(pick_id(&v, gb(24)).as_deref(), Some("gemma-4-26B-A4B-it-q4_0"));
        assert_eq!(pick_id(&v, gb(32)).as_deref(), Some("gemma-4-26B-A4B-it-q4_0"));
    }

    #[test]
    fn thresholds_are_data_not_code() {
        let mut v = table(true);
        for m in v.iter_mut() { if m.id.contains("12B") { m.desktop_min_ram_gb = Some(32); } }
        assert_eq!(pick_id(&v, gb(16)).as_deref(), Some("gemma-4-E4B-it-q4_0"));
    }

    #[test]
    fn under_the_floor_falls_back_or_nothing() {
        let v = table(false);
        assert_eq!(pick_id(&v, gb(4)), None);
    }

    #[test]
    fn saved_pick_must_be_approved_and_fit() {
        let v = table(false);
        assert!(valid_pick(&v, "gemma-4-E2B-it-q4_0", gb(16)).is_some());
        assert!(valid_pick(&v, "gemma-4-12B-it-q4_0", gb(64)).is_none()); // unapproved
        assert!(valid_pick(&v, "nope", gb(64)).is_none());
        let c = choose(&v, Some("gemma-4-26B-A4B-it-q4_0"), gb(64)).unwrap();
        assert_eq!(c.id, "gemma-4-E4B-it-q4_0"); // bad saved pick ignored
        assert_eq!(choose(&v, Some("gemma-4-E2B-it-q4_0"), gb(64)).unwrap().id, "gemma-4-E2B-it-q4_0");
    }

    #[test]
    fn next_size_down_lists_only_approved_smaller() {
        let v = table(false);
        let top = auto_pick(&v, gb(16)).unwrap();
        let d: Vec<_> = sizes_down(&v, top, gb(16)).iter().map(|m| m.id.clone()).collect();
        assert_eq!(d, vec!["gemma-4-E2B-it-q4_0"]);
        let v2 = table(true);
        let top2 = auto_pick(&v2, gb(24)).unwrap();
        let d2: Vec<_> = sizes_down(&v2, top2, gb(24)).iter().map(|m| m.id.clone()).collect();
        assert_eq!(d2[0], "gemma-4-12B-it-q4_0");
    }

    #[test]
    fn next_size_down_skips_an_unapproved_middle_entry() {
        let mut v = table(true);
        for m in v.iter_mut() { if m.id.contains("12B") { m.approved = false; } }
        let top = auto_pick(&v, gb(24)).unwrap();
        let d: Vec<_> = sizes_down(&v, top, gb(24)).iter().map(|m| m.id.clone()).collect();
        assert_eq!(d, vec!["gemma-4-E4B-it-q4_0", "gemma-4-E2B-it-q4_0"]);
    }

    #[test]
    fn guard_refuses_below_file_plus_headroom_and_when_unknown() {
        let v = table(false);
        let m = v.iter().find(|m| m.id.contains("E4B")).unwrap();
        let need = m.size_bytes + m.headroom_gb * GIB;
        assert!(guard(m, Some(need)).is_ok());
        assert!(matches!(guard(m, Some(need - 1)), Err(ModelState::RefusedLowMemory { need_bytes, .. }) if need_bytes == need));
        assert!(matches!(guard(m, None), Err(ModelState::RefusedMemoryUnknown { .. })));
    }

    #[test]
    fn meminfo_and_vm_stat_available() {
        assert_eq!(parse_meminfo_available("MemTotal: 100 kB\nMemAvailable:    2048 kB\n"), Some(2048 * 1024));
        assert_eq!(parse_meminfo_available("MemTotal: 100 kB\n"), None);
        let vm = "Mach Virtual Memory Statistics: (page size of 16384 bytes)\nPages free:                               10.\nPages active:                             99.\nPages inactive:                           5.\nPages speculative:                        1.\n";
        assert_eq!(parse_vm_stat_available(vm), Some(16 * 16384));
        assert_eq!(parse_vm_stat_available("junk"), None);
    }

    fn tmp(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("firstrun-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn saving_a_pick_keeps_the_idle_setting() {
        let d = tmp("keepidle");
        std::fs::write(d.join("settings.json"), r#"{"model_pick":null,"idle_seconds":120}"#).unwrap();
        save_pick(&d, &table(false), "gemma-4-E2B-it-q4_0", gb(16)).unwrap();
        assert_eq!(load_settings(&d).idle_seconds(), 120);
    }

    #[test]
    fn settings_round_trip_and_refusal() {
        let d = tmp("set");
        let v = table(false);
        assert_eq!(load_settings(&d), Settings::default());
        save_pick(&d, &v, "gemma-4-E2B-it-q4_0", gb(16)).unwrap();
        assert_eq!(load_settings(&d).model_pick.as_deref(), Some("gemma-4-E2B-it-q4_0"));
        assert!(save_pick(&d, &v, "gemma-4-12B-it-q4_0", gb(64)).is_err());
        assert_eq!(load_settings(&d).model_pick.as_deref(), Some("gemma-4-E2B-it-q4_0")); // unchanged
        std::fs::write(d.join("settings.json"), "{broken").unwrap();
        assert_eq!(load_settings(&d), Settings::default());
    }

    /// A one-model manifest whose URL is unreachable, so any attempt to download fails loudly: no network.
    fn local_manifest(content: &[u8]) -> (Manifest, Model) {
        use sha2::{Digest, Sha256};
        let sha: String = Sha256::digest(content).iter().map(|b| format!("{b:02x}")).collect();
        let mut m = models::load_manifest().models.into_iter().find(|m| m.id.contains("E4B")).unwrap();
        m.source_host = "127.0.0.1:1".into();
        m.size_bytes = content.len() as u64;
        m.sha256 = sha;
        (Manifest { models: vec![m.clone()] }, m)
    }

    #[test]
    fn matching_file_is_reused_without_network() {
        let d = tmp("reuse");
        let (mf, m) = local_manifest(b"pinned bytes");
        std::fs::write(d.join(&m.file), b"pinned bytes").unwrap();
        assert_eq!(ensure_model(&mf, &m, &d).unwrap(), d.join(&m.file));
    }

    #[test]
    fn any_other_file_is_never_returned() {
        let d = tmp("other");
        let (mf, m) = local_manifest(b"pinned bytes");
        std::fs::write(d.join(&m.file), b"same size!!!").unwrap(); // wrong content, same length
        assert!(ensure_model(&mf, &m, &d).is_err()); // tries the (dead) network, never accepts the file
        std::fs::write(d.join(&m.file), b"x").unwrap();
        assert!(ensure_model(&mf, &m, &d).is_err());
    }

    #[test]
    fn prepare_refuses_on_low_memory_before_touching_disk() {
        let d = tmp("prep");
        let (mf, m) = local_manifest(b"pinned bytes");
        std::fs::write(d.join(&m.file), b"pinned bytes").unwrap();
        let r = prepare(&mf, &d, &d, Some(gb(16)), &|| Some(1));
        assert!(matches!(r, Err(ModelState::RefusedLowMemory { .. })));
        let ok = prepare(&mf, &d, &d, Some(gb(16)), &|| Some(gb(64))).unwrap();
        assert_eq!(ok.1, d.join(&m.file));
        assert!(matches!(prepare(&mf, &d, &d, None, &|| Some(gb(64))), Err(ModelState::Unavailable(_))));
        assert!(matches!(prepare(&Manifest { models: vec![] }, &d, &d, Some(gb(16)), &|| Some(gb(64))), Err(ModelState::NoApprovedFit)));
    }

    #[test]
    fn memory_is_read_again_after_the_download_step() {
        let d = tmp("recheck");
        let (mf, m) = local_manifest(b"pinned bytes");
        std::fs::write(d.join(&m.file), b"pinned bytes").unwrap();
        let calls = std::cell::Cell::new(0u32);
        let plenty_then_little = || {
            calls.set(calls.get() + 1);
            if calls.get() == 1 { Some(gb(64)) } else { Some(1) }
        };
        let r = prepare(&mf, &d, &d, Some(gb(16)), &plenty_then_little);
        assert!(matches!(r, Err(ModelState::RefusedLowMemory { .. })), "{r:?}");
        assert_eq!(calls.get(), 2);
    }

    #[test]
    fn prepare_uses_the_saved_pick() {
        let d = tmp("prepsave");
        let mut e2b = models::load_manifest().models.into_iter().find(|m| m.id.contains("E2B")).unwrap();
        let content = b"small model";
        use sha2::{Digest, Sha256};
        e2b.sha256 = Sha256::digest(content).iter().map(|b| format!("{b:02x}")).collect();
        e2b.size_bytes = content.len() as u64;
        e2b.source_host = "127.0.0.1:1".into();
        let (_, e4b) = local_manifest(b"other");
        let mf = Manifest { models: vec![e2b.clone(), e4b] };
        std::fs::write(d.join(&e2b.file), content).unwrap();
        save_pick(&d, &mf.models, &e2b.id, gb(16)).unwrap();
        assert_eq!(prepare(&mf, &d, &d, Some(gb(16)), &|| Some(gb(64))).unwrap().0.id, e2b.id);
    }

    #[test]
    fn slowness_line_branches() {
        assert_eq!(slowness_kind(Some(1), Some(2)), None, "E2B");
        assert_eq!(slowness_kind(Some(2), Some(2)), None, "E4B");
        assert_eq!(slowness_kind(Some(3), Some(2)), Some(Slowness::Specific), "above E4B");
        assert_eq!(slowness_kind(None, Some(2)), Some(Slowness::Generic), "running tier unknown");
        assert_eq!(slowness_kind(Some(1), None), Some(Slowness::Generic), "E4B tier unknown");
        let mf = crate::models::load_manifest();
        let e4b = mf.models.iter().find(|m| m.id.contains("E4B")).unwrap().tier;
        assert!(mf.models.iter().filter(|m| m.approved && !m.offer_only).all(|m| slowness_kind(Some(m.tier), Some(e4b)).is_none()), "the automatic picks are E2B and E4B; the offered larger ones DO get the slowness line (the next assert)");
        assert!(mf.models.iter().filter(|m| m.approved && m.offer_only).all(|m| slowness_kind(Some(m.tier), Some(e4b)) == Some(Slowness::Specific)), "a much larger model is honest about being slower");
    }

    #[test]
    fn ready_note_sizes_and_fallback() {
        assert_eq!(ready_note(Some(1), Some(2), false), "Model ready: Standard");
        assert_eq!(ready_note(Some(2), Some(2), true), "Modèle prêt : Standard");
        assert_eq!(ready_note(Some(3), Some(2), false), "Model ready: Larger");
        assert_eq!(ready_note(Some(4), Some(2), true), "Modèle prêt : Plus grand");
        assert_eq!(ready_note(None, Some(2), false), "Model ready.");
        assert_eq!(ready_note(Some(1), None, true), "Modèle prêt.");
        assert_eq!(slowness_kind(Some(3), Some(2)) == Some(Slowness::Specific), above_e4b(Some(3), Some(2)) == Some(true));
        let (t, e) = tiers_for("gemma-4-E4B-it-q4_0");
        assert_eq!(ready_note(t, e, false), "Model ready: Standard");
    }

    #[test]
    fn user_facing_strings_never_carry_a_model_name_or_id() {
        let mf = crate::models::load_manifest();
        let raw: serde_json::Value = serde_json::from_str(crate::models::MANIFEST_JSON).unwrap();
        let names: Vec<String> = raw["models"].as_array().unwrap().iter().filter_map(|m| m["display_name"].as_str().map(str::to_string)).collect();
        assert!(!names.is_empty());
        let all = [STATUS_RAW, include_str!("../strings/uninstall.json")];
        let mut needles: Vec<&str> = names.iter().map(|s| s.as_str()).collect();
        for m in &mf.models { needles.extend([m.id.as_str(), m.file.as_str(), m.repo.as_str()]); }
        for needle in &needles {
            for a in all { assert!(!a.contains(needle), "strings carry {needle}"); }
        }
        for fr in [false, true] {
            for (t, e) in [(Some(1), Some(2)), (Some(3), Some(2)), (None, None)] {
                let n = ready_note(t, e, fr);
                for needle in &needles { assert!(!n.contains(needle), "{n}"); }
            }
        }
    }

    #[test]
    fn sec_332_lines_exact() {
        for (k, en, fr) in [
            ("tray_open", "Open", "Ouvrir"), ("tray_quit", "Quit", "Quitter"),
            ("tray_initial", "ArrowBridge: starting", "ArrowBridge : démarrage"),
            ("note_ready", "Model ready.", "Modèle prêt."),
            ("note_services", "Background services installed", "Services d'arrière-plan installés"),
        ] {
            assert_eq!(status_line(k, false), en);
            assert_eq!(status_line(k, true), fr);
        }
        assert!(status_line("note_services_no_address", false).starts_with("Background services installed. No private network address"));
        assert!(status_line("note_services_no_address", true).ends_with("Connectez cet ordinateur à votre réseau."));
        assert!(!status_line("note_ready", false).contains("{"), "no model name");
    }

    #[test]
    fn status_lines_in_both_languages() {
        assert_eq!(status_line("note_starting", false), "Starting the model.");
        assert_eq!(status_line("note_starting", true), "Démarrage du modèle.");
        assert_eq!(status_line("tray_paired", true), "ArrowBridge : téléphone jumelé");
    }

    #[test]
    fn refusal_lines_come_from_the_strings_file_in_both_languages() {
        let low = ModelState::RefusedLowMemory { id: "m".into(), need_bytes: 2, available_bytes: 1 };
        assert_eq!(refusal_text(&low, false).unwrap(), "There is not enough free memory to load the model, so it was not started. Close other apps and try again.");
        assert_eq!(refusal_text(&low, true).unwrap(), "La mémoire libre est insuffisante pour charger le modèle, alors il n'a pas été démarré. Fermez d'autres applications et réessayez.");
        assert!(refusal_text(&ModelState::RefusedMemoryUnknown { id: "m".into() }, false).unwrap().starts_with("ArrowBridge could not check"));
        assert!(refusal_text(&ModelState::NoApprovedFit, true).unwrap().starts_with("Aucun modèle"));
        assert!(refusal_text(&ModelState::Preparing, false).is_none());
    }
}
