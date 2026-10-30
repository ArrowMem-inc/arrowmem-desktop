//! Release 11, S6: uninstall. Stops and removes the two user units, asks the packaged helper to remove the
//! firewall rule (the narrow polkit action), removes the autostart entry and the launcher entry and icon the app
//! wrote. The /usr files belong to pacman and are never touched. With purge the state dir (paired phones) and the
//! models dir are deleted too. Every step runs whatever the others did, and each is reported.

use crate::{desktop, firewall::FwOutcome, linuxrun};
use std::path::{Path, PathBuf};

const RAW: &str = include_str!("../strings/uninstall.json");

#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct Strings {
    pub confirm: String,
    pub purge_checkbox: String,
    pub purge_note: String,
    pub done_kept: String,
    pub done_purged: String,
    pub firewall_removed: String,
    pub button_uninstall: String,
    pub button_cancel: String,
    pub menu_uninstall: String,
    pub problems: String,
    pub step_units: String,
    pub step_firewall: String,
    pub step_autostart: String,
    pub step_launcher: String,
    pub step_purge_state: String,
    pub step_purge_models: String,
}

#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct AllStrings {
    pub en: Strings,
    pub fr: Strings,
}

pub fn strings() -> AllStrings {
    serde_json::from_str(RAW).expect("strings/uninstall.json is part of the build")
}

/// Substitute the two real paths into a template.
pub fn fill(t: &str, folder: &Path, model_folder: &Path) -> String {
    t.replace("<model_folder>", &model_folder.to_string_lossy()).replace("<folder>", &folder.to_string_lossy())
}

fn fill_all(s: &Strings, folder: &Path, mf: &Path) -> Strings {
    let f = |t: &String| fill(t, folder, mf);
    Strings {
        confirm: f(&s.confirm), purge_checkbox: s.purge_checkbox.clone(), purge_note: s.purge_note.clone(),
        done_kept: f(&s.done_kept), done_purged: f(&s.done_purged), firewall_removed: s.firewall_removed.clone(),
        button_uninstall: s.button_uninstall.clone(), button_cancel: s.button_cancel.clone(), menu_uninstall: s.menu_uninstall.clone(), problems: s.problems.clone(),
        step_units: s.step_units.clone(), step_firewall: s.step_firewall.clone(), step_autostart: s.step_autostart.clone(),
        step_launcher: s.step_launcher.clone(), step_purge_state: s.step_purge_state.clone(), step_purge_models: s.step_purge_models.clone(),
    }
}

/// What the confirm window shows, both languages, paths substituted.
pub fn texts(folder: &Path, model_folder: &Path) -> AllStrings {
    let s = strings();
    AllStrings { en: fill_all(&s.en, folder, model_folder), fr: fill_all(&s.fr, folder, model_folder) }
}

/// The state dir the units were written with: ARROWBRIDGE_STATE_DIR, else XDG_STATE_HOME or ~/.local/state, plus
/// "arrowbridge". Relative values are ignored.
pub fn state_dir(env_dir: Option<&str>, xdg_state: Option<&str>, home: &str) -> PathBuf {
    if let Some(d) = env_dir.filter(|d| d.starts_with('/')) {
        return PathBuf::from(d);
    }
    match xdg_state.filter(|d| d.starts_with('/')) {
        Some(x) => PathBuf::from(x).join("arrowbridge"),
        None => PathBuf::from(home).join(".local/state/arrowbridge"),
    }
}

pub struct Plan<'a> {
    pub ctl: &'a Path,
    pub unit_dir: &'a Path,
    pub pkexec: &'a Path,
    pub helper: &'a Path,
    pub autostart_dir: Option<&'a Path>,
    pub apps_dir: &'a Path,
    pub icons_dir: &'a Path,
    pub state_dir: &'a Path,
    pub model_dir: &'a Path,
    pub home: &'a Path,
    pub xdg_state: Option<&'a Path>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct Step {
    pub step: String,
    pub ok: bool,
    pub detail: String,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct Report {
    pub steps: Vec<Step>,
    pub purged: bool,
    pub firewall_rule_removed: bool,
    /// Both languages: [en, fr].
    pub message: Vec<String>,
}

impl Report {
    pub fn all_ok(&self) -> bool { self.steps.iter().all(|s| s.ok) }
}

fn step(name: &str, r: Result<String, String>) -> Step {
    match r {
        Ok(d) => Step { step: name.into(), ok: true, detail: d },
        Err(e) => Step { step: name.into(), ok: false, detail: e },
    }
}

/// A path we agree to delete recursively: absolute, deep enough, and neither the home dir nor above it.
fn deletable(p: &Path, home: &Path) -> Result<(), String> {
    if !p.is_absolute() || p.components().count() < 3 || home.starts_with(p) {
        return Err(format!("refusing to delete {}", p.display()));
    }
    Ok(())
}

fn remove_dir_if_there(p: &Path) -> Result<String, String> {
    match std::fs::remove_dir_all(p) {
        Ok(()) => Ok("deleted".into()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok("not there".into()),
        Err(e) => Err(e.to_string()),
    }
}

/// The companion's own files in the state dir (cred_store.py FILE_NAME, its mkstemp tmp files and its ".bad"
/// quarantine copy, machine_id.py FILE_NAME). The companion takes no lock file.
fn is_companion_file(n: &str) -> bool {
    n == "credentials.json" || n == "credentials.json.bad" || n == "machine_id"
        || n == crate::apikey::KEY_FILE || n == crate::apikey::ENV_FILE
        || (n.starts_with('.') && n.ends_with(".tmp") && (n[1..n.len() - 4] == *crate::apikey::KEY_FILE || n[1..n.len() - 4] == *crate::apikey::ENV_FILE)) || (n.starts_with(".credentials.") && n.ends_with(".tmp"))
}

/// Mirrors install.sh purge_state_dir: refuse a symlink or a dir not ours, require HOME or XDG_STATE_HOME, delete
/// only the companion's own regular files, then rmdir (never a recursive delete).
fn purge_state(dir: &Path, home: &Path, xdg: Option<&Path>) -> Result<String, String> {
    purge_state_as(dir, home, xdg, unsafe { libc::getuid() })
}

fn purge_state_as(dir: &Path, home: &Path, xdg: Option<&Path>, uid: u32) -> Result<String, String> {
    use std::os::unix::fs::MetadataExt;
    if !dir.is_absolute() || dir.components().any(|c| matches!(c, std::path::Component::ParentDir)) {
        return Err(format!("refusing a relative or dotted state folder: {}", dir.display()));
    }
    let md = match std::fs::symlink_metadata(dir) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok("not there".into()),
        Err(e) => return Err(e.to_string()),
    };
    if md.file_type().is_symlink() || !md.is_dir() {
        return Err(format!("refusing {}: not a plain directory (symlink or file)", dir.display()));
    }
    if md.uid() != uid {
        return Err(format!("refusing {}: not owned by this user", dir.display()));
    }
    // Under HOME or XDG_STATE_HOME, also after resolving symlinks in the parents.
    let canon = std::fs::canonicalize(dir).map_err(|e| e.to_string())?;
    let raw: Vec<&Path> = [Some(home), xdg].into_iter().flatten().collect();
    let canon_roots: Vec<PathBuf> = raw.iter().filter_map(|r| std::fs::canonicalize(r).ok()).collect();
    let lexical = raw.iter().any(|r| dir.starts_with(r) && dir != *r);
    let resolved = canon_roots.iter().any(|r| canon.starts_with(r) && canon != *r);
    if !(lexical && resolved) {
        return Err(format!("refusing {}: not under the home or state folder", dir.display()));
    }
    for e in std::fs::read_dir(dir).map_err(|e| e.to_string())?.flatten() {
        let n = e.file_name().to_string_lossy().into_owned();
        if is_companion_file(&n) && e.file_type().map(|t| t.is_file()).unwrap_or(false) {
            std::fs::remove_file(e.path()).map_err(|er| format!("{n}: {er}"))?;
        }
    }
    match std::fs::remove_dir(dir) {
        Ok(()) => Ok("deleted".into()),
        Err(e) => {
            let left: Vec<String> = std::fs::read_dir(dir).map(|r| r.flatten().map(|x| x.file_name().to_string_lossy().into_owned()).collect()).unwrap_or_default();
            Err(format!("companion files deleted; the folder was kept ({e}); left in it: {}", left.join(", ")))
        }
    }
}

fn is_model_file(n: &str) -> bool { n.ends_with(".gguf") || n.ends_with(".gguf.part") }

/// The models dir holds model files and partial downloads only (settings.json and the first-install marker live
/// in its parent). If someone pointed ARROWMEM_MODEL_DIR at a folder with other things in it, delete the model
/// files and keep the folder: the step then fails, and says what was left.
fn purge_models(dir: &Path, home: &Path) -> Result<String, String> {
    deletable(dir, home)?;
    let rd = match std::fs::read_dir(dir) {
        Ok(r) => r,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok("not there".into()),
        Err(e) => return Err(e.to_string()),
    };
    let names: Vec<(String, bool)> = rd
        .filter_map(|e| e.ok())
        .map(|e| (e.file_name().to_string_lossy().into_owned(), e.file_type().map(|t| t.is_file()).unwrap_or(false)))
        .collect();
    if names.iter().all(|(n, f)| *f && is_model_file(n)) {
        return remove_dir_if_there(dir);
    }
    let mut other = Vec::new();
    for (n, f) in &names {
        if *f && is_model_file(n) {
            std::fs::remove_file(dir.join(n)).map_err(|e| e.to_string())?;
        } else {
            other.push(n.clone());
        }
    }
    Err(format!("model files deleted; the folder also holds other things and was kept: {}", other.join(", ")))
}

pub fn run(p: &Plan, purge: bool) -> Report {
    let ur = linuxrun::uninstall_all(p.ctl, p.unit_dir, p.pkexec, p.helper);
    let mut steps = vec![
        step("units", ur.units.map(|_| "removed".to_string())),
        step("firewall", match &ur.firewall {
            Ok(FwOutcome::Done) => Ok("rule removed".into()),
            Ok(FwOutcome::NoFirewall) => Ok("no active firewall".into()),
            Ok(FwOutcome::HelperMissing) => Ok("helper not installed".into()),
            Ok(FwOutcome::Failed(c)) => Err(format!("helper exit {c}")),
            Err(e) => Err(e.clone()),
        }),
    ];
    let removed = matches!(ur.firewall, Ok(FwOutcome::Done));
    steps.push(step("autostart", match p.autostart_dir {
        Some(d) => crate::autostart::remove_autostart(d).map(|_| "removed".into()).map_err(|e| e.to_string()),
        None => Ok("no autostart dir".into()),
    }));
    steps.push(step("launcher", desktop::remove_launcher(p.apps_dir, p.icons_dir).map(|_| "removed".into()).map_err(|e| e.to_string())));
    if purge {
        steps.push(step("purge_state", purge_state(p.state_dir, p.home, p.xdg_state)));
        steps.push(step("purge_models", purge_models(p.model_dir, p.home)));
    }
    let t = texts(p.state_dir, p.model_dir);
    let mut report = Report { steps, purged: purge, firewall_rule_removed: removed, message: vec![] };
    report.message = [&t.en, &t.fr].iter().map(|s| message(&report, s)).collect();
    report
}

fn message(r: &Report, s: &Strings) -> String {
    let mut out = String::new();
    if r.all_ok() {
        out.push_str(if r.purged { &s.done_purged } else { &s.done_kept });
    } else {
        out.push_str(&s.problems);
        for st in r.steps.iter().filter(|x| !x.ok) {
            out.push('\n');
            out.push_str(match st.step.as_str() {
                "units" => &s.step_units,
                "firewall" => &s.step_firewall,
                "autostart" => &s.step_autostart,
                "launcher" => &s.step_launcher,
                "purge_state" => &s.step_purge_state,
                _ => &s.step_purge_models,
            });
        }
    }
    if r.firewall_rule_removed {
        out.push(' ');
        out.push_str(&s.firewall_removed);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn tmp(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("unin-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }
    fn exe(p: &Path, body: &str) {
        std::fs::write(p, body).unwrap();
        std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    struct W { d: PathBuf }
    impl W {
        fn new(tag: &str, pk_code: i32) -> W {
            let d = tmp(tag);
            exe(&d.join("ctl"), &format!("#!/bin/sh\ncase \"$2\" in is-active) exit 1;; esac\nexit 0\n"));
            exe(&d.join("pkexec"), &format!("#!/bin/sh\necho \"$@\" >> {}/pk.log\nexit {pk_code}\n", d.display()));
            std::fs::write(d.join("helper"), "x").unwrap();
            for s in ["fakehome/.local/state/arrowbridge", "models", "app/autostart", "app/apps", "app/icons", "units"] { std::fs::create_dir_all(d.join(s)).unwrap(); }
            let sd = d.join("fakehome/.local/state/arrowbridge");
            std::fs::write(sd.join("credentials.json"), "p").unwrap();
            std::fs::write(sd.join(crate::apikey::KEY_FILE), "k").unwrap();
            std::fs::write(sd.join(crate::apikey::ENV_FILE), "k").unwrap();
            std::fs::write(sd.join("machine_id"), "p").unwrap();
            std::fs::write(sd.join(".credentials.ab12.tmp"), "p").unwrap();
            std::fs::write(sd.join("credentials.json.bad"), "p").unwrap();
            std::fs::write(d.join("models/m.gguf"), "m").unwrap();
            std::fs::write(d.join("models/m.gguf.part"), "m").unwrap();
            std::fs::write(d.join("app/autostart").join(crate::autostart::FILE_NAME), "a").unwrap();
            std::fs::write(d.join("app/apps").join(desktop::FILE_NAME), "a").unwrap();
            std::fs::write(d.join("app/icons").join(desktop::ICON_NAME), "a").unwrap();
            W { d }
        }
        fn run(&self, purge: bool) -> Report {
            let d = &self.d;
            let (home, ctl, units, pk, helper) = (d.join("fakehome"), d.join("ctl"), d.join("units"), d.join("pkexec"), d.join("helper"));
            let (au, ap, ic, st, md) = (d.join("app/autostart"), d.join("app/apps"), d.join("app/icons"), d.join("fakehome/.local/state/arrowbridge"), d.join("models"));
            run(&Plan { ctl: &ctl, unit_dir: &units, pkexec: &pk, helper: &helper, autostart_dir: Some(&au), apps_dir: &ap, icons_dir: &ic, state_dir: &st, model_dir: &md, home: &home, xdg_state: None }, purge)
        }
    }

    #[test]
    fn purge_deletes_both_dirs_and_the_entries() {
        let w = W::new("purge", 0);
        let r = w.run(true);
        assert!(r.all_ok(), "{r:?}");
        assert!(!w.d.join("fakehome/.local/state/arrowbridge").exists(), "state {r:?}");
        assert!(!w.d.join("models").exists(), "models {r:?}");
        assert!(!w.d.join("app/autostart").join(crate::autostart::FILE_NAME).exists());
        assert!(!w.d.join("app/apps").join(desktop::FILE_NAME).exists() && !w.d.join("app/icons").join(desktop::ICON_NAME).exists());
        assert_eq!(std::fs::read_to_string(w.d.join("pk.log")).unwrap(), format!("{} remove\n", w.d.join("helper").display()));
        assert!(r.firewall_rule_removed && r.message[0].starts_with("ArrowBridge is uninstalled. Your paired phones and the downloaded model were deleted."));
        assert!(r.message[0].contains("The firewall rule was removed."));
    }

    #[test]
    fn no_purge_deletes_neither_dir() {
        let w = W::new("keep", 0);
        let r = w.run(false);
        assert!(r.all_ok(), "{r:?}");
        assert!(w.d.join("fakehome/.local/state/arrowbridge/credentials.json").exists() && w.d.join("models/m.gguf").exists());
        assert!(!w.d.join("app/autostart").join(crate::autostart::FILE_NAME).exists());
        assert!(r.steps.iter().all(|s| !s.step.starts_with("purge")));
        assert!(r.message[0].contains(&format!("kept in {}", w.d.join("fakehome/.local/state/arrowbridge").display())));
    }

    #[test]
    fn a_failed_step_is_reported_without_stopping_the_others() {
        let w = W::new("fail", 4); // helper exits 4
        let r = w.run(true);
        let fw = r.steps.iter().find(|s| s.step == "firewall").unwrap();
        assert!(!fw.ok && fw.detail == "helper exit 4");
        assert!(!r.all_ok() && !r.firewall_rule_removed);
        assert!(!w.d.join("fakehome/.local/state/arrowbridge").exists() && !w.d.join("models").exists(), "later steps still ran");
        assert!(!w.d.join("app/apps").join(desktop::FILE_NAME).exists());
        assert!(r.message[0].starts_with("The uninstall finished with problems:\nfirewall rule"));
        assert!(!r.message[0].contains("helper exit"), "step names only, no raw detail");
        assert!(r.message[1].starts_with("La désinstallation s'est terminée avec des problèmes :\nrègle de pare-feu"));
        assert!(!r.message[0].contains("were deleted"), "no success claim when a step failed");
        assert!(!r.message[0].contains("firewall rule was removed"));
    }

    #[test]
    fn missing_helper_is_not_a_prompt_and_not_a_removed_rule() {
        let w = W::new("nohelper", 0);
        std::fs::remove_file(w.d.join("helper")).unwrap();
        let r = w.run(false);
        assert!(r.all_ok() && !r.firewall_rule_removed && !w.d.join("pk.log").exists());
        assert!(!r.message[0].contains("firewall rule"));
    }

    #[test]
    fn foreign_files_in_the_models_dir_are_kept_and_reported() {
        let w = W::new("foreign", 0);
        std::fs::write(w.d.join("models/notes.txt"), "n").unwrap();
        let r = w.run(true);
        let m = r.steps.iter().find(|s| s.step == "purge_models").unwrap();
        assert!(!m.ok && m.detail.contains("notes.txt"));
        assert!(!w.d.join("models/m.gguf").exists() && w.d.join("models/notes.txt").exists());
    }

    fn sd(w: &W) -> PathBuf { w.d.join("fakehome/.local/state/arrowbridge") }

    #[test]
    fn the_purge_list_includes_the_key_files_and_a_keep_uninstall_leaves_them() {
        for n in [crate::apikey::KEY_FILE, crate::apikey::ENV_FILE, ".llama-api-key.tmp", ".upstream.env.tmp", "credentials.json", "machine_id"] {
            assert!(is_companion_file(n), "{n}");
        }
        for n in ["notes.txt", ".other.tmp", "llama-api-key.bak"] {
            assert!(!is_companion_file(n), "{n}");
        }
        let w = W::new("keyfiles", 0);
        let r = w.run(false);
        assert!(r.all_ok());
        assert!(sd(&w).join(crate::apikey::KEY_FILE).exists() && sd(&w).join(crate::apikey::ENV_FILE).exists(), "kept without purge");
        let r2 = w.run(true);
        assert!(r2.all_ok(), "{r2:?}");
        assert!(!sd(&w).exists(), "key files are deleted with purge and the folder goes with them");
    }

    #[test]
    fn a_stray_file_in_the_state_dir_survives_and_the_step_is_reported_failed() {
        let w = W::new("stray", 0);
        std::fs::write(sd(&w).join("notes.txt"), "mine").unwrap();
        let r = w.run(true);
        let st = r.steps.iter().find(|s| s.step == "purge_state").unwrap();
        assert!(!st.ok && st.detail.contains("notes.txt"), "{st:?}");
        assert!(sd(&w).join("notes.txt").exists(), "a stray file must survive");
        assert!(!sd(&w).join("credentials.json").exists() && !sd(&w).join("machine_id").exists());
        assert!(!sd(&w).join(".credentials.ab12.tmp").exists() && !sd(&w).join("credentials.json.bad").exists());
        assert!(!w.d.join("models").exists(), "later steps still ran");
        assert!(!r.message[0].contains("were deleted"));
    }

    #[test]
    fn a_symlinked_state_dir_is_refused_and_its_target_untouched() {
        let w = W::new("symlink", 0);
        let real = w.d.join("fakehome/elsewhere"); // inside home, so only the symlink rule can refuse it
        std::fs::create_dir_all(&real).unwrap();
        std::fs::write(real.join("credentials.json"), "p").unwrap();
        std::fs::remove_dir_all(sd(&w)).unwrap();
        std::os::unix::fs::symlink(&real, sd(&w)).unwrap();
        let r = w.run(true);
        let st = r.steps.iter().find(|s| s.step == "purge_state").unwrap();
        assert!(!st.ok && st.detail.contains("refusing"), "{st:?}");
        assert!(real.join("credentials.json").exists());
    }

    #[test]
    fn a_dir_not_owned_by_this_user_is_refused() {
        use std::os::unix::fs::MetadataExt;
        let w = W::new("uid", 0);
        let me = std::fs::metadata(sd(&w)).unwrap().uid();
        let home = w.d.join("fakehome");
        let e = purge_state_as(&sd(&w), &home, None, me + 1).unwrap_err();
        assert!(e.contains("not owned"), "{e}");
        assert!(sd(&w).join("credentials.json").exists());
        assert!(purge_state_as(&sd(&w), &home, None, me).is_ok());
    }

    #[test]
    fn a_symlink_named_like_a_companion_file_is_not_followed_or_removed() {
        let w = W::new("symfile", 0);
        let target = w.d.join("fakehome/precious");
        std::fs::write(&target, "x").unwrap();
        std::fs::remove_file(sd(&w).join("machine_id")).unwrap();
        std::os::unix::fs::symlink(&target, sd(&w).join("machine_id")).unwrap();
        let r = w.run(true);
        let st = r.steps.iter().find(|s| s.step == "purge_state").unwrap();
        assert!(!st.ok && st.detail.contains("machine_id"), "{st:?}");
        assert!(target.exists() && std::fs::symlink_metadata(sd(&w).join("machine_id")).is_ok());
    }

    #[test]
    fn a_state_dir_outside_home_is_refused() {
        let w = W::new("outside", 0);
        let out = w.d.join("outside/arrowbridge");
        std::fs::create_dir_all(&out).unwrap();
        std::fs::write(out.join("credentials.json"), "p").unwrap();
        let home = w.d.join("fakehome");
        let e = purge_state(&out, &home, None).unwrap_err();
        assert!(e.contains("not under"), "{e}");
        assert!(out.join("credentials.json").exists());
        // but XDG_STATE_HOME counts
        assert!(purge_state(&out, &home, Some(&w.d.join("outside"))).is_ok());
    }

    #[test]
    fn purge_refuses_home_and_shallow_paths() {
        let h = Path::new("/home/u");
        assert!(deletable(Path::new("/home/u"), h).is_err());
        assert!(deletable(Path::new("/home"), h).is_err());
        assert!(deletable(Path::new("/"), h).is_err());
        assert!(deletable(Path::new("rel/dir/x"), h).is_err());
        assert!(deletable(Path::new("/home/u/.local/state/arrowbridge"), h).is_ok());
    }

    #[test]
    fn strings_substitute_and_en_is_exact() {
        let t = texts(Path::new("/s/arrowbridge"), Path::new("/m/models"));
        assert_eq!(t.en.done_kept, "ArrowBridge is uninstalled. Your paired phones were kept in /s/arrowbridge, and the downloaded model was kept in /m/models. To remove the paired phones, delete /s/arrowbridge. To remove the downloaded model, delete /m/models.");
        assert_eq!(t.en.confirm, "This stops and removes ArrowBridge's two background services, its automatic start and its menu entry. Your paired phones are kept on this computer, in /s/arrowbridge. The downloaded model is kept too, in /m/models. While the phones are kept, phones paired before can still connect if you install ArrowBridge again.");
        assert_eq!(t.en.purge_checkbox, "Also delete all paired phones and the downloaded model");
        assert_eq!(t.en.purge_note, "Every phone must pair again, and the model must be downloaded again, if you install ArrowBridge again.");
        assert_eq!(t.en.done_purged, "ArrowBridge is uninstalled. Your paired phones and the downloaded model were deleted. Every phone must pair again if you install ArrowBridge again.");
        for s in [&t.en, &t.fr] {
            for x in [&s.confirm, &s.done_kept, &s.done_purged] {
                assert!(!x.contains('<') && !x.contains('>'), "unsubstituted token in {x}");
            }
            assert!(s.confirm.contains("/s/arrowbridge") && s.confirm.contains("/m/models"));
        }
        assert!(t.fr.done_kept.contains("/s/arrowbridge") && t.fr.done_kept.contains("/m/models"));
    }

    #[test]
    fn state_dir_precedence() {
        assert_eq!(state_dir(Some("/a/b"), Some("/x"), "/h"), PathBuf::from("/a/b"));
        assert_eq!(state_dir(Some("rel"), Some("/x"), "/h"), PathBuf::from("/x/arrowbridge"));
        assert_eq!(state_dir(None, None, "/h"), PathBuf::from("/h/.local/state/arrowbridge"));
    }
}
