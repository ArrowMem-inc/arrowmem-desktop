//! Linux systemd USER units (release 11, S1). The app writes and manages two units instead of supervising
//! children, so both survive the window closing. Pure render functions; systemctl is called with argv only,
//! never through a shell, and its path is a parameter so tests inject a fake.
//! No key or secret ever enters a unit: the companion manages its pair key as a file in its state dir.

use std::path::{Path, PathBuf};
use std::process::Command;

pub const BRIDGE_UNIT: &str = "ca.arrowmem.arrowbridge.service";
pub const LLAMA_UNIT: &str = "ca.arrowmem.llama.service";

/// Only [A-Za-z0-9/._-], absolute, no `..` segment. Nothing else can reach a unit file.
pub fn safe_path(p: &Path) -> Result<String, String> {
    let s = p.to_str().ok_or("path is not UTF-8")?;
    let ok = s.starts_with('/')
        && !s.is_empty()
        && s.chars().all(|c| c.is_ascii_alphanumeric() || "/._-".contains(c))
        && !s.split('/').any(|seg| seg == "..");
    if ok { Ok(s.to_string()) } else { Err(format!("unsafe path refused: {s}")) }
}

/// RFC1918 IPv4 only (the `--lan` rule: never 0.0.0.0, never public). A leading zero is refused (bind may read
/// it as octal); the canonical form is built from the parsed bytes.
pub fn private_lan_ip(ip: &str) -> Result<String, String> {
    let bad = || format!("not a private LAN IPv4: {ip}");
    let parts: Vec<&str> = ip.split('.').collect();
    if parts.len() != 4 { return Err(bad()); }
    let mut o = [0u8; 4];
    for (i, p) in parts.iter().enumerate() {
        if p.is_empty() || p.len() > 3 || !p.bytes().all(|b| b.is_ascii_digit()) || (p.len() > 1 && p.starts_with('0')) {
            return Err(bad());
        }
        o[i] = p.parse::<u8>().map_err(|_| bad())?;
    }
    let private = o[0] == 10 || (o[0] == 172 && (16..=31).contains(&o[1])) || (o[0] == 192 && o[1] == 168);
    if private { Ok(format!("{}.{}.{}.{}", o[0], o[1], o[2], o[3])) } else { Err(bad()) }
}

pub struct BridgeUnit<'a> {
    pub companion_bin: &'a Path,
    pub state_dir: &'a Path,
    pub lan_ip: &'a str,
    pub port: u16,
    /// The loopback port of the model server (chosen at start, never a fixed 8080: another program may hold it).
    pub llama_port: u16,
    /// The model name the model server answers to (its --alias, from [`model_alias`]); the companion asks for exactly this name and lists it to the phone.
    pub upstream_model: &'a str,
}

pub struct LlamaUnit<'a> {
    pub llama_bin: &'a Path,
    pub model: &'a Path,
    pub port: u16,
    pub idle_seconds: u32,
    /// The 0600 file llama-server reads its API key from. Only the path is ever in the unit.
    pub key_file: &'a Path,
}

/// The name the model server answers to and the phone is shown: the model file name without its folder and ".gguf", reduced to letters, digits, dot, dash and underscore
/// (so it is safe in a unit file and never carries a folder name, which for a model found on this computer could be the owner's own).
pub fn model_alias(model: &Path) -> String {
    let stem = model.file_name().map(|f| f.to_string_lossy().into_owned()).unwrap_or_default();
    let stem = stem.strip_suffix(".gguf").unwrap_or(&stem);
    let a: String = stem.chars().map(|c| if c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_' { c } else { '-' }).take(60).collect();
    if a.is_empty() { "model".into() } else { a }
}

pub fn render_bridge(u: &BridgeUnit) -> Result<String, String> {
    let bin = safe_path(u.companion_bin)?;
    let state = safe_path(u.state_dir)?;
    let ip = private_lan_ip(u.lan_ip)?;
    if u.upstream_model.is_empty() || !u.upstream_model.bytes().all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b)) { return Err("unsafe model name".into()); }
    Ok(format!(
"[Unit]
Description=ArrowBridge companion
After=ca.arrowmem.llama.service
# A port still held (the old copy during an upgrade, or TIME-WAIT sockets of the window's polls: the companion binds without SO_REUSEADDR) made five restarts in a second trip the default start limit and left it dead (0.1.0-4 finding, 19:04; again 20:3x): a pause between tries and about 96 s of them, longer than the 60 s TIME-WAIT.
StartLimitIntervalSec=300
StartLimitBurst=12

[Service]
ExecStart={bin}
Environment=ARROWBRIDGE_BIND={ip}
Environment=ARROWBRIDGE_PORT={port}
Environment=ARROWBRIDGE_STATE_DIR={state}
Environment=ARROWBRIDGE_UPSTREAM_URL=http://127.0.0.1:{llama_port}
Environment=ARROWBRIDGE_UPSTREAM_MODEL={upstream_model}
EnvironmentFile={state}/upstream.env
Restart=on-failure
RestartSec=8
NoNewPrivileges=yes
MemoryDenyWriteExecute=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=read-only
ReadWritePaths={state}
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
RestrictNamespaces=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
LockPersonality=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
SystemCallArchitectures=native
UMask=0077

[Install]
WantedBy=default.target
", port = u.port, llama_port = u.llama_port, upstream_model = u.upstream_model))
}

pub fn render_llama(u: &LlamaUnit) -> Result<String, String> {
    let bin = safe_path(u.llama_bin)?;
    let model = safe_path(u.model)?;
    let key_file = safe_path(u.key_file)?;
    let alias = model_alias(u.model);
    Ok(format!(
"[Unit]
Description=ArrowMem local model (llama-server, loopback only)
# No model file yet (the download is not done, was refused, or this computer is too small): systemd skips the start quietly, inactive and not failed, so no restart loop
# and no start limit (the Victus finding). The app starts the unit when the verified file is there.
ConditionPathExists={model}
StartLimitIntervalSec=300
StartLimitBurst=3

[Service]
ExecStart={bin} --host 127.0.0.1 --port {port} --alias {alias} --models-max 1 --sleep-idle-seconds {idle} --api-key-file {key_file} --no-webui --cors-origins localhost --no-cors-credentials -m {model}
Restart=on-failure
RestartSec=30
NoNewPrivileges=yes
# MemoryDenyWriteExecute is deliberately NOT set on this unit: the Vulkan and CPU builds of llama-server
# may need writable+executable memory (JIT / driver). The companion unit does set it.
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=read-only
IPAddressDeny=any
IPAddressAllow=localhost
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
RestrictSUIDSGID=yes
LockPersonality=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
UMask=0077

[Install]
WantedBy=default.target
", port = u.port, idle = u.idle_seconds, key_file = key_file, alias = alias))
}

pub fn unit_dir(xdg_config_home: Option<&str>, home: &str) -> PathBuf {
    match xdg_config_home {
        Some(x) if x.starts_with('/') => PathBuf::from(x).join("systemd/user"),
        _ => PathBuf::from(home).join(".config/systemd/user"),
    }
}

fn systemctl(bin: &Path, args: &[&str]) -> Result<std::process::Output, String> {
    let mut a = vec!["--user"];
    a.extend_from_slice(args);
    Command::new(bin).args(&a).output().map_err(|e| format!("systemctl: {e}"))
}

fn must(bin: &Path, args: &[&str]) -> Result<(), String> {
    let o = systemctl(bin, args)?;
    if o.status.success() { Ok(()) } else { Err(format!("systemctl {} failed", args.join(" "))) }
}

fn write_unit(dir: &Path, name: &str, text: &str) -> Result<(), String> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
    let p = dir.join(name);
    let mut f = std::fs::OpenOptions::new().write(true).create(true).truncate(true).mode(0o644)
        .open(&p).map_err(|e| e.to_string())?;
    f.write_all(text.as_bytes()).map_err(|e| e.to_string())?;
    // mode() only applies on create; force it on an existing file too.
    std::fs::set_permissions(&p, std::os::unix::fs::PermissionsExt::from_mode(0o644)).map_err(|e| e.to_string())
}

/// Write only when the content differs from what is on disk (or the file is absent). Returns whether it wrote.
pub fn write_if_changed(dir: &Path, name: &str, text: &str) -> Result<bool, String> {
    if std::fs::read_to_string(dir.join(name)).map(|c| c == text).unwrap_or(false) {
        return Ok(false);
    }
    write_unit(dir, name, text)?;
    Ok(true)
}

/// `systemctl --user show` for the few properties that say whether a unit failed. Output is key=value lines.
pub fn show(bin: &Path, unit: &str) -> Result<String, String> {
    let o = systemctl(bin, &["show", "-p", "ActiveState", "-p", "SubState", "-p", "NRestarts", "-p", "Result", unit])?;
    if o.status.success() { Ok(String::from_utf8_lossy(&o.stdout).into_owned()) } else { Err("systemctl show failed".into()) }
}

/// `systemctl --user <args>` with the same argv-only rule; Ok on exit 0.
pub fn ctl(bin: &Path, args: &[&str]) -> Result<(), String> {
    must(bin, args)
}

/// Write both units, daemon-reload, enable --now (llama first).
pub fn install(systemctl_bin: &Path, dir: &Path, bridge: &BridgeUnit, llama: &LlamaUnit) -> Result<(), String> {
    let (b, l) = (render_bridge(bridge)?, render_llama(llama)?); // refuse before touching disk
    write_unit(dir, LLAMA_UNIT, &l)?;
    write_unit(dir, BRIDGE_UNIT, &b)?;
    must(systemctl_bin, &["daemon-reload"])?;
    must(systemctl_bin, &["enable", "--now", LLAMA_UNIT])?;
    if let Err(e) = must(systemctl_bin, &["enable", "--now", BRIDGE_UNIT]) {
        // Roll back: leave nothing half-installed.
        let _ = systemctl(systemctl_bin, &["disable", "--now", LLAMA_UNIT]);
        let _ = std::fs::remove_file(dir.join(LLAMA_UNIT));
        let _ = std::fs::remove_file(dir.join(BRIDGE_UNIT));
        let _ = systemctl(systemctl_bin, &["daemon-reload"]);
        return Err(e);
    }
    Ok(())
}

/// One property of a unit (`systemctl --user show -p <prop> --value <unit>`), trimmed. None when the call fails.
pub fn property(bin: &Path, unit: &str, prop: &str) -> Option<String> {
    let o = systemctl(bin, &["show", "-p", prop, "--value", unit]).ok()?;
    if o.status.success() { Some(String::from_utf8_lossy(&o.stdout).trim().to_string()) } else { None }
}

/// The unit stopped for good (a tripped start limit stays `failed` until reset-failed).
pub fn is_failed(bin: &Path, unit: &str) -> bool {
    property(bin, unit, "ActiveState").as_deref() == Some("failed")
}

/// What /proc/<pid>/exe says about a program whose file was replaced while it ran (a package upgrade writes a new file and unlinks the old one).
pub fn exe_deleted(link: &str) -> bool {
    link.ends_with(" (deleted)")
}

/// True when the process is running a program file that no longer exists on disk. `proc_root` is /proc (a folder of fake processes in the tests).
pub fn pid_runs_deleted_exe(proc_root: &Path, pid: u32) -> bool {
    std::fs::read_link(proc_root.join(pid.to_string()).join("exe")).map(|l| exe_deleted(&l.to_string_lossy())).unwrap_or(false)
}

/// A RUNNING unit whose main process runs a replaced program file: it must be restarted to run the new one (an upgrade). False when it cannot be told.
pub fn runs_replaced_binary(bin: &Path, unit: &str) -> bool {
    match property(bin, unit, "MainPID").and_then(|s| s.parse::<u32>().ok()).filter(|p| *p > 0) {
        Some(pid) => pid_runs_deleted_exe(Path::new("/proc"), pid),
        None => false,
    }
}

/// is-active for one unit: true only on exit 0.
pub fn status(systemctl_bin: &Path, unit: &str) -> bool {
    systemctl(systemctl_bin, &["is-active", "--quiet", unit]).map(|o| o.status.success()).unwrap_or(false)
}

/// disable --now both, remove the files, daemon-reload. Missing files are fine.
pub fn uninstall(systemctl_bin: &Path, dir: &Path) -> Result<(), String> {
    for u in [BRIDGE_UNIT, LLAMA_UNIT] {
        let _ = systemctl(systemctl_bin, &["disable", "--now", u]);
        if status(systemctl_bin, u) {
            let _ = systemctl(systemctl_bin, &["stop", u]);
            if status(systemctl_bin, u) {
                // Still running: keep the file so the unit stays manageable.
                return Err(format!("{u} is still active after disable and stop"));
            }
        }
        match std::fs::remove_file(dir.join(u)) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.to_string()),
        }
    }
    must(systemctl_bin, &["daemon-reload"])
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn bridge() -> BridgeUnit<'static> {
        BridgeUnit { companion_bin: Path::new("/opt/am/arrowbridge-companion"), state_dir: Path::new("/home/u/.local/state/arrowbridge"), lan_ip: "192.168.1.20", port: 8788, llama_port: 8080, upstream_model: "e4b" }
    }
    fn llama() -> LlamaUnit<'static> {
        LlamaUnit { llama_bin: Path::new("/opt/am/llama-server"), model: Path::new("/home/u/m/e4b.gguf"), port: 8080, idle_seconds: 600, key_file: Path::new("/home/u/.local/state/arrowbridge/llama-api-key") }
    }
    fn tmp(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("userunit-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }
    /// A fake systemctl that logs argv. State files in `d`: `failon` (exit 1 when args contain its text),
    /// `stuck` (disable and stop do not deactivate), `inactive` (set by disable/stop, cleared by enable).
    fn fake(d: &Path) -> PathBuf {
        let p = d.join("fakectl");
        let dd = d.display();
        std::fs::write(&p, format!("#!/bin/sh\necho \"$@\" >> {dd}/calls.log\nif [ -f {dd}/failon ] && echo \"$@\" | grep -q -- \"$(cat {dd}/failon)\"; then exit 1; fi\ncase \"$2\" in\n disable|stop) [ -f {dd}/stuck ] || touch {dd}/inactive;;\n enable) rm -f {dd}/inactive;;\n is-active) [ -f {dd}/inactive ] && exit 1;;\nesac\nexit 0\n")).unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
        p
    }

    #[test]
    fn bridge_text_has_hardening_env_and_no_secret() {
        let t = render_bridge(&bridge()).unwrap();
        for l in ["StartLimitIntervalSec=300", "StartLimitBurst=12", "RestartSec=8", "MemoryDenyWriteExecute=yes", "NoNewPrivileges=yes", "ProtectSystem=strict", "ReadWritePaths=/home/u/.local/state/arrowbridge",
                  "Environment=ARROWBRIDGE_UPSTREAM_URL=http://127.0.0.1:8080", "Environment=ARROWBRIDGE_UPSTREAM_MODEL=e4b",
                  "Environment=ARROWBRIDGE_PORT=8788", "EnvironmentFile=/home/u/.local/state/arrowbridge/upstream.env", "Environment=ARROWBRIDGE_BIND=192.168.1.20", "WantedBy=default.target"] {
            assert!(t.lines().any(|x| x == l), "missing {l}");
        }
        assert!(!t.to_uppercase().contains("PAIR_KEY") && !t.contains("0.0.0.0"));
    }

    #[test]
    fn llama_text_loopback_only_and_no_mdwe() {
        let t = render_llama(&llama()).unwrap();
        assert!(t.lines().any(|x| x == "ExecStart=/opt/am/llama-server --host 127.0.0.1 --port 8080 --alias e4b --models-max 1 --sleep-idle-seconds 600 --api-key-file /home/u/.local/state/arrowbridge/llama-api-key --no-webui --cors-origins localhost --no-cors-credentials -m /home/u/m/e4b.gguf"));
        assert!(!t.lines().any(|x| x.starts_with("MemoryDenyWriteExecute")));
        assert!(t.contains("deliberately NOT set"));
        assert!(!t.contains("0.0.0.0"));
        for l in ["ConditionPathExists=/home/u/m/e4b.gguf", "StartLimitIntervalSec=300", "StartLimitBurst=3", "RestartSec=30", "IPAddressDeny=any", "IPAddressAllow=localhost", "RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX"] {
            assert!(t.lines().any(|x| x == l), "missing {l}");
        }
    }

    #[test]
    fn unsafe_paths_refused() {
        for bad in ["/opt/a b/x", "/opt/a;rm", "rel/x", "/opt/$HOME/x", "/opt/../x", "/opt/\u{e9}/x", "/opt/a\nb"] {
            assert!(safe_path(Path::new(bad)).is_err(), "{bad}");
        }
        assert!(safe_path(Path::new("/a/B-c_d.e/9")).is_ok());
        let mut b = bridge();
        b.state_dir = Path::new("/x y");
        assert!(render_bridge(&b).is_err());
        let mut l = llama();
        l.model = Path::new("/m/a\"b.gguf");
        assert!(render_llama(&l).is_err());
    }

    #[test]
    fn lan_ip_must_be_private() {
        for ok in ["10.0.0.5", "172.16.0.1", "172.31.9.9", "192.168.0.1"] { assert!(private_lan_ip(ok).is_ok(), "{ok}"); }
        for bad in ["010.0.0.1", "192.168.01.1", "10.00.0.1", "0.0.0.0", "127.0.0.1", "8.8.8.8", "172.32.0.1", "172.15.0.1", "192.169.0.1", "10.0.0", "10.0.0.256", "a.b.c.d", "10.0.0.1\nx", ""] {
            assert!(private_lan_ip(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn unit_dir_prefers_xdg() {
        assert_eq!(unit_dir(Some("/x/cfg"), "/h"), PathBuf::from("/x/cfg/systemd/user"));
        assert_eq!(unit_dir(None, "/h"), PathBuf::from("/h/.config/systemd/user"));
        assert_eq!(unit_dir(Some("rel"), "/h"), PathBuf::from("/h/.config/systemd/user"));
    }

    #[test]
    fn install_writes_0644_and_calls_argv_in_order() {
        let d = tmp("inst");
        let ctl = fake(&d);
        let dir = d.join("cfg/systemd/user");
        install(&ctl, &dir, &bridge(), &llama()).unwrap();
        for n in [BRIDGE_UNIT, LLAMA_UNIT] {
            let m = std::fs::metadata(dir.join(n)).unwrap().permissions().mode() & 0o777;
            assert_eq!(m, 0o644, "{n}");
        }
        let log = std::fs::read_to_string(d.join("calls.log")).unwrap();
        let want = format!("--user daemon-reload\n--user enable --now {LLAMA_UNIT}\n--user enable --now {BRIDGE_UNIT}\n");
        assert_eq!(log, want);
    }

    #[test]
    fn install_refuses_before_touching_disk() {
        let d = tmp("refuse");
        let ctl = fake(&d);
        let dir = d.join("u");
        let mut b = bridge();
        b.lan_ip = "8.8.8.8";
        assert!(install(&ctl, &dir, &b, &llama()).is_err());
        assert!(!dir.exists());
        assert!(!d.join("calls.log").exists());
    }

    #[test]
    fn install_reports_systemctl_failure() {
        let d = tmp("fail");
        let ctl = fake(&d);
        std::fs::write(d.join("failon"), "enable").unwrap();
        assert!(install(&ctl, &d.join("u"), &bridge(), &llama()).is_err());
    }

    #[test]
    fn status_follows_exit_code_and_missing_binary_is_inactive() {
        let d = tmp("stat");
        let ctl = fake(&d);
        assert!(status(&ctl, BRIDGE_UNIT));
        std::fs::write(d.join("failon"), "is-active").unwrap();
        assert!(!status(&ctl, BRIDGE_UNIT));
        assert!(!status(Path::new("/nonexistent/systemctl"), BRIDGE_UNIT));
    }

    #[test]
    fn uninstall_disables_removes_and_reloads() {
        let d = tmp("un");
        let ctl = fake(&d);
        let dir = d.join("u");
        install(&ctl, &dir, &bridge(), &llama()).unwrap();
        std::fs::remove_file(d.join("calls.log")).unwrap();
        uninstall(&ctl, &dir).unwrap();
        assert!(!dir.join(BRIDGE_UNIT).exists() && !dir.join(LLAMA_UNIT).exists());
        let log = std::fs::read_to_string(d.join("calls.log")).unwrap();
        assert_eq!(log, format!("--user disable --now {BRIDGE_UNIT}\n--user is-active --quiet {BRIDGE_UNIT}\n--user disable --now {LLAMA_UNIT}\n--user is-active --quiet {LLAMA_UNIT}\n--user daemon-reload\n"));
        uninstall(&ctl, &dir).unwrap(); // idempotent
    }

    #[test]
    fn lan_ip_returned_canonical() {
        assert_eq!(private_lan_ip("192.168.1.20").unwrap(), "192.168.1.20");
    }

    #[test]
    fn uninstall_stuck_unit_errs_and_keeps_files() {
        let d = tmp("stuck");
        let ctl = fake(&d);
        let dir = d.join("u");
        install(&ctl, &dir, &bridge(), &llama()).unwrap();
        std::fs::write(d.join("stuck"), "").unwrap();
        std::fs::remove_file(d.join("calls.log")).unwrap();
        assert!(uninstall(&ctl, &dir).is_err());
        assert!(dir.join(BRIDGE_UNIT).exists() && dir.join(LLAMA_UNIT).exists());
        let log = std::fs::read_to_string(d.join("calls.log")).unwrap();
        assert!(log.contains(&format!("--user stop {BRIDGE_UNIT}")));
    }

    #[test]
    fn uninstall_disable_fails_but_stop_works_still_removes() {
        let d = tmp("stopok");
        let ctl = fake(&d);
        let dir = d.join("u");
        install(&ctl, &dir, &bridge(), &llama()).unwrap();
        std::fs::write(d.join("failon"), "disable").unwrap(); // disable exits 1 and does not deactivate
        assert!(uninstall(&ctl, &dir).is_ok());
        assert!(!dir.join(BRIDGE_UNIT).exists());
        let log = std::fs::read_to_string(d.join("calls.log")).unwrap();
        assert!(log.contains(&format!("--user stop {BRIDGE_UNIT}")));
    }

    #[test]
    fn install_rolls_back_when_second_enable_fails() {
        let d = tmp("rb");
        let ctl = fake(&d);
        let dir = d.join("u");
        std::fs::write(d.join("failon"), format!("enable --now {BRIDGE_UNIT}")).unwrap();
        assert!(install(&ctl, &dir, &bridge(), &llama()).is_err());
        assert!(!dir.join(BRIDGE_UNIT).exists() && !dir.join(LLAMA_UNIT).exists());
        let log = std::fs::read_to_string(d.join("calls.log")).unwrap();
        assert!(log.contains(&format!("--user disable --now {LLAMA_UNIT}")));
    }

    #[test]
    fn exe_deleted_reads_the_proc_suffix_only() {
        assert!(exe_deleted("/usr/lib/arrowmem/arrowbridge-companion (deleted)"));
        assert!(!exe_deleted("/usr/lib/arrowmem/arrowbridge-companion"));
        assert!(!exe_deleted("/x/(deleted)/y"));
    }

    #[test]
    fn a_process_running_a_replaced_file_is_found_through_proc() {
        let d = std::env::temp_dir().join(format!("userunit-proc-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(d.join("4242")).unwrap();
        std::fs::create_dir_all(d.join("4343")).unwrap();
        std::os::unix::fs::symlink("/usr/lib/arrowmem/arrowbridge-companion (deleted)", d.join("4242/exe")).unwrap();
        std::os::unix::fs::symlink("/usr/lib/arrowmem/arrowbridge-companion", d.join("4343/exe")).unwrap();
        assert!(pid_runs_deleted_exe(&d, 4242));
        assert!(!pid_runs_deleted_exe(&d, 4343));
        assert!(!pid_runs_deleted_exe(&d, 9999), "no such process: not stale");
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn the_model_alias_is_the_file_name_without_folder_or_extension_and_safe_in_a_unit() {
        assert_eq!(model_alias(Path::new("/home/someone/.local/share/x/models/gemma-4-E4B_q4_0-it.gguf")), "gemma-4-E4B_q4_0-it", "no folder, no .gguf");
        assert_eq!(model_alias(Path::new("/m/My Model (v2).gguf")), "My-Model--v2-", "spaces and brackets cannot reach a unit file");
        assert_eq!(model_alias(Path::new("/m/a\nb=c.gguf")), "a-b-c");
        assert_eq!(model_alias(Path::new("/")), "model");
        assert_eq!(model_alias(Path::new(&format!("/m/{}.gguf", "x".repeat(200)))).len(), 60);
        let mut b = bridge();
        b.upstream_model = "bad name";
        assert!(render_bridge(&b).is_err(), "an unsafe model name never reaches the companion unit");
    }
}
