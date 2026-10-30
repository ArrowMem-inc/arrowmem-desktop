//! Linux run path (release 11, S1 wiring): at app start, install or refresh the two systemd user units and
//! report health with is-active. Pure and testable on any unix; only the getifaddrs call is OS-specific.
//! No child supervision happens here.

use crate::userunit::{self, BridgeUnit, LlamaUnit, BRIDGE_UNIT, LLAMA_UNIT};
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};

/// The old fixed port. Only the default of the tests now: the real port is chosen by [`choose_llama_port`].
pub const LLAMA_PORT: u16 = 8080;
/// An unusual fixed first choice and a short range after it (another program, often a dev server, may hold the common ports: his Victus had 8080 taken).
const PORT_FIRST: u16 = 41717;
const PORT_LAST: u16 = 41747;

fn loopback_free(port: u16) -> bool { std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, port)).is_ok() }

/// The loopback port for the model server, kept across starts so the unit text does not change: the saved one while it is still ours or free, else the first free
/// one from an unusual range; saved back. `ours` says the model unit is running (then its own port is not "taken"). Pure apart from the bind test and the file.
pub fn choose_llama_port(settings_dir: &Path, ours: bool, free: &dyn Fn(u16) -> bool) -> u16 {
    let mut s = crate::firstrun::load_settings(settings_dir);
    if let Some(p) = s.llama_port {
        if p >= 1024 && (ours || free(p)) { return p; }
    }
    let p = (PORT_FIRST..=PORT_LAST).find(|p| free(*p)).unwrap_or(PORT_FIRST);
    s.llama_port = Some(p);
    let _ = std::fs::create_dir_all(settings_dir).and_then(|_| std::fs::write(settings_dir.join("settings.json"), serde_json::to_string(&s).unwrap_or_default()));
    p
}

/// The real thing: bind-test on this machine, and whether the model unit is running now.
pub fn pick_llama_port(settings_dir: &Path, ctl: &Path) -> u16 {
    choose_llama_port(settings_dir, userunit::status(ctl, LLAMA_UNIT), &loopback_free)
}

/// What the status window reads. Recorded, not worded: any text for these is written separately.
#[derive(Debug, Clone, PartialEq)]
pub enum LanState {
    /// Bridge unit installed, bound to this private address.
    Lan(Ipv4Addr),
    /// No private IPv4 found: only the llama unit is installed.
    NoPrivateAddress,
}

/// One IPv4 interface address.
#[derive(Debug, Clone, PartialEq)]
pub struct Iface {
    pub name: String,
    pub ip: Ipv4Addr,
    pub mask: Ipv4Addr,
}

/// Container, VM-bridge and overlay interfaces are never the home network.
const SKIP_PREFIXES: [&str; 9] = ["docker", "virbr", "br-", "veth", "tailscale", "tun", "wg", "ppp", "zt"];

/// The LAN interface address: a private IPv4 on the default-route interface if there is one, else the first
/// private IPv4 on any interface that is not a container, bridge or overlay.
pub fn pick_lan<'a>(ifaces: &'a [Iface], default_if: Option<&str>) -> Option<&'a Iface> {
    let ok = |i: &&Iface| userunit::private_lan_ip(&i.ip.to_string()).is_ok() && !SKIP_PREFIXES.iter().any(|p| i.name.starts_with(p));
    default_if
        .and_then(|d| ifaces.iter().filter(ok).find(|i| i.name == d))
        .or_else(|| ifaces.iter().filter(ok).next())
}

/// Default-route interface from /proc/net/route text: destination and mask 0, UP and GATEWAY flags, lowest metric.
pub fn default_route_iface(table: &str) -> Option<String> {
    table
        .lines()
        .skip(1)
        .filter_map(|l| {
            let f: Vec<&str> = l.split_whitespace().collect();
            if f.len() < 8 || f[1] != "00000000" || f[7] != "00000000" {
                return None;
            }
            let flags = u32::from_str_radix(f[3], 16).ok()?;
            if flags & 0x3 != 0x3 {
                return None;
            }
            Some((f[6].parse::<u32>().ok()?, f[0].to_string()))
        })
        .min_by_key(|(metric, _)| *metric)
        .map(|(_, name)| name)
}

/// Reads the route table at `path` (injectable); None when unreadable.
pub fn default_iface(path: &Path) -> Option<String> {
    default_route_iface(&std::fs::read_to_string(path).ok()?)
}

/// IPv4 address and netmask of every interface.
#[cfg(unix)]
pub fn list_ipv4() -> Vec<Iface> {
    let mut out = Vec::new();
    unsafe {
        let mut head: *mut libc::ifaddrs = std::ptr::null_mut();
        if libc::getifaddrs(&mut head) != 0 {
            return out;
        }
        let mut cur = head;
        while !cur.is_null() {
            let (a, m) = ((*cur).ifa_addr, (*cur).ifa_netmask);
            if !a.is_null() && !m.is_null() && (*a).sa_family as i32 == libc::AF_INET && (*m).sa_family as i32 == libc::AF_INET {
                let ip = u32::from_be((*(a as *const libc::sockaddr_in)).sin_addr.s_addr);
                let mk = u32::from_be((*(m as *const libc::sockaddr_in)).sin_addr.s_addr);
                let name = std::ffi::CStr::from_ptr((*cur).ifa_name).to_string_lossy().into_owned();
                out.push(Iface { name, ip: Ipv4Addr::from(ip), mask: Ipv4Addr::from(mk) });
            }
            cur = (*cur).ifa_next;
        }
        libc::freeifaddrs(head);
    }
    out
}

pub struct Paths<'a> {
    pub companion_bin: &'a Path,
    pub state_dir: &'a Path,
    pub llama_bin: &'a Path,
    pub model: &'a Path,
    pub idle_seconds: u32,
    /// The loopback port the model server listens on (from the launcher).
    pub llama_port: u16,
}

/// Returns whether the unit was started or restarted by this call.
/// Three things that left the companion dead or stale after an upgrade (the 0.1.0-2 to 0.1.0-4 finding): a unit that
/// tripped its start limit stays failed until reset-failed, so it is reset first; a running unit whose program file was
/// replaced by the package is restarted to run the new one; a changed unit text restarts as before.
fn apply(ctl: &Path, dir: &Path, name: &str, text: &str, reload_needed: &mut bool) -> Result<bool, String> {
    let changed = userunit::write_if_changed(dir, name, text)?;
    if changed {
        *reload_needed = true;
        userunit::ctl(ctl, &["daemon-reload"])?;
    }
    if userunit::is_failed(ctl, name) {
        let _ = userunit::ctl(ctl, &["reset-failed", name]);
    }
    if !userunit::status(ctl, name) {
        userunit::ctl(ctl, &["enable", "--now", name]).map(|_| true)
    } else if changed || userunit::runs_replaced_binary(ctl, name) {
        userunit::ctl(ctl, &["restart", name]).map(|_| true)
    } else {
        Ok(false)
    }
}

/// What the window should do about a companion that does not answer (the service heals itself, silently; the card shows only when
/// restarts truly fail). Pure: the caller says whether the companion answered and what time it is.
#[derive(Debug, Default)]
pub struct Heal {
    attempts: u32,
    last: Option<std::time::Instant>,
}

#[derive(Debug, PartialEq, Clone, Copy)]
pub enum HealStep {
    /// The companion answers: nothing to do (and the count starts again).
    Up,
    /// It does not answer and a restart should be made NOW (the caller runs [`recover`]).
    Attempt,
    /// It does not answer and a restart was made a moment ago: the window shows "restarting", not a failure.
    Waiting,
    /// Three restarts, each given time to work, and it still does not answer: only now does the window show the down card.
    Failed,
}

impl Heal {
    pub const MAX_ATTEMPTS: u32 = 3;
    pub const GAP: std::time::Duration = std::time::Duration::from_secs(20);

    pub fn step(&mut self, up: bool, now: std::time::Instant) -> HealStep {
        if up {
            *self = Heal::default();
            return HealStep::Up;
        }
        let waited = self.last.map(|t| now.saturating_duration_since(t) >= Self::GAP);
        match waited {
            None => self.attempt(now),
            Some(true) if self.attempts < Self::MAX_ATTEMPTS => self.attempt(now),
            Some(true) => HealStep::Failed,
            Some(false) => HealStep::Waiting,
        }
    }

    fn attempt(&mut self, now: std::time::Instant) -> HealStep {
        self.attempts += 1;
        self.last = Some(now);
        HealStep::Attempt
    }

    /// The person chose Restart: the count starts over so the card can go away again.
    pub fn reset(&mut self) { *self = Heal::default(); }
}

/// The window's Restart button: clear a failed state and restart both units (the companion needs the model server up, so the model server first).
/// Both are attempted whatever the first did; the answer is whether the companion unit came back.
pub fn recover(ctl: &Path) -> bool {
    for name in [LLAMA_UNIT, BRIDGE_UNIT] {
        let _ = userunit::ctl(ctl, &["reset-failed", name]);
        let _ = userunit::ctl(ctl, &["restart", name]);
    }
    userunit::status(ctl, BRIDGE_UNIT)
}

/// A unit already running with the old key is restarted after a rotation, unless this call already (re)started it.
fn restart_for_new_key(ctl: &Path, name: &str, restarted: bool) -> Result<(), String> {
    if restarted { Ok(()) } else { userunit::ctl(ctl, &["restart", name]) }
}

/// Install or refresh. A unit file is rewritten (and an active unit restarted) only when its text changed;
/// an unchanged, active unit gets no systemctl call beyond is-active.
pub fn sync(ctl: &Path, dir: &Path, p: &Paths, lan: Option<Ipv4Addr>) -> Result<LanState, String> {
    let key_file = p.state_dir.join(crate::apikey::KEY_FILE);
    let llama = userunit::render_llama(&LlamaUnit { llama_bin: p.llama_bin, model: p.model, port: p.llama_port, idle_seconds: p.idle_seconds, key_file: &key_file })?;
    let alias = userunit::model_alias(p.model);
    let bridge = match lan {
        Some(ip) => Some(userunit::render_bridge(&BridgeUnit {
            companion_bin: p.companion_bin,
            state_dir: p.state_dir,
            lan_ip: &ip.to_string(),
            port: 8788,
            llama_port: p.llama_port,
            upstream_model: &alias,
        })?),
        None => None,
    };
    std::fs::create_dir_all(p.state_dir).map_err(|e| e.to_string())?;
    // A new key on every install: when there is no valid key, or when a unit is new or about to change (a fresh
    // install or an upgrade). An unchanged refresh at app start keeps its key and restarts nothing.
    let on_disk = |name: &str, text: &str| std::fs::read_to_string(dir.join(name)).map(|c| c == text).unwrap_or(false);
    // (A moved LAN address only changes the bridge unit: that is a refresh, not an install.)
    let installing = !on_disk(LLAMA_UNIT, &llama) || (bridge.is_some() && !dir.join(BRIDGE_UNIT).exists());
    let rotated = installing || !crate::apikey::valid(p.state_dir);
    if rotated {
        crate::apikey::rotate(p.state_dir)?;
    }
    let mut reload = false;
    let llama_started = apply(ctl, dir, LLAMA_UNIT, &llama, &mut reload)?;
    if rotated {
        restart_for_new_key(ctl, LLAMA_UNIT, llama_started)?;
    }
    match (&bridge, lan) {
        (Some(text), Some(ip)) => {
            let bridge_started = apply(ctl, dir, BRIDGE_UNIT, text, &mut reload)?;
            if rotated {
                restart_for_new_key(ctl, BRIDGE_UNIT, bridge_started)?;
            }
            Ok(LanState::Lan(ip))
        }
        _ => {
            // No private address: a stale bridge unit must not keep binding the old one.
            if dir.join(BRIDGE_UNIT).exists() {
                let _ = userunit::ctl(ctl, &["disable", "--now", BRIDGE_UNIT]);
                let _ = std::fs::remove_file(dir.join(BRIDGE_UNIT));
                userunit::ctl(ctl, &["daemon-reload"])?;
            }
            Ok(LanState::NoPrivateAddress)
        }
    }
}

/// Both halves of an uninstall, each attempted whatever the other did.
#[derive(Debug, PartialEq)]
pub struct UninstallReport {
    pub units: Result<(), String>,
    pub firewall: Result<crate::firewall::FwOutcome, String>,
}

impl UninstallReport {
    /// A host with no active firewall has nothing to remove: not a failure.
    pub fn is_clean(&self) -> bool {
        use crate::firewall::FwOutcome::*;
        self.units.is_ok() && matches!(self.firewall, Ok(Done) | Ok(NoFirewall) | Ok(HelperMissing))
    }
}

/// Uninstall: stop and remove both units AND remove the firewall rule (one prompt). Never returns early: a
/// failure in one still attempts the other, and both results are reported.
pub fn uninstall_all(ctl: &Path, dir: &Path, pkexec: &Path, helper: &Path) -> UninstallReport {
    let units = userunit::uninstall(ctl, dir);
    let firewall = crate::firewall::remove(pkexec, helper);
    UninstallReport { units, firewall }
}

/// Everything needed to re-render the llama unit with the CPU build.
pub struct LlamaPlan {
    pub port: u16,
    pub cpu_bin: PathBuf,
    pub model: PathBuf,
    pub idle_seconds: u32,
    pub state_dir: PathBuf,
}

/// Did the unit fail? `show` is `systemctl --user show -p ActiveState -p SubState -p NRestarts -p Result`.
/// Failed, waiting to auto-restart, or inactive after a restart or a non-success result (which includes a tripped
/// StartLimit). A unit the user stopped (inactive, dead, success, no restarts) is not a failure.
pub fn unit_failed(show: &str) -> bool {
    let get = |k: &str| show.lines().find_map(|l| l.strip_prefix(&format!("{k}="))).unwrap_or("").trim().to_string();
    let (active, sub, result) = (get("ActiveState"), get("SubState"), get("Result"));
    let restarts: u32 = get("NRestarts").parse().unwrap_or(0);
    active == "failed"
        || sub == "auto-restart"
        || (active != "active" && (restarts > 0 || (!result.is_empty() && result != "success")))
}

/// One switch from the Vulkan build to the CPU build per app start.
pub struct Fallback {
    pub plan: LlamaPlan,
    pub switched: bool,
}

impl Fallback {
    pub fn new(plan: LlamaPlan) -> Fallback { Fallback { plan, switched: false } }

    /// Call from the tick. When the variant is vulkan and the unit has failed: rewrite the unit with the CPU
    /// binary, daemon-reload, reset-failed, start; set `variant` to cpu. Returns true when it switched now.
    /// `switched` is set before any systemctl call, so a failing switch is never retried.
    pub fn step(&mut self, ctl: &Path, dir: &Path, variant: &mut Option<String>) -> Result<bool, String> {
        if self.switched || variant.as_deref() != Some("vulkan") {
            return Ok(false);
        }
        if !unit_failed(&userunit::show(ctl, LLAMA_UNIT)?) {
            return Ok(false);
        }
        self.switched = true;
        let key_file = self.plan.state_dir.join(crate::apikey::KEY_FILE);
        let text = userunit::render_llama(&LlamaUnit { llama_bin: &self.plan.cpu_bin, model: &self.plan.model, port: self.plan.port, idle_seconds: self.plan.idle_seconds, key_file: &key_file })?;
        userunit::write_if_changed(dir, LLAMA_UNIT, &text)?;
        userunit::ctl(ctl, &["daemon-reload"])?;
        userunit::ctl(ctl, &["reset-failed", LLAMA_UNIT])?;
        userunit::ctl(ctl, &["restart", LLAMA_UNIT])?;
        *variant = Some("cpu".to_string());
        Ok(true)
    }
}

/// Health for the tray: (bridge active, llama active).
pub fn health(ctl: &Path) -> (bool, bool) {
    (userunit::status(ctl, BRIDGE_UNIT), userunit::status(ctl, LLAMA_UNIT))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;

    fn ip(s: &str) -> Ipv4Addr { s.parse().unwrap() }
    fn mask() -> Ipv4Addr { ip("255.255.255.0") }
    fn tmp(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("linuxrun-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }
    /// Logs argv. Per-unit state: enable creates `active.<unit>`, disable removes it, is-active tests it.
    fn fake(d: &Path) -> PathBuf {
        let p = d.join("fakectl");
        let dd = d.display();
        std::fs::write(&p, format!("#!/bin/sh\necho \"$@\" >> {dd}/calls.log\nfor u; do :; done\ncase \"$2\" in\n enable) touch {dd}/active.$u;;\n disable) rm -f {dd}/active.$u;;\n is-active) [ -f {dd}/active.$u ] || exit 1;;\nesac\nexit 0\n")).unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
        p
    }
    fn helper(d: &Path) -> PathBuf { let h = d.join("helper"); std::fs::write(&h, "x").unwrap(); h }
    fn paths(d: &Path) -> (PathBuf, PathBuf) { (d.join("state"), d.join("u")) }

    fn ifc(name: &str, a: &str) -> Iface { Iface { name: name.into(), ip: ip(a), mask: mask() } }

    #[test]
    fn pick_first_private_skips_loopback_public_linklocal() {
        let l = [ifc("lo", "127.0.0.1"), ifc("eth1", "8.8.8.8"), ifc("eth2", "169.254.1.1"), ifc("wlan0", "192.168.1.7"), ifc("eth0", "10.0.0.2")];
        assert_eq!(pick_lan(&l, None).unwrap().ip, ip("192.168.1.7"));
        assert!(pick_lan(&l[..3], None).is_none());
        assert!(pick_lan(&[], None).is_none());
    }

    #[test]
    fn docker_listed_first_does_not_win() {
        let l = [ifc("docker0", "172.17.0.1"), ifc("wlan0", "192.168.1.5")];
        assert_eq!(pick_lan(&l, None).unwrap().name, "wlan0");
        assert_eq!(pick_lan(&l, Some("wlan0")).unwrap().name, "wlan0");
        for n in ["docker0", "virbr0", "br-1a2b3c", "veth12ab", "tailscale0"] {
            let l = [ifc(n, "10.9.9.9"), ifc("wlan0", "192.168.1.5")];
            assert_eq!(pick_lan(&l, None).unwrap().name, "wlan0", "{n}");
            assert!(pick_lan(&l[..1], Some(n)).is_none(), "{n} alone must not be picked even as default");
        }
    }

    #[test]
    fn vpn_default_route_falls_back_to_the_real_lan() {
        let l = [ifc("wg0", "10.8.0.2"), ifc("wlan0", "192.168.1.5")];
        assert_eq!(pick_lan(&l, Some("wg0")).unwrap().name, "wlan0"); // full-tunnel default route on the VPN
        for n in ["tun0", "wg0", "ppp0", "zt5u4abcde"] {
            let l = [ifc(n, "10.8.0.2"), ifc("wlan0", "192.168.1.5")];
            assert_eq!(pick_lan(&l, Some(n)).unwrap().name, "wlan0", "{n}");
            assert!(pick_lan(&l[..1], Some(n)).is_none(), "{n}");
        }
    }

    #[test]
    fn default_route_interface_wins_over_order() {
        let l = [ifc("wlan0", "192.168.1.5"), ifc("eth0", "10.0.0.7")];
        assert_eq!(pick_lan(&l, Some("eth0")).unwrap().name, "eth0");
        assert_eq!(pick_lan(&l, Some("gone")).unwrap().name, "wlan0"); // unknown default: first usable
    }

    const ROUTES: &str = "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT\n\
docker0\t000011AC\t00000000\t0001\t0\t0\t0\t0000FFFF\t0\t0\t0\n\
wlan0\t00000000\t0101A8C0\t0003\t0\t0\t600\t00000000\t0\t0\t0\n\
eth0\t00000000\t0101A8C0\t0003\t0\t0\t100\t00000000\t0\t0\t0\n\
odd0\t00001234\t0101A8C0\t0003\t0\t0\t0\t00000000\t0\t0\t0\n\
down0\t00000000\t0101A8C0\t0002\t0\t0\t1\t00000000\t0\t0\t0\n";

    #[test]
    fn default_route_parse_lowest_metric_up_gateway_only() {
        assert_eq!(default_route_iface(ROUTES).as_deref(), Some("eth0"));
        assert_eq!(default_route_iface("Iface\tDestination\n"), None);
        assert_eq!(default_route_iface(""), None);
    }

    #[test]
    fn default_iface_reads_an_injected_path() {
        let d = tmp("route");
        std::fs::write(d.join("route"), ROUTES).unwrap();
        assert_eq!(default_iface(&d.join("route")).as_deref(), Some("eth0"));
        assert_eq!(default_iface(&d.join("missing")), None);
    }

    #[test]
    fn sync_with_lan_installs_both_then_second_run_touches_nothing() {
        let d = tmp("both");
        let ctl = fake(&d);
        let (state, dir) = paths(&d);
        let p = Paths { companion_bin: Path::new("/opt/am/c"), state_dir: &state, llama_bin: Path::new("/opt/am/l"), model: Path::new("/m/e.gguf"), idle_seconds: 600, llama_port: LLAMA_PORT };
        let ifs = Some(ip("192.168.1.7"));
        assert_eq!(sync(&ctl, &dir, &p, ifs).unwrap(), LanState::Lan(ip("192.168.1.7")));
        assert!(dir.join(BRIDGE_UNIT).exists() && dir.join(LLAMA_UNIT).exists());
        let log = std::fs::read_to_string(d.join("calls.log")).unwrap();
        assert!(log.contains(&format!("--user enable --now {LLAMA_UNIT}")) && log.contains(&format!("--user enable --now {BRIDGE_UNIT}")));
        // second run: everything active (fake cleared inactive on enable) and unchanged
        std::fs::remove_file(d.join("calls.log")).unwrap();
        let m0 = std::fs::metadata(dir.join(LLAMA_UNIT)).unwrap().modified().unwrap();
        sync(&ctl, &dir, &p, ifs).unwrap();
        let log = std::fs::read_to_string(d.join("calls.log")).unwrap();
        assert!(!log.contains("daemon-reload") && !log.contains("enable") && !log.contains("restart"), "{log}");
        assert_eq!(std::fs::metadata(dir.join(LLAMA_UNIT)).unwrap().modified().unwrap(), m0);
    }

    #[test]
    fn sync_without_private_address_installs_llama_only() {
        let d = tmp("nolan");
        let ctl = fake(&d);
        let (state, dir) = paths(&d);
        let p = Paths { companion_bin: Path::new("/opt/am/c"), state_dir: &state, llama_bin: Path::new("/opt/am/l"), model: Path::new("/m/e.gguf"), idle_seconds: 600, llama_port: LLAMA_PORT };
        assert_eq!(sync(&ctl, &dir, &p, None).unwrap(), LanState::NoPrivateAddress);
        assert!(dir.join(LLAMA_UNIT).exists() && !dir.join(BRIDGE_UNIT).exists());
    }

    #[test]
    fn changed_unit_is_rewritten_and_restarted_unchanged_one_is_not() {
        let d = tmp("chg");
        let ctl = fake(&d);
        let (state, dir) = paths(&d);
        let p = Paths { companion_bin: Path::new("/opt/am/c"), state_dir: &state, llama_bin: Path::new("/opt/am/l"), model: Path::new("/m/e.gguf"), idle_seconds: 600, llama_port: LLAMA_PORT };
        sync(&ctl, &dir, &p, Some(ip("192.168.1.7"))).unwrap();
        std::fs::remove_file(d.join("calls.log")).unwrap();
        sync(&ctl, &dir, &p, Some(ip("10.1.2.3"))).unwrap(); // address moved
        let log = std::fs::read_to_string(d.join("calls.log")).unwrap();
        assert!(log.contains(&format!("--user restart {BRIDGE_UNIT}")) && !log.contains(&format!("restart {LLAMA_UNIT}")), "{log}");
        assert!(std::fs::read_to_string(dir.join(BRIDGE_UNIT)).unwrap().contains("ARROWBRIDGE_BIND=10.1.2.3"));
    }

    /// A fake systemctl whose `show` prints the contents of `d/show` and which logs every call.
    fn fake_show(d: &Path) -> PathBuf {
        let p = d.join("showctl");
        let dd = d.display();
        std::fs::write(&p, format!("#!/bin/sh\necho \"$@\" >> {dd}/calls.log\ncase \"$2\" in\n show) cat {dd}/show; exit 0;;\nesac\nexit 0\n")).unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
        p
    }

    #[test]
    fn unit_failure_reading() {
        let f = |a: &str, s: &str, n: u32, r: &str| unit_failed(&format!("ActiveState={a}\nSubState={s}\nNRestarts={n}\nResult={r}\n"));
        assert!(f("failed", "failed", 3, "start-limit-hit"));
        assert!(f("failed", "failed", 0, "success"), "the failed state alone");
        assert!(f("activating", "auto-restart", 0, "success"), "waiting to auto-restart alone");
        assert!(f("activating", "auto-restart", 1, "exit-code"));
        assert!(f("inactive", "dead", 2, "success"), "inactive after restarts");
        assert!(f("inactive", "dead", 0, "exit-code"));
        assert!(!f("active", "running", 0, "success"));
        assert!(!f("active", "running", 2, "success"), "running again after a restart is not a failure");
        assert!(!f("inactive", "dead", 0, "success"), "a unit the user stopped");
        assert!(!unit_failed(""));
    }

    fn fb(d: &Path) -> (Fallback, PathBuf, PathBuf) {
        let (state, dir) = paths(d);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join(LLAMA_UNIT), "old vulkan unit").unwrap();
        (Fallback::new(LlamaPlan { port: LLAMA_PORT, cpu_bin: PathBuf::from("/usr/lib/arrowmem/llama-server-cpu"), model: PathBuf::from("/m/e.gguf"), idle_seconds: 600, state_dir: state }), dir, d.join("showctl"))
    }

    #[test]
    fn a_failed_vulkan_unit_is_switched_to_cpu_once() {
        let d = tmp("fb");
        fake_show(&d);
        let (mut f, dir, ctl) = fb(&d);
        let mut variant = Some("vulkan".to_string());
        // healthy: nothing happens
        std::fs::write(d.join("show"), "ActiveState=active\nSubState=running\nNRestarts=0\nResult=success\n").unwrap();
        assert!(!f.step(&ctl, &dir, &mut variant).unwrap());
        assert_eq!(variant.as_deref(), Some("vulkan"));
        // StartLimit tripped
        std::fs::write(d.join("show"), "ActiveState=failed\nSubState=failed\nNRestarts=3\nResult=start-limit-hit\n").unwrap();
        std::fs::remove_file(d.join("calls.log")).unwrap();
        assert!(f.step(&ctl, &dir, &mut variant).unwrap());
        assert_eq!(variant.as_deref(), Some("cpu"));
        assert!(f.switched);
        let unit = std::fs::read_to_string(dir.join(LLAMA_UNIT)).unwrap();
        assert!(unit.contains("ExecStart=/usr/lib/arrowmem/llama-server-cpu "), "{unit}");
        let log = std::fs::read_to_string(d.join("calls.log")).unwrap();
        let pos = |needle: &str| log.find(needle).unwrap_or_else(|| panic!("{needle} missing in {log}"));
        assert!(pos("daemon-reload") < pos("reset-failed") && pos("reset-failed") < pos(&format!("restart {LLAMA_UNIT}")), "{log}");
        // no loop: it keeps failing, nothing more is done
        std::fs::remove_file(d.join("calls.log")).unwrap();
        assert!(!f.step(&ctl, &dir, &mut variant).unwrap());
        assert!(!d.join("calls.log").exists(), "no systemctl call after the one switch");
    }

    #[test]
    fn a_cpu_unit_or_an_unknown_variant_is_never_switched() {
        let d = tmp("fb2");
        fake_show(&d);
        std::fs::write(d.join("show"), "ActiveState=failed\nSubState=failed\nNRestarts=3\nResult=start-limit-hit\n").unwrap();
        for v in [Some("cpu".to_string()), None] {
            let (mut f, dir, ctl) = fb(&d);
            let mut variant = v.clone();
            assert!(!f.step(&ctl, &dir, &mut variant).unwrap());
            assert_eq!(variant, v);
            assert_eq!(std::fs::read_to_string(dir.join(LLAMA_UNIT)).unwrap(), "old vulkan unit");
        }
    }

    #[test]
    fn a_switch_that_errors_is_still_only_one_attempt() {
        let d = tmp("fb3");
        fake_show(&d);
        std::fs::write(d.join("show"), "ActiveState=failed\nSubState=failed\nNRestarts=1\nResult=exit-code\n").unwrap();
        // reset-failed fails
        let ctl = d.join("badctl");
        std::fs::write(&ctl, format!("#!/bin/sh\necho \"$@\" >> {0}/calls.log\ncase \"$2\" in show) cat {0}/show;; reset-failed) exit 1;; esac\nexit 0\n", d.display())).unwrap();
        std::fs::set_permissions(&ctl, std::fs::Permissions::from_mode(0o755)).unwrap();
        let (mut f, dir, _) = fb(&d);
        let mut variant = Some("vulkan".to_string());
        assert!(f.step(&ctl, &dir, &mut variant).is_err());
        assert!(f.switched);
        std::fs::remove_file(d.join("calls.log")).unwrap();
        assert!(!f.step(&ctl, &dir, &mut variant).unwrap());
        assert!(!d.join("calls.log").exists(), "no second attempt");
    }

    #[test]
    fn key_is_rotated_on_install_kept_on_refresh_and_never_in_a_unit() {
        let d = tmp("key");
        let ctl = fake(&d);
        let (state, dir) = paths(&d);
        let p = Paths { companion_bin: Path::new("/opt/am/c"), state_dir: &state, llama_bin: Path::new("/opt/am/l"), model: Path::new("/m/e.gguf"), idle_seconds: 600, llama_port: LLAMA_PORT };
        sync(&ctl, &dir, &p, Some(ip("192.168.1.7"))).unwrap();
        let k1 = crate::apikey::read_key(&state).expect("a key exists after the first install");
        for u in [LLAMA_UNIT, BRIDGE_UNIT] {
            let t = std::fs::read_to_string(dir.join(u)).unwrap();
            assert!(!t.contains(&k1), "the key must not be in {u}");
            assert_eq!(std::fs::metadata(dir.join(u)).unwrap().permissions().mode() & 0o777, 0o644);
        }
        let llama = std::fs::read_to_string(dir.join(LLAMA_UNIT)).unwrap();
        assert!(llama.contains(&format!("--api-key-file {}", state.join("llama-api-key").display())));
        assert!(std::fs::read_to_string(dir.join(BRIDGE_UNIT)).unwrap().contains(&format!("EnvironmentFile={}", state.join("upstream.env").display())));
        // an unchanged refresh keeps the key and restarts nothing
        std::fs::remove_file(d.join("calls.log")).unwrap();
        sync(&ctl, &dir, &p, Some(ip("192.168.1.7"))).unwrap();
        assert_eq!(crate::apikey::read_key(&state).unwrap(), k1);
        assert!(!std::fs::read_to_string(d.join("calls.log")).unwrap().contains("restart"));
        // an upgrade (llama unit changes) rotates the key and restarts both units
        std::fs::remove_file(d.join("calls.log")).unwrap();
        let p2 = Paths { idle_seconds: 90, ..p };
        sync(&ctl, &dir, &p2, Some(ip("192.168.1.7"))).unwrap();
        let k2 = crate::apikey::read_key(&state).unwrap();
        assert_ne!(k1, k2);
        let log = std::fs::read_to_string(d.join("calls.log")).unwrap();
        assert!(log.contains(&format!("restart {LLAMA_UNIT}")) && log.contains(&format!("restart {BRIDGE_UNIT}")), "{log}");
        // the key file is lost: next start writes a new one and restarts both
        std::fs::remove_file(state.join("llama-api-key")).unwrap();
        std::fs::remove_file(d.join("calls.log")).unwrap();
        sync(&ctl, &dir, &p2, Some(ip("192.168.1.7"))).unwrap();
        assert!(crate::apikey::valid(&state));
        assert!(std::fs::read_to_string(d.join("calls.log")).unwrap().contains(&format!("restart {BRIDGE_UNIT}")));
    }

    #[test]
    fn losing_the_address_removes_a_stale_bridge_unit() {
        let d = tmp("lost");
        let ctl = fake(&d);
        let (state, dir) = paths(&d);
        let p = Paths { companion_bin: Path::new("/opt/am/c"), state_dir: &state, llama_bin: Path::new("/opt/am/l"), model: Path::new("/m/e.gguf"), idle_seconds: 600, llama_port: LLAMA_PORT };
        sync(&ctl, &dir, &p, Some(ip("192.168.1.7"))).unwrap();
        assert_eq!(sync(&ctl, &dir, &p, None).unwrap(), LanState::NoPrivateAddress);
        assert!(!dir.join(BRIDGE_UNIT).exists());
    }

    fn pk(d: &Path, code: i32) -> PathBuf {
        let p = d.join("pkexec");
        std::fs::write(&p, format!("#!/bin/sh\necho \"$@\" >> {}/pk.log\nexit {code}\n", d.display())).unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
        p
    }

    #[test]
    fn uninstall_all_calls_units_then_firewall_remove() {
        let d = tmp("uall");
        let ctl = fake(&d);
        let r = uninstall_all(&ctl, &d.join("u"), &pk(&d, 0), &helper(&d));
        assert!(r.is_clean(), "{r:?}");
        assert_eq!(std::fs::read_to_string(d.join("pk.log")).unwrap(), format!("{} remove\n", helper(&d).display()));
        assert!(std::fs::read_to_string(d.join("calls.log")).unwrap().contains("daemon-reload"));
    }

    #[test]
    fn uninstall_all_attempts_both_and_reports_both_failures() {
        let d = tmp("uall2");
        let ctl = fake(&d);
        // units fail (a stuck unit: is-active keeps succeeding), firewall helper also fails: both still run
        let dir = d.join("u");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join(BRIDGE_UNIT), "x").unwrap();
        std::fs::write(d.join(format!("active.{BRIDGE_UNIT}")), "").unwrap();
        let stuck = d.join("stuckctl");
        std::fs::write(&stuck, "#!/bin/sh\nexit 0\n").unwrap(); // every call succeeds, so is-active is always true
        std::fs::set_permissions(&stuck, std::fs::Permissions::from_mode(0o755)).unwrap();
        let r = uninstall_all(&stuck, &dir, &pk(&d, 4), &helper(&d));
        assert!(r.units.is_err());
        assert_eq!(r.firewall, Ok(crate::firewall::FwOutcome::Failed(4)));
        assert!(!r.is_clean());
        assert!(d.join("pk.log").exists(), "firewall remove must run even when the units failed");
        // and the other way round: firewall errors, units still removed
        let d2 = tmp("uall3");
        let ctl2 = fake(&d2);
        let r2 = uninstall_all(&ctl2, &d2.join("u"), Path::new("/nonexistent/pkexec"), &helper(&d2));
        assert!(r2.units.is_ok() && r2.firewall.is_err());
        assert!(std::fs::read_to_string(d2.join("calls.log")).unwrap().contains("daemon-reload"));
    }

    #[test]
    fn health_reads_is_active() {
        let d = tmp("hl");
        let ctl = fake(&d);
        assert_eq!(health(&ctl), (false, false));
        std::fs::write(d.join(format!("active.{BRIDGE_UNIT}")), "").unwrap();
        assert_eq!(health(&ctl), (true, false));
        std::fs::write(d.join(format!("active.{LLAMA_UNIT}")), "").unwrap();
        assert_eq!(health(&ctl), (true, true));
    }

    #[test]
    fn unsafe_model_path_refused_before_any_write() {
        let d = tmp("unsafe");
        let ctl = fake(&d);
        let (state, dir) = paths(&d);
        let p = Paths { companion_bin: Path::new("/opt/am/c"), state_dir: &state, llama_bin: Path::new("/opt/am/l"), model: Path::new("/m/a b.gguf"), idle_seconds: 600, llama_port: LLAMA_PORT };
        assert!(sync(&ctl, &dir, &p, Some(ip("192.168.1.7"))).is_err());
        assert!(!dir.exists());
    }

    /// A fake systemctl for the upgrade cases: `show -p ActiveState` and `show -p MainPID` print the contents of d/state and d/pid; logs every call.
    fn fake_upgrade(d: &Path) -> PathBuf {
        let p = d.join("upctl");
        let dd = d.display();
        std::fs::write(&p, format!("#!/bin/sh\necho \"$@\" >> {dd}/calls.log\nfor u; do :; done\ncase \"$2\" in\n show) case \"$4\" in ActiveState) cat {dd}/state;; MainPID) cat {dd}/pid;; esac; exit 0;;\n is-active) [ -f {dd}/active.$u ] || exit 1;;\n enable) touch {dd}/active.$u;;\nesac\nexit 0\n")).unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
        p
    }

    #[test]
    fn a_failed_unit_is_reset_before_it_is_started_again() {
        let d = tmp("failed");
        let ctl = fake_upgrade(&d);
        std::fs::write(d.join("state"), "failed\n").unwrap();
        std::fs::write(d.join("pid"), "0\n").unwrap();
        let dir = d.join("u"); std::fs::create_dir_all(&dir).unwrap();
        let mut reload = false;
        let started = apply(&ctl, &dir, BRIDGE_UNIT, "text", &mut reload).unwrap();
        let log = std::fs::read_to_string(d.join("calls.log")).unwrap();
        assert!(started);
        let (r, e) = (log.find(&format!("reset-failed {BRIDGE_UNIT}")).expect(&log), log.find(&format!("enable --now {BRIDGE_UNIT}")).expect(&log));
        assert!(r < e, "reset-failed first: {log}");
    }

    #[test]
    fn a_healthy_unit_with_the_current_program_is_left_alone() {
        let d = tmp("healthy");
        let ctl = fake_upgrade(&d);
        std::fs::write(d.join("state"), "active\n").unwrap();
        std::fs::write(d.join("pid"), "999999999\n").unwrap(); // no such process: cannot be stale
        let dir = d.join("u"); std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(d.join("active.ca.arrowmem.arrowbridge.service"), "").unwrap();
        let mut reload = false;
        userunit::write_if_changed(&dir, BRIDGE_UNIT, "text").unwrap();
        assert!(!apply(&ctl, &dir, BRIDGE_UNIT, "text", &mut reload).unwrap());
        let log = std::fs::read_to_string(d.join("calls.log")).unwrap();
        assert!(!log.contains("restart") && !log.contains("reset-failed") && !log.contains("enable"), "{log}");
    }

    #[test]
    fn recover_resets_and_restarts_both_units_model_server_first() {
        let d = tmp("recover");
        let ctl = fake_upgrade(&d);
        std::fs::write(d.join(format!("active.{BRIDGE_UNIT}")), "").unwrap();
        assert!(recover(&ctl));
        let log = std::fs::read_to_string(d.join("calls.log")).unwrap();
        let at = |s: &str| log.find(s).unwrap_or_else(|| panic!("missing {s} in {log}"));
        assert!(at(&format!("reset-failed {LLAMA_UNIT}")) < at(&format!("restart {LLAMA_UNIT}")));
        assert!(at(&format!("restart {LLAMA_UNIT}")) < at(&format!("reset-failed {BRIDGE_UNIT}")));
        assert!(at(&format!("reset-failed {BRIDGE_UNIT}")) < at(&format!("restart {BRIDGE_UNIT}")));
    }

    #[test]
    fn the_service_heals_silently_and_the_card_waits_for_three_failed_restarts() {
        let t0 = std::time::Instant::now();
        let mut h = Heal::default();
        assert_eq!(h.step(false, t0), HealStep::Attempt);
        assert_eq!(h.step(false, t0 + std::time::Duration::from_secs(5)), HealStep::Waiting, "a restart was just made: no card");
        assert_eq!(h.step(false, t0 + std::time::Duration::from_secs(21)), HealStep::Attempt);
        assert_eq!(h.step(false, t0 + std::time::Duration::from_secs(30)), HealStep::Waiting);
        assert_eq!(h.step(false, t0 + std::time::Duration::from_secs(42)), HealStep::Attempt);
        assert_eq!(h.step(false, t0 + std::time::Duration::from_secs(50)), HealStep::Waiting, "the third restart still has its 20 seconds");
        assert_eq!(h.step(false, t0 + std::time::Duration::from_secs(63)), HealStep::Failed, "only now the card");
        assert_eq!(h.step(false, t0 + std::time::Duration::from_secs(200)), HealStep::Failed, "and it stays until the companion answers or the person restarts");
    }

    #[test]
    fn a_companion_that_answers_clears_everything_and_a_new_outage_starts_again() {
        let t0 = std::time::Instant::now();
        let mut h = Heal::default();
        h.step(false, t0);
        assert_eq!(h.step(true, t0 + std::time::Duration::from_secs(3)), HealStep::Up);
        assert_eq!(h.step(false, t0 + std::time::Duration::from_secs(4)), HealStep::Attempt, "the count began again");
        h.reset();
        assert_eq!(h.step(false, t0 + std::time::Duration::from_secs(5)), HealStep::Attempt);
    }

    #[test]
    fn the_model_port_is_unusual_kept_and_never_a_port_someone_else_holds() {
        let d = tmp("port");
        let all_free = |_: u16| true;
        assert_eq!(choose_llama_port(&d, false, &all_free), PORT_FIRST, "first run: the unusual fixed port, saved");
        assert_eq!(crate::firstrun::load_settings(&d).llama_port, Some(PORT_FIRST));
        let first_taken = |p: u16| p != PORT_FIRST;
        assert_eq!(choose_llama_port(&d, false, &first_taken), PORT_FIRST + 1, "the saved one is held by another program: the next free one");
        assert_eq!(crate::firstrun::load_settings(&d).llama_port, Some(PORT_FIRST + 1));
        let all_taken_but_ours = |_: u16| false;
        assert_eq!(choose_llama_port(&d, true, &all_taken_but_ours), PORT_FIRST + 1, "held by our own running model unit: kept");
        assert_eq!(choose_llama_port(&d, false, &all_taken_but_ours), PORT_FIRST, "nothing free in the range: the first one (the window then says port in use)");
        let old = tmp("port-low");
        std::fs::write(old.join("settings.json"), r#"{"llama_port":80}"#).unwrap();
        assert!(choose_llama_port(&old, true, &all_free) >= PORT_FIRST, "a saved privileged port is never trusted");
    }

    #[test]
    fn the_companion_unit_names_the_chosen_model_port() {
        let d = tmp("port-unit");
        let ctl = fake(&d);
        let (state, dir) = paths(&d);
        let p = Paths { companion_bin: Path::new("/opt/am/c"), state_dir: &state, llama_bin: Path::new("/opt/am/l"), model: Path::new("/m/e.gguf"), idle_seconds: 600, llama_port: 41717 };
        sync(&ctl, &dir, &p, Some(ip("192.168.1.7"))).unwrap();
        assert!(std::fs::read_to_string(dir.join(BRIDGE_UNIT)).unwrap().contains("ARROWBRIDGE_UPSTREAM_URL=http://127.0.0.1:41717"));
        assert!(std::fs::read_to_string(dir.join(LLAMA_UNIT)).unwrap().contains("--port 41717"));
    }
}
