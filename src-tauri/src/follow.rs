//! Round 3a: the bridge follows the network (RULINGS ADD 804 d, 806, 807). The desktop polls the interface list; when the
//! one private address the companion should bind changes (a hotspot comes up, the LAN goes away) it rewrites the bridge
//! user unit with the new single address, runs `reset-failed` and then `restart`, and moves the firewall allow to the new
//! network. std plus the existing getifaddrs walk: no netlink, no new dependency.
//!
//! Linux only. The bridge is a systemd user unit only there; the macOS and Windows supervisors in this crate start the
//! companion without a bind address, so there is no unit to rewrite on them. A pick of None writes nothing and restarts nothing.
//! All side effects go through the argv-only `userunit::ctl` and the injected firewall closures, so every rule below is tested with fakes.

use std::net::Ipv4Addr;
use std::path::Path;

use crate::firewall::{self, FwOutcome};
use crate::linuxrun::{self, Iface};
use crate::userunit::{self, BridgeUnit, BRIDGE_UNIT};

/// Seconds between polls. A number to MEASURE on a real hotspot, not a design input (brief section 1 A).
pub const FOLLOW_POLL_SECS: u64 = 3;
/// A restart is deferred while a pairing window is open, but never longer than this.
pub const DEFER_CAP_SECS: u64 = 60;
/// After a failed unit write or restart the same target is not retried for this long (no hammering every poll).
const RETRY_AFTER_FAIL_SECS: u64 = 30;

/// (address, netmask) of the interface the companion binds.
pub type Lan = (Ipv4Addr, Ipv4Addr);

/// What the unit needs besides the address.
pub struct Ctx<'a> {
    pub ctl: &'a Path,
    pub dir: &'a Path,
    pub companion_bin: &'a Path,
    pub state_dir: &'a Path,
    pub llama_port: u16,
    pub upstream_model: &'a str,
}

/// The three effects the follow asks of its caller, all injected.
pub struct Hooks<'a> {
    /// Called once, right after the restart succeeded and before any firewall prompt: the window's address and pair code are recomputed from it.
    pub bound: &'a dyn Fn(Lan),
    /// Allow TCP 8788 from this interface's network (one admin prompt).
    pub allow: &'a dyn Fn(Lan) -> Result<FwOutcome, String>,
    /// Withdraw the allow for exactly this CIDR.
    pub remove: &'a dyn Fn(&str) -> Result<FwOutcome, String>,
    /// True while a pairing window is open. Asked only when the pick changed.
    pub busy: &'a dyn Fn() -> bool,
}

#[derive(Debug, Clone, PartialEq)]
pub enum FwStep {
    /// Same network as before: nothing asked.
    NotNeeded,
    Done,
    /// A prompt was refused or a helper step failed: the companion is bound, the firewall is closed for the new network (the safe direction).
    Waiting(String),
}

#[derive(Debug, PartialEq)]
pub enum Step {
    /// Same pick as the one the unit is bound to (or a failed target inside its back-off): nothing was called.
    Unchanged,
    /// No private address: nothing written, nothing restarted.
    NoAddress,
    /// The pick changed but a pairing window is open: nothing written yet.
    Deferred,
    Followed { to: Lan, forced: bool, firewall: FwStep },
    Failed(String),
}

/// `Failed` code the poll thread's firewall hooks answer with: the follow never raises an admin prompt itself (brief C: one prompt per new network,
/// from the window, never silently on join). The window's firewall button (`retry_firewall`) asks, and withdraws the networks left behind.
pub const PROMPT_FROM_WINDOW: i32 = -3;

/// Poll-thread hook for `Hooks::allow`: no pkexec, the prompt belongs to the window.
pub fn defer_allow(_: Lan) -> Result<FwOutcome, String> {
    Ok(FwOutcome::Failed(PROMPT_FROM_WINDOW))
}

/// Poll-thread hook for `Hooks::remove`: no pkexec, see [`defer_allow`].
pub fn defer_remove(_: &str) -> Result<FwOutcome, String> {
    Ok(FwOutcome::Failed(PROMPT_FROM_WINDOW))
}

/// The window's button, after the current network was allowed: withdraw every network left behind (never `current`, the one that is up).
/// A withdrawal that is not answered stays on the list.
pub fn withdraw_stale(stale: &mut Vec<String>, current: Option<&str>, remove: &dyn Fn(&str) -> Result<FwOutcome, String>) {
    stale.retain(|c| Some(c.as_str()) != current);
    for c in stale.clone() {
        if ok_outcome(&remove(&c)) {
            stale.retain(|s| *s != c);
        }
    }
}

#[derive(Default)]
pub struct Follower {
    /// What the bridge unit is bound to now. Kept across a None pick, so the old network can still be withdrawn later.
    pub bound: Option<Lan>,
    deferred_since: Option<u64>,
    failed: Option<(Lan, u64)>,
    /// Networks whose allow is still in ufw although the bridge left them (a withdrawal not yet asked or refused). Shared with the window through Info.
    pub stale: Vec<String>,
}

fn ok_outcome(r: &Result<FwOutcome, String>) -> bool {
    matches!(r, Ok(FwOutcome::Done) | Ok(FwOutcome::NoFirewall) | Ok(FwOutcome::HelperMissing))
}

impl Follower {
    pub fn tick(&mut self, ifaces: &[Iface], default_if: Option<&str>, ctx: &Ctx, h: &Hooks, now: u64) -> Step {
        let Some(to) = linuxrun::pick_lan(ifaces, default_if).map(|i| (i.ip, i.mask)) else {
            self.deferred_since = None;
            return Step::NoAddress;
        };
        if self.bound == Some(to) {
            self.deferred_since = None;
            self.failed = None;
            return Step::Unchanged;
        }
        if let Some((t, until)) = self.failed {
            if t == to && now < until {
                return Step::Unchanged;
            }
        }
        let mut forced = false;
        if (h.busy)() {
            let since = *self.deferred_since.get_or_insert(now);
            if now.saturating_sub(since) < DEFER_CAP_SECS {
                return Step::Deferred;
            }
            forced = true;
        }
        let from = self.bound;
        if let Err(e) = self.rebind(to, ctx) {
            self.failed = Some((to, now + RETRY_AFTER_FAIL_SECS));
            return Step::Failed(e);
        }
        self.bound = Some(to);
        self.deferred_since = None;
        self.failed = None;
        (h.bound)(to);
        let firewall = self.firewall(from, to, h);
        Step::Followed { to, forced, firewall }
    }

    /// Re-render for the new single address and bring the unit in line. Refuses before touching disk (render_bridge only takes RFC1918).
    fn rebind(&self, to: Lan, ctx: &Ctx) -> Result<(), String> {
        let text = userunit::render_bridge(&BridgeUnit {
            companion_bin: ctx.companion_bin,
            state_dir: ctx.state_dir,
            lan_ip: &to.0.to_string(),
            port: 8788,
            llama_port: ctx.llama_port,
            upstream_model: ctx.upstream_model,
        })?;
        let wrote = userunit::write_if_changed(ctx.dir, BRIDGE_UNIT, &text)?;
        // Only the address is in the unit, so a mask-only change (same address) needs no restart. A retry after a failed restart finds the
        // file already written, so the address, not the write, decides.
        if wrote || self.bound.map_or(true, |b| b.0 != to.0) {
            userunit::ctl(ctx.ctl, &["daemon-reload"])?;
            if self.bound.is_none() {
                // The unit was removed while there was no address (linuxrun::sync): it comes back enabled.
                userunit::ctl(ctx.ctl, &["enable", BRIDGE_UNIT])?;
            }
            // A tripped start limit leaves the unit failed until reset-failed, so it comes first.
            let _ = userunit::ctl(ctx.ctl, &["reset-failed", BRIDGE_UNIT]);
            userunit::ctl(ctx.ctl, &["restart", BRIDGE_UNIT])?;
        }
        Ok(())
    }

    /// After the restart: allow the new network, then withdraw the old one. Never a rule for a network that is not up, never a
    /// withdrawal of the network that is. A refused prompt keeps the old network on the stale list for the next successful move.
    fn firewall(&mut self, from: Option<Lan>, to: Lan, h: &Hooks) -> FwStep {
        let new = match firewall::cidr_from(to.0, to.1) {
            Ok(c) => c,
            Err(e) => return FwStep::Waiting(e),
        };
        let old = from.and_then(|l| firewall::cidr_from(l.0, l.1).ok()).filter(|c| *c != new);
        if let Some(o) = &old {
            if !self.stale.contains(o) {
                self.stale.push(o.clone());
            }
        }
        self.stale.retain(|c| *c != new); // back on a network we had left: its rule is wanted again
        if old.is_none() && self.stale.is_empty() && from.is_some() {
            return FwStep::NotNeeded;
        }
        let a = (h.allow)(to);
        if !ok_outcome(&a) {
            return FwStep::Waiting(format!("allow: {a:?}"));
        }
        let mut waiting = None;
        for c in self.stale.clone() {
            let r = (h.remove)(&c);
            if ok_outcome(&r) {
                self.stale.retain(|s| *s != c);
            } else {
                waiting = Some(format!("remove {c}: {r:?}"));
            }
        }
        match waiting {
            Some(w) => FwStep::Waiting(w),
            None => FwStep::Done,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;
    use std::process::Command;

    fn ip(s: &str) -> Ipv4Addr { s.parse().unwrap() }
    fn ifc(name: &str, a: &str) -> Iface { Iface { name: name.into(), ip: ip(a), mask: ip("255.255.255.0") } }
    fn lan(a: &str) -> Lan { (ip(a), ip("255.255.255.0")) }
    fn tmp(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("follow-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }
    /// Fake systemctl: logs argv; `fail_restart` in the folder makes `restart` exit 1.
    fn fake_ctl(d: &Path) -> PathBuf {
        let p = d.join("fakectl");
        let dd = d.display();
        std::fs::write(&p, format!("#!/bin/sh\n[ \"$1\" = __probe ] && exit 0\necho \"$@\" >> {dd}/calls.log\nif [ \"$2\" = restart ] && [ -f {dd}/fail_restart ]; then exit 1; fi\nexit 0\n")).unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
        exec_ready(&p);
        p
    }
    /// Parallel tests fork while a script is being written, and a child that still holds the write fd makes the first exec fail with ETXTBSY (os error 26).
    /// Probe until it can run; after that no copy of the write fd exists.
    fn exec_ready(p: &Path) {
        for _ in 0..200 {
            match Command::new(p).arg("__probe").output() {
                Err(e) if e.raw_os_error() == Some(26) => std::thread::sleep(std::time::Duration::from_millis(10)),
                _ => return,
            }
        }
        panic!("script never became executable");
    }
    fn calls(d: &Path) -> Vec<String> {
        std::fs::read_to_string(d.join("calls.log")).unwrap_or_default().lines().map(String::from).collect()
    }
    fn unit_text(d: &Path) -> String { std::fs::read_to_string(d.join("u").join(BRIDGE_UNIT)).unwrap() }

    /// The interfaces of a laptop. Always present and never to be picked: loopback, a docker bridge, a tailscale address on a non-skipped name.
    fn noise() -> Vec<Iface> {
        vec![ifc("lo", "127.0.0.1"), ifc("docker0", "172.17.0.1"), ifc("tailscale0", "100.101.102.103"), ifc("wlan1", "100.64.0.9")]
    }
    fn with(mut v: Vec<Iface>) -> Vec<Iface> { let mut n = noise(); n.append(&mut v); n }

    struct Rig {
        d: PathBuf,
        ctl: PathBuf,
        state: PathBuf,
        dir: PathBuf,
        fw: RefCell<Vec<String>>,
        bound: RefCell<Vec<Lan>>,
        busy: RefCell<bool>,
        busy_asked: RefCell<u32>,
        allow_code: RefCell<i32>,
    }
    impl Rig {
        fn new(tag: &str) -> Rig {
            let d = tmp(tag);
            Rig { ctl: fake_ctl(&d), state: d.join("state"), dir: d.join("u"), d, fw: RefCell::new(vec![]), bound: RefCell::new(vec![]),
                  busy: RefCell::new(false), busy_asked: RefCell::new(0), allow_code: RefCell::new(0) }
        }
        fn tick(&self, f: &mut Follower, ifaces: &[Iface], default_if: Option<&str>, now: u64) -> Step {
            let ctx = Ctx { ctl: &self.ctl, dir: &self.dir, companion_bin: Path::new("/opt/am/c"), state_dir: &self.state, llama_port: 41717, upstream_model: "m-1" };
            let out = |c: i32| if c == 0 { Ok(FwOutcome::Done) } else { Ok(FwOutcome::Failed(c)) };
            let allow = |l: Lan| { self.fw.borrow_mut().push(format!("allow {}", firewall::cidr_from(l.0, l.1).unwrap())); out(*self.allow_code.borrow()) };
            let remove = |c: &str| { self.fw.borrow_mut().push(format!("remove {c}")); out(*self.allow_code.borrow()) };
            let bound = |l: Lan| self.bound.borrow_mut().push(l);
            let busy = || { *self.busy_asked.borrow_mut() += 1; *self.busy.borrow() };
            f.tick(ifaces, default_if, &ctx, &Hooks { bound: &bound, allow: &allow, remove: &remove, busy: &busy }, now)
        }
        fn fw(&self) -> Vec<String> { self.fw.borrow().clone() }
    }
    fn at(lan_addr: &str) -> Follower { Follower { bound: Some(lan(lan_addr)), ..Default::default() } }
    const U: &str = "ca.arrowmem.arrowbridge.service";

    fn lan_net() -> Vec<Iface> { with(vec![ifc("enp3s0", "192.168.1.7")]) }
    fn hotspot_net() -> Vec<Iface> { with(vec![ifc("wlan0", "10.42.0.1")]) }

    #[test]
    fn lan_to_hotspot_rewrites_byte_exact_then_reset_failed_then_restart_then_firewall() {
        let r = Rig::new("l2h");
        let mut f = at("192.168.1.7");
        // baseline: the unit as the install wrote it for the LAN address
        let old = userunit::render_bridge(&BridgeUnit { companion_bin: Path::new("/opt/am/c"), state_dir: &r.state, lan_ip: "192.168.1.7", port: 8788, llama_port: 41717, upstream_model: "m-1" }).unwrap();
        userunit::write_if_changed(&r.dir, BRIDGE_UNIT, &old).unwrap();
        let s = r.tick(&mut f, &hotspot_net(), Some("wlan0"), 100);
        assert_eq!(s, Step::Followed { to: lan("10.42.0.1"), forced: false, firewall: FwStep::Done });
        // byte exact: the same render with only the address changed
        assert_eq!(unit_text(&r.d), old.replace("192.168.1.7", "10.42.0.1"));
        assert!(unit_text(&r.d).contains("\nEnvironment=ARROWBRIDGE_BIND=10.42.0.1\n"));
        assert!(!unit_text(&r.d).contains("192.168.1.7"));
        assert_eq!(calls(&r.d), vec!["--user daemon-reload".to_string(), format!("--user reset-failed {U}"), format!("--user restart {U}")]);
        assert_eq!(*r.bound.borrow(), vec![lan("10.42.0.1")]);
        assert_eq!(r.fw(), vec!["allow 10.42.0.0/24", "remove 192.168.1.0/24"]);
        assert_eq!(f.bound, Some(lan("10.42.0.1")));
    }

    #[test]
    fn an_unchanged_pick_calls_and_writes_nothing() {
        let r = Rig::new("same");
        let mut f = at("192.168.1.7");
        for t in 0..5 {
            assert_eq!(r.tick(&mut f, &lan_net(), Some("enp3s0"), t * 3), Step::Unchanged);
        }
        assert!(calls(&r.d).is_empty());
        assert!(!r.dir.join(BRIDGE_UNIT).exists(), "wrote a unit with nothing changed");
        assert!(r.fw().is_empty() && r.bound.borrow().is_empty());
        assert_eq!(*r.busy_asked.borrow(), 0, "asked the companion with nothing changed");
    }

    #[test]
    fn hotspot_to_none_calls_nothing_and_a_return_to_the_same_network_restarts_nothing() {
        let r = Rig::new("none");
        let mut f = at("10.42.0.1");
        assert_eq!(r.tick(&mut f, &noise(), None, 0), Step::NoAddress);
        assert_eq!(r.tick(&mut f, &[], None, 3), Step::NoAddress);
        assert!(calls(&r.d).is_empty() && r.fw().is_empty() && !r.dir.join(BRIDGE_UNIT).exists());
        assert_eq!(f.bound, Some(lan("10.42.0.1")), "the bound address is remembered across the gap");
        // the same hotspot returns: the unit is still bound to it
        assert_eq!(r.tick(&mut f, &hotspot_net(), Some("wlan0"), 6), Step::Unchanged);
        assert!(calls(&r.d).is_empty());
        // a different network returns: the old one is withdrawn then
        let s = r.tick(&mut f, &lan_net(), Some("enp3s0"), 9);
        assert!(matches!(s, Step::Followed { firewall: FwStep::Done, .. }), "{s:?}");
        assert_eq!(r.fw(), vec!["allow 192.168.1.0/24", "remove 10.42.0.0/24"]);
    }

    #[test]
    fn flapping_follows_each_real_change_once_and_never_twice_for_one() {
        let r = Rig::new("flap");
        let mut f = at("192.168.1.7");
        let seq: [(&str, Vec<Iface>, &str); 8] = [
            ("a", lan_net(), "enp3s0"), ("b", hotspot_net(), "wlan0"), ("b", hotspot_net(), "wlan0"), ("a", lan_net(), "enp3s0"),
            ("b", hotspot_net(), "wlan0"), ("none", noise(), ""), ("b", hotspot_net(), "wlan0"), ("a", lan_net(), "enp3s0")];
        let mut followed = 0;
        for (i, (_, net, def)) in seq.iter().enumerate() {
            let before = calls(&r.d).len();
            let s = r.tick(&mut f, net, if def.is_empty() { None } else { Some(def) }, i as u64 * 3);
            match s {
                Step::Followed { to, .. } => {
                    followed += 1;
                    let c = calls(&r.d);
                    let tail = &c[before..];
                    let rf = tail.iter().position(|l| l == &format!("--user reset-failed {U}")).unwrap();
                    let rs = tail.iter().position(|l| l == &format!("--user restart {U}")).unwrap();
                    assert!(rf < rs, "reset-failed after restart: {tail:?}");
                    assert!(unit_text(&r.d).contains(&format!("ARROWBRIDGE_BIND={}\n", to.0)));
                }
                _ => assert_eq!(calls(&r.d).len(), before, "tick {i} called systemctl without a change"),
            }
        }
        // a>a no, a>b yes, b>b no, b>a yes, a>b yes, b>none no, none>b no (still bound to b), b>a yes
        assert_eq!(followed, 4);
        assert_eq!(calls(&r.d).iter().filter(|l| l.contains("restart")).count(), 4);
        assert_eq!(unit_text(&r.d).matches("ARROWBRIDGE_BIND=192.168.1.7\n").count(), 1);
    }

    #[test]
    fn never_binds_a_non_private_or_tailscale_or_wildcard_address() {
        let r = Rig::new("refuse");
        let mut f = Follower::default();
        let bad = ["0.0.0.0", "8.8.8.8", "100.64.0.1", "100.127.255.254", "169.254.1.1", "127.0.0.1", "172.15.0.1", "172.32.0.1", "192.169.0.1", "11.0.0.1", "224.0.0.1", "255.255.255.255"];
        let v: Vec<Iface> = bad.iter().enumerate().map(|(i, a)| ifc(&format!("wlan{i}"), a)).collect();
        assert_eq!(r.tick(&mut f, &v, None, 0), Step::NoAddress);
        assert!(calls(&r.d).is_empty() && !r.dir.join(BRIDGE_UNIT).exists() && r.fw().is_empty());
        // and the renderer itself refuses each, so a bad pick could not reach a unit even if the filter were wrong
        for a in bad.iter().chain(["::", "::1", "fe80::1", "010.0.0.1", "10.0.0.256", ""].iter()) {
            let bu = BridgeUnit { companion_bin: Path::new("/opt/am/c"), state_dir: Path::new("/s"), lan_ip: a, port: 8788, llama_port: 1, upstream_model: "m" };
            assert!(userunit::render_bridge(&bu).is_err(), "{a}");
        }
        // a private address next to the bad ones is the one that is bound
        let mut v2 = v.clone();
        v2.push(ifc("wlan9", "10.42.0.1"));
        assert!(matches!(r.tick(&mut f, &v2, None, 3), Step::Followed { to, .. } if to.0 == ip("10.42.0.1")));
        assert!(!unit_text(&r.d).contains("0.0.0.0") && !unit_text(&r.d).contains("100.64") && !unit_text(&r.d).contains("::"));
    }

    #[test]
    fn a_pairing_window_defers_the_restart_for_at_most_60_seconds_then_forces_it() {
        let r = Rig::new("busy");
        let mut f = at("192.168.1.7");
        *r.busy.borrow_mut() = true;
        for t in [0u64, 3, 30, 59] {
            assert_eq!(r.tick(&mut f, &hotspot_net(), Some("wlan0"), t), Step::Deferred, "t={t}");
        }
        assert!(calls(&r.d).is_empty() && !r.dir.join(BRIDGE_UNIT).exists() && r.bound.borrow().is_empty(), "deferral wrote or restarted");
        assert_eq!(f.bound, Some(lan("192.168.1.7")), "the address in use is unchanged while deferred");
        let s = r.tick(&mut f, &hotspot_net(), Some("wlan0"), 60);
        assert!(matches!(s, Step::Followed { forced: true, .. }), "{s:?}");
        assert!(calls(&r.d).iter().any(|l| l.contains("restart")));
        // the window closing before the cap restarts at once and is not forced
        let r2 = Rig::new("busy2");
        let mut f2 = at("192.168.1.7");
        *r2.busy.borrow_mut() = true;
        assert_eq!(r2.tick(&mut f2, &hotspot_net(), Some("wlan0"), 0), Step::Deferred);
        *r2.busy.borrow_mut() = false;
        assert!(matches!(r2.tick(&mut f2, &hotspot_net(), Some("wlan0"), 3), Step::Followed { forced: false, .. }));
    }

    #[test]
    fn a_failed_restart_keeps_the_old_binding_and_is_not_retried_every_poll() {
        let r = Rig::new("fail");
        let mut f = at("192.168.1.7");
        std::fs::write(r.d.join("fail_restart"), "").unwrap();
        assert!(matches!(r.tick(&mut f, &hotspot_net(), Some("wlan0"), 0), Step::Failed(_)));
        assert_eq!(f.bound, Some(lan("192.168.1.7")));
        assert!(r.bound.borrow().is_empty() && r.fw().is_empty(), "announced or opened the firewall for a restart that failed");
        let n = calls(&r.d).len();
        assert_eq!(r.tick(&mut f, &hotspot_net(), Some("wlan0"), 3), Step::Unchanged);
        assert_eq!(calls(&r.d).len(), n);
        std::fs::remove_file(r.d.join("fail_restart")).unwrap();
        assert!(matches!(r.tick(&mut f, &hotspot_net(), Some("wlan0"), 30), Step::Followed { .. }));
        // the retry finds the unit file already written and must still restart
        assert_eq!(calls(&r.d).iter().filter(|l| l.contains("restart")).count(), 2);
    }

    #[test]
    fn a_mask_only_change_restarts_nothing() {
        let r = Rig::new("mask");
        let mut f = at("192.168.1.7");
        let wide = Iface { name: "enp3s0".into(), ip: ip("192.168.1.7"), mask: ip("255.255.0.0") };
        let old = userunit::render_bridge(&BridgeUnit { companion_bin: Path::new("/opt/am/c"), state_dir: &r.state, lan_ip: "192.168.1.7", port: 8788, llama_port: 41717, upstream_model: "m-1" }).unwrap();
        userunit::write_if_changed(&r.dir, BRIDGE_UNIT, &old).unwrap();
        let s = r.tick(&mut f, &with(vec![wide]), Some("enp3s0"), 0);
        assert!(matches!(s, Step::Followed { .. }), "{s:?}");
        assert!(calls(&r.d).is_empty(), "restarted for a mask change");
        assert_eq!(r.fw(), vec!["allow 192.168.0.0/16", "remove 192.168.1.0/24"]);
    }

    #[test]
    fn with_no_unit_yet_the_unit_is_enabled_before_the_restart() {
        let r = Rig::new("first");
        let mut f = Follower::default();
        let s0 = r.tick(&mut f, &hotspot_net(), Some("wlan0"), 0); assert!(matches!(s0, Step::Followed { firewall: FwStep::Done, .. }), "{s0:?}");
        assert_eq!(calls(&r.d), vec!["--user daemon-reload".to_string(), format!("--user enable {U}"), format!("--user reset-failed {U}"), format!("--user restart {U}")]);
        assert_eq!(r.fw(), vec!["allow 10.42.0.0/24"], "nothing to withdraw on the first network");
    }

    #[test]
    fn a_refused_prompt_leaves_it_bound_and_closed_and_the_old_network_is_withdrawn_at_the_next_success() {
        let r = Rig::new("fwwait");
        let mut f = at("192.168.1.7");
        *r.allow_code.borrow_mut() = 126; // the person cancels the admin prompt
        let s = r.tick(&mut f, &hotspot_net(), Some("wlan0"), 0);
        assert!(matches!(s, Step::Followed { firewall: FwStep::Waiting(_), .. }), "{s:?}");
        assert_eq!(f.bound, Some(lan("10.42.0.1")), "the companion is bound even though the prompt was cancelled");
        assert_eq!(r.fw(), vec!["allow 10.42.0.0/24"], "withdrew a network while the new one was not allowed");
        // no prompt again on the next polls
        assert_eq!(r.tick(&mut f, &hotspot_net(), Some("wlan0"), 3), Step::Unchanged);
        assert_eq!(r.fw().len(), 1);
        // the person later moves on and answers: the LAN allow is still withdrawn, and the hotspot one too
        *r.allow_code.borrow_mut() = 0;
        let s = r.tick(&mut f, &with(vec![ifc("wlp2s0", "172.16.5.9")]), Some("wlp2s0"), 6);
        assert!(matches!(s, Step::Followed { firewall: FwStep::Done, .. }), "{s:?}");
        let fw = r.fw();
        assert_eq!(fw[1], "allow 172.16.5.0/24");
        assert!(fw[2..].contains(&"remove 192.168.1.0/24".to_string()) && fw[2..].contains(&"remove 10.42.0.0/24".to_string()), "{fw:?}");
    }

    #[test]
    fn returning_to_a_network_never_withdraws_the_rule_of_the_network_that_is_up() {
        let r = Rig::new("back");
        let mut f = at("192.168.1.7");
        *r.allow_code.borrow_mut() = 126;
        r.tick(&mut f, &hotspot_net(), Some("wlan0"), 0); // LAN left on the stale list
        *r.allow_code.borrow_mut() = 0;
        r.tick(&mut f, &lan_net(), Some("enp3s0"), 3); // back on the LAN
        let fw = r.fw();
        assert!(!fw.contains(&"remove 192.168.1.0/24".to_string()), "{fw:?}");
        assert_eq!(fw.last().unwrap(), "remove 10.42.0.0/24");
    }

    #[test]
    fn a_new_address_on_the_same_network_asks_nothing_of_the_firewall() {
        let r = Rig::new("samenet");
        let mut f = at("192.168.1.7");
        let s = r.tick(&mut f, &with(vec![ifc("enp3s0", "192.168.1.50")]), Some("enp3s0"), 0);
        assert_eq!(s, Step::Followed { to: lan("192.168.1.50"), forced: false, firewall: FwStep::NotNeeded });
        assert!(r.fw().is_empty());
        assert!(calls(&r.d).iter().any(|l| l.contains("restart")), "a new address in the unit needs the restart");
    }

    /// A pkexec that records every call. The poll thread's hooks must never reach it.
    fn recording_pkexec(d: &Path) -> PathBuf {
        let pk = d.join("pkexec");
        std::fs::write(&pk, format!("#!/bin/sh\n[ \"$1\" = __probe ] && exit 0\necho \"$@\" >> {}/pk.log\nexit 0\n", d.display())).unwrap();
        std::fs::set_permissions(&pk, std::fs::Permissions::from_mode(0o755)).unwrap();
        exec_ready(&pk);
        pk
    }
    fn helper_path() -> PathBuf { Path::new(env!("CARGO_MANIFEST_DIR")).join("../scripts/arrowbridge-fw") }

    #[test]
    fn the_poll_thread_never_prompts_and_the_window_button_allows_then_withdraws_the_old_networks() {
        let r = Rig::new("noprompt");
        let pk = recording_pkexec(&r.d);
        let helper = helper_path();
        let ctx = Ctx { ctl: &r.ctl, dir: &r.dir, companion_bin: Path::new("/opt/am/c"), state_dir: &r.state, llama_port: 41717, upstream_model: "m-1" };
        let mut f = at("192.168.1.7");
        // two moves with the poll thread's own hooks: bound each time, closed each time, no pkexec call
        let hooks = Hooks { bound: &|_| {}, allow: &defer_allow, remove: &defer_remove, busy: &|| false };
        let s = f.tick(&hotspot_net(), Some("wlan0"), &ctx, &hooks, 0);
        assert_eq!(s, Step::Followed { to: lan("10.42.0.1"), forced: false, firewall: FwStep::Waiting(format!("allow: Ok(Failed({PROMPT_FROM_WINDOW}))")) });
        let s = f.tick(&with(vec![ifc("wlp2s0", "172.16.5.9")]), Some("wlp2s0"), &ctx, &hooks, 3);
        assert!(matches!(s, Step::Followed { firewall: FwStep::Waiting(_), .. }), "{s:?}");
        assert!(!r.d.join("pk.log").exists(), "the poll thread raised an admin prompt");
        assert_eq!(f.stale, vec!["192.168.1.0/24".to_string(), "10.42.0.0/24".to_string()]);
        // the window's button: allow the network that is up, then withdraw the two that were left
        assert_eq!(firewall::allow_for(&pk, &helper, lan("172.16.5.9")).unwrap(), FwOutcome::Done);
        let cur = firewall::cidr_from(ip("172.16.5.9"), ip("255.255.255.0")).unwrap();
        withdraw_stale(&mut f.stale, Some(&cur), &|c| firewall::remove_for(&pk, &helper, c));
        assert!(f.stale.is_empty());
        let log: Vec<String> = std::fs::read_to_string(r.d.join("pk.log")).unwrap().lines().map(|l| l.splitn(2, ' ').nth(1).unwrap().to_string()).collect();
        assert_eq!(log, vec!["allow 172.16.5.0/24", "remove 192.168.1.0/24", "remove 10.42.0.0/24"]);
    }

    #[test]
    fn the_button_never_withdraws_the_network_that_is_up_and_keeps_an_unanswered_withdrawal() {
        let mut stale = vec!["10.42.0.0/24".to_string(), "192.168.1.0/24".to_string()];
        let asked = RefCell::new(vec![]);
        withdraw_stale(&mut stale, Some("10.42.0.0/24"), &|c| { asked.borrow_mut().push(c.to_string()); Ok(FwOutcome::Failed(126)) });
        assert_eq!(*asked.borrow(), vec!["192.168.1.0/24"]);
        assert_eq!(stale, vec!["192.168.1.0/24"], "a cancelled withdrawal must stay on the list");
    }

    #[test]
    fn the_firewall_moves_through_the_real_helper_calls_with_the_right_argv() {
        let r = Rig::new("realfw");
        let pk = r.d.join("pkexec");
        std::fs::write(&pk, format!("#!/bin/sh\n[ \"$1\" = __probe ] && exit 0\necho \"$@\" >> {}/pk.log\nexit 0\n", r.d.display())).unwrap();
        std::fs::set_permissions(&pk, std::fs::Permissions::from_mode(0o755)).unwrap();
        exec_ready(&pk);
        let helper = Path::new(env!("CARGO_MANIFEST_DIR")).join("../scripts/arrowbridge-fw");
        let mut f = at("192.168.1.7");
        let ctx = Ctx { ctl: &r.ctl, dir: &r.dir, companion_bin: Path::new("/opt/am/c"), state_dir: &r.state, llama_port: 41717, upstream_model: "m-1" };
        let allow = |l: Lan| firewall::allow_for(&pk, &helper, l);
        let remove = |c: &str| firewall::remove_for(&pk, &helper, c);
        let s = f.tick(&hotspot_net(), Some("wlan0"), &ctx, &Hooks { bound: &|_| {}, allow: &allow, remove: &remove, busy: &|| false }, 0);
        assert!(matches!(s, Step::Followed { firewall: FwStep::Done, .. }), "{s:?}");
        let log: Vec<String> = std::fs::read_to_string(r.d.join("pk.log")).unwrap().lines().map(|l| l.rsplit(' ').take(2).collect::<Vec<_>>().into_iter().rev().collect::<Vec<_>>().join(" ")).collect();
        assert_eq!(log, vec!["allow 10.42.0.0/24", "remove 192.168.1.0/24"]);
    }
}
