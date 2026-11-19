//! Release 11, S2: the firewall rule for TCP 8788. The app never touches ufw itself; it calls the fixed root
//! helper (scripts/arrowbridge-fw) through pkexec with an argv list, never a shell. The CIDR comes from the
//! interface netmask. The Rust validator mirrors the helper's; both are tested against the same vectors.

use std::net::Ipv4Addr;
use std::path::Path;
use std::process::Command;

/// Where the package installs the helper (read-only, root-owned). Matches the polkit action's exec.path.
pub const HELPER_PATH: &str = "/usr/lib/arrowmem/arrowbridge-fw";

#[derive(Debug, PartialEq)]
pub enum FwOutcome {
    Done,
    /// Helper exit 3: ufw missing or inactive. Nothing changed; the status window says so.
    NoFirewall,
    /// The packaged helper is not on this machine (AppImage run). Nothing was asked of the user.
    HelperMissing,
    Failed(i32),
}

/// Network CIDR (e.g. "192.168.1.0/24") for an interface address and netmask. The mask must be contiguous with
/// a prefix of /16 to /30, the address private, and the whole network inside one RFC1918 block.
pub fn cidr_from(ip: Ipv4Addr, mask: Ipv4Addr) -> Result<String, String> {
    let m = u32::from(mask);
    let prefix = m.leading_ones();
    if m.count_ones() != prefix || !(16..=30).contains(&prefix) {
        return Err(format!("mask {mask} is not a /16 to /30 contiguous mask"));
    }
    let net = Ipv4Addr::from(u32::from(ip) & m);
    let c = format!("{net}/{prefix}");
    validate_cidr(&c).map(|_| c)
}

pub fn validate_cidr(c: &str) -> Result<(), String> {
    let bad = || format!("refused CIDR: {c}");
    let (addr, pre) = c.split_once('/').ok_or_else(bad)?;
    let canon = |s: &str| !s.is_empty() && s.len() <= 3 && s.bytes().all(|b| b.is_ascii_digit()) && (s == "0" || !s.starts_with('0'));
    let parts: Vec<&str> = addr.split('.').collect();
    if parts.len() != 4 || !parts.iter().all(|p| canon(p)) || !canon(pre) || pre.len() != 2 {
        return Err(bad());
    }
    let o: Vec<u8> = parts.iter().map(|p| p.parse::<u8>()).collect::<Result<_, _>>().map_err(|_| bad())?;
    let p: u32 = pre.parse().map_err(|_| bad())?;
    if !(16..=30).contains(&p) {
        return Err(bad());
    }
    let block_ok = match (o[0], o[1]) {
        (10, _) => true,
        (172, b) if (16..=31).contains(&b) => true,
        (192, 168) => true,
        _ => false,
    };
    let ip = u32::from(Ipv4Addr::new(o[0], o[1], o[2], o[3]));
    let mask = u32::MAX << (32 - p);
    if block_ok && ip & mask == ip { Ok(()) } else { Err(bad()) }
}

fn run(pkexec: &Path, helper: &Path, args: &[&str]) -> Result<FwOutcome, String> {
    let out = Command::new(pkexec).arg(helper).args(args).output().map_err(|e| format!("pkexec: {e}"))?;
    Ok(match out.status.code() {
        Some(0) => FwOutcome::Done,
        Some(3) => FwOutcome::NoFirewall,
        Some(c) => FwOutcome::Failed(c),
        None => FwOutcome::Failed(-1),
    })
}

/// A Linux interface name as the helper takes it: 1 to 15 characters of letters, digits and `_ . : -`, the first a letter or digit.
pub fn validate_iface(n: &str) -> Result<(), String> {
    let ok = !n.is_empty() && n.len() <= 15 && n.bytes().all(|b| b.is_ascii_alphanumeric() || b"_.:-".contains(&b)) && n.as_bytes()[0].is_ascii_alphanumeric();
    if ok { Ok(()) } else { Err(format!("refused interface name: {n}")) }
}

/// The address the companion is bound to must be a literal inside the network the rule names (the helper checks the same).
fn bound_in(ip: Ipv4Addr, cidr: &str) -> Result<(), String> {
    validate_cidr(cidr)?;
    let (net, p) = cidr.split_once('/').ok_or_else(|| format!("refused CIDR: {cidr}"))?;
    let (net, p): (Ipv4Addr, u32) = (net.parse().map_err(|_| format!("refused CIDR: {cidr}"))?, p.parse().map_err(|_| format!("refused CIDR: {cidr}"))?);
    let mask = u32::MAX << (32 - p);
    if u32::from(ip) & mask == u32::from(net) { Ok(()) } else { Err(format!("{ip} is not inside {cidr}")) }
}

/// One elevated prompt: allow TCP 8788 in on this interface, from this network, to the bound address only.
pub fn allow(pkexec: &Path, helper: &Path, iface: &str, cidr: &str, bound: Ipv4Addr) -> Result<FwOutcome, String> {
    scoped_run(pkexec, helper, "allow", iface, cidr, bound)
}

/// `allow` and `replace` take the same three scoped arguments, validated the same way before pkexec.
fn scoped_run(pkexec: &Path, helper: &Path, verb: &str, iface: &str, cidr: &str, bound: Ipv4Addr) -> Result<FwOutcome, String> {
    validate_iface(iface)?;
    bound_in(bound, cidr)?;
    run(pkexec, helper, &[verb, iface, cidr, &bound.to_string()])
}

/// `Failed` code when no interface holds the address the follow picked: nothing is asked, no interface name is ever taken from anywhere else.
pub const NO_IFACE: i32 = -4;

/// The rules the app asked for, one line "interface network bound address" each, in a file in the data dir (a record in memory is lost at every
/// restart, and a withdrawal after one then reported Done without asking). A withdrawal names the interface, network and address the allow named,
/// because the helper deletes that one rule by its spec. A network never allowed has no line, so its withdrawal has nothing to ask.
const RECORD: &str = "fw-allowed";

type Rule = (String, String, String);

/// One read, change, write of the record at a time, across threads and across app processes: an exclusive flock on a lock file
/// in the data dir, held until the returned file is dropped. The temp file has one fixed name, so two writers without this lose a line or interleave it.
/// Each call opens its own file, and flock is per open file, so two threads of one process exclude each other too.
fn lock_record(store: &Path) -> Result<std::fs::File, String> {
    use std::os::unix::fs::OpenOptionsExt;
    let open = || -> std::io::Result<std::fs::File> {
        std::fs::create_dir_all(store)?;
        let f = std::fs::OpenOptions::new().write(true).create(true).truncate(false).mode(0o600).open(store.join(format!("{RECORD}.lock")))?;
        f.lock()?;
        Ok(f)
    };
    open().map_err(|e| format!("firewall record lock: {e}"))
}

fn record_path(store: &Path) -> std::path::PathBuf { store.join(RECORD) }

/// The recorded rules. An absent file is none; a line that is not three well formed fields is ignored (the helper validates again at use).
fn recorded_rules(store: &Path) -> Vec<Rule> {
    let text = std::fs::read_to_string(record_path(store)).unwrap_or_default();
    text.lines().filter_map(|l| {
        let mut f = l.split(' ');
        let (i, c, b) = (f.next()?, f.next()?, f.next()?);
        (f.next().is_none() && validate_iface(i).is_ok() && validate_cidr(c).is_ok() && b.parse::<Ipv4Addr>().is_ok()).then(|| (i.to_string(), c.to_string(), b.to_string()))
    }).collect()
}

/// Temp file in the same dir, fsync, rename, 0600: a crash leaves the old record or the new one, never half of one.
fn write_record(store: &Path, rules: &[Rule]) -> Result<(), String> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let body: String = rules.iter().map(|(i, c, b)| format!("{i} {c} {b}\n")).collect();
    let tmp = store.join(format!("{RECORD}.tmp"));
    let w = || -> std::io::Result<()> {
        std::fs::create_dir_all(store)?;
        let mut f = std::fs::OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).open(&tmp)?;
        f.write_all(body.as_bytes())?;
        f.sync_all()?;
        std::fs::rename(&tmp, record_path(store))?;
        std::fs::File::open(store)?.sync_all() // the rename itself is durable only once the directory is synced
    };
    w().map_err(|e| format!("firewall record: {e}"))
}

/// The networks with a recorded rule: what a restarted app must treat as possibly stale (the caller drops the one that is up).
pub fn recorded_cidrs(store: &Path) -> Vec<String> {
    let mut v: Vec<String> = Vec::new();
    for (_, c, _) in recorded_rules(store) {
        if !v.contains(&c) { v.push(c); }
    }
    v
}

/// `Failed` code for a helper too old to know `remove <iface> <cidr> <bound>` (reported, never skipped silently).
pub const VERSION_REFUSED: i32 = -2;

/// The `HELPER_VERSION=N` line of the installed helper (root-owned, world-readable; reading it costs no prompt). None when absent or unreadable.
pub fn helper_version(helper: &Path) -> Option<u32> {
    std::fs::read_to_string(helper).ok()?.lines().find_map(|l| l.strip_prefix("HELPER_VERSION=")?.trim().parse().ok())
}

/// The follow's allow: this interface's network (address and mask) as one CIDR, scoped to the interface that holds that address (read from `ifaces`, the
/// follow's own list; no other name is ever passed) and to that address. A missing helper is `HelperMissing`, no prompt. A helper older than 3 does not know
/// this form and is refused as `Failed(VERSION_REFUSED)`; an address no interface holds is `Failed(NO_IFACE)`; neither reaches pkexec.
pub fn allow_for(pkexec: &Path, helper: &Path, store: &Path, lan: (Ipv4Addr, Ipv4Addr), ifaces: &[crate::linuxrun::Iface]) -> Result<FwOutcome, String> {
    scoped_for("allow", 3, pkexec, helper, store, lan, ifaces)
}

/// The upgrade from 0.1.2 in one admin prompt: the helper's `replace` (version 5) removes every tagged rule and adds this scoped allow in the same
/// run. Same checks and the same record as `allow_for`; a helper older than 5 is refused as `Failed(VERSION_REFUSED)` before any prompt.
pub fn replace_for(pkexec: &Path, helper: &Path, store: &Path, lan: (Ipv4Addr, Ipv4Addr), ifaces: &[crate::linuxrun::Iface]) -> Result<FwOutcome, String> {
    scoped_for("replace", 5, pkexec, helper, store, lan, ifaces)
}

fn scoped_for(verb: &str, min_version: u32, pkexec: &Path, helper: &Path, store: &Path, lan: (Ipv4Addr, Ipv4Addr), ifaces: &[crate::linuxrun::Iface]) -> Result<FwOutcome, String> {
    let cidr = cidr_from(lan.0, lan.1)?;
    if !helper.exists() {
        return Ok(FwOutcome::HelperMissing);
    }
    if !helper_version(helper).is_some_and(|v| v >= min_version) {
        return Ok(FwOutcome::Failed(VERSION_REFUSED));
    }
    let Some(i) = ifaces.iter().find(|i| i.ip == lan.0 && i.mask == lan.1) else { return Ok(FwOutcome::Failed(NO_IFACE)) };
    let r = scoped_run(pkexec, helper, verb, &i.name, &cidr, lan.0)?;
    if r == FwOutcome::Done {
        let _g = lock_record(store)?;
        let mut a = recorded_rules(store);
        let rule = (i.name.clone(), cidr, lan.0.to_string());
        if !a.contains(&rule) {
            a.push(rule);
            write_record(store, &a)?;
        }
    }
    Ok(r)
}

/// The follow's withdrawal: delete the recorded rule for exactly this network, by its spec (interface, network, bound address). Needs helper version 4: an
/// older helper reads the four word form as bad usage, so it is refused here as `Failed(VERSION_REFUSED)` (the existing Failed state), never skipped silently.
/// A network with no recorded rule has nothing to withdraw: `Done`, no prompt. The record is read from disk, so this holds after a restart.
pub fn remove_for(pkexec: &Path, helper: &Path, store: &Path, cidr: &str) -> Result<FwOutcome, String> {
    validate_cidr(cidr)?;
    if !helper.exists() {
        return Ok(FwOutcome::HelperMissing);
    }
    if !helper_version(helper).is_some_and(|v| v >= 4) {
        return Ok(FwOutcome::Failed(VERSION_REFUSED));
    }
    for (iface, c, bound) in recorded_rules(store).into_iter().filter(|(_, c, _)| c == cidr) {
        let r = run(pkexec, helper, &["remove", &iface, cidr, &bound])?;
        if r != FwOutcome::Done {
            return Ok(r);
        }
        let _g = lock_record(store)?;
        let mut a = recorded_rules(store);
        a.retain(|x| *x != (iface.clone(), c.clone(), bound.clone()));
        write_record(store, &a)?;
    }
    Ok(FwOutcome::Done)
}

/// The status window shows the waiting firewall step while the poll thread left it for the button (`flag`) or a left network's allow is still on
/// the stale list: both need one press, and neither is announced any other way. Not while the last press found no active firewall (`no_firewall`):
/// nothing blocks the phone then, and the stale list is kept silently for the day ufw comes back.
pub fn button_needed(flag: bool, stale: &[String], no_firewall: bool) -> bool {
    !no_firewall && (flag || !stale.is_empty())
}

/// Remove exactly the rules the helper tagged.
pub fn remove(pkexec: &Path, helper: &Path) -> Result<FwOutcome, String> {
    if !helper.exists() {
        return Ok(FwOutcome::HelperMissing); // no helper, no rule of ours, and no prompt
    }
    run(pkexec, helper, &["remove"])
}

/// Test helper for every fake script in this crate. Parallel tests fork while a script is being written, and a child that still holds the write fd makes the
/// first exec fail with ETXTBSY (os error 26). Run the script with `__probe` until it can run (the script must exit 0 on `__probe` before doing anything);
/// after that no copy of the write fd exists.
#[cfg(test)]
pub(crate) fn exec_ready(p: &Path) {
    for _ in 0..200 {
        match Command::new(p).arg("__probe").output() {
            Err(e) if e.raw_os_error() == Some(26) => std::thread::sleep(std::time::Duration::from_millis(10)),
            _ => return,
        }
    }
    panic!("script never became executable");
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;

    const GOOD: &[&str] = &["192.168.1.0/24", "192.168.0.0/16", "10.0.0.0/16", "10.1.2.0/30", "172.16.0.0/16", "172.31.255.252/30", "10.0.0.0/24"];
    const BAD: &[&str] = &["010.0.0.0/24", "192.168.01.0/24", "192.168.1.0/024", "192.168.1.0/8", "10.0.0.0/15", "10.0.0.0/31", "10.0.0.0/32",
        "8.8.8.0/24", "172.15.0.0/16", "172.32.0.0/16", "172.16.0.0/11", "192.169.0.0/24", "0.0.0.0/24", "127.0.0.0/24",
        "192.168.1.5/24", "10.0.0.0", "10.0.0.0/", "/24", "10.0.0/24", "10.0.0.0.0/24", "10.0.0.256/24", "10.0.0.0/24 ", "10.0.0.0/2a",
        "10.0.0.0/24;ls", "-1.0.0.0/24", "10.0.0.0/+4"];

    fn script() -> PathBuf { Path::new(env!("CARGO_MANIFEST_DIR")).join("../scripts/arrowbridge-fw") }
    fn tmp(tag: &str) -> crate::testtmp::TmpDir {
        crate::testtmp::TmpDir::new(&format!("fw-{tag}"))
    }
    /// Stateful fake ufw in `d`. Files: `rules` (lines "to|from|comment"), `active` (present = active),
    /// `ufw_fail`, `french` (print French unless LC_ALL=C), `shift_at` (on that numbered-listing call, first drop
    /// rule 1, as another process would), `listcalls` (counter). Every call is appended to calls.log.
    fn fake_ufw(d: &Path, active: bool, rules: &[&str]) {
        std::fs::write(d.join("rules"), rules.iter().map(|r| format!("{r}\n")).collect::<String>()).unwrap();
        if active { std::fs::write(d.join("active"), "").unwrap(); } else { let _ = std::fs::remove_file(d.join("active")); }
        let p = d.join("ufw");
        let dd = d.display();
        std::fs::write(&p, format!(r#"#!/bin/sh
D={dd}
[ "$1" = __probe ] && exit 0
echo "$@" >> $D/calls.log
if [ -f $D/slow ]; then mkdir $D/busy 2>/dev/null || touch $D/overlap; sleep 0.05; rmdir $D/busy 2>/dev/null; fi
if [ "$1" = status ]; then
  if [ ! -f $D/active ]; then
    if [ -f $D/french ] && [ "$LC_ALL" != C ]; then echo "Statut : inactif"; else echo "Status: inactive"; fi; exit 0
  fi
  if [ -f $D/french ] && [ "$LC_ALL" != C ]; then echo "Statut : actif"; else echo "Status: active"; fi
  if [ "$2" = numbered ]; then
    c=$(cat $D/listcalls 2>/dev/null || echo 0); c=$((c+1)); echo $c > $D/listcalls
    if [ -f $D/shift_at ] && [ "$c" = "$(cat $D/shift_at)" ]; then awk 'NR!=1' $D/rules > $D/rules.new && mv $D/rules.new $D/rules; fi
    awk -F'|' '{{ printf "[%2d] %s ALLOW IN    %s", NR, $1, $2; if ($3 != "") printf "             # %s", $3; printf "\n" }}' $D/rules
  fi
  exit 0
fi
[ -f $D/ufw_fail ] && exit 1
if [ "$1" = --force ] && [ "$2" = delete ] && [ "$3" = allow ]; then
  awk -F'|' -v w="${{10}} 8788/tcp on $6" -v s="$8" '$1==w && $2==s && !d {{ d=1; next }} {{ print }}' $D/rules > $D/rules.new && mv $D/rules.new $D/rules
elif [ "$1" = --force ] && [ "$2" = delete ]; then awk -v n="$3" 'NR!=n' $D/rules > $D/rules.new && mv $D/rules.new $D/rules; fi
exit 0
"#)).unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
        exec_ready(&p);
    }
    /// Copy of the shipped script in `d` with only its `UFW=` line pointed at `ufw_path`.
    fn script_copy(d: &Path, ufw_path: &Path) -> PathBuf {
        let src = std::fs::read_to_string(script()).unwrap();
        let lines: Vec<&str> = src.lines().collect();
        assert_eq!(lines.iter().filter(|l| **l == "UFW=/usr/sbin/ufw").count(), 1, "shipped script must carry exactly one UFW= line");
        assert_eq!(lines.iter().filter(|l| **l == "LOCK=/run/arrowbridge-fw.lock").count(), 1, "shipped script must carry exactly one LOCK= line");
        let lock = ufw_path.with_file_name("fw.lock");
        let out: Vec<String> = lines.iter().map(|l| match *l {
            "UFW=/usr/sbin/ufw" => format!("UFW={}", ufw_path.display()),
            "LOCK=/run/arrowbridge-fw.lock" => format!("LOCK={}", lock.display()),
            _ => l.to_string(),
        }).collect();
        let p = d.join("arrowbridge-fw.test");
        std::fs::write(&p, out.join("\n") + "\n").unwrap();
        p
    }
    fn sh_env(d: &Path, args: &[&str], lc_all: &str) -> (i32, String) {
        let o = Command::new("/bin/bash").arg(script_copy(d, &d.join("ufw"))).args(args)
            .env_clear().env("PATH", "/usr/bin:/bin").env("LC_ALL", lc_all).output().unwrap();
        (o.status.code().unwrap(), std::fs::read_to_string(d.join("calls.log")).unwrap_or_default())
    }
    fn sh(d: &Path, args: &[&str]) -> (i32, String) { sh_env(d, args, "C") }
    fn rules(d: &Path) -> Vec<String> { std::fs::read_to_string(d.join("rules")).unwrap().lines().map(String::from).collect() }
    fn mutations(log: &str) -> Vec<&str> { log.lines().filter(|l| l.contains("delete") || l.starts_with("allow")).collect() }

    #[test]
    fn rust_validator_vectors() {
        for g in GOOD { assert!(validate_cidr(g).is_ok(), "{g}"); }
        for b in BAD { assert!(validate_cidr(b).is_err(), "{b}"); }
    }

    #[test]
    fn script_validator_same_vectors() {
        let d = tmp("val");
        fake_ufw(&d, true, &[]);
        for g in GOOD {
            let _ = std::fs::remove_file(d.join("calls.log"));
            let ip = inside(g);
            let (c, log) = sh(&d, &["allow", "wlan0", g, &ip]);
            assert_eq!(c, 0, "{g}");
            // The rule is scoped to the interface and to the bound address
            assert!(log.contains(&format!("allow in on wlan0 from {g} to {ip} port 8788 proto tcp comment arrowbridge")), "{log}");
        }
        for b in BAD {
            let _ = std::fs::remove_file(d.join("calls.log"));
            let (c, log) = sh(&d, &["allow", "wlan0", b, "10.0.0.1"]);
            assert_eq!(c, 2, "{b}");
            assert_eq!(log, "", "{b} reached ufw");
        }
    }

    /// A bad interface name or a bound address outside the network exits 2 and ufw is never called.
    #[test]
    fn script_refuses_a_bad_interface_name_or_a_bound_address_outside_the_network() {
        let d = tmp("iface");
        fake_ufw(&d, true, &[]);
        let long = "a".repeat(16);
        for n in ["", "-x", "_x", ".x", "wlan 0", "wlan0;ls", "wl/an0", "../x", "wlan0\n", "wlan0 ", "$(id)", "wlan0'", long.as_str()] {
            let _ = std::fs::remove_file(d.join("calls.log"));
            let (c, log) = sh(&d, &["allow", n, "10.0.0.0/24", "10.0.0.1"]);
            assert_eq!(c, 2, "allow {n:?}");
            assert_eq!(log, "", "{n:?} reached ufw");
            let (c, log) = sh(&d, &["remove", n, "10.0.0.0/24", "10.0.0.1"]);
            assert_eq!(c, 2, "remove {n:?}");
            assert_eq!(log, "", "{n:?} reached ufw");
        }
        for ip in ["10.0.1.1", "192.168.1.1", "8.8.8.8", "10.0.0.01", "10.0.0.256", "10.0.0", "10.0.0.1.1", "10.0.0.1;ls", "", "0.0.0.0"] {
            let _ = std::fs::remove_file(d.join("calls.log"));
            let (c, log) = sh(&d, &["allow", "wlan0", "10.0.0.0/24", ip]);
            assert_eq!(c, 2, "bound {ip:?}");
            assert_eq!(log, "", "bound {ip:?} reached ufw");
        }
        // a name of the longest legal length and the usual shapes pass
        for n in ["wlan0", "enp3s0", "wlp0s20f3", "eth0.100", "br0:1", "a-b_c", "a23456789012345"] {
            assert_eq!(sh(&d, &["allow", n, "10.0.0.0/24", "10.0.0.1"]).0, 0, "{n}");
        }
    }

    /// A withdrawal names the interface AND the network; the same network on another interface, and another network on the same one, stay.
    #[test]
    fn remove_deletes_only_the_exact_interface_and_network() {
        let d = tmp("rmiface");
        let (a, b, c, e) = (scoped("wlan0", "192.168.43.0/24"), scoped("enp3s0", "192.168.43.0/24"), scoped("wlan0", "10.42.0.0/24"), scoped("wlan01", "192.168.43.0/24"));
        let f = "192.168.43.1 8788/tcp on xwlan0|192.168.43.0/24|arrowbridge".to_string();
        fake_ufw(&d, true, &[&a, &b, &c, &e, &f, "22/tcp|192.168.43.0/24|"]);
        let (code, log) = sh(&d, &["remove", "wlan0", "192.168.43.0/24", "192.168.43.1"]);
        assert_eq!(code, 0);
        assert_eq!(rules(&d), vec![b, c, e, f, "22/tcp|192.168.43.0/24|".to_string()], "only the wlan0 plus 192.168.43.0/24 rule may go: {log}");
        assert_eq!(log.lines().filter(|l| l.contains("delete")).count(), 1, "{log}");
    }

    /// A per network withdrawal deletes by the rule spec, never by a listing number, so a shifting list cannot make it delete another rule.
    #[test]
    fn remove_by_spec_names_the_spec_and_never_a_number() {
        let d = tmp("spec");
        let a = scoped("wlan0", "192.168.43.0/24");
        fake_ufw(&d, true, &["22/tcp|Anywhere|", &a, "443/tcp|Anywhere|"]);
        std::fs::write(d.join("shift_at"), "1").unwrap(); // the very first numbered listing drops rule 1, as another root process would
        let (code, log) = sh(&d, &["remove", "wlan0", "192.168.43.0/24", "192.168.43.1"]);
        assert_eq!(code, 0, "{log}");
        let dels: Vec<&str> = log.lines().filter(|l| l.contains("delete")).collect();
        assert_eq!(dels, vec!["--force delete allow in on wlan0 from 192.168.43.0/24 to 192.168.43.1 port 8788 proto tcp"], "{log}");
        assert_eq!(rules(&d), vec!["443/tcp|Anywhere|"], "the untagged 443 rule must survive; the 22 rule went to the outside edit only");
    }

    /// Two helper runs at once never interleave their ufw calls (the lock). The fake flags any ufw call that starts while another is running.
    #[test]
    fn two_helper_runs_at_once_take_turns() {
        let d = tmp("lock");
        let (a, b) = (scoped("wlan0", "192.168.43.0/24"), scoped("enp3s0", "10.0.0.0/24"));
        fake_ufw(&d, true, &["22/tcp|Anywhere|", &a, &b]);
        std::fs::write(d.join("slow"), "").unwrap();
        let (d1, d2) = (d.to_path_buf(), d.to_path_buf());
        let t1 = std::thread::spawn(move || sh(&d1, &["remove", "wlan0", "192.168.43.0/24", "192.168.43.1"]).0);
        let t2 = std::thread::spawn(move || sh(&d2, &["remove", "enp3s0", "10.0.0.0/24", "10.0.0.1"]).0);
        assert_eq!((t1.join().unwrap(), t2.join().unwrap()), (0, 0));
        assert!(!d.join("overlap").exists(), "two helper runs were inside ufw at the same time");
        assert_eq!(rules(&d), vec!["22/tcp|Anywhere|"]);
    }

    /// The real ufw is not run here: the fake's listing and delete forms were written by the same author. The real ufw remove test is the VM lab's.
    #[test]
    fn the_shipped_helper_lock_is_root_owned_run_not_world_writable_tmp() {
        let src = std::fs::read_to_string(script()).unwrap();
        assert_eq!(src.lines().filter(|l| l.starts_with("LOCK=")).collect::<Vec<_>>(), vec!["LOCK=/run/arrowbridge-fw.lock"]);
        assert!(src.contains("flock -w 60 9"));
    }

    /// The root lock file is mode 0600 whatever the umask and whatever an earlier run left, so no other user can open it and hold the lock.
    #[test]
    fn the_helper_lock_file_is_0600_fresh_or_left_over() {
        let d = tmp("lockmode");
        fake_ufw(&d, true, &[]);
        let lock = d.join("fw.lock");
        let mode = || std::fs::metadata(&lock).unwrap().permissions().mode() & 0o777;
        assert_eq!(sh(&d, &["remove"]).0, 0);
        assert_eq!(mode(), 0o600, "fresh lock file");
        std::fs::set_permissions(&lock, std::fs::Permissions::from_mode(0o644)).unwrap(); // what the 0.2 helper before this fix left
        assert_eq!(sh(&d, &["remove"]).0, 0);
        assert_eq!(mode(), 0o600, "left over lock file");
    }

    /// The file mode test cannot tell umask from chmod. The umask is what closes the moment between the open creating the lock file and
    /// the chmod, so a source guard: `umask 077` comes before the line that opens the lock file, inside take_lock.
    #[test]
    fn the_helper_sets_umask_077_before_it_opens_the_lock_file() {
        let src = std::fs::read_to_string(script()).unwrap();
        let body = src.split("take_lock() {").nth(1).unwrap().split("\n}\n").next().unwrap();
        let (umask, open, chmod) = (body.find("umask 077").expect("no umask 077 in take_lock"), body.find("exec 9>\"$LOCK\"").unwrap(), body.find("chmod 600").unwrap());
        assert!(umask < open && open < chmod, "order must be umask 077, open the lock file, chmod 600");
    }

    #[test]
    fn script_rejects_other_commands_and_extra_args() {
        let d = tmp("cmd");
        fake_ufw(&d, true, &[]);
        for a in [vec![], vec!["reset"], vec!["allow"], vec!["allow", "10.0.0.0/24", "x"], vec!["remove", "x"], vec!["delete", "1"],
                  // the version 2 forms are gone: no interface, no scope
                  vec!["allow", "10.0.0.0/24"], vec!["allow", "wlan0", "10.0.0.0/24"], vec!["allow", "wlan0", "10.0.0.0/24", "10.0.0.1", "x"],
                  vec!["remove", "10.0.0.0/24"], vec!["remove", "wlan0"], vec!["remove", "wlan0", "10.0.0.0/24", "x"],
                  // the version 3 withdrawal form (no bound address) is gone: the spec needs the address
                  vec!["remove", "wlan0", "10.0.0.0/24"]] {
            let (c, log) = sh(&d, &a);
            assert_eq!(c, 2, "{a:?}");
            assert_eq!(log, "");
        }
    }

    #[test]
    fn inactive_or_missing_ufw_exits_3_and_changes_nothing() {
        let d = tmp("inact");
        fake_ufw(&d, false, &["8788/tcp|10.0.0.0/24|arrowbridge"]);
        for a in [vec!["allow", "wlan0", "10.0.0.0/24", "10.0.0.1"], vec!["remove"]] {
            let _ = std::fs::remove_file(d.join("calls.log"));
            let (c, log) = sh(&d, &a);
            assert_eq!(c, 3, "{a:?}");
            assert!(mutations(&log).is_empty(), "{log}");
        }
        assert_eq!(rules(&d).len(), 1);
        // a ufw that does not exist at all
        let o = Command::new("/bin/bash").arg(script_copy(&d, &d.join("no-such-ufw"))).arg("remove")
            .env_clear().env("PATH", "/usr/bin:/bin").output().unwrap();
        assert_eq!(o.status.code(), Some(3));
    }

    #[test]
    fn translated_ufw_output_is_forced_to_c_locale() {
        let d = tmp("fr");
        fake_ufw(&d, true, &["8788/tcp|10.0.0.0/24|arrowbridge"]);
        std::fs::write(d.join("french"), "").unwrap();
        // the caller's locale is French; the script must still see "Status: active" and delete the rule
        let (c, _) = sh_env(&d, &["remove"], "fr_FR.UTF-8");
        assert_eq!(c, 0);
        assert!(rules(&d).is_empty());
        let (c2, _) = sh_env(&d, &["allow", "wlan0", "10.0.0.0/24", "10.0.0.1"], "fr_FR.UTF-8");
        assert_eq!(c2, 0);
    }

    #[test]
    fn shipped_script_has_no_test_hook_and_no_env_driven_binary() {
        let src = std::fs::read_to_string(script()).unwrap();
        assert!(!src.contains("ARROWBRIDGE_FW_TEST"));
        assert!(!src.contains("ARROWBRIDGE_"), "the helper reads no ARROWBRIDGE_ variable");
        assert_eq!(src.lines().filter(|l| l.starts_with("PATH=")).collect::<Vec<_>>(), vec!["PATH=/usr/sbin:/usr/bin:/sbin:/bin"]);
        assert_eq!(src.lines().filter(|l| l.starts_with("UFW=")).collect::<Vec<_>>(), vec!["UFW=/usr/sbin/ufw"]);
        // ufw is only ever run through $UFW; no bare call and no id/uid branch
        assert!(!src.lines().any(|l| { let t = l.trim_start(); t.starts_with("ufw ") || t.contains("$(ufw ") || t.contains("id -u") }));
        // nothing in the script is resolved from the environment: the only ${...} expansions are plain positional/array ones
        assert!(!src.contains("${UFW:-") && !src.contains("${UFW="));
    }

    #[test]
    fn remove_deletes_only_tagged_rules_highest_first() {
        let d = tmp("rm");
        fake_ufw(&d, true, &[
            "22/tcp|Anywhere|", "8788/tcp|192.168.1.0/24|arrowbridge", "80/tcp|Anywhere|arrowbridge2",
            "9000/tcp|10.0.0.0/24|not arrowbridge", "8788/tcp|10.1.0.0/16|arrowbridge", "443/tcp|Anywhere|",
            "8788/tcp|172.16.0.0/16|arrowbridge"]);
        let (c, log) = sh(&d, &["remove"]);
        assert_eq!(c, 0);
        assert_eq!(rules(&d), vec!["22/tcp|Anywhere|", "80/tcp|Anywhere|arrowbridge2", "9000/tcp|10.0.0.0/24|not arrowbridge", "443/tcp|Anywhere|"]);
        let dels: Vec<&str> = log.lines().filter(|l| l.contains("delete")).collect();
        assert_eq!(dels, vec!["--force delete 7", "--force delete 5", "--force delete 2"], "{log}");
    }

    #[test]
    fn remove_survives_numbering_that_shifts_mid_run() {
        let d = tmp("shift");
        fake_ufw(&d, true, &["22/tcp|Anywhere|", "8788/tcp|10.0.0.0/24|arrowbridge", "443/tcp|Anywhere|", "8788/tcp|10.1.0.0/16|arrowbridge"]);
        // On the 2nd listing (the confirm read before the first delete) another process drops rule 1.
        std::fs::write(d.join("shift_at"), "2").unwrap();
        let (c, _) = sh(&d, &["remove"]);
        assert_eq!(c, 0);
        // Every tagged rule is gone and the untagged one that survived the outside edit is untouched.
        assert_eq!(rules(&d), vec!["443/tcp|Anywhere|"]);
    }

    #[test]
    fn remove_never_deletes_an_untagged_rule_when_numbers_shift() {
        let d = tmp("shift2");
        fake_ufw(&d, true, &["8788/tcp|10.0.0.0/24|arrowbridge", "22/tcp|Anywhere|", "443/tcp|Anywhere|"]);
        std::fs::write(d.join("shift_at"), "2").unwrap(); // rule 1 (the tagged one) vanishes between the reads
        let (c, log) = sh(&d, &["remove"]);
        assert_eq!(c, 0);
        assert!(!log.contains("delete"), "deleted something after the target moved: {log}");
        assert_eq!(rules(&d), vec!["22/tcp|Anywhere|", "443/tcp|Anywhere|"]);
    }

    #[test]
    fn remove_cidr_takes_the_same_good_and_bad_vectors() {
        let d = tmp("rmv");
        for g in GOOD {
            fake_ufw(&d, true, &[&scoped("wlan0", g), "22/tcp|Anywhere|"]);
            let _ = std::fs::remove_file(d.join("calls.log"));
            let (c, log) = sh(&d, &["remove", "wlan0", g, &inside(g)]);
            assert_eq!(c, 0, "{g}");
            assert_eq!(rules(&d), vec!["22/tcp|Anywhere|"], "{g}");
            assert_eq!(log.lines().filter(|l| l.contains("delete")).count(), 1, "{log}");
        }
        for b in BAD {
            fake_ufw(&d, true, &[&scoped("wlan0", "10.0.0.0/24")]);
            let _ = std::fs::remove_file(d.join("calls.log"));
            let (c, log) = sh(&d, &["remove", "wlan0", b, "10.0.0.1"]);
            assert_eq!(c, 2, "{b}");
            assert_eq!(log, "", "{b} reached ufw");
            assert_eq!(rules(&d).len(), 1);
        }
    }

    /// One tagged rule as ufw lists it for `allow in on IFACE from CIDR to <an address inside it> port 8788 proto tcp`: "<to> <port>/tcp on <iface>|<from>|arrowbridge".
    fn scoped(iface: &str, cidr: &str) -> String { format!("{} 8788/tcp on {iface}|{cidr}|arrowbridge", inside(cidr)) }
    /// An address inside a network: its network address plus one in the last part.
    fn inside(cidr: &str) -> String {
        let (net, _) = cidr.split_once('/').unwrap();
        let mut o: Vec<u32> = net.split('.').map(|p| p.parse().unwrap()).collect();
        o[3] += 1;
        format!("{}.{}.{}.{}", o[0], o[1], o[2], o[3])
    }

    #[test]
    fn remove_cidr_deletes_exactly_that_network_and_never_a_substring_match() {
        let d = tmp("rmone");
        let (r16, r24, r192, r110, r240) = (scoped("wlan0", "10.0.0.0/16"), scoped("wlan0", "10.0.0.0/24"), scoped("wlan0", "192.168.1.0/24"), scoped("wlan0", "110.0.0.0/24"), "10.0.0.1 8788/tcp on wlan0|10.0.0.0/240|arrowbridge".to_string());
        fake_ufw(&d, true, &[&r16, "22/tcp|10.0.0.0/24|", &r24, &r192, &r110, &r240]);
        // a tagged 110.0.0.0/24 and a tagged 10.0.0.0/240 both contain the text 10.0.0.0/24: only the exact source goes
        let (c, _) = sh(&d, &["remove", "wlan0", "10.0.0.0/24", "10.0.0.1"]);
        assert_eq!(c, 0);
        assert_eq!(rules(&d), vec![r16.clone(), "22/tcp|10.0.0.0/24|".to_string(), r192.clone(), r110.clone(), r240.clone()]);
        // the other way round: the /16 goes, the /24 of another block stays
        let (c, _) = sh(&d, &["remove", "wlan0", "10.0.0.0/16", "10.0.0.1"]);
        assert_eq!(c, 0);
        assert_eq!(rules(&d), vec!["22/tcp|10.0.0.0/24|".to_string(), r192, r110, r240]);
    }

    #[test]
    fn remove_cidr_is_idempotent() {
        let d = tmp("rmidem");
        let (a, b) = (scoped("wlan0", "10.0.0.0/24"), scoped("wlan0", "192.168.1.0/24"));
        fake_ufw(&d, true, &["22/tcp|Anywhere|", &a, &b]);
        assert_eq!(sh(&d, &["remove", "wlan0", "192.168.1.0/24", "192.168.1.1"]).0, 0);
        assert_eq!(rules(&d), vec!["22/tcp|Anywhere|".to_string(), a.clone()]);
        // already gone: still 0, and the rules are as they were
        assert_eq!(sh(&d, &["remove", "wlan0", "192.168.1.0/24", "192.168.1.1"]).0, 0);
        assert_eq!(rules(&d), vec!["22/tcp|Anywhere|".to_string(), a]);
    }

    #[test]
    fn remove_cidr_with_two_tagged_rules_leaves_the_no_argument_remove_to_take_both() {
        let d = tmp("rmboth");
        let (a, b) = (scoped("wlan0", "10.0.0.0/24"), scoped("wlan0", "192.168.1.0/24"));
        fake_ufw(&d, true, &[&a, &b]);
        assert_eq!(sh(&d, &["remove", "wlan0", "10.0.0.0/24", "10.0.0.1"]).0, 0);
        assert_eq!(rules(&d), vec![b.clone()]);
        fake_ufw(&d, true, &[&a, &b]);
        assert_eq!(sh(&d, &["remove"]).0, 0);
        assert!(rules(&d).is_empty());
    }

    #[test]
    fn remove_cidr_on_an_inactive_ufw_exits_3_and_changes_nothing() {
        let d = tmp("rminact");
        fake_ufw(&d, false, &[&scoped("wlan0", "10.0.0.0/24")]);
        let (c, log) = sh(&d, &["remove", "wlan0", "10.0.0.0/24", "10.0.0.1"]);
        assert_eq!(c, 3);
        assert!(mutations(&log).is_empty(), "{log}");
        assert_eq!(rules(&d).len(), 1);
    }

    #[test]
    fn remove_for_needs_helper_version_4_and_names_the_interface_network_and_address_the_allow_named() {
        let d = tmp("rmfor");
        let pk = fake_pkexec(&d, 0);
        let ip = |s: &str| -> Ipv4Addr { s.parse().unwrap() };
        let log = || std::fs::read_to_string(d.join("pk.log")).unwrap_or_default();
        // the shipped script is version 5 and the app reads that same line
        assert_eq!(helper_version(&script()), Some(5));
        // an allow records the interface and address it named; the withdrawal then names that rule, and only that
        let ifs = [crate::linuxrun::Iface { name: "wlp2s0".into(), ip: ip("172.20.7.1"), mask: ip("255.255.255.0") }];
        assert_eq!(allow_for(&pk, &script(), &d, (ip("172.20.7.1"), ip("255.255.255.0")), &ifs).unwrap(), FwOutcome::Done);
        assert_eq!(remove_for(&pk, &script(), &d, "172.20.7.0/24").unwrap(), FwOutcome::Done);
        assert!(log().ends_with(" remove wlp2s0 172.20.7.0/24 172.20.7.1\n"), "{}", log());
        // the record is spent: a second withdrawal asks nothing, and a network never allowed has nothing to withdraw
        let before = log();
        assert_eq!(remove_for(&pk, &script(), &d, "172.20.7.0/24").unwrap(), FwOutcome::Done);
        assert_eq!(remove_for(&pk, &script(), &d, "10.77.0.0/24").unwrap(), FwOutcome::Done);
        assert_eq!(log(), before, "a withdrawal with nothing recorded reached pkexec");
        // a version 3 helper (it reads the four word form as bad usage), older ones, one with no version line, and an unreadable one: refused before any prompt
        for (i, body) in ["HELPER_VERSION=3\n", "HELPER_VERSION=2\n", "HELPER_VERSION=1\n", "echo hi\n", "HELPER_VERSION=x\n"].iter().enumerate() {
            let h = d.join(format!("old{i}"));
            std::fs::write(&h, body).unwrap();
            assert_eq!(remove_for(&pk, &h, &d, "192.168.1.0/24").unwrap(), FwOutcome::Failed(VERSION_REFUSED), "{body}");
        }
        assert_eq!(log(), before, "a refused helper reached pkexec");
        // a bad CIDR never reaches pkexec; a missing helper is no prompt
        assert!(remove_for(&pk, &script(), &d, "8.8.8.0/24").is_err());
        assert!(remove_for(&pk, &script(), &d, "10.0.0.0/24;ls").is_err());
        assert_eq!(remove_for(&pk, &d.join("absent"), &d, "10.0.0.0/24").unwrap(), FwOutcome::HelperMissing);
        assert_eq!(log(), before);
        // helper exit codes map as for allow, and an unanswered withdrawal keeps its record for the next press
        let ifs2 = [crate::linuxrun::Iface { name: "wlan7".into(), ip: ip("172.21.9.1"), mask: ip("255.255.255.0") }];
        assert_eq!(allow_for(&pk, &script(), &d, (ip("172.21.9.1"), ip("255.255.255.0")), &ifs2).unwrap(), FwOutcome::Done);
        assert_eq!(remove_for(&fake_pkexec(&d, 3), &script(), &d, "172.21.9.0/24").unwrap(), FwOutcome::NoFirewall);
        assert_eq!(remove_for(&fake_pkexec(&d, 126), &script(), &d, "172.21.9.0/24").unwrap(), FwOutcome::Failed(126));
        assert_eq!(remove_for(&fake_pkexec(&d, 0), &script(), &d, "172.21.9.0/24").unwrap(), FwOutcome::Done);
        assert!(log().ends_with(" remove wlan7 172.21.9.0/24 172.21.9.1\n"), "{}", log());
    }

    /// The record is a file, so a withdrawal after a restart really calls the helper. A restart is simulated by dropping everything the
    /// process held: only the data dir remains. Fails on the old in-memory record (the withdrawal then reported Done and asked nothing).
    #[test]
    fn a_withdrawal_after_a_restart_still_calls_the_helper() {
        let d = tmp("restart");
        let pk = fake_pkexec(&d, 0);
        let ip = |s: &str| -> Ipv4Addr { s.parse().unwrap() };
        let log = || std::fs::read_to_string(d.join("pk.log")).unwrap_or_default();
        let ifs = [crate::linuxrun::Iface { name: "enp3s0".into(), ip: ip("192.168.1.7"), mask: ip("255.255.255.0") }];
        assert_eq!(allow_for(&pk, &script(), &d, (ip("192.168.1.7"), ip("255.255.255.0")), &ifs).unwrap(), FwOutcome::Done);
        assert_eq!(std::fs::metadata(d.join("fw-allowed")).unwrap().permissions().mode() & 0o777, 0o600);
        assert!(!d.join("fw-allowed.tmp").exists());
        // the restarted app seeds its stale list from the record, minus the network that is up
        assert_eq!(recorded_cidrs(&d), vec!["192.168.1.0/24".to_string()]);
        assert_eq!(remove_for(&pk, &script(), &d, "192.168.1.0/24").unwrap(), FwOutcome::Done);
        assert!(log().ends_with(" remove enp3s0 192.168.1.0/24 192.168.1.7\n"), "{}", log());
        assert!(recorded_cidrs(&d).is_empty());
        // a damaged or hostile record line is ignored, never passed on
        std::fs::write(d.join("fw-allowed"), "wlan0;ls 10.0.0.0/24 10.0.0.1\nwlan0 8.8.8.0/24 8.8.8.8\nwlan0 10.0.0.0/24 10.0.0.1 x\nwlan0 10.0.0.0/24 10.0.0.1\n").unwrap();
        assert_eq!(recorded_cidrs(&d), vec!["10.0.0.0/24".to_string()]);
        assert_eq!(recorded_rules(&d).len(), 1);
    }

    /// `replace` removes the 0.1.2 rule (tagged, no interface) and adds the scoped allow in ONE helper run, delete first, and leaves untagged rules alone.
    #[test]
    fn replace_removes_the_old_rule_then_adds_the_scoped_one_in_one_run() {
        let d = tmp("replace");
        let old = "8788/tcp|192.168.1.0/24|arrowbridge"; // what 0.1.2 left: tagged, no interface
        fake_ufw(&d, true, &["22/tcp|Anywhere|", old, "443/tcp|Anywhere|"]);
        let (code, log) = sh(&d, &["replace", "wlan0", "192.168.1.0/24", "192.168.1.9"]);
        assert_eq!(code, 0, "{log}");
        assert_eq!(rules(&d), vec!["22/tcp|Anywhere|", "443/tcp|Anywhere|"]);
        let m = mutations(&log);
        assert_eq!(m, vec!["--force delete 2", "allow in on wlan0 from 192.168.1.0/24 to 192.168.1.9 port 8788 proto tcp comment arrowbridge"], "{log}");
        // an inactive ufw changes nothing; bad arguments never reach ufw
        let d2 = tmp("replace2");
        fake_ufw(&d2, false, &[old]);
        let (code, log) = sh(&d2, &["replace", "wlan0", "192.168.1.0/24", "192.168.1.9"]);
        assert_eq!(code, 3);
        assert!(mutations(&log).is_empty(), "{log}");
        fake_ufw(&d2, true, &[old]);
        let _ = std::fs::remove_file(d2.join("calls.log"));
        for bad in [vec!["replace"], vec!["replace", "wlan0", "8.8.8.0/24", "8.8.8.8"], vec!["replace", "wlan0;ls", "192.168.1.0/24", "192.168.1.9"],
                    vec!["replace", "wlan0", "192.168.1.0/24", "10.0.0.1"], vec!["replace", "wlan0", "192.168.1.0/24", "192.168.1.9", "x"]] {
            let (code, log) = sh(&d2, &bad);
            assert_eq!((code, log.as_str()), (2, ""), "{bad:?}");
        }
        assert_eq!(rules(&d2), vec![old]);
    }

    /// App side: `replace_for` asks pkexec once with the replace form, needs helper version 5 (refused before any prompt), and records the rule.
    #[test]
    fn replace_for_is_one_prompt_needs_version_5_and_records_the_rule() {
        let d = tmp("replfor");
        let pk = fake_pkexec(&d, 0);
        let (a, m) = (Ipv4Addr::new(192, 168, 1, 9), Ipv4Addr::new(255, 255, 255, 0));
        let ifs = [crate::linuxrun::Iface { name: "wlan0".into(), ip: a, mask: m }];
        let v4 = d.join("v4");
        std::fs::write(&v4, "HELPER_VERSION=4\n").unwrap();
        assert_eq!(replace_for(&pk, &v4, &d, (a, m), &ifs).unwrap(), FwOutcome::Failed(VERSION_REFUSED));
        assert!(!d.join("pk.log").exists() && recorded_rules(&d).is_empty(), "a refused helper reached pkexec");
        assert_eq!(replace_for(&pk, &script(), &d, (a, m), &ifs).unwrap(), FwOutcome::Done);
        let log = std::fs::read_to_string(d.join("pk.log")).unwrap();
        assert_eq!(log.lines().count(), 1, "{log}");
        assert!(log.ends_with(" replace wlan0 192.168.1.0/24 192.168.1.9\n"), "{log}");
        assert_eq!(recorded_cidrs(&d), vec!["192.168.1.0/24".to_string()]);
        assert_eq!(replace_for(&fake_pkexec(&d, 126), &script(), &d, (a, m), &ifs).unwrap(), FwOutcome::Failed(126));
        assert_eq!(replace_for(&pk, &script(), &d, (a, m), &[]).unwrap(), FwOutcome::Failed(NO_IFACE));
    }

    /// Two threads each allow a different rule 50 times against the fake helper; every one of the 100 lines must be in the record.
    #[test]
    fn two_threads_allowing_at_once_lose_no_record_line() {
        let d = tmp("d5");
        let pk = fake_pkexec(&d, 0);
        let hs: Vec<_> = (0..2u8).map(|t| {
            let (d, pk) = (d.to_path_buf(), pk.clone());
            std::thread::spawn(move || for i in 0..50u8 {
                let (a, m) = (Ipv4Addr::new(10, t + 1, i, 5), Ipv4Addr::new(255, 255, 255, 0));
                let ifs = [crate::linuxrun::Iface { name: format!("wlan{t}"), ip: a, mask: m }];
                assert_eq!(allow_for(&pk, &script(), &d, (a, m), &ifs).unwrap(), FwOutcome::Done);
            })
        }).collect();
        for h in hs { h.join().unwrap(); }
        assert_eq!(recorded_rules(&d).len(), 100);
    }

    /// A holder outside this call (standing in for a second app process, which opens its own file the same way) keeps allow_for from touching
    /// the record until it lets go, and nothing is lost after.
    #[test]
    fn a_second_holder_of_the_record_lock_makes_allow_for_wait() {
        let d = tmp("d5file");
        let pk = fake_pkexec(&d, 0);
        let held = lock_record(&d).unwrap();
        let (a, m) = (Ipv4Addr::new(192, 168, 1, 9), Ipv4Addr::new(255, 255, 255, 0));
        let d2 = d.to_path_buf();
        let t = std::thread::spawn(move || {
            let ifs = [crate::linuxrun::Iface { name: "wlan0".into(), ip: a, mask: m }];
            allow_for(&pk, &script(), &d2, (a, m), &ifs).unwrap()
        });
        std::thread::sleep(std::time::Duration::from_millis(400));
        assert!(recorded_rules(&d).is_empty(), "the record was written while another holder had the lock");
        drop(held);
        assert_eq!(t.join().unwrap(), FwOutcome::Done);
        assert_eq!(recorded_rules(&d).len(), 1);
        assert_eq!(std::fs::metadata(d.join("fw-allowed.lock")).unwrap().permissions().mode() & 0o777, 0o600);
    }

    /// A power cut is not testable here, so the guard reads the source: write_record syncs the parent directory after the rename.
    #[test]
    fn write_record_syncs_the_directory_after_the_rename() {
        let src = std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("src/firewall.rs")).unwrap();
        let body = src.split("fn write_record").nth(1).unwrap().split("\n}\n").next().unwrap();
        let (rename, sync) = (body.find("std::fs::rename").unwrap(), body.find("File::open(store)?.sync_all()").expect("no directory sync in write_record"));
        assert!(sync > rename, "the directory sync must come after the rename");
        let d = tmp("dsync");
        write_record(&d, &[("wlan0".into(), "10.0.0.0/24".into(), "10.0.0.1".into())]).unwrap();
        assert_eq!(recorded_rules(&d).len(), 1);
    }

    /// Rust side: the interface name comes only from the follow's own list, by the address it picked; nothing else can name one.
    #[test]
    fn allow_for_scopes_to_the_interface_that_holds_the_address_and_refuses_any_other() {
        let d = tmp("alfor");
        let ip = |s: &str| -> Ipv4Addr { s.parse().unwrap() };
        let m = ip("255.255.255.0");
        let ifc = |n: &str, a: &str| crate::linuxrun::Iface { name: n.into(), ip: ip(a), mask: m };
        let ifs = [ifc("enp3s0", "192.168.1.7"), ifc("wlan0", "192.168.43.1")];
        let log = || std::fs::read_to_string(d.join("pk.log")).unwrap_or_default();
        assert_eq!(allow_for(&fake_pkexec(&d, 0), &script(), &d, (ip("192.168.43.1"), m), &ifs).unwrap(), FwOutcome::Done);
        assert!(log().ends_with(" allow wlan0 192.168.43.0/24 192.168.43.1\n"), "{}", log());
        let before = log();
        // an address no interface holds, and the right address under a different mask (not the follow's pick): nothing is asked
        assert_eq!(allow_for(&fake_pkexec(&d, 0), &script(), &d, (ip("192.168.50.1"), m), &ifs).unwrap(), FwOutcome::Failed(NO_IFACE));
        assert_eq!(allow_for(&fake_pkexec(&d, 0), &script(), &d, (ip("192.168.43.1"), ip("255.255.0.0")), &ifs).unwrap(), FwOutcome::Failed(NO_IFACE));
        assert_eq!(allow_for(&fake_pkexec(&d, 0), &script(), &d, (ip("192.168.43.1"), m), &[]).unwrap(), FwOutcome::Failed(NO_IFACE));
        // an interface name the helper would refuse never reaches pkexec
        assert!(allow_for(&fake_pkexec(&d, 0), &script(), &d, (ip("192.168.43.1"), m), &[ifc("wlan0;ls", "192.168.43.1")]).is_err());
        assert!(allow(&fake_pkexec(&d, 0), &script(), "wlan0", "192.168.43.0/24", ip("192.168.44.1")).is_err(), "a bound address outside the network");
        assert_eq!(log(), before);
        // a public address, a missing helper and a helper that does not know this form
        assert!(allow_for(&fake_pkexec(&d, 0), &script(), &d, (ip("8.8.8.8"), m), &ifs).is_err());
        assert_eq!(allow_for(&fake_pkexec(&d, 0), &d.join("absent"), &d, (ip("10.0.0.5"), m), &ifs).unwrap(), FwOutcome::HelperMissing);
        let old = d.join("v2");
        std::fs::write(&old, "HELPER_VERSION=2\n").unwrap();
        assert_eq!(allow_for(&fake_pkexec(&d, 0), &old, &d, (ip("192.168.43.1"), m), &ifs).unwrap(), FwOutcome::Failed(VERSION_REFUSED));
        assert_eq!(log(), before);
    }

    #[test]
    fn validate_iface_matches_the_helper() {
        for g in ["wlan0", "enp3s0", "wlp0s20f3", "eth0.100", "br0:1", "a-b_c", "a23456789012345", "0"] { assert!(validate_iface(g).is_ok(), "{g}"); }
        for b in ["", "-x", "_x", ".x", "wlan 0", "wlan0;ls", "wl/an0", "../x", "wlan0\n", "wlan0 ", "$(id)", "wlan0'", "a234567890123456", "wl\u{e4}n0"] { assert!(validate_iface(b).is_err(), "{b:?}"); }
    }

    #[test]
    fn remove_with_no_tagged_rules_deletes_nothing() {
        let d = tmp("rm0");
        fake_ufw(&d, true, &["22/tcp|Anywhere|"]);
        let (c, log) = sh(&d, &["remove"]);
        assert_eq!(c, 0);
        assert!(!log.contains("delete"));
    }

    #[test]
    fn ufw_failure_is_exit_4() {
        let d = tmp("f4");
        fake_ufw(&d, true, &["8788/tcp|10.0.0.0/24|arrowbridge"]);
        std::fs::write(d.join("ufw_fail"), "").unwrap();
        assert_eq!(sh(&d, &["allow", "wlan0", "10.0.0.0/24", "10.0.0.1"]).0, 4);
        assert_eq!(sh(&d, &["remove"]).0, 4);
        // a per network withdrawal whose delete did not take (the rule is still listed) is 4, never a silent 0
        fake_ufw(&d, true, &[&scoped("wlan0", "10.0.0.0/24")]);
        std::fs::write(d.join("ufw_fail"), "").unwrap();
        assert_eq!(sh(&d, &["remove", "wlan0", "10.0.0.0/24", "10.0.0.1"]).0, 4);
        assert_eq!(rules(&d).len(), 1);
    }

    #[test]
    fn cidr_from_mask() {
        let ip = |s: &str| -> Ipv4Addr { s.parse().unwrap() };
        assert_eq!(cidr_from(ip("192.168.1.77"), ip("255.255.255.0")).unwrap(), "192.168.1.0/24");
        assert_eq!(cidr_from(ip("10.9.8.7"), ip("255.255.0.0")).unwrap(), "10.9.0.0/16");
        for (a, m) in [("192.168.1.77", "255.0.255.0"), ("192.168.1.77", "255.0.0.0"), ("192.168.1.77", "255.255.255.255"),
                       ("8.8.8.8", "255.255.255.0"), ("127.0.0.1", "255.255.255.0"), ("172.16.5.5", "255.240.0.0"), ("192.168.1.77", "255.255.0.255")] {
            assert!(cidr_from(ip(a), ip(m)).is_err(), "{a} {m}");
        }
    }

    /// Fake pkexec records argv and exits with the code in `code`.
    fn fake_pkexec(d: &Path, code: i32) -> PathBuf {
        let p = d.join("pkexec");
        std::fs::write(&p, format!("#!/bin/sh\n[ \"$1\" = __probe ] && exit 0\necho \"$@\" >> {}/pk.log\nexit {code}\n", d.display())).unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
        exec_ready(&p);
        p
    }

    /// Review T1: a fake script run right after it was written failed with ETXTBSY (os error 26) when another test forked in that window.
    /// The fakes now probe until they can run; this forks hard from other threads while writing and running them, and fails on the old fakes.
    #[test]
    fn a_fake_script_is_runnable_at_once_even_while_other_threads_fork() {
        use std::sync::atomic::{AtomicBool, Ordering};
        let stop = std::sync::Arc::new(AtomicBool::new(false));
        let forkers: Vec<_> = (0..3).map(|_| {
            let s = stop.clone();
            std::thread::spawn(move || while !s.load(Ordering::Relaxed) { let _ = Command::new("/bin/true").status(); })
        }).collect();
        let mut bad = vec![];
        for i in 0..100 {
            let d = tmp(&format!("etx{i}"));
            let p = fake_pkexec(&d, 0);
            match Command::new(&p).arg("go").status() { Ok(_) => {}, Err(e) => bad.push(format!("{i}: {e}")) }
            let _ = std::fs::remove_dir_all(&d);
        }
        stop.store(true, Ordering::Relaxed);
        for f in forkers { f.join().unwrap(); }
        assert!(bad.is_empty(), "{} of 100 fake scripts hit ETXTBSY: {:?}", bad.len(), &bad[..bad.len().min(3)]);
    }

    #[test]
    fn app_calls_pkexec_with_argv_and_maps_codes() {
        let d = tmp("pk");
        let helper = Path::new("/usr/lib/arrowmem/arrowbridge-fw");
        let ip: Ipv4Addr = "192.168.1.7".parse().unwrap();
        assert_eq!(allow(&fake_pkexec(&d, 0), helper, "enp3s0", "192.168.1.0/24", ip).unwrap(), FwOutcome::Done);
        assert_eq!(std::fs::read_to_string(d.join("pk.log")).unwrap(), "/usr/lib/arrowmem/arrowbridge-fw allow enp3s0 192.168.1.0/24 192.168.1.7\n");
        let present = d.join("helper");
        std::fs::write(&present, "x").unwrap();
        assert_eq!(remove(&fake_pkexec(&d, 3), &present).unwrap(), FwOutcome::NoFirewall);
        assert_eq!(remove(&fake_pkexec(&d, 4), &present).unwrap(), FwOutcome::Failed(4));
        assert_eq!(remove(&fake_pkexec(&d, 126), &present).unwrap(), FwOutcome::Failed(126));
        let before = std::fs::read_to_string(d.join("pk.log")).unwrap();
        assert_eq!(remove(&fake_pkexec(&d, 0), &d.join("absent")).unwrap(), FwOutcome::HelperMissing);
        assert_eq!(std::fs::read_to_string(d.join("pk.log")).unwrap(), before, "no pkexec call for a missing helper");
        assert!(allow(&fake_pkexec(&d, 0), helper, "enp3s0", "8.8.8.0/24", "8.8.8.8".parse().unwrap()).is_err());
        assert!(allow(Path::new("/nonexistent/pkexec"), helper, "enp3s0", "10.0.0.0/24", "10.0.0.1".parse().unwrap()).is_err());
    }
}
