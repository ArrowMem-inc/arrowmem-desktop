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

/// One elevated prompt: allow TCP 8788 from this network only.
pub fn allow(pkexec: &Path, helper: &Path, cidr: &str) -> Result<FwOutcome, String> {
    validate_cidr(cidr)?;
    run(pkexec, helper, &["allow", cidr])
}

/// Remove exactly the rules the helper tagged.
pub fn remove(pkexec: &Path, helper: &Path) -> Result<FwOutcome, String> {
    if !helper.exists() {
        return Ok(FwOutcome::HelperMissing); // no helper, no rule of ours, and no prompt
    }
    run(pkexec, helper, &["remove"])
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
    fn tmp(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("fw-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
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
echo "$@" >> $D/calls.log
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
if [ "$1" = --force ] && [ "$2" = delete ]; then awk -v n="$3" 'NR!=n' $D/rules > $D/rules.new && mv $D/rules.new $D/rules; fi
exit 0
"#)).unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    /// Copy of the shipped script in `d` with only its `UFW=` line pointed at `ufw_path`.
    fn script_copy(d: &Path, ufw_path: &Path) -> PathBuf {
        let src = std::fs::read_to_string(script()).unwrap();
        let lines: Vec<&str> = src.lines().collect();
        assert_eq!(lines.iter().filter(|l| **l == "UFW=/usr/sbin/ufw").count(), 1, "shipped script must carry exactly one UFW= line");
        let out: Vec<String> = lines.iter().map(|l| if *l == "UFW=/usr/sbin/ufw" { format!("UFW={}", ufw_path.display()) } else { l.to_string() }).collect();
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
            let (c, log) = sh(&d, &["allow", g]);
            assert_eq!(c, 0, "{g}");
            assert!(log.contains(&format!("allow from {g} to any port 8788 proto tcp comment arrowbridge")), "{log}");
        }
        for b in BAD {
            let _ = std::fs::remove_file(d.join("calls.log"));
            let (c, log) = sh(&d, &["allow", b]);
            assert_eq!(c, 2, "{b}");
            assert_eq!(log, "", "{b} reached ufw");
        }
    }

    #[test]
    fn script_rejects_other_commands_and_extra_args() {
        let d = tmp("cmd");
        fake_ufw(&d, true, &[]);
        for a in [vec![], vec!["reset"], vec!["allow"], vec!["allow", "10.0.0.0/24", "x"], vec!["remove", "x"], vec!["delete", "1"]] {
            let (c, log) = sh(&d, &a);
            assert_eq!(c, 2, "{a:?}");
            assert_eq!(log, "");
        }
    }

    #[test]
    fn inactive_or_missing_ufw_exits_3_and_changes_nothing() {
        let d = tmp("inact");
        fake_ufw(&d, false, &["8788/tcp|10.0.0.0/24|arrowbridge"]);
        for a in [vec!["allow", "10.0.0.0/24"], vec!["remove"]] {
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
        let (c2, _) = sh_env(&d, &["allow", "10.0.0.0/24"], "fr_FR.UTF-8");
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
        assert_eq!(sh(&d, &["allow", "10.0.0.0/24"]).0, 4);
        assert_eq!(sh(&d, &["remove"]).0, 4);
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
        std::fs::write(&p, format!("#!/bin/sh\necho \"$@\" >> {}/pk.log\nexit {code}\n", d.display())).unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
        p
    }

    #[test]
    fn app_calls_pkexec_with_argv_and_maps_codes() {
        let d = tmp("pk");
        let helper = Path::new("/usr/lib/arrowmem/arrowbridge-fw");
        assert_eq!(allow(&fake_pkexec(&d, 0), helper, "192.168.1.0/24").unwrap(), FwOutcome::Done);
        assert_eq!(std::fs::read_to_string(d.join("pk.log")).unwrap(), "/usr/lib/arrowmem/arrowbridge-fw allow 192.168.1.0/24\n");
        let present = d.join("helper");
        std::fs::write(&present, "x").unwrap();
        assert_eq!(remove(&fake_pkexec(&d, 3), &present).unwrap(), FwOutcome::NoFirewall);
        assert_eq!(remove(&fake_pkexec(&d, 4), &present).unwrap(), FwOutcome::Failed(4));
        assert_eq!(remove(&fake_pkexec(&d, 126), &present).unwrap(), FwOutcome::Failed(126));
        let before = std::fs::read_to_string(d.join("pk.log")).unwrap();
        assert_eq!(remove(&fake_pkexec(&d, 0), &d.join("absent")).unwrap(), FwOutcome::HelperMissing);
        assert_eq!(std::fs::read_to_string(d.join("pk.log")).unwrap(), before, "no pkexec call for a missing helper");
        assert!(allow(&fake_pkexec(&d, 0), helper, "8.8.8.0/24").is_err());
        assert!(allow(Path::new("/nonexistent/pkexec"), helper, "10.0.0.0/24").is_err());
    }
}
