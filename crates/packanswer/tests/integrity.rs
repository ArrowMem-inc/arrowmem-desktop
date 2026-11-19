mod common;
use common::*;
use packanswer::integrity::{load, load_with, read_nofollow, sha256_hex, Unavailable};
use packanswer::Pack;
use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use std::fs;
use std::os::unix::fs::symlink;
use std::path::Path;

fn open(dir: &Path, pin: &str) -> Result<Pack, Unavailable> {
    open_with(dir, pin, &HashSet::new(), &YES)
}

fn why(r: Result<Pack, Unavailable>) -> &'static str {
    r.err().expect("expected the pack to be refused").0
}

#[test]
fn the_good_pack_opens() {
    let (dir, pin) = write_pack("i-good", &default_files());
    assert!(open(&dir, &pin).is_ok());
}

#[test]
fn t7_one_flipped_byte_in_any_jsonl_turns_the_pack_off() {
    let (dir, pin) = write_pack("i-t7", &default_files());
    for f in ["survival.jsonl", "natmed_shippable.jsonl", "hosts.json"] {
        let path = dir.join(f);
        let orig = fs::read(&path).unwrap();
        let mut bad = orig.clone();
        let at = bad.len() / 2;
        bad[at] ^= 1;
        fs::write(&path, &bad).unwrap();
        assert_eq!(why(open(&dir, &pin)), "file hash", "{f}");
        fs::write(&path, &orig).unwrap();
    }
    assert!(open(&dir, &pin).is_ok());
}

#[test]
fn t8_a_consistently_edited_manifest_is_caught_by_the_pin() {
    let mut files = default_files();
    let (_, pin) = write_pack("i-t8a", &files);
    files[1].1.push_str(&rec("fx-new-0001", "survival", "An added sentence.", CDC));
    let (dir, _own_pin) = write_pack("i-t8b", &files);
    // the edited folder is self consistent (its own manifest matches its files) but is not the pinned manifest
    assert_eq!(why(open(&dir, &pin)), "manifest does not match the pin");
}

#[test]
fn t9_each_pack_file_is_opened_once() {
    let (dir, pin) = write_pack("i-t9", &default_files());
    let counts = RefCell::new(HashMap::new());
    let files = load_with(&dir, &pin, |p| {
        *counts.borrow_mut().entry(p.to_path_buf()).or_insert(0) += 1;
        read_nofollow(p)
    })
    .unwrap();
    let counts = counts.into_inner();
    assert_eq!(counts.len(), files.len() + 1);
    assert!(counts.values().all(|&n| n == 1), "{counts:?}");
}

#[test]
fn t10_a_symlinked_file_a_symlinked_dir_and_a_dotdot_path_are_refused() {
    let (dir, pin) = write_pack("i-t10", &default_files());
    let target = dir.join("survival.jsonl");
    let keep = fs::read(&target).unwrap();
    fs::remove_file(&target).unwrap();
    let outside = dir.with_file_name("i-t10-outside.jsonl");
    fs::write(&outside, &keep).unwrap();
    symlink(&outside, &target).unwrap();
    assert_eq!(why(open(&dir, &pin)), "file read");

    let (real, pin) = write_pack("i-t10-real", &default_files());
    let link = real.with_file_name("i-t10-link");
    let _ = fs::remove_file(&link);
    symlink(&real, &link).unwrap();
    assert_eq!(why(open(&link, &pin)), "dir is not a real directory");

    for bad in ["../x.jsonl", "/etc/passwd", "a//b", "./a", "a b", "sub/x.jsonl", "..", "."] {
        let manifest = format!("{}  {bad}\n", sha256_hex(b"x"));
        let d = Path::new(env!("CARGO_TARGET_TMPDIR")).join("i-t10-path");
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).unwrap();
        fs::write(d.join("PACK.sha256"), &manifest).unwrap();
        assert_eq!(load(&d, &sha256_hex(manifest.as_bytes())).unwrap_err().0, "manifest entry", "{bad}");
    }
}

#[test]
fn a_fifo_in_place_of_a_pack_file_is_refused_not_hung_on() {
    let (dir, pin) = write_pack("i-fifo", &default_files());
    let target = dir.join("survival.jsonl");
    fs::remove_file(&target).unwrap();
    assert!(std::process::Command::new("mkfifo").arg(&target).status().unwrap().success());
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || tx.send(load(&dir, &pin).unwrap_err().0).ok());
    assert_eq!(rx.recv_timeout(std::time::Duration::from_secs(5)).expect("the load hung on a fifo"), "file read");
}

#[test]
fn t11_a_redirected_folder_with_other_bytes_is_refused_whatever_the_path() {
    let (_, pin) = write_pack("i-t11a", &default_files());
    let mut files = default_files();
    files[0].1 = files[0].1.replace("Credit line for cdc.", "Another credit line.");
    let (other, _) = write_pack("i-t11b", &files);
    assert_eq!(why(open(&other, &pin)), "manifest does not match the pin");
    assert_eq!(why(open(&other, "")), "manifest does not match the pin");
}

#[test]
fn a_manifest_that_lists_a_file_twice_or_nothing_is_refused() {
    let d = Path::new(env!("CARGO_TARGET_TMPDIR")).join("i-dup");
    let _ = fs::remove_dir_all(&d);
    fs::create_dir_all(&d).unwrap();
    fs::write(d.join("a.jsonl"), "x").unwrap();
    let h = sha256_hex(b"x");
    let twice = format!("{h}  a.jsonl\n{h}  a.jsonl\n");
    fs::write(d.join("PACK.sha256"), &twice).unwrap();
    assert_eq!(load(&d, &sha256_hex(twice.as_bytes())).unwrap_err().0, "manifest entry");
    fs::write(d.join("PACK.sha256"), "").unwrap();
    assert_eq!(load(&d, &sha256_hex(b"")).unwrap_err().0, "empty manifest");
}

// ---- the v2 loader ----

fn files_with(name: &str, edit: impl Fn(&mut Vec<(&'static str, String)>)) -> Result<Pack, Unavailable> {
    let mut f = default_files();
    edit(&mut f);
    open_files(name, &f)
}

#[test]
fn a_held_record_makes_the_loader_refuse_the_whole_pack() {
    let (dir, pin) = write_pack("l-held", &default_files());
    let held: HashSet<String> = ["fx-tent-0001".to_string()].into();
    assert_eq!(open_with(&dir, &pin, &held, &YES).err().unwrap().0, "held record");
    // a held plant id too
    let held: HashSet<String> = ["chamomile".to_string()].into();
    assert_eq!(open_with(&dir, &pin, &held, &YES).err().unwrap().0, "held record");
    // control: an id that is not in the pack changes nothing
    let held: HashSet<String> = ["fx-nowhere".to_string()].into();
    assert!(open_with(&dir, &pin, &held, &YES).is_ok());
}

#[test]
fn a_natmed_line_with_any_authored_key_is_refused_and_the_sentinel_never_loads() {
    let r = files_with("l-key", |f| {
        let mut v: serde_json::Value = serde_json::from_str(f[6].1.lines().next().unwrap()).unwrap();
        v["plant_id"] = "ginger2".into();
        v["common_name"] = "Ginger two".into();
        v["evidence"] = serde_json::json!({"sentence": "SENTINEL-AUTHORED"});
        f[6].1.push_str(&(v.to_string() + "\n"));
    });
    assert_eq!(why(r), "natmed keys");
    let r = files_with("l-key2", |f| f[6].1 = f[6].1.replace("\"traditional\":true", "\"traditional\":true,\"notes\":\"x\""));
    assert_eq!(why(r), "natmed keys");
}

#[test]
fn a_record_from_a_host_not_in_hosts_json_fails_the_build() {
    assert_eq!(why(files_with("l-host", |f| f[1].1 = f[1].1.replace("www.cdc.gov", "www.other.example"))), "host not in hosts.json");
    assert_eq!(why(files_with("l-host2", |f| f[6].1 = f[6].1.replace("www.nccih.nih.gov", "www.other.example"))), "natmed source");
    assert_eq!(why(files_with("l-host3", |f| f[1].1 = f[1].1.replace("https://www.cdc.gov", "http://www.cdc.gov"))), "host not in hosts.json");
    assert_eq!(why(files_with("l-host4", |f| { f.remove(0); })), "no hosts.json");
}

#[test]
fn a_quote_that_is_not_a_byte_substring_of_its_context_is_refused() {
    let r = files_with("l-ctx", |f| f[1].1 = f[1].1.replace("\\nAfter the quote.\"", "\\nAfter.\"").replacen("Boil the water", "Boil the  water", 1));
    assert_eq!(why(r), "quote is not in its context");
}

#[test]
fn an_empty_quote_a_missing_field_and_bad_json_are_refused() {
    assert_eq!(why(files_with("l-e1", |f| f[1].1 = rec("a", "survival", "", CDC) + "\n")), "quote is not in its context");
    assert_eq!(why(files_with("l-e2", |f| f[1].1 = "{\"id\":\"a\"}\n".into())), "record keys");
    assert_eq!(why(files_with("l-e3", |f| f[1].1 = "not json\n".into())), "json");
}

#[test]
fn the_yes_list_decides_what_ships() {
    let (dir, pin) = write_pack("l-yes", &default_files());
    let none = Pack::open(&dir, &pin, &HashSet::new(), &[]).unwrap();
    assert_eq!(packanswer::answer(Some(&none), "ginger", "en", None), packanswer::Answer::NoAnswer);
}

// ---- hardening cases ----

#[test]
fn r2_1_a_yes_binds_the_plant_id_to_the_hash_of_its_shipped_line() {
    let ginger_line = |f: &[(&str, String)]| f[6].1.lines().next().unwrap().to_string();
    let files = default_files();
    let h = sha256_hex(ginger_line(&files).as_bytes());
    let shows = |p: &Pack| quotes(&packanswer::answer(Some(p), "tell me about ginger", "en", None)).iter().any(|q| q.contains("Ginger"));
    let (dir, pin) = write_pack("r21a", &files);
    let held = HashSet::new();
    // approved by (id, hash of its line): shown
    assert!(shows(&Pack::open(&dir, &pin, &held, &[("ginger", h.as_str())]).unwrap()));
    // the same id, its content changed (here: another plant's sources under it): the old approval no longer shows it
    let mut changed = default_files();
    changed[6].1 = changed[6].1.replacen("Ginger is used traditionally for nausea.", "Garlic may raise bleeding risk.", 1);
    let (dir2, pin2) = write_pack("r21b", &changed);
    assert!(!shows(&Pack::open(&dir2, &pin2, &held, &[("ginger", h.as_str())]).unwrap()));
    // an approval of another plant's line hash does not approve this id
    let other = sha256_hex(files[6].1.lines().nth(1).unwrap().as_bytes());
    assert!(!shows(&Pack::open(&dir, &pin, &held, &[("ginger", other.as_str())]).unwrap()));
}

#[test]
fn r2_6_a_topic_file_name_strips_the_jsonl_suffix_once() {
    let r = files_with("r26", |f| f.push(("survival.jsonl.jsonl", f[1].1.replace("fx-", "fy-"))));
    assert_eq!(why(r), "topic");
}

#[test]
fn f2_a_userinfo_or_port_or_uppercase_or_backslash_host_is_refused() {
    for bad in [
        "https://www.cdc.gov:443@attacker.example/x",
        "https://www.cdc.gov@attacker.example/x",
        "https://www.cdc.gov:443/x",
        "https://WWW.CDC.GOV/x",
        "https://www.cdc.gov\\\\@attacker.example/x", // a JSON escaped backslash
        "https://www.cdc.gov?x=1",
        "https://www.cdc.gov#x",
    ] {
        let r = files_with("f2", |f| f[1].1 = f[1].1.replace("https://www.cdc.gov/fixture/page.html", bad));
        assert_eq!(why(r), "host not in hosts.json", "{bad}");
    }
    // control: a bare host and a path both load
    assert!(files_with("f2c", |f| f[1].1 = f[1].1.replace("https://www.cdc.gov/fixture/page.html", "https://www.cdc.gov")).is_ok());
}

#[test]
fn f3_topic_is_a_closed_set_equal_to_the_file_name() {
    assert_eq!(why(files_with("f3a", |f| f[2].1 = f[2].1.replace("\"preservation\"", "\"Preservation\""))), "topic");
    assert_eq!(why(files_with("f3b", |f| f[3].1 = f[3].1.replace("\"game_fish\"", "\"game-fish\""))), "topic");
    // a member of the set, but not this file's
    assert_eq!(why(files_with("f3c", |f| f[1].1 = f[1].1.replace("\"survival\"", "\"trapping\""))), "topic");
    // a file whose name is not in the set
    let r = files_with("f3b", |f| f.push(("fishing.jsonl", f[3].1.replace("fx-fish", "fx-fishb").replace("game_fish", "fishing"))));
    assert_eq!(why(r), "topic");
}

#[test]
fn f5_context_url_is_required_host_checked_and_carried_to_the_block() {
    assert_eq!(why(files_with("f5a", |f| f[1].1 = f[1].1.replace("\"context_url\"", "\"context_urlx\""))), "record keys");
    let r = files_with("f5b", |f| f[1].1 = f[1].1.replacen("\"context_url\":\"https://www.cdc.gov/fixture/page.html\"", "\"context_url\":\"https://www.other.example/x\"", 1));
    assert_eq!(why(r), "host not in hosts.json");
    let p = files_with("f5c", |f| f[1].1 = f[1].1.replacen("\"context_url\":\"https://www.cdc.gov/fixture/page.html\"", "\"context_url\":\"https://www.cdc.gov/other/page.html\"", 1)).unwrap();
    let packanswer::Answer::Blocks(f) = packanswer::answer(Some(&p), "boil water", "en", None) else { panic!() };
    assert_eq!(f.blocks[0].context_url.as_deref(), Some("https://www.cdc.gov/other/page.html"));
    assert_eq!(f.blocks[0].url, CDC);
}

#[test]
fn f7_a_repeated_id_across_files_or_in_the_natmed_file_is_refused() {
    assert_eq!(why(files_with("f7", |f| f[5].1 = f[5].1.replace("fx-dup-0001", "fx-tent-0001"))), "duplicate id");
    assert_eq!(why(files_with("f7b", |f| f[6].1 = f[6].1.replace("\"plant_id\":\"garlic\"", "\"plant_id\":\"ginger\""))), "duplicate id");
}

#[test]
fn r3_2_one_id_rule_for_record_ids_and_plant_ids_and_nothing_else_loads() {
    assert!(files_with("r32ok", |_| {}).is_ok());
    for bad in ["fx dup", "fx\\nPIN\\tx", ".fx", "-fx", "fx\u{e9}", ""] {
        assert_eq!(why(files_with("r32a", |f| f[5].1 = f[5].1.replace("fx-dup-0001", bad))), "id", "record {bad:?}");
        assert_eq!(why(files_with("r32b", |f| f[6].1 = f[6].1.replace("\"plant_id\":\"garlic\"", &format!("\"plant_id\":\"{bad}\"")))), "id", "plant {bad:?}");
    }
}

#[test]
fn f8_hosts_json_keys_are_lowercase_and_values_are_exactly_credit_and_disclaimer() {
    assert_eq!(why(files_with("f8a", |f| f[0].1 = f[0].1.replace("\"www.cdc.gov\"", "\"WWW.CDC.GOV\""))), "hosts key");
    assert_eq!(why(files_with("f8b", |f| f[0].1 = f[0].1.replace("\"credit\"", "\"condition\":\"x\",\"credit\""))), "hosts keys");
}

#[test]
fn f9_a_manifest_name_must_start_with_a_letter_or_digit() {
    for bad in ["-", ".hidden.jsonl", "_x.jsonl"] {
        let d = Path::new(env!("CARGO_TARGET_TMPDIR")).join("f9");
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).unwrap();
        fs::write(d.join(bad), "x").unwrap();
        let manifest = format!("{}  {bad}\n", sha256_hex(b"x"));
        fs::write(d.join("PACK.sha256"), &manifest).unwrap();
        assert_eq!(load(&d, &sha256_hex(manifest.as_bytes())).unwrap_err().0, "manifest entry", "{bad}");
    }
}

#[test]
fn f10_a_record_with_a_key_outside_the_required_seven_is_refused() {
    let r = files_with("f10", |f| f[1].1 = f[1].1.replacen("\"id\"", "\"licence\":\"free text\",\"id\"", 1));
    assert_eq!(why(r), "record keys");
}

#[test]
fn d4_a_symlink_in_any_component_or_with_a_trailing_slash_is_refused() {
    let (real, pin) = write_pack("d4-real", &default_files());
    let link = real.with_file_name("d4-link");
    let _ = fs::remove_file(&link);
    symlink(&real, &link).unwrap();
    for p in [link.clone(), link.join("")] {
        assert_eq!(why(open(&p, &pin)), "dir is not a real directory", "{p:?}");
    }
    // a symlinked parent
    let up = real.with_file_name("d4-parent-link");
    let _ = fs::remove_file(&up);
    symlink(real.parent().unwrap(), &up).unwrap();
    let via = up.join("d4-real");
    assert_eq!(why(open(&via, &pin)), "dir is not a real directory");
    // controls: the real dir opens, also with a trailing slash; a relative or dotdot path does not
    assert!(open(&real, &pin).is_ok());
    assert!(open(&real.join(""), &pin).is_ok());
    assert_eq!(why(open(&real.join("..").join("d4-real"), &pin)), "dir is not a real directory");
}

#[test]
fn f14_a_file_over_the_size_cap_is_refused_before_it_is_read() {
    let d = Path::new(env!("CARGO_TARGET_TMPDIR")).join("f14");
    let _ = fs::remove_dir_all(&d);
    fs::create_dir_all(&d).unwrap();
    let f = fs::File::create(d.join("big.jsonl")).unwrap();
    f.set_len(packanswer::integrity::MAX_FILE + 1).unwrap();
    assert!(read_nofollow(&d.join("big.jsonl")).is_err());
    f.set_len(1024).unwrap();
    assert_eq!(read_nofollow(&d.join("big.jsonl")).unwrap().len(), 1024);
}
