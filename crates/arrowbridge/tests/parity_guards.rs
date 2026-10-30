//! Parity of the Rust output guards with the pinned Python originals (vectors made by scripts/gen_guard_vectors.py).
use arrowbridge::gates::{factguard, linkgate, packsafety, telguard};
use serde_json::Value;
use std::collections::BTreeSet;
use std::path::Path;

fn vectors() -> Value {
    serde_json::from_str(&std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/vectors/guards_vectors.json")).unwrap()).unwrap()
}

fn set(v: &Value) -> BTreeSet<String> { v.as_array().unwrap().iter().map(|x| x.as_str().unwrap().to_string()).collect() }
fn list(v: &Value) -> Vec<String> { v.as_array().unwrap().iter().map(|x| x.as_str().unwrap().to_string()).collect() }

fn pack_dir(name: &str) -> std::path::PathBuf { Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/vectors/packs").join(name) }

#[test]
fn the_floor_numbers_and_allowed_facts_of_the_real_packs_match_the_original() {
    let v = vectors();
    for name in ["vac", "cpp"] {
        let want_tel = set(&v["packs"][name]["tel"]);
        let want_facts = set(&v["packs"][name]["facts"]);
        assert_eq!(telguard::floor_numbers(Some(&pack_dir(name))), want_tel, "{name} floor numbers");
        assert_eq!(factguard::allowed_facts(Some(&pack_dir(name))), want_facts, "{name} facts");
    }
    // no pack, an empty path and an unreadable pack all allow only 911 / nothing (fail closed)
    let only_911: BTreeSet<String> = ["911".to_string()].into();
    assert_eq!(telguard::floor_numbers(None), only_911);
    assert_eq!(telguard::floor_numbers(Some(Path::new(""))), only_911);
    assert_eq!(telguard::floor_numbers(Some(&pack_dir("does-not-exist"))), only_911);
    assert!(factguard::allowed_facts(None).is_empty());
    assert!(factguard::allowed_facts(Some(&pack_dir("does-not-exist"))).is_empty());
}

#[test]
fn tel_guard_redacts_and_scans_like_the_original() {
    let v = vectors();
    let cases = v["tel"].as_array().unwrap();
    let mut bad = Vec::new();
    for c in cases {
        let text = c["text"].as_str().unwrap();
        let allowed = set(&c["allowed"]);
        let (cleaned, offenders) = telguard::redact(text, &allowed);
        if cleaned != c["cleaned"].as_str().unwrap() || offenders != list(&c["offenders"]) || telguard::scan(text, &allowed) != list(&c["scan"]) {
            bad.push(format!("{text:?} got {cleaned:?} want {}", c["cleaned"]));
        }
    }
    assert!(bad.is_empty(), "{} of {} differ, first: {:#?}", bad.len(), cases.len(), &bad[..bad.len().min(5)]);
}

#[test]
fn fact_guard_redacts_and_scans_like_the_original() {
    let v = vectors();
    let cases = v["fact"].as_array().unwrap();
    let mut bad = Vec::new();
    for c in cases {
        let text = c["text"].as_str().unwrap();
        let allowed = set(&c["allowed"]);
        let (cleaned, offenders) = factguard::redact(text, &allowed);
        if cleaned != c["cleaned"].as_str().unwrap() || offenders != list(&c["offenders"]) || factguard::scan(text, &allowed) != list(&c["scan"]) {
            bad.push(format!("{text:?} got {cleaned:?} want {}", c["cleaned"]));
        }
    }
    assert!(bad.is_empty(), "{} of {} differ, first: {:#?}", bad.len(), cases.len(), &bad[..bad.len().min(5)]);
}

#[test]
fn link_gate_rewrites_like_the_original() {
    let v = vectors();
    let cases = v["link"].as_array().unwrap();
    let mut bad = Vec::new();
    for c in cases {
        let (text, typed) = (c["text"].as_str().unwrap(), c["typed"].as_str().unwrap());
        let got = linkgate::rewrite(text, typed);
        if got != c["out"].as_str().unwrap() { bad.push(format!("{text:?} typed {typed:?} got {got:?} want {}", c["out"])); }
    }
    assert!(bad.is_empty(), "{} of {} differ, first: {:#?}", bad.len(), cases.len(), &bad[..bad.len().min(5)]);
}

#[test]
fn the_engine_floor_and_the_filtered_reply_match_the_original_in_every_language() {
    let v = vectors();
    for c in v["safety"].as_array().unwrap() {
        let lang = c["lang"].as_str().unwrap();
        assert_eq!(packsafety::crisis_lines_default(lang), list(&c["crisis"]), "crisis lines for {lang:?}");
        assert_eq!(list(&c["crisis_empty_manifest"]), list(&c["crisis"]), "an empty manifest changes nothing");
        assert_eq!(packsafety::practitioner_line_none(), c["practitioner"].as_str().map(str::to_string));
        assert_eq!(packsafety::filtered_reply(lang), c["filtered"].as_str().unwrap(), "filtered reply for {lang:?}");
    }
}
