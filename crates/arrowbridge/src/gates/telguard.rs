//! Port of mvf_tel_guard (scan, redact, floor_numbers): refuse any telephone number the MODEL produced; only the floor speaks. The streaming gate and the pack
//! row check are not ported (the companion replies in one piece and never checks pack files).
use super::patterns_gen as p;
use super::rx::{tidy, Rx};
use std::collections::BTreeSet;
use std::path::Path;
use std::sync::OnceLock;

fn tel() -> &'static Rx { static R: OnceLock<Rx> = OnceLock::new(); R.get_or_init(|| Rx::new(&p::TEL)) }
fn non_digit() -> &'static fancy_regex::Regex { static R: OnceLock<fancy_regex::Regex> = OnceLock::new(); R.get_or_init(|| fancy_regex::Regex::new(r"\D").unwrap()) }

pub const UNIVERSAL_EMERGENCY: &str = "911";

/// The numbers the crisis floor delivers, read from the pack manifest, never hardcoded. No pack, or an unreadable manifest: only 911 (fail closed).
pub fn floor_numbers(pack_dir: Option<&Path>) -> BTreeSet<String> {
    let mut set: BTreeSet<String> = BTreeSet::new();
    set.insert(UNIVERSAL_EMERGENCY.to_string());
    let Some(dir) = pack_dir.filter(|d| !d.as_os_str().is_empty()) else { return set };
    let Ok(raw) = std::fs::read_to_string(dir.join("manifest.json")) else { return set };
    let Ok(v) = serde_json::from_str::<serde_json::Value>(&raw) else { return set };
    // An engine give-up reading the pack allows nothing extra: only 911 stays.
    if let Some(found) = tel().find_all(&super::pyjson::dumps(&v)) { set.extend(found); }
    set
}

fn digits(num: &str) -> String {
    let d = non_digit().replace_all(num, "").into_owned();
    if d.chars().count() == 11 && d.starts_with('1') { d[1..].to_string() } else { d }
}

fn on_floor(found: &str, allowed: &BTreeSet<String>) -> bool {
    allowed.contains(found) || { let f = digits(found); allowed.iter().any(|a| digits(a) == f) }
}

/// Every telephone-shaped string in `text` that the floor does not stand behind. An engine give-up reports the whole text as an offender (fail closed).
pub fn scan(text: &str, allowed: &BTreeSet<String>) -> Vec<String> {
    match tel().find_all(text) {
        Some(all) => all.into_iter().filter(|m| !on_floor(m, allowed)).collect(),
        None => vec![text.to_string()],
    }
}

/// (cleaned text, offenders). Offenders are removed, not masked. If the engine gives up the WHOLE text is removed (fail closed: the caller then has no reply
/// and falls to its own floor).
pub fn redact(text: &str, allowed: &BTreeSet<String>) -> (String, Vec<String>) {
    let mut offenders = Vec::new();
    let cleaned = tel().sub_with(text, |c| {
        let found = c.whole;
        if on_floor(found, allowed) { found.to_string() } else { offenders.push(found.to_string()); String::new() }
    });
    match cleaned {
        Some(c) => (tidy(&c), offenders),
        None => (String::new(), vec![text.to_string()]),
    }
}
