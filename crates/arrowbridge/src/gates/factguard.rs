//! Port of mvf_fact_guard (allowed_facts, scan, redact): a chapter, table or form number the pack does not state is removed from the model's reply.
use super::patterns_gen as p;
use super::rx::{tidy, Rx};
use std::collections::BTreeSet;
use std::path::Path;
use std::sync::OnceLock;

fn fact() -> &'static Rx { static R: OnceLock<Rx> = OnceLock::new(); R.get_or_init(|| Rx::new(&p::FACT)) }

/// What the pack states (citations.json and manifest.json). No pack: nothing is allowed (fail closed).
pub fn allowed_facts(pack_dir: Option<&Path>) -> BTreeSet<String> {
    let mut set = BTreeSet::new();
    let Some(dir) = pack_dir.filter(|d| !d.as_os_str().is_empty()) else { return set };
    for name in ["citations.json", "manifest.json"] {
        let Ok(raw) = std::fs::read_to_string(dir.join(name)) else { continue };
        let Ok(v) = serde_json::from_str::<serde_json::Value>(&raw) else { continue };
        if let Some(found) = fact().find_all(&super::pyjson::dumps(&v)) { set.extend(found); }
    }
    set
}

pub fn scan(text: &str, allowed: &BTreeSet<String>) -> Vec<String> {
    match fact().find_all(text) {
        Some(all) => all.into_iter().filter(|m| !allowed.contains(m)).collect(),
        None => vec![text.to_string()],
    }
}

/// (cleaned text, offenders); on an engine give-up the whole text is removed (fail closed).
pub fn redact(text: &str, allowed: &BTreeSet<String>) -> (String, Vec<String>) {
    let mut offenders = Vec::new();
    let cleaned = fact().sub_with(text, |c| {
        let found = c.whole;
        if allowed.contains(found) { found.to_string() } else { offenders.push(found.to_string()); String::new() }
    });
    match cleaned {
        Some(c) => (tidy(&c), offenders),
        None => (String::new(), vec![text.to_string()]),
    }
}
