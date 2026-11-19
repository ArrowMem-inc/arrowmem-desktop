//! Fixture pack builder. Every sentence here is invented for the tests; no real pack content is copied.
#![allow(dead_code)]
use packanswer::integrity::sha256_hex;
use packanswer::{Candidate, Pack, Selector};
use serde_json::json;
use std::cell::Cell;
use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};

pub const YES: [&str; 2] = ["ginger", "garlic"];
pub const CDC: &str = "https://www.cdc.gov/fixture/page.html";
pub const NPS: &str = "https://home.nps.gov/fixture/page.html";
pub const NCCIH: &str = "https://www.nccih.nih.gov/fixture/page";

pub fn rec(id: &str, topic: &str, quote: &str, url: &str) -> String {
    let context = format!("A heading\nBefore the quote.\n{quote}\nAfter the quote.");
    json!({"topic": topic, "id": id, "quote": quote, "source_url": url, "context_url": url, "retrieved": "2026-11-05", "context": context}).to_string()
}

pub fn plant(id: &str, common: &str, latin: &str, aliases: &[&str], sources: &[(&str, bool)]) -> String {
    let s: Vec<_> = sources.iter().map(|(q, t)| json!({"quote": q, "url": NCCIH, "fetched": "2026-11-14", "traditional": t})).collect();
    json!({"plant_id": id, "common_name": common, "latin_name": latin, "aliases": aliases, "sources": s}).to_string()
}

fn jsonl(lines: &[String]) -> String {
    lines.join("\n") + "\n"
}

pub fn hosts_json() -> String {
    let h = |c: &str| json!({"credit": format!("Credit line for {c}."), "disclaimer": format!("Disclaimer line for {c}.")});
    json!({"www.cdc.gov": h("cdc"), "home.nps.gov": h("nps"), "www.nccih.nih.gov": h("nccih")}).to_string()
}

pub fn default_files() -> Vec<(&'static str, String)> {
    vec![
        ("hosts.json", hosts_json()),
        (
            "survival.jsonl",
            jsonl(&[
                rec("fx-water-0001", "survival", "Boil the water for 1 minute before drinking it.", CDC),
                rec("fx-tent-0001", "survival", "Drive the tent pegs in at an angle.", NPS),
                rec("fx-nausea-0001", "survival", "Sip clear fluids slowly when nausea comes on.", CDC),
            ]),
        ),
        ("preservation.jsonl", jsonl(&[rec("fx-jar-0001", "preservation", "Keep jars of canned beans in a cool dark cupboard.", CDC)])),
        ("game_fish.jsonl", jsonl(&[rec("fx-fish-0001", "game_fish", "Check the regional rules before setting a fishing line.", NPS)])),
        ("trapping.jsonl", jsonl(&[rec("fx-trap-0001", "trapping", "Wear gloves when handling a trapped animal.", NPS)])),
        ("grid_down.jsonl", jsonl(&[rec("fx-dup-0001", "grid_down", "Drive the tent pegs in at an angle.", NPS)])),
        (
            "natmed_shippable.jsonl",
            jsonl(&[
                plant("ginger", "Ginger", "Zingiber officinale", &[], &[("Ginger is used traditionally for nausea.", true), ("Ginger can interact with blood thinners.", false)]),
                plant("garlic", "Garlic", "Allium sativum", &["stinking rose"], &[("Garlic may raise bleeding risk.", false)]),
                plant("chamomile", "Chamomile", "Matricaria chamomilla", &[], &[("Chamomile tea is used for nausea.", true)]),
            ]),
        ),
    ]
}

/// Write the files plus a PACK.sha256 over them; returns the dir and the pin (the sha256 of PACK.sha256).
pub fn write_pack(name: &str, files: &[(&str, String)]) -> (PathBuf, String) {
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join(name);
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    let mut sorted: Vec<_> = files.iter().collect();
    sorted.sort_by(|a, b| a.0.cmp(b.0));
    let mut manifest = String::new();
    for (p, c) in sorted {
        fs::write(dir.join(p), c).unwrap();
        manifest.push_str(&format!("{}  {p}\n", sha256_hex(c.as_bytes())));
    }
    fs::write(dir.join("PACK.sha256"), &manifest).unwrap();
    (dir, sha256_hex(manifest.as_bytes()))
}

/// Open with a yes list built the way the app's compiled one is: (plant_id, SHA-256 of that plant's shipped line), here taken from the files in `dir`
/// for the given plant ids.
pub fn open_with(dir: &Path, pin: &str, held: &HashSet<String>, ids: &[&str]) -> Result<Pack, packanswer::integrity::Unavailable> {
    let text = fs::read_to_string(dir.join("natmed_shippable.jsonl")).unwrap_or_default();
    let yes: Vec<(String, String)> = text
        .lines()
        .filter_map(|l| {
            let id = serde_json::from_str::<serde_json::Value>(l).ok()?["plant_id"].as_str()?.to_string();
            ids.contains(&id.as_str()).then(|| (id, sha256_hex(l.as_bytes())))
        })
        .collect();
    Pack::open(dir, pin, held, &yes.iter().map(|(i, h)| (i.as_str(), h.as_str())).collect::<Vec<_>>())
}

pub fn open_files(name: &str, files: &[(&str, String)]) -> Result<Pack, packanswer::integrity::Unavailable> {
    let (dir, pin) = write_pack(name, files);
    open_with(&dir, &pin, &HashSet::new(), &YES)
}

pub fn pack(name: &str) -> Pack {
    open_files(name, &default_files()).unwrap()
}

/// A selector that records how often it ran and returns what it is told.
pub struct Sel {
    pub calls: Cell<usize>,
    pub reply: Vec<String>,
}

impl Sel {
    pub fn new(reply: &[&str]) -> Sel {
        Sel { calls: Cell::new(0), reply: reply.iter().map(|s| s.to_string()).collect() }
    }
}

impl Selector for Sel {
    fn select(&self, _q: &str, _c: &[Candidate]) -> Vec<String> {
        self.calls.set(self.calls.get() + 1);
        self.reply.clone()
    }
}

pub fn quotes(a: &packanswer::Answer) -> Vec<String> {
    match a {
        packanswer::Answer::Blocks(f) | packanswer::Answer::EnglishOnly(f) => f.blocks.iter().map(|b| b.quote.clone()).collect(),
        _ => Vec::new(),
    }
}
