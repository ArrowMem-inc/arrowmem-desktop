//! The v2 loader: topic jsonl files (the v2 content shape), the derived natural medicine file, hosts.json. Strict and fail closed: any record that
//! does not parse, whose quote is not a byte substring of its stored context, whose host is not in hosts.json, or whose id is on the held list turns the
//! whole pack off. Natural medicine ships only the plants on the explicit yes list.
use crate::index::{tokens, Index};
use crate::integrity::{self, Unavailable};
use serde_json::{Map, Value};
use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};

pub const HOSTS_FILE: &str = "hosts.json";
/// The derived natural medicine file: plant_id, common_name, latin_name, aliases, sources of quote, url, fetched, traditional. Nothing authored.
pub const NATMED_FILE: &str = "natmed_shippable.jsonl";
const CANDIDATES: usize = 8;
/// The closed topic set. A topic file is named `<topic>.jsonl` and every record in it carries exactly that topic.
pub const TOPICS: [&str; 7] = ["survival", "preservation", "game_fish", "trapping", "grid_down", "vehicle", "farming"];
/// The loader's exact key lists. The converter's lists must equal these (tests/real_v2.rs compares `packconv keys`).
pub const RECORD_KEYS: [&str; 7] = ["id", "topic", "quote", "source_url", "context", "context_url", "retrieved"];
pub const NATMED_KEYS: [&str; 5] = ["plant_id", "common_name", "latin_name", "aliases", "sources"];
pub const SOURCE_KEYS: [&str; 4] = ["quote", "url", "fetched", "traditional"];
pub const HOSTS_KEYS: [&str; 2] = ["credit", "disclaimer"];

pub struct Record {
    pub id: String,
    pub topic: String,
    pub quote: String,
    pub url: String,
    pub retrieved: String,
    pub context: String,
    pub context_url: String,
}

pub struct Source {
    pub quote: String,
    pub url: String,
    pub fetched: String,
    pub traditional: bool,
}

pub struct Plant {
    names: Vec<Vec<String>>,
    pub sources: Vec<Source>,
}

pub struct Host {
    pub credit: String,
    pub disclaimer: String,
}

pub struct Pack {
    pub(crate) records: Vec<Record>,
    pub(crate) plants: Vec<Plant>,
    hosts: HashMap<String, Host>,
    index: Index,
    retrievals: AtomicUsize,
}

fn field<'a>(m: &'a Map<String, Value>, k: &str) -> Result<&'a str, Unavailable> {
    m.get(k).and_then(Value::as_str).ok_or(Unavailable("field"))
}

fn object(v: Value) -> Result<Map<String, Value>, Unavailable> {
    match v {
        Value::Object(m) => Ok(m),
        _ => Err(Unavailable("not an object")),
    }
}

fn exact(m: &Map<String, Value>, keys: &[&str], why: &'static str) -> Result<(), Unavailable> {
    if m.len() == keys.len() && keys.iter().all(|k| m.contains_key(*k)) { Ok(()) } else { Err(Unavailable(why)) }
}

fn host_char(b: u8) -> bool {
    matches!(b, b'a'..=b'z' | b'0'..=b'9' | b'.' | b'-')
}

/// Each non blank line with its raw text: the yes list hashes the line exactly as shipped.
type Line<'a> = (&'a str, Map<String, Value>);

fn lines(bytes: &[u8]) -> Result<Vec<Line<'_>>, Unavailable> {
    let text = std::str::from_utf8(bytes).map_err(|_| Unavailable("utf8"))?;
    text.lines().filter(|l| !l.trim().is_empty()).map(|l| Ok((l, object(serde_json::from_str(l).map_err(|_| Unavailable("json"))?)?))).collect()
}

/// The host of an https URL, fail closed: the authority runs to the first "/" or the end and is lowercase letters, digits, "." and "-" only,
/// so userinfo ("@"), a port (":"), a backslash and uppercase never parse.
pub fn host_of(url: &str) -> Option<&str> {
    let rest = url.strip_prefix("https://")?;
    let auth = &rest[..rest.find('/').unwrap_or(rest.len())];
    (!auth.is_empty() && auth.bytes().all(host_char)).then_some(auth)
}

fn hosts(bytes: &[u8]) -> Result<HashMap<String, Host>, Unavailable> {
    let v: Value = serde_json::from_slice(bytes).map_err(|_| Unavailable("hosts json"))?;
    let mut out = HashMap::new();
    for (name, h) in object(v)? {
        let h = object(h)?;
        exact(&h, &HOSTS_KEYS, "hosts keys")?;
        if name.is_empty() || !name.bytes().all(host_char) {
            return Err(Unavailable("hosts key"));
        }
        out.insert(name, Host { credit: field(&h, "credit")?.to_string(), disclaimer: field(&h, "disclaimer")?.to_string() });
    }
    Ok(out)
}

impl Pack {
    /// Open and verify the pack folder, then parse the very buffers that were hashed.
    pub fn open(dir: &Path, pin: &str, held: &HashSet<String>, yes: &[(&str, &str)]) -> Result<Pack, Unavailable> {
        Pack::from_files(integrity::load(dir, pin)?, held, yes)
    }

    /// `held` is the explicit held id list kept outside every repository. `yes` is the natural medicine yes list: each entry is (plant_id, SHA-256 of
    /// that plant's shipped line, hex). A plant whose line hash differs from its yes entry is dropped, so a changed entry needs a fresh yes.
    pub fn from_files(mut files: Vec<(String, Vec<u8>)>, held: &HashSet<String>, yes: &[(&str, &str)]) -> Result<Pack, Unavailable> {
        files.sort_by(|a, b| a.0.cmp(&b.0));
        let host_bytes = files.iter().find(|f| f.0 == HOSTS_FILE).ok_or(Unavailable("no hosts.json"))?;
        let hosts = hosts(&host_bytes.1)?;
        let host_known = |url: &str| host_of(url).is_some_and(|h| hosts.contains_key(h));
        let (mut records, mut plants) = (Vec::new(), Vec::new());
        let mut ids = HashSet::new();
        for (name, bytes) in &files {
            if name == HOSTS_FILE || !name.ends_with(".jsonl") {
                continue;
            }
            for (raw, m) in lines(bytes)? {
                if name == NATMED_FILE {
                    let id = field(&m, "plant_id")?;
                    if !integrity::safe_path(id) {
                        return Err(Unavailable("id"));
                    }
                    if !ids.insert(id.to_string()) {
                        return Err(Unavailable("duplicate id"));
                    }
                    plants.extend(plant(&m, held, yes.contains(&(id, integrity::sha256_hex(raw.as_bytes()).as_str())), &host_known)?);
                } else {
                    let r = record(&m, name.strip_suffix(".jsonl").unwrap_or(name), held, &host_known)?;
                    if !ids.insert(r.id.clone()) {
                        return Err(Unavailable("duplicate id"));
                    }
                    records.push(r);
                }
            }
        }
        let index = Index::new(records.iter().map(|r| format!("{} {}", r.quote, r.context)));
        Ok(Pack { records, plants, hosts, index, retrievals: AtomicUsize::new(0) })
    }

    pub fn record_count(&self) -> usize {
        self.records.len()
    }

    pub fn record_ids(&self) -> impl Iterator<Item = &str> {
        self.records.iter().map(|r| r.id.as_str())
    }

    /// How many times retrieval ran: the proof that a crisis turn never reached the index.
    pub fn retrievals(&self) -> usize {
        self.retrievals.load(Ordering::Relaxed)
    }

    /// Top 8 by BM25 over quote and context, identical quote bytes once. Natural medicine is not in the index, so a symptom word can never select a plant.
    pub(crate) fn retrieve(&self, question: &str) -> Vec<usize> {
        self.retrievals.fetch_add(1, Ordering::Relaxed);
        let mut seen = HashSet::new();
        let mut out = Vec::new();
        for i in self.index.rank(question) {
            if seen.insert(self.records[i].quote.as_str()) {
                out.push(i);
                if out.len() == CANDIDATES {
                    break;
                }
            }
        }
        out
    }

    /// Plants whose common name, latin name or alias appears in the question as whole words, in stored order.
    pub(crate) fn named_plants(&self, question: &str) -> Vec<&Plant> {
        let q = tokens(question);
        self.plants.iter().filter(|p| p.names.iter().any(|n| q.windows(n.len()).any(|w| w == n.as_slice()))).collect()
    }

    pub(crate) fn host(&self, url: &str) -> Option<&Host> {
        self.hosts.get(host_of(url)?)
    }
}

fn record(m: &Map<String, Value>, stem: &str, held: &HashSet<String>, host_known: &dyn Fn(&str) -> bool) -> Result<Record, Unavailable> {
    exact(m, &RECORD_KEYS, "record keys")?;
    let (id, quote, url, context) = (field(m, "id")?, field(m, "quote")?, field(m, "source_url")?, field(m, "context")?);
    let (topic, context_url) = (field(m, "topic")?, field(m, "context_url")?);
    if !integrity::safe_path(id) {
        return Err(Unavailable("id"));
    }
    if held.contains(id) {
        return Err(Unavailable("held record"));
    }
    if topic != stem || !TOPICS.contains(&topic) {
        return Err(Unavailable("topic"));
    }
    if quote.is_empty() || !context.contains(quote) {
        return Err(Unavailable("quote is not in its context"));
    }
    if !host_known(url) || !host_known(context_url) {
        return Err(Unavailable("host not in hosts.json"));
    }
    Ok(Record {
        id: id.to_string(),
        topic: topic.to_string(),
        quote: quote.to_string(),
        url: url.to_string(),
        retrieved: field(m, "retrieved")?.to_string(),
        context: context.to_string(),
        context_url: context_url.to_string(),
    })
}

fn plant(m: &Map<String, Value>, held: &HashSet<String>, approved: bool, host_known: &dyn Fn(&str) -> bool) -> Result<Option<Plant>, Unavailable> {
    exact(m, &NATMED_KEYS, "natmed keys")?;
    let id = field(m, "plant_id")?;
    if held.contains(id) {
        return Err(Unavailable("held record"));
    }
    let mut names = vec![field(m, "common_name")?, field(m, "latin_name")?]
        .into_iter()
        .map(tokens)
        .collect::<Vec<_>>();
    for a in m["aliases"].as_array().ok_or(Unavailable("aliases"))? {
        names.push(tokens(a.as_str().ok_or(Unavailable("alias"))?));
    }
    if names.iter().any(Vec::is_empty) {
        return Err(Unavailable("empty plant name"));
    }
    let mut sources = Vec::new();
    for s in m["sources"].as_array().ok_or(Unavailable("sources"))? {
        let s = s.as_object().ok_or(Unavailable("source"))?;
        exact(s, &SOURCE_KEYS, "natmed keys")?;
        let (quote, url) = (field(s, "quote")?, field(s, "url")?);
        if quote.is_empty() || !host_known(url) {
            return Err(Unavailable("natmed source"));
        }
        let traditional = s["traditional"].as_bool().ok_or(Unavailable("traditional flag"))?;
        sources.push(Source { quote: quote.to_string(), url: url.to_string(), fetched: field(s, "fetched")?.to_string(), traditional });
    }
    if sources.is_empty() {
        return Err(Unavailable("plant without sources"));
    }
    Ok(approved.then_some(Plant { names, sources }))
}
