//! Model manifest, RAM-based selection, and the verified downloader. Model-agnostic: nothing here names a model;
//! selection and download read only `models/manifest.json` data.
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

pub const MANIFEST_JSON: &str = include_str!("../../models/manifest.json");
const GIB: u64 = 1024 * 1024 * 1024;
/// A machine reports a little less than its marketed RAM; accept this fraction of min_ram_gb.
const RAM_TOLERANCE_PCT: u64 = 90;
/// The file itself must also fit with this multiple (percent) in RAM, for context and the OS.
const FILE_HEADROOM_PCT: u64 = 150;

#[derive(Debug, Clone, Deserialize)]
pub struct Model {
    pub id: String,
    pub repo: String,
    pub commit: String,
    pub source_host: String,
    pub file: String,
    pub size_bytes: u64,
    pub sha256: String,
    pub min_ram_gb: u64,
    /// RAM this machine class needs on the desktop (the desktop tier table); falls back to min_ram_gb.
    #[serde(default)]
    pub desktop_min_ram_gb: Option<u64>,
    /// GiB that must stay free on top of the model file before a load (memory guard).
    #[serde(default)]
    pub headroom_gb: u64,
    pub tier: u32,
    pub approved: bool,
    #[serde(default)]
    pub default: bool,
    /// Shown in the picker and usable when chosen, but never the AUTOMATIC pick (a very large model must be asked for, never downloaded by default).
    #[serde(default)]
    pub offer_only: bool,
    /// A person-readable model name for the picker (a fact about the model, not a sentence of ours).
    #[serde(default)]
    pub display_name: String,
    /// A model made of several files (a very large model is split into shards): every file with its own size and sha256. Empty for a single-file model.
    /// For these `file` is the repo path of the FIRST shard (the one llama-server is pointed at: it finds the others beside it), `size_bytes` is the total.
    #[serde(default)]
    pub parts: Vec<Part>,
    /// A top-tier model: listed only on a computer that could hold it (or when it is already installed).
    #[serde(default)]
    pub hide_unless_fits: bool,
    pub license: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Part {
    /// The path inside the repository (a shard may sit in a folder there).
    pub file: String,
    pub size_bytes: u64,
    pub sha256: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Manifest {
    pub models: Vec<Model>,
}

pub fn load_manifest() -> Manifest {
    serde_json::from_str(MANIFEST_JSON).expect("models/manifest.json is embedded and validated by tests")
}

impl Model {
    /// A stand-in entry for a model file that is not in the manifest (one the person chose from the files already on this computer): no URL, no hash, never approved.
    pub fn synthetic(id: &str, size_bytes: u64) -> Model {
        Model { id: id.into(), repo: String::new(), commit: String::new(), source_host: String::new(), file: String::new(), size_bytes, sha256: String::new(),
                min_ram_gb: 0, desktop_min_ram_gb: None, headroom_gb: 1, tier: 0, approved: false, default: false, offer_only: false, display_name: String::new(), parts: Vec::new(), hide_unless_fits: false, license: String::new() }
    }

    /// Every file this model is made of: (repo path, local file name, size, sha256). One entry for a single-file model.
    pub fn files(&self) -> Vec<(String, String, u64, String)> {
        let base = |p: &str| p.rsplit('/').next().unwrap_or(p).to_string();
        if self.parts.is_empty() {
            vec![(self.file.clone(), base(&self.file), self.size_bytes, self.sha256.clone())]
        } else {
            self.parts.iter().map(|x| (x.file.clone(), base(&x.file), x.size_bytes, x.sha256.clone())).collect()
        }
    }

    /// The local file name llama-server is pointed at (the first shard for a split model).
    pub fn main_name(&self) -> String {
        self.files().into_iter().next().map(|f| f.1).unwrap_or_default()
    }

    /// The URL of one file of this model, built only from the manifest's host, repo and pinned revision.
    pub fn url_of(&self, repo_path: &str) -> String {
        let scheme = if self.source_host.starts_with("127.0.0.1") { "http" } else { "https" };
        format!("{scheme}://{}/{}/resolve/{}/{}", self.source_host, self.repo, self.commit, repo_path)
    }

    /// The only URL this model may be fetched from. Loopback hosts (tests) use http, everything else https.
    pub fn url(&self) -> String {
        let scheme = if self.source_host.starts_with("127.0.0.1") { "http" } else { "https" };
        format!("{scheme}://{}/{}/resolve/{}/{}", self.source_host, self.repo, self.commit, self.file)
    }
}

/// Largest approved entry whose RAM need fits; ties go to the default-flagged entry, then the smaller file.
pub fn select(models: &[Model], ram_bytes: u64) -> Option<&Model> {
    models
        .iter()
        .filter(|m| m.approved && !m.offer_only && fits(m, ram_bytes))
        .max_by_key(|m| (m.tier, m.default, std::cmp::Reverse(m.size_bytes)))
}

pub fn fits(m: &Model, ram_bytes: u64) -> bool {
    ram_bytes >= m.desktop_min_ram_gb.unwrap_or(m.min_ram_gb) * GIB * RAM_TOLERANCE_PCT / 100
        && ram_bytes >= m.size_bytes * FILE_HEADROOM_PCT / 100
}

pub fn total_ram_bytes() -> Option<u64> {
    #[cfg(target_os = "linux")]
    {
        return parse_meminfo(&fs::read_to_string("/proc/meminfo").ok()?);
    }
    #[cfg(target_os = "macos")]
    {
        let out = std::process::Command::new("/usr/sbin/sysctl").args(["-n", "hw.memsize"]).output().ok()?;
        return String::from_utf8_lossy(&out.stdout).trim().parse().ok();
    }
    #[allow(unreachable_code)]
    None
}

pub fn parse_meminfo(s: &str) -> Option<u64> {
    let line = s.lines().find(|l| l.starts_with("MemTotal:"))?;
    let kb: u64 = line.split_whitespace().nth(1)?.parse().ok()?;
    Some(kb * 1024)
}

pub fn sha256_file(p: &Path) -> std::io::Result<String> {
    let mut f = File::open(p)?;
    let mut h = Sha256::new();
    let mut buf = vec![0u8; 1 << 20];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
    }
    Ok(h.finalize().iter().map(|b| format!("{b:02x}")).collect())
}

fn file_ok(path: &Path, size: u64, sha: &str) -> bool {
    path.metadata().map(|md| md.len() == size).unwrap_or(false) && sha256_file(path).map(|h| h == sha).unwrap_or(false)
}

/// The model is on disk and every file of it matches its pinned size and sha256. `path` is the main file (the first shard of a split model); the other shards
/// are looked for beside it. This reads the whole model: never call it on a poll.
pub fn verified(m: &Model, path: &Path) -> bool {
    if m.parts.is_empty() {
        return file_ok(path, m.size_bytes, &m.sha256);
    }
    let Some(dir) = path.parent() else { return false };
    m.files().iter().all(|(_, local, size, sha)| file_ok(&dir.join(local), *size, sha))
}

/// Which approved models have passed their full sha256, remembered by the size and modified time of every file (a changed file is unproven again).
/// The picker shows "Installed" only for a proven model; the hash itself runs once on a worker, never in a poll.
#[derive(Default)]
pub struct Proofs {
    ok: std::collections::HashMap<String, Vec<(u64, u64)>>,
    busy: std::collections::HashSet<String>,
}

fn stamp(m: &Model, dir: &Path) -> Option<Vec<(u64, u64)>> {
    m.files().iter().map(|(_, local, _, _)| {
        let md = dir.join(local).metadata().ok()?;
        let t = md.modified().ok()?.duration_since(std::time::UNIX_EPOCH).ok()?.as_secs();
        Some((md.len(), t))
    }).collect()
}

impl Proofs {
    pub fn is_proven(&self, m: &Model, dir: &Path) -> bool {
        match (self.ok.get(&m.id), stamp(m, dir)) { (Some(a), Some(b)) => *a == b, _ => false }
    }
    /// Record a proof the caller just made (a download that checked every file, or a full verified()).
    pub fn mark(&mut self, m: &Model, dir: &Path) {
        if let Some(s) = stamp(m, dir) { self.ok.insert(m.id.clone(), s); }
    }
    /// True for the one caller that should start the check now (none is running for this id).
    pub fn begin(&mut self, id: &str) -> bool { self.busy.insert(id.to_string()) }
    pub fn end(&mut self, id: &str) { self.busy.remove(id); }
}

/// What is on disk for an approved model, decided before anything is written or started.
#[derive(Debug, PartialEq)]
pub enum Presence {
    /// Not there, or not all of it (a half-downloaded split model): the model service idles.
    Missing,
    /// There and equal to the manifest, size and sha256 of every file: the main file to load.
    Verified(PathBuf),
    /// There, but not what the manifest pins: never handed to llama.cpp.
    Mismatch,
}

pub fn presence(m: &Model, dir: &Path) -> Presence {
    if !installed_cheap(m, dir) {
        return Presence::Missing;
    }
    let main = dir.join(m.main_name());
    if verified(m, &main) { Presence::Verified(main) } else { Presence::Mismatch }
}

/// A cheap look (sizes only, no hashing) for polls: every file of the model is there with the manifest size.
pub fn installed_cheap(m: &Model, dir: &Path) -> bool {
    m.files().iter().all(|(_, local, size, _)| dir.join(local).metadata().map(|md| md.len() == *size).unwrap_or(false))
}

/// Bytes of this model on disk so far (finished files plus the partial one), for the percent a download shows.
pub fn bytes_so_far(m: &Model, dir: &Path) -> u64 {
    m.files().iter().map(|(_, local, size, _)| {
        let done = dir.join(local).metadata().map(|md| md.len()).unwrap_or(0);
        if done > 0 { done.min(*size) } else { dir.join(format!("{local}.part")).metadata().map(|md| md.len()).unwrap_or(0).min(*size) }
    }).sum()
}

#[derive(Debug)]
pub enum DlError {
    NotInManifest,
    Http(String),
    Io(std::io::Error),
    BadHash,
}
impl From<std::io::Error> for DlError {
    fn from(e: std::io::Error) -> Self {
        DlError::Io(e)
    }
}

/// Fetch `url` into `dir`, but only if it is exactly the URL of an approved manifest entry (its first file). A split model is fetched file by file. Resumes a
/// `.part` file with a Range request. A file is renamed into place only after its size and sha256 match; a bad file is deleted. Returns the main file's path.
pub fn download(manifest: &Manifest, url: &str, dir: &Path) -> Result<PathBuf, DlError> {
    let m = manifest.models.iter().find(|m| m.approved && m.url() == url).ok_or(DlError::NotInManifest)?;
    fs::create_dir_all(dir)?;
    for (repo_path, local, size, sha) in m.files() {
        fetch_file(&m.url_of(&repo_path), dir, &local, size, &sha)?;
    }
    Ok(dir.join(m.main_name()))
}

fn fetch_file(url: &str, dir: &Path, local: &str, size: u64, sha: &str) -> Result<(), DlError> {
    let dest = dir.join(local);
    if file_ok(&dest, size, sha) {
        return Ok(());
    }
    let part = dir.join(format!("{local}.part"));
    let have = part.metadata().map(|x| x.len()).unwrap_or(0);
    let have = if have > size { 0 } else { have };
    // A complete .part (killed before the verify) must not be asked for bytes=size-, which servers answer 416.
    if have < size {
        let mut req = ureq::get(url);
        if have > 0 {
            req = req.set("Range", &format!("bytes={have}-"));
        }
        let resp = req.call().map_err(|e| DlError::Http(e.to_string()))?;
        let append = resp.status() == 206;
        let mut f = if append {
            OpenOptions::new().append(true).open(&part)?
        } else {
            File::create(&part)? // server ignored Range (200): restart from zero
        };
        let mut r = resp.into_reader();
        let mut buf = vec![0u8; 1 << 20];
        loop {
            let n = r.read(&mut buf)?;
            if n == 0 {
                break;
            }
            f.write_all(&buf[..n])?;
        }
        f.flush()?;
        drop(f);
    }
    if !file_ok(&part, size, sha) {
        // Wrong size short of the end is a truncated transfer: keep the .part so the next call resumes.
        let len = part.metadata().map(|x| x.len()).unwrap_or(0);
        if len >= size {
            let _ = fs::remove_file(&part);
        }
        return Err(DlError::BadHash);
    }
    fs::rename(&part, &dest)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{BufRead, BufReader};
    use std::net::TcpListener;

    fn m(id: &str, tier: u32, ram: u64, size: u64, approved: bool, default: bool) -> Model {
        Model {
            id: id.into(), repo: "r/x".into(), commit: "c0".into(), source_host: "huggingface.co".into(),
            file: format!("{id}.gguf"), size_bytes: size, sha256: "0".repeat(64), min_ram_gb: ram, desktop_min_ram_gb: None, headroom_gb: 2, tier,
            approved, default, offer_only: false, display_name: String::new(), parts: Vec::new(), hide_unless_fits: false, license: "Apache-2.0".into(),
        }
    }
    fn set() -> Vec<Model> {
        vec![
            m("small", 1, 8, 3 * GIB, true, false),
            m("mid", 2, 16, 5 * GIB, true, true),
            m("big", 3, 24, 14 * GIB, true, false),
        ]
    }

    #[test]
    fn real_manifest_parses_and_has_a_default() {
        let mf = load_manifest();
        assert!(mf.models.iter().any(|x| x.default));
        assert!(mf.models.iter().any(|x| x.tier > mf.models.iter().find(|y| y.default).unwrap().tier));
    }

    #[test]
    fn selection_boundaries() {
        let s = set();
        let id = |b: u64| select(&s, b).map(|x| x.id.clone());
        assert_eq!(id(0), None);
        assert_eq!(id(7 * GIB), None); // 7 GiB < 90% of 8 GiB = 7.2
        assert_eq!(id(72 * GIB / 10 + 1), Some("small".into()));
        assert_eq!(id(8 * GIB), Some("small".into()));
        assert_eq!(id(144 * GIB / 10 - 1), Some("small".into()));
        assert_eq!(id(144 * GIB / 10), Some("mid".into()));
        assert_eq!(id(16 * GIB), Some("mid".into()));
        assert_eq!(id(216 * GIB / 10 - 1), Some("mid".into()));
        assert_eq!(id(216 * GIB / 10), Some("big".into()));
        assert_eq!(id(64 * GIB), Some("big".into()));
    }

    #[test]
    fn unapproved_never_chosen_and_file_must_fit() {
        let mut s = set();
        s[2].approved = false;
        assert_eq!(select(&s, 64 * GIB).unwrap().id, "mid");
        let s2 = vec![m("odd", 1, 1, 10 * GIB, true, false)]; // tiny RAM class, huge file
        assert!(select(&s2, 12 * GIB).is_none()); // 12 < 15 GiB needed
        assert!(select(&s2, 15 * GIB).is_some());
    }

    #[test]
    fn selection_uses_data_only() {
        // a brand-new entry with a higher tier and unknown name wins when it fits
        let mut s = set();
        s.push(m("zzz-future", 9, 32, 20 * GIB, true, false));
        assert_eq!(select(&s, 32 * GIB).unwrap().id, "zzz-future");
        assert_eq!(select(&s, 24 * GIB).unwrap().id, "big");
    }

    #[test]
    fn meminfo_parse() {
        assert_eq!(parse_meminfo("MemTotal:       16384000 kB\nMemFree: 1 kB\n"), Some(16384000 * 1024));
        assert_eq!(parse_meminfo("nope"), None);
    }

    /// One-shot-per-connection HTTP server over loopback with Range support. `drop_after` truncates the first
    /// response to simulate a broken transfer.
    fn serve(body: Vec<u8>, drop_after: Option<usize>, hits: std::sync::Arc<std::sync::Mutex<Vec<String>>>) -> u16 {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        std::thread::spawn(move || {
            let mut first = true;
            for s in l.incoming() {
                let mut s = s.unwrap();
                let mut rd = BufReader::new(s.try_clone().unwrap());
                let mut range = 0usize;
                let mut path = String::new();
                loop {
                    let mut line = String::new();
                    if rd.read_line(&mut line).unwrap_or(0) == 0 || line == "\r\n" {
                        break;
                    }
                    if line.starts_with("GET ") {
                        path = line.split_whitespace().nth(1).unwrap().to_string();
                    }
                    if let Some(r) = line.to_lowercase().strip_prefix("range: bytes=") {
                        range = r.trim().trim_end_matches('-').parse().unwrap();
                    }
                }
                hits.lock().unwrap().push(format!("{path} range={range}"));
                let part = &body[range..];
                let (code, hdr) = if range > 0 { ("206 Partial Content", "") } else { ("200 OK", "") };
                let _ = hdr;
                let send = if first { drop_after.map(|d| d.min(part.len())).unwrap_or(part.len()) } else { part.len() };
                first = false;
                let _ = write!(s, "HTTP/1.1 {code}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", part.len());
                let _ = s.write_all(&part[..send]);
            }
        });
        port
    }

    fn fixture(port: u16, body: &[u8]) -> (Manifest, String) {
        let mut e = m("fix", 1, 1, body.len() as u64, true, true);
        e.source_host = format!("127.0.0.1:{port}");
        e.sha256 = Sha256::digest(body).iter().map(|b| format!("{b:02x}")).collect();
        let url = e.url();
        (Manifest { models: vec![e] }, url)
    }
    fn tmp(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("arrowmem-dl-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        d
    }

    #[test]
    fn refuses_url_not_in_manifest() {
        let body = vec![7u8; 1000];
        let hits = Default::default();
        let port = serve(body.clone(), None, std::sync::Arc::clone(&hits));
        let (mf, url) = fixture(port, &body);
        let d = tmp("refuse");
        assert!(matches!(download(&mf, &format!("{url}x"), &d), Err(DlError::NotInManifest)));
        assert!(matches!(download(&mf, "http://evil.example/a.gguf", &d), Err(DlError::NotInManifest)));
        assert!(hits.lock().unwrap().is_empty(), "no request may be made for a refused URL");
    }

    #[test]
    fn downloads_resumes_and_verifies() {
        let body: Vec<u8> = (0..300_000u32).map(|i| (i % 251) as u8).collect();
        let hits: std::sync::Arc<std::sync::Mutex<Vec<String>>> = Default::default();
        let port = serve(body.clone(), Some(100_000), hits.clone());
        let (mf, url) = fixture(port, &body);
        let d = tmp("resume");
        // first attempt truncated: error, .part kept
        assert!(download(&mf, &url, &d).is_err());
        let part = d.join("fix.gguf.part");
        assert!(part.metadata().unwrap().len() < body.len() as u64);
        // second attempt resumes with a Range header and completes
        let p = download(&mf, &url, &d).unwrap();
        assert_eq!(fs::read(&p).unwrap(), body);
        assert!(!part.exists());
        let h = hits.lock().unwrap().clone();
        assert!(h[0].ends_with("range=0"), "{h:?}");
        assert!(h[1].ends_with("range=100000") || !h[1].ends_with("range=0"), "{h:?}");
        // already-verified file: no further request
        let n = hits.lock().unwrap().len();
        download(&mf, &url, &d).unwrap();
        assert_eq!(hits.lock().unwrap().len(), n);
    }

    #[test]
    fn wrong_bytes_are_deleted_not_installed() {
        let body = vec![1u8; 5000];
        let hits = Default::default();
        let port = serve(vec![2u8; 5000], None, hits); // serves different bytes of the same size
        let (mf, url) = fixture(port, &body);
        let d = tmp("bad");
        assert!(matches!(download(&mf, &url, &d), Err(DlError::BadHash)));
        assert!(!d.join("fix.gguf").exists());
        assert!(!d.join("fix.gguf.part").exists());
    }

    #[test]
    fn the_offered_models_are_never_the_automatic_pick_and_carry_checkable_hashes() {
        let mf = load_manifest();
        let offered: Vec<&Model> = mf.models.iter().filter(|m| m.offer_only).collect();
        assert!(offered.len() >= 2, "the two much larger models are in the manifest");
        for m in &offered {
            assert!(m.approved && m.sha256.len() == 64 && m.sha256.bytes().all(|b| b.is_ascii_hexdigit()), "{}", m.id);
            assert!(m.commit.len() == 40 && m.commit.bytes().all(|b| b.is_ascii_hexdigit()), "{}: a pinned revision, never a branch", m.id);
            assert_eq!(m.source_host, "huggingface.co");
            assert!(m.url().contains(&m.commit) && m.url().starts_with("https://huggingface.co/"));
        }
        for ram in [8u64, 16, 32, 64, 256] {
            let pick = select(&mf.models, ram * GIB).map(|m| m.id.clone()).unwrap_or_default();
            assert!(!mf.models.iter().find(|m| m.id == pick).map(|m| m.offer_only).unwrap_or(false), "{ram} GiB picked an offered model: {pick}");
        }
    }

    #[test]
    fn a_top_tier_can_be_added_later_by_data_alone() {
        // a machine class far above today's: a new entry with a higher tier and offer_only is listed and fits by its own floor, and still never becomes the automatic pick
        let mut v = set();
        let mut top = m("top", 9, 96, 70 * GIB, true, false);
        top.offer_only = true;
        v.push(top);
        assert_eq!(select(&v, 256 * GIB).map(|x| x.id.clone()), Some("big".to_string()));
        assert!(fits(v.last().unwrap(), 256 * GIB) && !fits(v.last().unwrap(), 64 * GIB));
    }

    /// A server that answers each path with its own body (a split model has one file per shard).
    fn serve_map(files: Vec<(String, Vec<u8>)>) -> u16 {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        std::thread::spawn(move || {
            for s in l.incoming() {
                let mut s = s.unwrap();
                let mut rd = BufReader::new(s.try_clone().unwrap());
                let mut path = String::new();
                loop {
                    let mut line = String::new();
                    if rd.read_line(&mut line).unwrap_or(0) == 0 || line == "\r\n" { break; }
                    if line.starts_with("GET ") { path = line.split_whitespace().nth(1).unwrap().to_string(); }
                }
                let body = files.iter().find(|(p, _)| path.ends_with(p.as_str())).map(|(_, b)| b.clone());
                match body {
                    Some(b) => { let _ = write!(s, "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", b.len()); let _ = s.write_all(&b); }
                    None => { let _ = write!(s, "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"); }
                }
            }
        });
        port
    }

    fn split_model(port: u16, a: &[u8], b: &[u8]) -> Model {
        let mut m = m("split", 8, 8, 1, true, false);
        m.source_host = format!("127.0.0.1:{port}");
        m.repo = "o/r".into();
        m.commit = "c0".into();
        m.file = "dir/split-00001-of-00002.gguf".into();
        m.parts = vec![
            Part { file: "dir/split-00001-of-00002.gguf".into(), size_bytes: a.len() as u64, sha256: hex(a) },
            Part { file: "dir/split-00002-of-00002.gguf".into(), size_bytes: b.len() as u64, sha256: hex(b) },
        ];
        m.size_bytes = (a.len() + b.len()) as u64;
        m.sha256 = hex(a);
        m
    }
    fn hex(b: &[u8]) -> String { Sha256::digest(b).iter().map(|x| format!("{x:02x}")).collect() }

    #[test]
    fn a_split_model_downloads_shard_by_shard_into_one_folder_and_every_shard_is_checked() {
        let (a, b) = (b"first shard bytes".to_vec(), b"second shard, a little longer".to_vec());
        let port = serve_map(vec![("split-00001-of-00002.gguf".into(), a.clone()), ("split-00002-of-00002.gguf".into(), b.clone())]);
        let model = split_model(port, &a, &b);
        let mf = Manifest { models: vec![model.clone()] };
        let dir = std::env::temp_dir().join(format!("split-dl-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        assert!(!installed_cheap(&model, &dir) && bytes_so_far(&model, &dir) == 0);
        let main = download(&mf, &model.url(), &dir).unwrap();
        assert_eq!(main, dir.join("split-00001-of-00002.gguf"), "the first shard is the file llama-server is pointed at");
        assert!(dir.join("split-00002-of-00002.gguf").exists() && !dir.join("dir").exists(), "shards sit side by side, no sub folder");
        assert!(installed_cheap(&model, &dir) && verified(&model, &main));
        assert_eq!(bytes_so_far(&model, &dir), model.size_bytes);
        assert_eq!(model.main_name(), "split-00001-of-00002.gguf");
        // one flipped byte in the second shard: not verified, and a fresh download repairs it only when the hash says so
        let mut bad = b.clone(); bad[0] ^= 1;
        fs::write(dir.join("split-00002-of-00002.gguf"), &bad).unwrap();
        assert!(installed_cheap(&model, &dir), "the cheap look sees only sizes");
        assert!(!verified(&model, &main), "the full check sees the flipped byte");
    }

    #[test]
    fn a_split_download_with_a_wrong_shard_is_refused_and_leaves_no_good_looking_file() {
        let (a, b) = (b"first shard bytes".to_vec(), b"second shard, a little longer".to_vec());
        let mut wrong = b.clone(); wrong[3] ^= 1;
        let port = serve_map(vec![("split-00001-of-00002.gguf".into(), a.clone()), ("split-00002-of-00002.gguf".into(), wrong)]);
        let model = split_model(port, &a, &b);
        let mf = Manifest { models: vec![model.clone()] };
        let dir = std::env::temp_dir().join(format!("split-bad-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        assert!(matches!(download(&mf, &model.url(), &dir), Err(DlError::BadHash)));
        assert!(!dir.join("split-00002-of-00002.gguf").exists(), "the wrong shard never gets its final name");
        assert!(!verified(&model, &dir.join("split-00001-of-00002.gguf")));
    }

    #[test]
    fn presence_tells_missing_partial_good_and_wrong_bytes_apart() {
        let (a, b) = (b"first shard bytes".to_vec(), b"second shard, a little longer".to_vec());
        let model = split_model(1, &a, &b);
        let dir = std::env::temp_dir().join(format!("presence-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        assert_eq!(presence(&model, &dir), Presence::Missing);
        fs::write(dir.join("split-00001-of-00002.gguf"), &a).unwrap();
        assert_eq!(presence(&model, &dir), Presence::Missing, "a half-downloaded split model is not started");
        fs::write(dir.join("split-00002-of-00002.gguf"), &b).unwrap();
        assert_eq!(presence(&model, &dir), Presence::Verified(dir.join("split-00001-of-00002.gguf")));
        let mut bad = b.clone(); bad[1] ^= 1;
        fs::write(dir.join("split-00002-of-00002.gguf"), &bad).unwrap();
        assert_eq!(presence(&model, &dir), Presence::Mismatch, "right size, wrong bytes: refused, never started");
        // single file model
        let mut one = m("one", 1, 8, 4, true, false);
        one.file = "one.gguf".into(); one.size_bytes = 4; one.sha256 = hex(b"abcd");
        fs::write(dir.join("one.gguf"), b"abce").unwrap();
        assert_eq!(presence(&one, &dir), Presence::Mismatch);
        fs::write(dir.join("one.gguf"), b"abcd").unwrap();
        assert_eq!(presence(&one, &dir), Presence::Verified(dir.join("one.gguf")));
    }

    #[test]
    fn a_proof_holds_until_the_file_changes() {
        let a = b"shard one".to_vec();
        let b = b"shard two longer".to_vec();
        let model = split_model(1, &a, &b);
        let dir = std::env::temp_dir().join(format!("proofs-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("split-00001-of-00002.gguf"), &a).unwrap();
        fs::write(dir.join("split-00002-of-00002.gguf"), &b).unwrap();
        let mut p = Proofs::default();
        assert!(!p.is_proven(&model, &dir), "present is not proven");
        assert!(p.begin(&model.id) && !p.begin(&model.id), "one check at a time");
        p.mark(&model, &dir);
        assert!(p.is_proven(&model, &dir));
        fs::write(dir.join("split-00002-of-00002.gguf"), b"shard two LONGER!!").unwrap();
        assert!(!p.is_proven(&model, &dir), "a changed file is unproven again");
        p.end(&model.id);
        assert!(p.begin(&model.id));
    }
}
