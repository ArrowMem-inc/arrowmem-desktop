//! The model picker: find the models already on this computer, list the approved ones with what fits, and recommend one.
//! Read only and local: file names and paths are the owner's own data, shown in this window and nowhere else (never sent, never logged). The page only ever
//! sees an opaque id; a path never comes from the page. Pure functions, tested on any unix.
use crate::models::{self, Manifest, Model};
use serde::Serialize;
use std::collections::HashSet;
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};

const GIB: u64 = 1024 * 1024 * 1024;
/// A model file below this is not a model worth listing (tokenizers, adapters, test files).
pub const MIN_MODEL_BYTES: u64 = 100 * 1024 * 1024;
const MAX_FOUND: usize = 40;
const MAX_VISITED: usize = 20_000;
const MAX_DEPTH: usize = 6;
/// Free disk kept beside a download.
const DISK_SLACK: u64 = GIB;
const HEADER_READ: usize = 4 * 1024 * 1024;

/// A model file already on this computer that is not one of our approved downloads.
#[derive(Debug, Clone, PartialEq)]
pub struct Found {
    /// Opaque: the same file always gets the same id, and the id says nothing about the path.
    pub id: String,
    pub path: PathBuf,
    pub size: u64,
    /// From the file header when it has one, else the file stem; shown as text, never interpreted.
    pub name: String,
    /// "ollama" or "folder".
    pub source: &'static str,
}

pub fn id_of(path: &Path) -> String {
    use sha2::{Digest, Sha256};
    let h = Sha256::digest(path.to_string_lossy().as_bytes());
    format!("f{}", h.iter().take(8).map(|b| format!("{b:02x}")).collect::<String>())
}

/// A regular file of at least [`MIN_MODEL_BYTES`] that starts with the GGUF magic. Symlinks are followed once by `metadata` (an Ollama blob may be linked).
pub fn is_gguf(path: &Path) -> bool {
    let Ok(md) = path.metadata() else { return false };
    if !md.is_file() || md.len() < MIN_MODEL_BYTES {
        return false;
    }
    let mut magic = [0u8; 4];
    File::open(path).and_then(|mut f| f.read_exact(&mut magic)).is_ok() && &magic == b"GGUF"
}

struct Cur<'a> { b: &'a [u8], at: usize }
impl<'a> Cur<'a> {
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let end = self.at.checked_add(n)?;
        let s = self.b.get(self.at..end)?;
        self.at = end;
        Some(s)
    }
    fn u32(&mut self) -> Option<u32> { Some(u32::from_le_bytes(self.take(4)?.try_into().ok()?)) }
    fn u64(&mut self) -> Option<u64> { Some(u64::from_le_bytes(self.take(8)?.try_into().ok()?)) }
    fn string(&mut self) -> Option<&'a [u8]> { let n = usize::try_from(self.u64()?).ok()?; if n > 1 << 20 { return None; } self.take(n) }
    /// Skips one value of GGUF type `t` (arrays recurse, but only two levels deep).
    fn skip(&mut self, t: u32, depth: u32) -> Option<()> {
        match t {
            0 | 1 | 7 => { self.take(1)?; }
            2 | 3 => { self.take(2)?; }
            4 | 5 | 6 => { self.take(4)?; }
            10 | 11 | 12 => { self.take(8)?; }
            8 => { self.string()?; }
            9 => {
                // Real headers nest arrays at most once (a list of strings): anything deeper is hostile and would overflow the stack.
                if depth >= 2 { return None; }
                let et = self.u32()?;
                let n = self.u64()?;
                if n > 1 << 24 { return None; }
                for _ in 0..n { self.skip(et, depth + 1)?; }
            }
            _ => return None,
        }
        Some(())
    }
}

/// `general.name` from the GGUF header, when it is in the first megabytes and well formed. Printable ASCII only, capped; otherwise None.
pub fn gguf_name(path: &Path) -> Option<String> {
    let mut buf = Vec::new();
    File::open(path).ok()?.take(HEADER_READ as u64).read_to_end(&mut buf).ok()?;
    let mut c = Cur { b: &buf, at: 0 };
    if c.take(4)? != b"GGUF" { return None; }
    let version = c.u32()?;
    if !(2..=3).contains(&version) { return None; }
    let _tensors = c.u64()?;
    let kvs = c.u64()?;
    for _ in 0..kvs.min(4096) {
        let key = c.string()?;
        let t = c.u32()?;
        if key == b"general.name" && t == 8 {
            let v = c.string()?;
            let s: String = String::from_utf8_lossy(v).chars().filter(|ch| ch.is_ascii_graphic() || *ch == ' ').take(60).collect();
            let s = s.trim().to_string();
            return if s.is_empty() { None } else { Some(s) };
        }
        c.skip(t, 0)?;
    }
    None
}

fn stem(path: &Path) -> String {
    let s = path.file_stem().map(|s| s.to_string_lossy().into_owned()).unwrap_or_default();
    let s: String = s.chars().filter(|c| c.is_ascii_graphic() || *c == ' ').take(60).collect();
    if s.is_empty() { "model".into() } else { s }
}

/// Ollama's own store: each manifest names its model layer by digest, and that blob IS a GGUF file.
fn ollama(home: &Path, out: &mut Vec<Found>, seen: &mut HashSet<PathBuf>) {
    let root = home.join(".ollama/models");
    let mf = root.join("manifests");
    let mut stack = vec![(mf.clone(), 0usize)];
    let mut visited = 0usize;
    while let Some((dir, depth)) = stack.pop() {
        let Ok(rd) = std::fs::read_dir(&dir) else { continue };
        for e in rd.flatten() {
            visited += 1;
            if visited > MAX_VISITED || out.len() >= MAX_FOUND { return; }
            let p = e.path();
            let Ok(ft) = e.file_type() else { continue };
            if ft.is_dir() { if depth < MAX_DEPTH { stack.push((p, depth + 1)); } continue; }
            if !ft.is_file() || e.metadata().map(|m| m.len() > 1 << 20).unwrap_or(true) { continue; }
            let Ok(text) = std::fs::read_to_string(&p) else { continue };
            let Ok(v) = serde_json::from_str::<serde_json::Value>(&text) else { continue };
            let Some(layers) = v.get("layers").and_then(|l| l.as_array()) else { continue };
            for l in layers {
                if l.get("mediaType").and_then(|m| m.as_str()) != Some("application/vnd.ollama.image.model") { continue; }
                let Some(d) = l.get("digest").and_then(|d| d.as_str()).and_then(|d| d.strip_prefix("sha256:")) else { continue };
                if d.len() != 64 || !d.bytes().all(|b| b.is_ascii_hexdigit()) { continue; }
                let blob = root.join("blobs").join(format!("sha256-{d}"));
                if !is_gguf(&blob) || !seen.insert(blob.clone()) { continue; }
                // name:tag from the manifest path (registry/namespace/name/tag), the plain "library" namespace dropped
                let rel: Vec<String> = p.strip_prefix(&mf).ok().map(|r| r.components().map(|c| c.as_os_str().to_string_lossy().into_owned()).collect()).unwrap_or_default();
                let name = match rel.as_slice() {
                    [.., ns, name, tag] if ns != "library" => format!("{ns}/{name}:{tag}"),
                    [.., name, tag] => format!("{name}:{tag}"),
                    _ => stem(&blob),
                };
                let name: String = name.chars().filter(|c| c.is_ascii_graphic()).take(60).collect();
                let size = blob.metadata().map(|m| m.len()).unwrap_or(0);
                out.push(Found { id: id_of(&blob), path: blob, size, name, source: "ollama" });
            }
        }
    }
}

/// .gguf files in the usual folders, a few levels deep, by extension AND the magic bytes.
fn folders(home: &Path, skip: &[PathBuf], out: &mut Vec<Found>, seen: &mut HashSet<PathBuf>) {
    let roots = ["models", "Models", "Downloads", ".cache/lm-studio/models", ".lmstudio/models", ".cache/huggingface/hub"];
    let mut visited = 0usize;
    for r in roots {
        let mut stack = vec![(home.join(r), 0usize)];
        while let Some((dir, depth)) = stack.pop() {
            let Ok(rd) = std::fs::read_dir(&dir) else { continue };
            for e in rd.flatten() {
                visited += 1;
                if visited > MAX_VISITED || out.len() >= MAX_FOUND { return; }
                let p = e.path();
                if skip.iter().any(|s| p.starts_with(s)) { continue; }
                let Ok(ft) = e.file_type() else { continue };
                if ft.is_dir() { if depth < MAX_DEPTH { stack.push((p, depth + 1)); } continue; }
                if p.extension().and_then(|x| x.to_str()).map(|x| x.eq_ignore_ascii_case("gguf")) != Some(true) { continue; }
                let real = p.canonicalize().unwrap_or(p.clone());
                if !is_gguf(&real) || !seen.insert(real.clone()) { continue; }
                let size = real.metadata().map(|m| m.len()).unwrap_or(0);
                let name = gguf_name(&real).unwrap_or_else(|| stem(&p));
                out.push(Found { id: id_of(&real), path: real, size, name, source: "folder" });
            }
        }
    }
}

/// Everything on this computer that looks like a model and is not under `skip` (our own download folder). Sorted by size, then name; capped.
pub fn scan(home: &Path, skip: &[PathBuf]) -> Vec<Found> {
    let mut out = Vec::new();
    let mut seen = HashSet::new();
    ollama(home, &mut out, &mut seen);
    folders(home, skip, &mut out, &mut seen);
    // The model unit file can only carry a plain path (letters, digits and . _ - / ~ +): a model whose path has a space, a bracket or a non-ASCII character is not listed,
    // because choosing it would be saved but could never be started.
    out.retain(|f| crate::userunit::safe_path(&f.path).is_ok());
    out.sort_by(|a, b| a.size.cmp(&b.size).then(a.name.cmp(&b.name)));
    out
}

/// Free bytes on the file system that holds `path` (or the nearest folder above it that exists). None when it cannot be read.
#[cfg(unix)]
pub fn free_bytes(path: &Path) -> Option<u64> {
    let mut p = path;
    while !p.exists() { p = p.parent()?; }
    let c = std::ffi::CString::new(p.to_string_lossy().as_bytes()).ok()?;
    let mut st: libc::statvfs = unsafe { std::mem::zeroed() };
    // SAFETY: `c` is a valid NUL-terminated path and `st` is a zeroed statvfs the call fills in.
    if unsafe { libc::statvfs(c.as_ptr(), &mut st) } != 0 { return None; }
    Some((st.f_bavail as u64).saturating_mul(st.f_frsize as u64))
}

/// Not Unix: no free-space reading (the picker then never claims there is enough disk).
#[cfg(not(unix))]
pub fn free_bytes(_path: &Path) -> Option<u64> { None }

/// One row of the picker. Strings are machine values; the page picks the words.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ModelOption {
    pub id: String,
    /// "approved" (our manifest) or "found" (already on this computer).
    pub kind: &'static str,
    /// Plain name for found models; for approved ones the tier word the page translates ("standard", "larger", "much_larger") plus the manifest id.
    pub name: String,
    /// The model's own name for approved rows ("Gemma 4 E4B"); empty for found ones, whose name is above.
    pub label: String,
    pub tier: u32,
    pub size_bytes: u64,
    /// False for a model that is not in our approved manifest: the page shows the "not tested by ArrowMem" label.
    pub tested: bool,
    pub fits: bool,
    /// "ram" (too big for this computer) or "disk" (not enough free disk to download); None when it fits.
    pub why_not: Option<&'static str>,
    /// "installed" (hash-checked), "checking" (on disk, not yet proven), "downloading" or "absent".
    pub state: &'static str,
    /// 0 to 100 while downloading.
    pub percent: Option<u32>,
    pub recommended: bool,
    pub chosen: bool,
}

/// What the picker knows about this computer and this moment.
pub struct Facts<'a> {
    pub manifest: &'a Manifest,
    pub ram: u64,
    pub free_disk: Option<u64>,
    /// The model is on this computer AND every file passed its sha256 (a proof kept by size and modified time, see models::Proofs): only then is it "installed".
    pub installed: &'a dyn Fn(&Model) -> bool,
    /// The files are there with the manifest sizes (a cheap look): present but not yet proven reads "checking", never "installed" and never a second Download.
    pub on_disk: &'a dyn Fn(&Model) -> bool,
    /// (approved id, bytes so far) while a download runs.
    pub downloading: Option<(String, u64)>,
    pub found: &'a [Found],
    /// The approved id in use (saved pick or the automatic one) or the id of the found model in use.
    pub chosen: Option<String>,
}

fn word(tier: u32) -> &'static str {
    match tier { 0 | 1 => "standard", 2 => "larger", _ => "much_larger" }
}

pub fn options(f: &Facts) -> Vec<ModelOption> {
    let rec = models::select(&f.manifest.models, f.ram).map(|m| m.id.clone());
    let mut out: Vec<ModelOption> = f.manifest.models.iter().filter(|m| m.approved).filter(|m| !m.hide_unless_fits || models::fits(m, f.ram) || (f.installed)(m) || (f.on_disk)(m)).map(|m| {
        let installed = (f.installed)(m);
        let present = installed || (f.on_disk)(m);
        let dl = f.downloading.as_ref().filter(|(id, _)| *id == m.id);
        let ram_ok = models::fits(m, f.ram);
        let disk_ok = present || f.free_disk.map(|d| d >= m.size_bytes + DISK_SLACK).unwrap_or(false);
        let why = if !ram_ok { Some("ram") } else if !disk_ok { Some("disk") } else { None };
        ModelOption {
            id: m.id.clone(), kind: "approved", name: word(m.tier).to_string(), label: m.display_name.clone(), tier: m.tier, size_bytes: m.size_bytes, tested: true,
            fits: why.is_none(), why_not: why,
            state: if installed { "installed" } else if dl.is_some() { "downloading" } else if present { "checking" } else { "absent" },
            percent: dl.map(|(_, b)| ((*b).min(m.size_bytes) * 100 / m.size_bytes.max(1)) as u32),
            recommended: rec.as_deref() == Some(m.id.as_str()),
            chosen: f.chosen.as_deref() == Some(m.id.as_str()),
        }
    }).collect();
    out.sort_by_key(|o| o.tier);
    for x in f.found {
        let fits = f.ram >= x.size.saturating_mul(150) / 100;
        out.push(ModelOption {
            id: x.id.clone(), kind: "found", name: x.name.clone(), label: String::new(), tier: 0, size_bytes: x.size, tested: false, fits,
            why_not: if fits { None } else { Some("ram") }, state: "installed", percent: None, recommended: false,
            chosen: f.chosen.as_deref() == Some(x.id.as_str()),
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn tmp(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("modelpick-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    /// A tiny valid-looking GGUF: magic, version 3, no tensors, the given kv pairs; padded with zeros to `size` (sparse where the filesystem allows).
    fn gguf(path: &Path, name: Option<&str>, size: u64) {
        let mut b = b"GGUF".to_vec();
        b.extend(3u32.to_le_bytes());
        b.extend(0u64.to_le_bytes());
        let mut kvs: Vec<Vec<u8>> = Vec::new();
        let mut other = Vec::new();
        other.extend(("general.architecture".len() as u64).to_le_bytes());
        other.extend(b"general.architecture");
        other.extend(8u32.to_le_bytes());
        other.extend(5u64.to_le_bytes());
        other.extend(b"llama");
        kvs.push(other);
        if let Some(n) = name {
            let mut kv = Vec::new();
            kv.extend(("general.name".len() as u64).to_le_bytes());
            kv.extend(b"general.name");
            kv.extend(8u32.to_le_bytes());
            kv.extend((n.len() as u64).to_le_bytes());
            kv.extend(n.as_bytes());
            kvs.push(kv);
        }
        b.extend((kvs.len() as u64).to_le_bytes());
        for k in kvs { b.extend(k); }
        let mut f = File::create(path).unwrap();
        f.write_all(&b).unwrap();
        f.set_len(size).unwrap();
    }

    #[test]
    fn free_space_is_read_for_an_existing_and_for_a_not_yet_existing_folder() {
        let d = tmp("free");
        assert!(free_bytes(&d).unwrap() > 0);
        assert!(free_bytes(&d.join("not/yet/there")).unwrap() > 0, "the nearest existing folder answers");
    }

    #[test]
    fn a_gguf_is_told_by_its_magic_and_size_not_its_name() {
        let d = tmp("magic");
        gguf(&d.join("a.gguf"), None, MIN_MODEL_BYTES);
        assert!(is_gguf(&d.join("a.gguf")));
        gguf(&d.join("small.gguf"), None, MIN_MODEL_BYTES - 1);
        assert!(!is_gguf(&d.join("small.gguf")), "below the size floor");
        std::fs::write(d.join("fake.gguf"), vec![0u8; MIN_MODEL_BYTES as usize]).unwrap();
        assert!(!is_gguf(&d.join("fake.gguf")), "no magic");
        assert!(!is_gguf(&d.join("missing.gguf")) && !is_gguf(&d), "missing file and a directory");
    }

    #[test]
    fn the_name_comes_from_the_header_and_hostile_headers_say_nothing() {
        let d = tmp("name");
        gguf(&d.join("n.gguf"), Some("Gemma 4 E2B\u{1b}[31m"), 1000);
        assert_eq!(gguf_name(&d.join("n.gguf")).as_deref(), Some("Gemma 4 E2B[31m"), "control characters never reach the window");
        gguf(&d.join("none.gguf"), None, 1000);
        assert_eq!(gguf_name(&d.join("none.gguf")), None);
        // a header that claims an enormous string, an unknown type, a cut-off file
        let mut b = b"GGUF".to_vec(); b.extend(3u32.to_le_bytes()); b.extend(0u64.to_le_bytes()); b.extend(1u64.to_le_bytes());
        b.extend(u64::MAX.to_le_bytes());
        std::fs::write(d.join("huge.gguf"), &b).unwrap();
        assert_eq!(gguf_name(&d.join("huge.gguf")), None);
        let mut c = b"GGUF".to_vec(); c.extend(3u32.to_le_bytes()); c.extend(0u64.to_le_bytes()); c.extend(1u64.to_le_bytes());
        c.extend(3u64.to_le_bytes()); c.extend(b"abc"); c.extend(99u32.to_le_bytes());
        std::fs::write(d.join("type.gguf"), &c).unwrap();
        assert_eq!(gguf_name(&d.join("type.gguf")), None);
        std::fs::write(d.join("cut.gguf"), b"GGUF").unwrap();
        assert_eq!(gguf_name(&d.join("cut.gguf")), None);
        assert_eq!(gguf_name(&d.join("nofile.gguf")), None);
    }

    #[test]
    fn a_hostile_header_with_a_hundred_thousand_nested_arrays_says_nothing_and_does_not_crash() {
        let d = tmp("nested");
        let mut b = b"GGUF".to_vec();
        b.extend(3u32.to_le_bytes());
        b.extend(0u64.to_le_bytes());
        b.extend(1u64.to_le_bytes());
        b.extend(1u64.to_le_bytes());
        b.extend(b"k");
        b.extend(9u32.to_le_bytes());
        for _ in 0..100_000 { b.extend(9u32.to_le_bytes()); b.extend(1u64.to_le_bytes()); }
        std::fs::write(d.join("nest.gguf"), &b).unwrap();
        assert_eq!(gguf_name(&d.join("nest.gguf")), None);
        // two levels (an array of arrays of numbers) still read, deeper does not
        let mut ok = b"GGUF".to_vec();
        ok.extend(3u32.to_le_bytes()); ok.extend(0u64.to_le_bytes()); ok.extend(2u64.to_le_bytes());
        ok.extend(1u64.to_le_bytes()); ok.extend(b"a"); ok.extend(9u32.to_le_bytes()); ok.extend(9u32.to_le_bytes()); ok.extend(1u64.to_le_bytes()); ok.extend(4u32.to_le_bytes()); ok.extend(1u64.to_le_bytes()); ok.extend(7u32.to_le_bytes());
        ok.extend(("general.name".len() as u64).to_le_bytes()); ok.extend(b"general.name"); ok.extend(8u32.to_le_bytes()); ok.extend(2u64.to_le_bytes()); ok.extend(b"Ok");
        std::fs::write(d.join("two.gguf"), &ok).unwrap();
        assert_eq!(gguf_name(&d.join("two.gguf")).as_deref(), Some("Ok"));
    }

    #[test]
    fn a_found_model_with_an_unsafe_path_is_not_listed() {
        let h = tmp("unsafe");
        std::fs::create_dir_all(h.join("models/My Models")).unwrap();
        std::fs::create_dir_all(h.join("models/plain")).unwrap();
        gguf(&h.join("models/My Models/spaced.gguf"), None, MIN_MODEL_BYTES);
        gguf(&h.join("models/plain/fine.gguf"), None, MIN_MODEL_BYTES);
        let names: Vec<_> = scan(&h, &[]).into_iter().map(|f| f.name).collect();
        assert_eq!(names, vec!["fine"], "a path the unit file cannot carry is never offered: {names:?}");
    }

    #[test]
    fn ollama_blobs_are_found_through_their_manifests_with_a_readable_name() {
        let h = tmp("ollama");
        let blobs = h.join(".ollama/models/blobs");
        let mdir = h.join(".ollama/models/manifests/registry.ollama.ai/library/llama3.2");
        std::fs::create_dir_all(&blobs).unwrap();
        std::fs::create_dir_all(&mdir).unwrap();
        let digest = "a".repeat(64);
        gguf(&blobs.join(format!("sha256-{digest}")), None, MIN_MODEL_BYTES);
        std::fs::write(mdir.join("latest"), format!(r#"{{"layers":[{{"mediaType":"application/vnd.ollama.image.model","digest":"sha256:{digest}"}},{{"mediaType":"application/vnd.ollama.image.license","digest":"sha256:{}"}}]}}"#, "b".repeat(64))).unwrap();
        let f = scan(&h, &[]);
        assert_eq!(f.len(), 1);
        assert_eq!((f[0].name.as_str(), f[0].source), ("llama3.2:latest", "ollama"));
        assert!(f[0].id.starts_with('f') && f[0].id.len() == 17 && !f[0].id.contains("llama"));
    }

    #[test]
    fn a_manifest_that_points_outside_the_blob_folder_or_at_a_non_model_is_ignored() {
        let h = tmp("ollama-bad");
        let mdir = h.join(".ollama/models/manifests/registry.ollama.ai/library/x");
        std::fs::create_dir_all(&mdir).unwrap();
        std::fs::create_dir_all(h.join(".ollama/models/blobs")).unwrap();
        // path-looking digest, short digest, a digest with no file, broken json
        for (n, body) in [("a", r#"{"layers":[{"mediaType":"application/vnd.ollama.image.model","digest":"sha256:../../../etc/passwd"}]}"#.to_string()),
                          ("b", r#"{"layers":[{"mediaType":"application/vnd.ollama.image.model","digest":"sha256:abc"}]}"#.to_string()),
                          ("c", format!(r#"{{"layers":[{{"mediaType":"application/vnd.ollama.image.model","digest":"sha256:{}"}}]}}"#, "c".repeat(64))),
                          ("d", "not json".to_string())] {
            std::fs::write(mdir.join(n), body).unwrap();
        }
        assert!(scan(&h, &[]).is_empty());
    }

    #[test]
    fn folders_are_searched_by_extension_and_magic_and_our_own_folder_is_skipped() {
        let h = tmp("folders");
        std::fs::create_dir_all(h.join("models/sub")).unwrap();
        std::fs::create_dir_all(h.join("Downloads")).unwrap();
        gguf(&h.join("models/sub/big.gguf"), Some("Qwen Test"), MIN_MODEL_BYTES * 2);
        gguf(&h.join("Downloads/small.gguf"), None, MIN_MODEL_BYTES);
        std::fs::write(h.join("Downloads/readme.txt"), b"x").unwrap();
        std::fs::write(h.join("Downloads/notes.gguf"), b"not a model").unwrap();
        gguf(&h.join("models/ours.gguf"), None, MIN_MODEL_BYTES);
        let f = scan(&h, &[h.join("models/ours.gguf")]);
        let names: Vec<_> = f.iter().map(|x| x.name.as_str()).collect();
        assert_eq!(names, vec!["small", "Qwen Test"], "sorted by size, the fake and our own file left out: {names:?}");
        assert!(f.iter().all(|x| x.source == "folder"));
    }

    #[test]
    fn the_same_file_found_twice_is_listed_once_and_the_id_is_stable() {
        let h = tmp("dup");
        std::fs::create_dir_all(h.join("models")).unwrap();
        std::fs::create_dir_all(h.join("Downloads")).unwrap();
        gguf(&h.join("models/m.gguf"), None, MIN_MODEL_BYTES);
        std::os::unix::fs::symlink(h.join("models/m.gguf"), h.join("Downloads/link.gguf")).unwrap();
        let a = scan(&h, &[]);
        let b = scan(&h, &[]);
        assert_eq!(a.len(), 1);
        assert_eq!(a[0].id, b[0].id);
    }

    fn mf() -> Manifest { models::load_manifest() }

    fn facts<'a>(m: &'a Manifest, ram_gb: u64, disk_gb: Option<u64>, installed: &'a dyn Fn(&Model) -> bool, found: &'a [Found]) -> Facts<'a> {
        Facts { manifest: m, ram: ram_gb * GIB, free_disk: disk_gb.map(|g| g * GIB), installed, on_disk: installed, downloading: None, found, chosen: None }
    }

    #[test]
    fn the_recommended_row_is_the_automatic_pick_and_only_one() {
        let m = mf();
        let none = |_: &Model| false;
        let o = options(&facts(&m, 16, Some(100), &none, &[]));
        let rec: Vec<_> = o.iter().filter(|x| x.recommended).map(|x| x.id.as_str()).collect();
        assert_eq!(rec.len(), 1);
        assert_eq!(Some(rec[0].to_string()), models::select(&m.models, 16 * GIB).map(|x| x.id.clone()));
        assert!(o.iter().all(|x| x.tested && x.kind == "approved"), "no unapproved model is ever offered");
    }

    #[test]
    fn a_model_the_computer_cannot_hold_is_greyed_with_ram_and_one_it_cannot_store_with_disk() {
        let m = mf();
        let none = |_: &Model| false;
        let small = options(&facts(&m, 4, Some(100), &none, &[]));
        assert!(small.iter().all(|x| !x.fits && x.why_not == Some("ram")));
        let nodisk = options(&facts(&m, 32, Some(2), &none, &[]));
        assert!(nodisk.iter().filter(|x| models::fits(m.models.iter().find(|y| y.id == x.id).unwrap(), 32 * GIB)).all(|x| x.why_not == Some("disk")));
        let unknown = options(&facts(&m, 32, None, &none, &[]));
        assert!(unknown.iter().any(|x| x.why_not == Some("disk")), "unknown free disk never counts as enough");
        let have = |_: &Model| true;
        let installed = options(&facts(&m, 32, Some(0), &have, &[]));
        assert!(installed.iter().filter(|x| x.fits).count() > 0 && installed.iter().all(|x| x.state == "installed"), "an installed model needs no disk");
    }

    #[test]
    fn a_download_shows_its_percent_and_never_more_than_a_hundred() {
        let m = mf();
        let none = |_: &Model| false;
        let id = m.models.iter().find(|x| x.approved).unwrap().clone();
        let mut f = facts(&m, 32, Some(100), &none, &[]);
        f.downloading = Some((id.id.clone(), id.size_bytes / 4));
        let o = options(&f);
        let row = o.iter().find(|x| x.id == id.id).unwrap();
        assert_eq!((row.state, row.percent), ("downloading", Some(25)));
        f.downloading = Some((id.id.clone(), id.size_bytes * 3));
        assert_eq!(options(&f).iter().find(|x| x.id == id.id).unwrap().percent, Some(100));
    }

    #[test]
    fn a_top_tier_model_is_listed_only_where_it_fits_or_is_already_installed() {
        let m = mf();
        let none = |_: &Model| false;
        let top: Vec<&Model> = m.models.iter().filter(|x| x.approved && x.hide_unless_fits).collect();
        assert!(top.len() >= 2, "the two top-tier models are in the manifest");
        let small = options(&facts(&m, 16, Some(900), &none, &[]));
        assert!(top.iter().all(|t| !small.iter().any(|o| o.id == t.id)), "a 16 GiB computer is never shown a 120B or 235B model");
        let have = |x: &Model| x.hide_unless_fits;
        let kept = options(&facts(&m, 16, Some(900), &have, &[]));
        assert!(top.iter().all(|t| kept.iter().any(|o| o.id == t.id)), "one that is already on disk stays listed");
        let big = options(&facts(&m, 128, Some(900), &none, &[]));
        assert!(top.iter().any(|t| big.iter().any(|o| o.id == t.id && o.fits)), "a 128 GiB computer is offered at least the 120B one");
    }

    #[test]
    fn found_models_are_untested_fit_by_the_same_headroom_rule_and_can_be_chosen() {
        let m = mf();
        let none = |_: &Model| false;
        let found = vec![Found { id: "f0123456789abcdef".into(), path: PathBuf::from("/x"), size: 8 * GIB, name: "My Model".into(), source: "folder" }];
        let mut f = facts(&m, 16, Some(100), &none, &found);
        f.chosen = Some("f0123456789abcdef".into());
        let o = options(&f);
        let row = o.iter().find(|x| x.kind == "found").unwrap();
        assert!(!row.tested && row.fits && row.chosen && row.state == "installed" && row.name == "My Model");
        assert!(!o.iter().filter(|x| x.kind == "approved").any(|x| x.chosen), "only one row is chosen");
        let tight = options(&facts(&m, 11, Some(100), &none, &found));
        assert!(!tight.iter().find(|x| x.kind == "found").unwrap().fits, "8 GiB needs 12 GiB of RAM at the 150 percent rule");
    }
}
