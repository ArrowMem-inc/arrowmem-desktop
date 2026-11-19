//! Pack integrity: PACK.sha256 is pinned by a const the caller supplies; every listed file is opened once without following a symlink,
//! hashed from the buffer that is then parsed (no second read), and any failure turns the whole pack off. Never partial.
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::fs::OpenOptions;
use std::io::{self, Read};
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

pub const MANIFEST: &str = "PACK.sha256";
/// No pack file is anywhere near this; a larger one is refused before any read.
pub const MAX_FILE: u64 = 64 << 20;

/// Why the pack is off. Never shown to a person; tests tell the causes apart.
#[derive(Debug, PartialEq, Eq)]
pub struct Unavailable(pub &'static str);

pub fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes).iter().map(|b| format!("{b:02x}")).collect()
}

/// Regular files only, never through a symlink. O_NONBLOCK so a FIFO cannot hang the open (it is then refused as not a regular file).
pub fn read_nofollow(path: &Path) -> io::Result<Vec<u8>> {
    let mut f = OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK).open(path)?;
    if !f.metadata()?.is_file() {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "not a regular file"));
    }
    if f.metadata()?.len() > MAX_FILE {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "file over the size cap"));
    }
    let mut v = Vec::new();
    (&mut f).take(MAX_FILE + 1).read_to_end(&mut v)?;
    if v.len() as u64 > MAX_FILE {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "file over the size cap"));
    }
    Ok(v)
}

/// Also the one id rule for every record id and plant_id: no control character, space or non ASCII byte can ship in an id.
pub(crate) fn safe_path(p: &str) -> bool {
    // Flat only: O_NOFOLLOW refuses a symlink in the last component, so no subfolder can be allowed. The first byte is a letter or digit, so a name
    // can be neither "-" (sha256sum reads it as standard input) nor hidden.
    p.bytes().next().is_some_and(|b| b.is_ascii_alphanumeric()) && p.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'_' || b == b'-')
}

/// Verify the pack folder against `pin` (the sha256 of PACK.sha256) and return every listed file as (relative path, bytes).
pub fn load(dir: &Path, pin: &str) -> Result<Vec<(String, Vec<u8>)>, Unavailable> {
    load_with(dir, pin, read_nofollow)
}

/// `read` is a parameter so a test can count the opens of each file.
pub fn load_with(dir: &Path, pin: &str, mut read: impl FnMut(&Path) -> io::Result<Vec<u8>>) -> Result<Vec<(String, Vec<u8>)>, Unavailable> {
    // The canonical path must equal the given absolute path (trailing separators dropped): a symlink in any component, parents included, is refused.
    let canon = std::fs::canonicalize(dir).map_err(|_| Unavailable("dir"))?;
    if !canon.is_dir() || canon != dir.components().collect::<std::path::PathBuf>() {
        return Err(Unavailable("dir is not a real directory"));
    }
    let manifest = read(&dir.join(MANIFEST)).map_err(|_| Unavailable("manifest read"))?;
    if sha256_hex(&manifest) != pin {
        return Err(Unavailable("manifest does not match the pin"));
    }
    let text = std::str::from_utf8(&manifest).map_err(|_| Unavailable("manifest utf8"))?;
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    for line in text.lines() {
        let (hash, path) = line.split_once("  ").ok_or(Unavailable("manifest line"))?;
        let hash_ok = hash.len() == 64 && hash.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
        if !hash_ok || !safe_path(path) || path == MANIFEST || !seen.insert(path) {
            return Err(Unavailable("manifest entry"));
        }
        let bytes = read(&dir.join(path)).map_err(|_| Unavailable("file read"))?;
        if sha256_hex(&bytes) != hash {
            return Err(Unavailable("file hash"));
        }
        out.push((path.to_string(), bytes));
    }
    if out.is_empty() {
        return Err(Unavailable("empty manifest"));
    }
    Ok(out)
}
