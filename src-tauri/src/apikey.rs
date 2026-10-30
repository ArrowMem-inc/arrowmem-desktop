//! The loopback API key for llama-server. A random 256-bit key (from the OS CSPRNG, /dev/urandom) is written to two
//! owner-only files in the state dir: `llama-api-key` (read by llama-server through --api-key-file) and
//! `upstream.env` (`ARROWBRIDGE_UPSTREAM_KEY=<key>`, read by the companion's unit through EnvironmentFile). Both
//! are created with O_EXCL and mode 0600, so the key is in no unit text, no argv and no log. Every install
//! rotates it. The key is never returned from this module except to the status read, which sends it as a header.

use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::Path;

pub const KEY_FILE: &str = "llama-api-key";
pub const ENV_FILE: &str = "upstream.env";
const KEY_BYTES: usize = 32;

fn new_key() -> Result<String, String> {
    let mut b = [0u8; KEY_BYTES];
    std::fs::File::open("/dev/urandom").and_then(|mut f| f.read_exact(&mut b)).map_err(|e| format!("no random source: {e}"))?;
    Ok(b.iter().map(|x| format!("{x:02x}")).collect())
}

fn our_dir(dir: &Path) -> Result<(), String> {
    let md = std::fs::symlink_metadata(dir).map_err(|e| e.to_string())?;
    if md.file_type().is_symlink() || !md.is_dir() || md.uid() != unsafe { libc::getuid() } {
        return Err("state folder is a symlink, not a folder, or not ours".into());
    }
    Ok(())
}

/// Write `text` as `dir/name`, mode 0600, created with O_EXCL under a temp name and renamed over the target.
fn write_private(dir: &Path, name: &str, text: &str) -> Result<(), String> {
    let tmp = dir.join(format!(".{name}.tmp"));
    let _ = std::fs::remove_file(&tmp); // a leftover from a crash; O_EXCL below still refuses a racing recreate
    let mut f = std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(&tmp).map_err(|e| e.to_string())?;
    f.write_all(text.as_bytes()).map_err(|e| e.to_string())?;
    f.sync_all().map_err(|e| e.to_string())?;
    std::fs::rename(&tmp, dir.join(name)).map_err(|e| e.to_string())
}

/// Create the state dir if needed (0700), then write a fresh key to both files.
pub fn rotate(state_dir: &Path) -> Result<(), String> {
    std::fs::create_dir_all(state_dir).map_err(|e| e.to_string())?;
    our_dir(state_dir)?;
    let _ = std::fs::set_permissions(state_dir, std::fs::Permissions::from_mode(0o700));
    let key = new_key()?;
    write_private(state_dir, KEY_FILE, &format!("{key}\n"))?;
    write_private(state_dir, ENV_FILE, &format!("ARROWBRIDGE_UPSTREAM_KEY={key}\n"))
}

fn private_file_ok(p: &Path) -> bool {
    std::fs::symlink_metadata(p)
        .map(|m| m.is_file() && m.uid() == unsafe { libc::getuid() } && m.mode() & 0o777 == 0o600)
        .unwrap_or(false)
}

/// Both files exist, are ours, 0600, and carry the same well-formed key.
pub fn valid(state_dir: &Path) -> bool {
    match (read_key(state_dir), std::fs::read_to_string(state_dir.join(ENV_FILE))) {
        (Some(k), Ok(e)) => private_file_ok(&state_dir.join(ENV_FILE)) && e == format!("ARROWBRIDGE_UPSTREAM_KEY={k}\n"),
        _ => false,
    }
}

/// The key, only from an owner-only 0600 regular file that is ours; anything else is None.
pub fn read_key(state_dir: &Path) -> Option<String> {
    let p = state_dir.join(KEY_FILE);
    if !private_file_ok(&p) {
        return None;
    }
    let k = std::fs::read_to_string(&p).ok()?.trim().to_string();
    (k.len() == KEY_BYTES * 2 && k.bytes().all(|b| b.is_ascii_hexdigit())).then_some(k)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(tag: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("apikey-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        d
    }

    #[test]
    fn files_are_0600_owned_and_hold_the_same_256_bit_key() {
        let d = tmp("modes");
        rotate(&d).unwrap();
        for n in [KEY_FILE, ENV_FILE] {
            let m = std::fs::symlink_metadata(d.join(n)).unwrap();
            assert_eq!(m.mode() & 0o777, 0o600, "{n}");
            assert_eq!(m.uid(), unsafe { libc::getuid() });
        }
        assert_eq!(std::fs::metadata(&d).unwrap().mode() & 0o777, 0o700);
        let k = read_key(&d).unwrap();
        assert_eq!(k.len(), 64);
        assert_eq!(std::fs::read_to_string(d.join(ENV_FILE)).unwrap(), format!("ARROWBRIDGE_UPSTREAM_KEY={k}\n"));
        assert!(valid(&d));
        assert!(!d.join(format!(".{KEY_FILE}.tmp")).exists() && !d.join(format!(".{ENV_FILE}.tmp")).exists());
    }

    #[test]
    fn rotation_rewrites_the_key() {
        let d = tmp("rot");
        rotate(&d).unwrap();
        let a = read_key(&d).unwrap();
        rotate(&d).unwrap();
        let b = read_key(&d).unwrap();
        assert_ne!(a, b);
        assert!(valid(&d));
    }

    #[test]
    fn a_loose_or_foreign_or_malformed_key_file_is_not_read() {
        let d = tmp("loose");
        rotate(&d).unwrap();
        std::fs::set_permissions(d.join(KEY_FILE), std::fs::Permissions::from_mode(0o644)).unwrap();
        assert_eq!(read_key(&d), None);
        assert!(!valid(&d));
        rotate(&d).unwrap();
        std::fs::write(d.join(KEY_FILE), "short\n").unwrap();
        std::fs::set_permissions(d.join(KEY_FILE), std::fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(read_key(&d), None);
        rotate(&d).unwrap();
        std::fs::remove_file(d.join(KEY_FILE)).unwrap();
        std::os::unix::fs::symlink(d.join(ENV_FILE), d.join(KEY_FILE)).unwrap();
        assert_eq!(read_key(&d), None, "a symlink is not followed");
    }

    #[test]
    fn a_symlinked_state_dir_is_refused() {
        let d = tmp("symdir");
        std::fs::create_dir_all(&d).unwrap();
        let real = d.join("real");
        std::fs::create_dir_all(&real).unwrap();
        let link = d.join("link");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        assert!(rotate(&link).is_err());
        assert!(!real.join(KEY_FILE).exists());
    }
}
