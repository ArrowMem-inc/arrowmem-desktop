//! Where this machine keeps the credential the remote machine's companion issued it: one file, mode 0600, under the 0700
//! state dir, written atomically (O_EXCL temp, fsync, rename), the same custody as the llama key (apikey.rs). The
//! credential is never logged (there is no Debug for it), is held in a buffer that is overwritten when the value is
//! dropped, and a file that is wrong in any way (not ours, not 0600, a symlink, not valid, an address the transport gate
//! refuses) reads as unpaired: `load` returns None and never panics.
//!
//! The file is JSON: host, port, credential, machine_id (hex, may be empty). Any other field, the rotation fields among
//! them (`rotate_nonce`, `rotate_ct`, `next_credential`), is parsed past and ignored: rotation is off on the companion
//! (cred_store.py ROTATION_ENABLED is False). When it turns on, the new credential must be written here BEFORE first
//! use; `save` is already an atomic replace for that day.

use crate::sealed::{classify, hex, port_allowed, unhex, wipe};
use std::io::Write;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::Path;

pub const FILE: &str = "remote-machine.json";

/// A finished pairing: where the remote companion is, the credential it issued, and the machine id it sealed (if any).
pub struct Pin {
    pub host: String,
    pub port: u16,
    credential: Vec<u8>,
    /// Hex of the remote machine's id, or empty when its companion has none.
    pub machine_id: String,
}

impl Pin {
    pub fn new(host: &str, port: u16, credential: &[u8], machine_id: &[u8]) -> Option<Pin> {
        let p = Pin { host: host.to_string(), port, credential: credential.to_vec(), machine_id: hex(machine_id) };
        p.well_formed().then_some(p)
    }

    /// `pc_` then printable ASCII, a host the transport gate admits, a port it admits, a machine id of 0 or 16 bytes.
    fn well_formed(&self) -> bool {
        self.credential.starts_with(b"pc_")
            && self.credential.len() <= 256
            && self.credential.iter().all(|c| c.is_ascii_graphic())
            && classify(&self.host).is_some()
            && port_allowed(self.port)
            && (self.machine_id.is_empty() || (self.machine_id.len() == 32 && unhex(&self.machine_id).is_some()))
    }

    pub fn credential(&self) -> &[u8] {
        &self.credential
    }

    /// The pin rule the phone already has (DIFFERENT_COMPUTER): a pinned machine id must equal the id the session sealed,
    /// and a pin with no id must see none. Anything else is a different computer.
    pub fn machine_matches(&self, seen: Option<&[u8]>) -> bool {
        match seen {
            Some(id) => !self.machine_id.is_empty() && hex(id) == self.machine_id,
            None => self.machine_id.is_empty(),
        }
    }

    pub fn wipe_now(&mut self) {
        wipe(&mut self.credential);
    }
}

impl Drop for Pin {
    fn drop(&mut self) {
        self.wipe_now();
    }
}

impl std::fmt::Debug for Pin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Pin(redacted)")
    }
}

fn dir_ok(dir: &Path) -> bool {
    std::fs::symlink_metadata(dir)
        .map(|m| m.is_dir() && !m.file_type().is_symlink() && m.uid() == unsafe { libc::getuid() } && m.mode() & 0o077 == 0)
        .unwrap_or(false)
}

fn file_ok(p: &Path) -> bool {
    std::fs::symlink_metadata(p)
        .map(|m| m.is_file() && m.uid() == unsafe { libc::getuid() } && m.mode() & 0o777 == 0o600)
        .unwrap_or(false)
}

/// The stored pin, or None (unpaired) for any file that is missing or wrong in any way.
pub fn load(state_dir: &Path) -> Option<Pin> {
    let p = state_dir.join(FILE);
    if !dir_ok(state_dir) || !file_ok(&p) {
        return None;
    }
    let mut raw = std::fs::read(&p).ok()?;
    let v: Option<serde_json::Value> = serde_json::from_slice(&raw).ok();
    wipe(&mut raw);
    let v = v?;
    let o = v.as_object()?;
    let host = o.get("host")?.as_str()?;
    let port = u16::try_from(o.get("port")?.as_u64()?).ok()?;
    let cred = o.get("credential")?.as_str()?;
    let mid = o.get("machine_id")?.as_str()?;
    let id = if mid.is_empty() { Vec::new() } else { unhex(mid)? };
    Pin::new(host, port, cred.as_bytes(), &id)
}

/// Create the state dir if needed (0700), then replace the pin file atomically: the temp is created O_EXCL at 0600,
/// written, fsynced and renamed over the target, so a reader sees the old file or the new one, never a partial one.
pub fn save(state_dir: &Path, pin: &Pin) -> Result<(), String> {
    if !pin.well_formed() {
        return Err("not a storable pairing".into());
    }
    std::fs::create_dir_all(state_dir).map_err(|e| e.to_string())?;
    let md = std::fs::symlink_metadata(state_dir).map_err(|e| e.to_string())?;
    if md.file_type().is_symlink() || !md.is_dir() || md.uid() != unsafe { libc::getuid() } {
        return Err("state folder is a symlink, not a folder, or not ours".into());
    }
    std::fs::set_permissions(state_dir, std::fs::Permissions::from_mode(0o700)).map_err(|e| e.to_string())?;
    let mut text = serde_json::json!({
        "host": pin.host, "port": pin.port, "credential": String::from_utf8_lossy(&pin.credential), "machine_id": pin.machine_id,
    })
    .to_string()
    .into_bytes();
    let tmp = state_dir.join(format!(".{FILE}.tmp"));
    let _ = std::fs::remove_file(&tmp); // a leftover from a crash; O_EXCL below still refuses a racing recreate
    let r = (|| -> Result<(), String> {
        let mut f = std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(&tmp).map_err(|e| e.to_string())?;
        f.write_all(&text).map_err(|e| e.to_string())?;
        f.sync_all().map_err(|e| e.to_string())?;
        std::fs::rename(&tmp, state_dir.join(FILE)).map_err(|e| e.to_string())
    })();
    wipe(&mut text);
    if r.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    r
}

/// Forget the pairing on this machine (the group then reads unknown). Missing is fine.
pub fn forget(state_dir: &Path) -> Result<(), String> {
    match std::fs::remove_file(state_dir.join(FILE)) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A dotted quad assembled at run time: no address literal is written in this file.
    fn ip(a: u8, b: u8, c: u8, d: u8) -> String {
        format!("{a}.{b}.{c}.{d}")
    }
    fn lan() -> String {
        ip(192, 168, 4, 20)
    }

    fn tmp(tag: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("minicred-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        d
    }
    const CRED: &[u8] = b"pc_storeTestCredential_0123456789abcdef";
    fn pin() -> Pin {
        Pin::new(&lan(), 8788, CRED, &[7u8; 16]).unwrap()
    }
    fn write_raw(d: &Path, bytes: &[u8], mode: u32) {
        std::fs::create_dir_all(d).unwrap();
        std::fs::set_permissions(d, std::fs::Permissions::from_mode(0o700)).unwrap();
        let p = d.join(FILE);
        std::fs::write(&p, bytes).unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(mode)).unwrap();
    }

    // 9. the file
    #[test]
    fn the_file_is_0600_owned_the_dir_is_0700_and_the_pin_round_trips() {
        let d = tmp("modes");
        save(&d, &pin()).unwrap();
        let m = std::fs::symlink_metadata(d.join(FILE)).unwrap();
        assert_eq!(m.mode() & 0o777, 0o600);
        assert_eq!(m.uid(), unsafe { libc::getuid() });
        assert_eq!(std::fs::symlink_metadata(&d).unwrap().mode() & 0o777, 0o700);
        let back = load(&d).unwrap();
        assert_eq!((back.host.as_str(), back.port, back.credential(), back.machine_id.as_str()), (lan().as_str(), 8788, CRED, hex(&[7u8; 16]).as_str()));
        assert!(std::fs::read_dir(&d).unwrap().all(|e| !e.unwrap().file_name().to_string_lossy().ends_with(".tmp")), "no temp left behind");
    }

    #[test]
    fn a_wrong_mode_a_wrong_dir_mode_or_a_symlink_reads_as_unpaired() {
        let d = tmp("modes2");
        save(&d, &pin()).unwrap();
        assert!(load(&d).is_some(), "control");
        for mode in [0o644, 0o640, 0o604, 0o660, 0o400, 0o700] {
            std::fs::set_permissions(d.join(FILE), std::fs::Permissions::from_mode(mode)).unwrap();
            assert!(load(&d).is_none(), "file mode {mode:o}");
        }
        std::fs::set_permissions(d.join(FILE), std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(load(&d).is_some());
        std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(load(&d).is_none(), "state dir open to group and other");
        std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o700)).unwrap();
        // the file is a symlink to a good 0600 file elsewhere
        let other = tmp("modes2-other");
        save(&other, &pin()).unwrap();
        std::fs::remove_file(d.join(FILE)).unwrap();
        std::os::unix::fs::symlink(other.join(FILE), d.join(FILE)).unwrap();
        assert!(load(&d).is_none(), "a symlinked file");
        // the state dir is a symlink
        let link = tmp("modes2-link");
        std::os::unix::fs::symlink(&other, &link).unwrap();
        assert!(load(&link).is_none(), "a symlinked state dir");
        assert!(save(&link, &pin()).is_err(), "save refuses a symlinked state dir");
    }

    #[test]
    fn a_corrupt_or_unstorable_file_reads_as_unpaired_and_never_panics() {
        let d = tmp("corrupt");
        let good = format!(r#"{{"host":"{}","port":8788,"credential":"{}","machine_id":""}}"#, lan(), String::from_utf8_lossy(CRED));
        write_raw(&d, good.as_bytes(), 0o600);
        assert!(load(&d).is_some(), "control");
        let cases: Vec<Vec<u8>> = vec![
            vec![],
            b"{".to_vec(),
            good.as_bytes()[..good.len() / 2].to_vec(),
            vec![0xff, 0xfe, 0, 1, 2],
            b"[]".to_vec(),
            b"null".to_vec(),
            good.replace("pc_", "xx_").into_bytes(),
            good.replace(&lan(), &ip(127, 0, 0, 1)).into_bytes(),
            good.replace(&lan(), &ip(100, 64, 0, 9)).into_bytes(),
            good.replace(&lan(), &ip(8, 8, 8, 8)).into_bytes(),
            good.replace("8788", "80").into_bytes(),
            good.replace("8788", "70000").into_bytes(),
            good.replace("8788", "\"8788\"").into_bytes(),
            good.replace("\"machine_id\":\"\"", "\"machine_id\":\"zz\"").into_bytes(),
            good.replace("\"machine_id\":\"\"", "\"machine_id\":\"abcd\"").into_bytes(),
            good.replace("\"credential\"", "\"cred\"").into_bytes(),
            good.replace(&*String::from_utf8_lossy(CRED), "pc_has space").into_bytes(),
            [good.as_bytes(), b"trailing"].concat(),
        ];
        for (i, c) in cases.iter().enumerate() {
            write_raw(&d, c, 0o600);
            assert!(load(&d).is_none(), "case {i}");
        }
        assert!(load(&tmp("missing")).is_none());
        assert!(Pin::new(&lan(), 8788, b"pc_x\n", &[]).is_none());
        assert!(Pin::new(&lan(), 8788, CRED, &[1u8; 15]).is_none());
    }

    #[test]
    fn rotation_fields_and_unknown_fields_are_ignored() {
        let d = tmp("rot");
        let text = format!(r#"{{"host":"{}","port":8788,"credential":"{}","machine_id":"","rotate_nonce":"00","rotate_ct":"11","next_credential":"pc_other","x":[1]}}"#, ip(10, 1, 2, 3), String::from_utf8_lossy(CRED));
        write_raw(&d, text.as_bytes(), 0o600);
        let p = load(&d).unwrap();
        assert_eq!(p.credential(), CRED, "the current credential is used, never a next one");
    }

    #[test]
    fn a_failed_replace_leaves_the_old_pairing_intact_and_a_stale_temp_is_swept() {
        let d = tmp("atomic");
        save(&d, &pin()).unwrap();
        // a crash leftover from an earlier run
        std::fs::write(d.join(format!(".{FILE}.tmp")), b"garbage").unwrap();
        let second = Pin::new(&ip(10, 9, 8, 7), 9000, b"pc_secondCredential_0123456789abcdefgh", &[]).unwrap();
        // the temp name is taken by a non empty folder: the write fails, the old file is untouched
        let stale = d.join(format!(".{FILE}.tmp"));
        std::fs::remove_file(&stale).unwrap();
        std::fs::create_dir_all(stale.join("x")).unwrap();
        assert!(save(&d, &second).is_err(), "a blocked temp name must fail the save");
        assert_eq!(load(&d).unwrap().credential(), CRED, "the old pairing survived the failed replace");
        std::fs::remove_dir_all(&stale).unwrap();
        std::fs::write(&stale, b"garbage").unwrap(); // a crash leftover is swept by the next save
        save(&d, &second).unwrap();
        assert_eq!(load(&d).unwrap().host, ip(10, 9, 8, 7), "the replace took");
        assert!(!d.join(format!(".{FILE}.tmp")).exists());
        forget(&d).unwrap();
        assert!(load(&d).is_none(), "with the file gone the group reads unknown");
        forget(&d).unwrap();
    }

    // 10. the pin
    #[test]
    fn a_pin_for_one_machine_id_refuses_another_and_a_missing_one() {
        let p = pin();
        assert!(p.machine_matches(Some(&[7u8; 16])));
        assert!(!p.machine_matches(Some(&[8u8; 16])), "a different machine id");
        assert!(!p.machine_matches(None), "a pinned id that is no longer sealed");
        let none = Pin::new(&lan(), 8788, CRED, &[]).unwrap();
        assert!(none.machine_matches(None));
        assert!(!none.machine_matches(Some(&[7u8; 16])), "an id appearing where the pin had none");
    }

    #[test]
    fn the_credential_buffer_is_overwritten_and_the_pin_never_prints_it() {
        let mut p = pin();
        assert_eq!(p.credential(), CRED);
        p.wipe_now();
        assert!(p.credential().iter().all(|b| *b == 0), "the buffer is zero after wipe");
        let q = pin();
        let shown = format!("{q:?}{:?}", Some(&q));
        assert!(!shown.contains("pc_") && !shown.contains("192.168"), "{shown}");
    }
}
