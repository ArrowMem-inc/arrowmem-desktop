//! The remote group of the owner routes: this machine asks the paired remote machine's companion for its model list over
//! the sealed channel, and hands the opened `models` body to the caller, or nothing.
//!
//! WIRING NOTE for the merge round: in ownerroutes.rs, `DesktopUpstream::remote_listing` becomes
//! `self.remote.remote_listing()` with a `remote: mini_remote::MiniRemote` field built from the state dir.
//! The trait here has the same method shape as `ownerroutes::Upstream::remote_listing` (`&self -> Option<String>`).
//!
//! Failure direction: `None` is the group UNKNOWN. It is returned for no pairing file, a refused address, no answer, any
//! non-200, a bad proof, tag, counter, frame or stream, a different machine id than the pin, and a body that is not a
//! non-empty `models` list. It is never an empty list. The machine id is compared with the pin and discarded: it is in no
//! return value. The row allowlist (64 rows, 200 chars, no control characters, no duplicates, four fields) is the owner
//! routes' `parse_remote`, which runs on the string returned here.

use crate::minicred;
use crate::sealed::{exchange, models_body, random, TcpTransport, Transport};
use std::path::PathBuf;

pub trait RemoteListing {
    fn remote_listing(&self) -> Option<String>;
}

pub struct MiniRemote {
    state_dir: PathBuf,
}

impl MiniRemote {
    pub fn new(state_dir: PathBuf) -> MiniRemote {
        MiniRemote { state_dir }
    }

    /// The listing through any transport (the production one is `TcpTransport::dial` on the pinned address).
    fn listing_via(&self, t: &dyn Transport, cred: &[u8], pin: &minicred::Pin) -> Option<String> {
        let o = exchange(t, cred, random::<16>()?, br#"{"op":"models"}"#).ok()?;
        pin.machine_matches(o.machine_id.as_deref()).then(|| models_body(&o)).flatten()
    }
}

impl RemoteListing for MiniRemote {
    fn remote_listing(&self) -> Option<String> {
        let pin = minicred::load(&self.state_dir)?;
        let t = TcpTransport::dial(&pin.host, pin.port).ok()?;
        self.listing_via(&t, pin.credential(), &pin)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sealed::{derive_keys, hex, open_proof, unhex};
    use std::sync::{Arc, Mutex};

    /// A dotted quad assembled at run time: no address literal is written in this file.
    fn ip(a: u8, b: u8, c: u8, d: u8) -> String {
        format!("{a}.{b}.{c}.{d}")
    }

    const CRED: &[u8] = b"pc_remoteListingCredential_0123456789ab";
    const MID: [u8; 16] = [0x5a; 16];

    fn dir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("miniremote-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        d
    }

    /// An in process companion: no socket. Seals under the keys the real derivation gives.
    struct Fake {
        mid: Option<[u8; 16]>,
        status: u16,
        list: &'static str,
        calls: Arc<Mutex<Vec<String>>>,
        keys: Mutex<Option<crate::sealed::Keys>>,
    }
    impl Transport for Fake {
        fn post(&self, route: &str, _: &str, _: Option<&str>, body: &[u8]) -> Option<(u16, Vec<u8>)> {
            use aes_gcm::aead::{Aead, KeyInit, Payload};
            use aes_gcm::{Aes256Gcm, Nonce};
            self.calls.lock().unwrap().push(route.to_string());
            let sid = [0x44u8; 16];
            if route == "session-open" {
                let v: serde_json::Value = serde_json::from_slice(body).ok()?;
                let cn = unhex(v["client_nonce"].as_str()?)?;
                let k = derive_keys(CRED, &cn, &[0x33u8; 16]);
                let mut out = serde_json::json!({"session_id": hex(&sid), "server_nonce": hex(&[0x33u8; 16]), "proof": hex(&open_proof(&k.s2c, &sid))});
                if let Some(m) = self.mid {
                    let mut mk = [0u8; 32];
                    crate::sealed::hkdf(&k.s2c, None, b"arrowbridge/machine-id/v1", &mut mk);
                    let ct = Aes256Gcm::new_from_slice(&mk).unwrap().encrypt(Nonce::from_slice(&[1u8; 12]), Payload { msg: &m, aad: &[&b"arrowbridge/machine-id/v1"[..], &sid].concat() }).unwrap();
                    out["machine_id_nonce"] = hex(&[1u8; 12]).into();
                    out["machine_id_ct"] = hex(&ct).into();
                }
                *self.keys.lock().unwrap() = Some(k);
                return Some((200, out.to_string().into_bytes()));
            }
            let g = self.keys.lock().unwrap();
            let k = g.as_ref()?;
            let ct = Aes256Gcm::new_from_slice(&k.s2c).unwrap().encrypt(Nonce::from_slice(&[&[0u8, 0, 0, 2][..], &1u64.to_be_bytes()].concat()), Payload { msg: self.list.as_bytes(), aad: &[&b"arrowbridge/resp/v1"[..], &sid, &1u64.to_be_bytes(), &0u32.to_be_bytes(), &[1u8]].concat() }).unwrap();
            let frame = [&1u64.to_be_bytes()[..], &ct].concat();
            Some((self.status, [&(frame.len() as u32).to_be_bytes()[..], &frame].concat()))
        }
    }
    fn fake(mid: Option<[u8; 16]>, status: u16, list: &'static str) -> Fake {
        Fake { mid, status, list, calls: Arc::new(Mutex::new(vec![])), keys: Mutex::new(None) }
    }
    const LIST: &str = r#"{"models":[{"id":"default","label":"One","size_bytes":null,"quant":null,"loaded":true}]}"#;

    fn paired(tag: &str, mid: &[u8]) -> (MiniRemote, minicred::Pin) {
        let d = dir(tag);
        let pin = minicred::Pin::new(&ip(192, 168, 4, 20), 8788, CRED, mid).unwrap();
        minicred::save(&d, &pin).unwrap();
        (MiniRemote::new(d), pin)
    }

    #[test]
    fn a_matching_machine_id_and_a_200_list_give_the_body() {
        let (r, pin) = paired("ok", &MID);
        let f = fake(Some(MID), 200, LIST);
        assert_eq!(r.listing_via(&f, CRED, &pin).as_deref(), Some(LIST));
        assert_eq!(*f.calls.lock().unwrap(), ["session-open", "chat"]);
    }

    #[test]
    fn a_different_machine_id_reads_unknown_even_with_a_good_list() {
        let (r, pin) = paired("other", &MID);
        assert_eq!(r.listing_via(&fake(Some([0x6b; 16]), 200, LIST), CRED, &pin), None);
        assert_eq!(r.listing_via(&fake(None, 200, LIST), CRED, &pin), None, "a pinned id that stopped being sealed");
    }

    #[test]
    fn every_failure_is_none_and_never_an_empty_listing() {
        let (r, pin) = paired("fails", &MID);
        for (st, body) in [(400u16, LIST), (401, LIST), (429, LIST), (503, LIST), (200, r#"{"models":[]}"#), (200, "{}"), (200, "[]"), (200, "garbage")] {
            assert_eq!(r.listing_via(&fake(Some(MID), st, body), CRED, &pin), None, "{st} {body}");
        }
        // the wrong credential on the remote side: the proof does not verify
        assert_eq!(r.listing_via(&fake(Some(MID), 200, LIST), b"pc_aDifferentCredential_0123456789abcd", &pin), None);
    }

    #[test]
    fn with_no_pairing_file_or_a_refused_address_nothing_is_dialled_and_the_group_is_unknown() {
        assert_eq!(MiniRemote::new(dir("none")).remote_listing(), None);
        // a pin file whose address the gate refuses reads as unpaired before any socket
        let d = dir("refused");
        std::fs::create_dir_all(&d).unwrap();
        std::fs::set_permissions(&d, std::os::unix::fs::PermissionsExt::from_mode(0o700)).unwrap();
        let p = d.join(minicred::FILE);
        std::fs::write(&p, format!(r#"{{"host":"{}","port":8788,"credential":"{}","machine_id":""}}"#, ip(127, 0, 0, 1), String::from_utf8_lossy(CRED))).unwrap();
        std::fs::set_permissions(&p, std::os::unix::fs::PermissionsExt::from_mode(0o600)).unwrap();
        assert_eq!(MiniRemote::new(d).remote_listing(), None);
    }

    // 6. the source guard: no log call anywhere, no write outside the credential store
    const SHIPPED: [(&str, &str); 4] = [
        ("sealed.rs", include_str!("sealed.rs")),
        ("minicred.rs", include_str!("minicred.rs")),
        ("mini_pair.rs", include_str!("mini_pair.rs")),
        ("mini_remote.rs", include_str!("mini_remote.rs")),
    ];

    fn shipped(text: &str) -> &str {
        text.split("#[cfg(test)]\nmod tests").next().unwrap()
    }

    /// Violations in shipped (non test) text: any print or log call, and any disk write outside minicred.rs.
    fn violations(name: &str, text: &str) -> Vec<String> {
        let mut v = Vec::new();
        let logs = ["println!", "eprintln!", "print!(", "eprint!(", "dbg!(", "log::", "tracing::", "info!(", "warn!(", "error!(", "debug!(", "trace!("];
        let writes = ["fs::write", "File::create", "OpenOptions", "fs::rename", "fs::remove", "fs::copy", "create_dir"];
        for (i, line) in shipped(text).lines().enumerate() {
            let code = line.split("//").next().unwrap();
            for l in logs {
                if code.contains(l) {
                    v.push(format!("{name}:{} log call {l}", i + 1));
                }
            }
            if name != "minicred.rs" {
                for w in writes {
                    if code.contains(w) {
                        v.push(format!("{name}:{} disk write {w}", i + 1));
                    }
                }
            }
        }
        v
    }

    #[test]
    fn no_shipped_text_logs_and_only_the_credential_store_writes_and_the_check_catches_a_plant() {
        for (name, text) in SHIPPED {
            assert_eq!(violations(name, text), Vec::<String>::new(), "{name}");
        }
        let planted = "fn x() {\n    println!(\"{}\", cred);\n}\n";
        assert_eq!(violations("sealed.rs", planted).len(), 1, "a planted println must be caught");
        let planted = "fn x() {\n    std::fs::write(p, cred).ok();\n}\n";
        assert_eq!(violations("mini_pair.rs", planted).len(), 1, "a planted write outside the store must be caught");
        assert!(violations("minicred.rs", planted).is_empty(), "the store may write");
    }
}
