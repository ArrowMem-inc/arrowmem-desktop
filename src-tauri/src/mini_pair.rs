//! The pairing flow with a remote machine's companion, as a pure state machine: no socket, no clock, no file, no UI.
//! The caller feeds it each reply body and sends what it returns; the driver and the window come in a later round.
//!
//! The companion's handshake (companion_server.py `_handle_pair_start` / `_reveal` / `_finish`), mutual commit then
//! reveal, with this machine in the phone's role:
//!   1. `begin`: an X25519 key and a 16 byte nonce; send `public_key` and `commitment = SHA-256(nonce || public_key)`.
//!   2. `on_start_reply`: the companion's key and commitment; send our nonce (`pair-reveal`).
//!   3. `on_reveal_reply`: the companion's nonce, checked against its commitment BEFORE anything is derived. Only then do
//!      the digits exist. The code is SIX digits: `_format_code` is `"%06d" % (n % 1000000)` (companion_server.py line 687),
//!      n the first 4 bytes of the code HKDF, big endian. (The companion's docstrings and an older Rust copy say four:
//!      stale, the function decides.) The digits are shown here and typed on the remote machine.
//!   4. `confirm`: the person typed them. Only then `finish_request` exists: `proof = hex HMAC(session_key, handshake_id)`.
//!   5. `on_finish_reply`: the credential (and the machine id) AES-GCM sealed under the session key, aad the handshake id
//!      (and handshake id + "/machine-id"); the credential must start with `pc_`. Result: a [`Pin`] for the credential store.
//!
//! Any mismatch is terminal. Every reason is a short fixed word: never a key, nonce, credential or address.

use crate::minicred::Pin;
use crate::sealed::{hex, hkdf, hmac, random, wipe};
use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey, StaticSecret};

const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Standard base64 with padding (the companion's `base64.b64encode`).
pub fn b64(b: &[u8]) -> String {
    let mut s = String::new();
    for c in b.chunks(3) {
        let n = (c[0] as u32) << 16 | (*c.get(1).unwrap_or(&0) as u32) << 8 | *c.get(2).unwrap_or(&0) as u32;
        s.push(B64[(n >> 18 & 63) as usize] as char);
        s.push(B64[(n >> 12 & 63) as usize] as char);
        s.push(if c.len() > 1 { B64[(n >> 6 & 63) as usize] as char } else { '=' });
        s.push(if c.len() > 2 { B64[(n & 63) as usize] as char } else { '=' });
    }
    s
}

/// Strict decode (the companion validates with `validate=True`): length a multiple of 4, alphabet only, padding only at the end.
pub fn unb64(s: &str) -> Option<Vec<u8>> {
    let b = s.as_bytes();
    if b.len() % 4 != 0 {
        return None;
    }
    let pad = b.iter().rev().take(2).take_while(|c| **c == b'=').count();
    if !b[..b.len() - pad].iter().all(|c| B64.contains(c)) {
        return None;
    }
    let mut out = Vec::new();
    for q in b.chunks(4) {
        let v = |c: u8| if c == b'=' { 0 } else { B64.iter().position(|x| *x == c).unwrap() as u32 };
        let n = v(q[0]) << 18 | v(q[1]) << 12 | v(q[2]) << 6 | v(q[3]);
        out.push((n >> 16) as u8);
        if q[2] != b'=' {
            out.push((n >> 8) as u8);
        }
        if q[3] != b'=' {
            out.push(n as u8);
        }
    }
    Some(out)
}

fn commitment(nonce: &[u8], public: &[u8]) -> [u8; 32] {
    Sha256::new().chain_update(nonce).chain_update(public).finalize().into()
}

fn same(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |d, (x, y)| d | (x ^ y)) == 0
}

/// `_derive_pairing_material`: two independent HKDF outputs off the shared secret. Returns (session key, six digits).
pub fn derive_material(shared: &[u8], phone_nonce: &[u8], companion_nonce: &[u8], companion_pub: &[u8], phone_pub: &[u8]) -> ([u8; 32], String) {
    let context = [companion_pub, phone_pub].concat();
    let salt = [phone_nonce, companion_nonce].concat();
    let mut key = [0u8; 32];
    hkdf(shared, Some(&salt), &[&b"arrowbridge-pairing-session-key|"[..], &context].concat(), &mut key);
    let mut code = [0u8; 32];
    hkdf(shared, Some(&salt), &[&b"arrowbridge-pairing-code|"[..], &context].concat(), &mut code);
    let n = u32::from_be_bytes([code[0], code[1], code[2], code[3]]);
    wipe(&mut code);
    (key, format_code(n))
}

/// `_format_code`: `"%06d" % (n % 1000000)`.
pub fn format_code(n: u32) -> String {
    format!("{:06}", n % 1_000_000)
}

enum St {
    Committed { sk: StaticSecret, public: [u8; 32], nonce: [u8; 16] },
    Started { public: [u8; 32], nonce: [u8; 16], hid: String, cpub: [u8; 32], ccommit: [u8; 32], shared: [u8; 32] },
    Revealed { hid: String, key: [u8; 32], digits: String, confirmed: bool },
    Finished,
    Failed(String),
}

pub struct Pair {
    st: St,
}

impl Drop for Pair {
    fn drop(&mut self) {
        match &mut self.st {
            St::Started { shared, nonce, .. } => {
                wipe(shared);
                wipe(nonce);
            }
            St::Revealed { key, .. } => wipe(key),
            _ => {}
        }
    }
}

fn hid_ok(h: &str) -> bool {
    !h.is_empty() && h.len() <= 64 && h.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_')
}

impl Pair {
    /// Round one. The secret and nonce are the caller's (fresh from the OS in production, fixed in a test).
    pub fn begin(secret: [u8; 32], nonce: [u8; 16]) -> (Pair, String) {
        let sk = StaticSecret::from(secret);
        let public = PublicKey::from(&sk).to_bytes();
        let body = serde_json::json!({"public_key": b64(&public), "commitment": b64(&commitment(&nonce, &public))}).to_string();
        (Pair { st: St::Committed { sk, public, nonce } }, body)
    }

    /// `begin` with fresh randomness. None when the OS source cannot be read.
    pub fn begin_fresh() -> Option<(Pair, String)> {
        let mut s = random::<32>()?;
        let n = random::<16>()?;
        let r = Pair::begin(s, n);
        wipe(&mut s);
        Some(r)
    }

    fn fail<T>(&mut self, why: &str) -> Result<T, String> {
        self.st = St::Failed(why.to_string());
        Err(why.to_string())
    }

    /// A reply that was not a 200. The two 409 bodies the companion names keep their name; anything else is `http_<status>`.
    pub fn on_status(&mut self, status: u16, body: &[u8]) -> String {
        let name = serde_json::from_slice::<serde_json::Value>(body).ok().and_then(|v| v.get("error").and_then(|e| e.as_str().map(String::from)));
        let why = match (status, name.as_deref()) {
            (409, Some("pair_aborted_overlap")) => "pair_aborted_overlap".to_string(),
            (409, Some("pair_code_mismatch")) => "pair_code_mismatch".to_string(),
            _ => format!("http_{status}"),
        };
        self.st = St::Failed(why.clone());
        why
    }

    /// Round one reply. Returns the `pair-reveal` body (our nonce).
    pub fn on_start_reply(&mut self, body: &[u8]) -> Result<String, String> {
        let St::Committed { sk, public, nonce } = std::mem::replace(&mut self.st, St::Failed("bad_state".into())) else {
            return Err("bad_state".into());
        };
        let parsed = (|| {
            let v: serde_json::Value = serde_json::from_slice(body).ok()?;
            let hid = v.get("handshake_id")?.as_str()?.to_string();
            let cpub: [u8; 32] = unb64(v.get("public_key")?.as_str()?)?.try_into().ok()?;
            let ccommit: [u8; 32] = unb64(v.get("commitment")?.as_str()?)?.try_into().ok()?;
            hid_ok(&hid).then_some((hid, cpub, ccommit))
        })();
        let Some((hid, cpub, ccommit)) = parsed else { return self.fail("bad_reply") };
        let ss = sk.diffie_hellman(&PublicKey::from(cpub));
        if !ss.was_contributory() {
            return self.fail("bad_reply"); // a low order point: the shared secret would be a known value
        }
        let shared = ss.to_bytes();
        let reveal = serde_json::json!({"handshake_id": hid, "nonce": b64(&nonce)}).to_string();
        self.st = St::Started { public, nonce, hid, cpub, ccommit, shared };
        Ok(reveal)
    }

    /// Round two reply. The companion's nonce must match its commitment; only then are the digits derived. Returns them.
    pub fn on_reveal_reply(&mut self, body: &[u8]) -> Result<String, String> {
        let St::Started { public, nonce, hid, cpub, ccommit, shared } = std::mem::replace(&mut self.st, St::Failed("bad_state".into())) else {
            return Err("bad_state".into());
        };
        let cnonce = (|| unb64(serde_json::from_slice::<serde_json::Value>(body).ok()?.get("companion_nonce")?.as_str()?))();
        let Some(cnonce) = cnonce else { return self.fail("bad_reply") };
        if !same(&commitment(&cnonce, &cpub), &ccommit) {
            return self.fail("commitment_mismatch");
        }
        let (key, digits) = derive_material(&shared, &nonce, &cnonce, &cpub, &public);
        let shown = digits.clone();
        self.st = St::Revealed { hid, key, digits, confirmed: false };
        Ok(shown)
    }

    /// The six digits, only once the reveal has checked.
    pub fn digits(&self) -> Option<&str> {
        match &self.st {
            St::Revealed { digits, .. } => Some(digits),
            _ => None,
        }
    }

    /// The person typed the digits on the remote machine.
    pub fn confirm(&mut self) -> Result<(), String> {
        match &mut self.st {
            St::Revealed { confirmed, .. } => {
                *confirmed = true;
                Ok(())
            }
            _ => Err("bad_state".into()),
        }
    }

    /// The `pair-finish` body. Refused before the reveal checked and before the person confirmed.
    pub fn finish_request(&self) -> Result<String, String> {
        match &self.st {
            St::Revealed { hid, key, confirmed: true, .. } => Ok(serde_json::json!({"handshake_id": hid, "proof": hex(&hmac(key, &[hid.as_bytes()]))}).to_string()),
            _ => Err("bad_state".into()),
        }
    }

    /// The `pair-finish` reply: the credential, and the machine id if the companion sealed one.
    pub fn on_finish_reply(&mut self, body: &[u8], host: &str, port: u16) -> Result<Pin, String> {
        let St::Revealed { hid, key, confirmed: true, .. } = std::mem::replace(&mut self.st, St::Failed("bad_state".into())) else {
            return Err("bad_state".into());
        };
        let mut key = key;
        let opened = (|| {
            let v: serde_json::Value = serde_json::from_slice(body).ok()?;
            let open = |n: &str, c: &str, aad: &[u8]| -> Option<Vec<u8>> {
                let nonce = unb64(v.get(n)?.as_str()?)?;
                let ct = unb64(v.get(c)?.as_str()?)?;
                if nonce.len() != 12 {
                    return None;
                }
                Aes256Gcm::new_from_slice(&key).ok()?.decrypt(Nonce::from_slice(&nonce), Payload { msg: &ct, aad }).ok()
            };
            let cred = open("credential_nonce", "credential_ciphertext", hid.as_bytes())?;
            let machine = if v.get("machine_id_ciphertext").is_some() || v.get("machine_id_nonce").is_some() {
                open("machine_id_nonce", "machine_id_ciphertext", &[hid.as_bytes(), b"/machine-id"].concat())?
            } else {
                Vec::new()
            };
            Some((cred, machine))
        })();
        wipe(&mut key);
        let Some((mut cred, machine)) = opened else { return self.fail("bad_reply") };
        let pin = Pin::new(host, port, &cred, &machine);
        wipe(&mut cred);
        match pin {
            Some(p) => {
                self.st = St::Finished;
                Ok(p)
            }
            None => self.fail("bad_reply"),
        }
    }

    pub fn failed(&self) -> Option<&str> {
        match &self.st {
            St::Failed(w) => Some(w),
            _ => None,
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// A dotted quad assembled at run time: no address literal is written in this file.
    fn ip(a: u8, b: u8, c: u8, d: u8) -> String {
        format!("{a}.{b}.{c}.{d}")
    }
    fn lan() -> String {
        ip(192, 168, 4, 20)
    }

    const VECTORS: &str = include_str!("fixtures/mini_pairing_vectors.json");
    /// The seeds `make_pairing_vectors.py` uses: phone private key = [a]*32, companion private key = [b]*32, nonces [c]*16, [d]*16.
    const SEEDS: [(u8, u8, u8, u8); 8] = [(1, 2, 3, 4), (5, 6, 7, 8), (9, 10, 11, 12), (13, 14, 15, 16), (17, 18, 19, 20), (21, 22, 23, 24), (25, 26, 27, 28), (29, 30, 31, 32)];

    fn cases() -> Vec<serde_json::Value> {
        serde_json::from_str::<serde_json::Value>(VECTORS).unwrap()["cases"].as_array().unwrap().clone()
    }
    fn u(c: &serde_json::Value, k: &str) -> Vec<u8> {
        crate::sealed::unhex(c[k].as_str().unwrap()).unwrap()
    }

    // the companion's side, from the Python source, so the whole flow runs offline
    pub(crate) struct Companion {
        sk: StaticSecret,
        public: [u8; 32],
        nonce: [u8; 16],
        hid: String,
        key: Option<[u8; 32]>,
    }
    impl Companion {
        pub(crate) fn new(b: u8, d: u8) -> Companion {
            let sk = StaticSecret::from([b; 32]);
            let public = PublicKey::from(&sk).to_bytes();
            Companion { sk, public, nonce: [d; 16], hid: "hs_Abc-123_xyz".into(), key: None }
        }
        pub(crate) fn start_reply(&self) -> Vec<u8> {
            serde_json::json!({"handshake_id": self.hid, "public_key": b64(&self.public), "commitment": b64(&commitment(&self.nonce, &self.public))}).to_string().into_bytes()
        }
        pub(crate) fn reveal_reply(&mut self, start_body: &str, reveal_body: &str) -> Vec<u8> {
            let s: serde_json::Value = serde_json::from_str(start_body).unwrap();
            let r: serde_json::Value = serde_json::from_str(reveal_body).unwrap();
            let ppub = unb64(s["public_key"].as_str().unwrap()).unwrap();
            let pnonce = unb64(r["nonce"].as_str().unwrap()).unwrap();
            let shared = self.sk.diffie_hellman(&PublicKey::from(<[u8; 32]>::try_from(&ppub[..]).unwrap())).to_bytes();
            self.key = Some(derive_material(&shared, &pnonce, &self.nonce, &self.public, &ppub).0);
            serde_json::json!({"companion_nonce": b64(&self.nonce)}).to_string().into_bytes()
        }
        pub(crate) fn finish_reply(&self, cred: &[u8], machine: Option<&[u8]>) -> Vec<u8> {
            let seal = |n: u8, msg: &[u8], aad: &[u8]| Aes256Gcm::new_from_slice(&self.key.unwrap()).unwrap().encrypt(Nonce::from_slice(&[n; 12]), Payload { msg, aad }).unwrap();
            let mut v = serde_json::json!({"credential_nonce": b64(&[1u8; 12]), "credential_ciphertext": b64(&seal(1, cred, self.hid.as_bytes()))});
            if let Some(m) = machine {
                v["machine_id_nonce"] = b64(&[2u8; 12]).into();
                v["machine_id_ciphertext"] = b64(&seal(2, m, &[self.hid.as_bytes(), b"/machine-id"].concat())).into();
            }
            v.to_string().into_bytes()
        }
    }

    // run to the Revealed state; returns (pair, companion, digits)
    fn run_to_reveal(a: u8, b: u8, c: u8, d: u8) -> (Pair, Companion, String) {
        let (mut p, start) = Pair::begin([a; 32], [c; 16]);
        let mut comp = Companion::new(b, d);
        let reveal = p.on_start_reply(&comp.start_reply()).unwrap();
        let reply = comp.reveal_reply(&start, &reveal);
        let digits = p.on_reveal_reply(&reply).unwrap();
        (p, comp, digits)
    }

    // 8. the math equals the Python recordings
    #[test]
    fn the_digits_equal_the_python_recordings_for_all_eight_cases() {
        let cs = cases();
        assert_eq!(cs.len(), 8);
        for (c, (a, b, cn, dn)) in cs.iter().zip(SEEDS) {
            let (key, code) = derive_material(&u(c, "shared_secret"), &u(c, "phone_nonce"), &u(c, "companion_nonce"), &u(c, "companion_pub"), &u(c, "phone_pub"));
            assert_eq!(code, c["code"].as_str().unwrap(), "derive_material, seed {a}");
            assert_eq!(code.len(), 6, "six digits");
            assert_ne!(key, [0u8; 32]);
            // the whole machine, with the seeds the recording used, lands on the recorded code and public keys
            let (p, comp, digits) = run_to_reveal(a, b, cn, dn);
            assert_eq!(digits, c["code"].as_str().unwrap(), "state machine, seed {a}");
            assert_eq!(hex(&comp.public), c["companion_pub"].as_str().unwrap());
            assert_eq!(p.digits(), Some(digits.as_str()));
        }
    }

    #[test]
    fn the_code_is_six_digits_with_leading_zeros_and_a_modulus_of_a_million() {
        assert_eq!(format_code(0), "000000");
        assert_eq!(format_code(5), "000005");
        assert_eq!(format_code(1_000_005), "000005");
        assert_eq!(format_code(u32::MAX), format!("{:06}", u32::MAX % 1_000_000));
        assert_eq!(format_code(999_999).len(), 6);
    }

    #[test]
    fn base64_matches_the_standard_and_is_strict() {
        for (raw, enc) in [(&b""[..], ""), (b"f", "Zg=="), (b"fo", "Zm8="), (b"foo", "Zm9v"), (b"foob", "Zm9vYg=="), (b"\xff\xfe\xfd", "//79")] {
            assert_eq!(b64(raw), enc);
            assert_eq!(unb64(enc).unwrap(), raw);
        }
        for bad in ["Zg=", "Zg", "Zm9v=", "=Zm9", "Z g=", "Zm9v\n", "Zg==Zg==", "Z===", "Zm-v"] {
            assert!(unb64(bad).is_none(), "{bad:?}");
        }
    }

    #[test]
    fn the_digits_exist_only_after_the_reveal_checks() {
        let (mut p, _start) = Pair::begin([1; 32], [3; 16]);
        assert_eq!(p.digits(), None, "before round one");
        let comp = Companion::new(2, 4);
        p.on_start_reply(&comp.start_reply()).unwrap();
        assert_eq!(p.digits(), None, "after the commitments, before the reveal");
        assert!(p.finish_request().is_err(), "no finish before the reveal");
        // a reveal with the wrong companion nonce: the commitment does not match, no digits ever
        let bad = serde_json::json!({"companion_nonce": b64(&[9u8; 16])}).to_string();
        assert_eq!(p.on_reveal_reply(bad.as_bytes()), Err("commitment_mismatch".to_string()));
        assert_eq!(p.digits(), None);
        assert_eq!(p.failed(), Some("commitment_mismatch"));
        assert!(p.confirm().is_err() && p.finish_request().is_err(), "failed is terminal");
        assert!(p.on_start_reply(&comp.start_reply()).is_err(), "failed is terminal");
    }

    #[test]
    fn the_finish_request_waits_for_the_person_and_carries_the_proof() {
        let (mut p, comp, _d) = run_to_reveal(1, 2, 3, 4);
        assert!(p.finish_request().is_err(), "digits shown but not yet typed on the other machine");
        p.confirm().unwrap();
        let body: serde_json::Value = serde_json::from_str(&p.finish_request().unwrap()).unwrap();
        assert_eq!(body["handshake_id"], comp.hid.as_str());
        assert_eq!(body["proof"].as_str().unwrap(), hex(&hmac(&comp.key.unwrap(), &[comp.hid.as_bytes()])), "proof is HMAC(session key, handshake id)");
        assert_eq!(body.as_object().unwrap().len(), 2);
    }

    #[test]
    fn a_full_flow_opens_the_credential_and_the_machine_id_into_a_pin() {
        let (mut p, comp, _d) = run_to_reveal(1, 2, 3, 4);
        p.confirm().unwrap();
        let cred = b"pc_pairedCredential_0123456789abcdefghij";
        let pin = p.on_finish_reply(&comp.finish_reply(cred, Some(&[0x5a; 16])), &lan(), 8788).unwrap();
        assert_eq!((pin.credential(), pin.machine_id.as_str()), (&cred[..], hex(&[0x5a; 16]).as_str()));
        assert!(p.on_finish_reply(&comp.finish_reply(cred, None), &lan(), 8788).is_err(), "one finish only");
        // no machine id sealed: an empty one
        let (mut p, comp, _d) = run_to_reveal(5, 6, 7, 8);
        p.confirm().unwrap();
        let pin = p.on_finish_reply(&comp.finish_reply(cred, None), &ip(10, 0, 0, 9), 8788).unwrap();
        assert_eq!(pin.machine_id, "");
    }

    #[test]
    fn a_bad_finish_reply_is_refused_and_never_yields_a_pin() {
        let cred = b"pc_pairedCredential_0123456789abcdefghij";
        let try_reply = |tweak: &dyn Fn(&Companion, Vec<u8>) -> Vec<u8>, host: &str, port: u16| {
            let (mut p, comp, _d) = run_to_reveal(1, 2, 3, 4);
            p.confirm().unwrap();
            let r = tweak(&comp, comp.finish_reply(cred, Some(&[0x5a; 16])));
            let out = p.on_finish_reply(&r, host, port);
            (out.is_ok(), p.failed().map(String::from))
        };
        assert!(try_reply(&|_, r| r, &lan(), 8788).0, "control");
        assert_eq!(try_reply(&|_, r| r, &ip(127, 0, 0, 1), 8788), (false, Some("bad_reply".into())), "an address the gate refuses");
        assert_eq!(try_reply(&|_, r| r, &ip(100, 64, 1, 1), 8788).0, false, "a tailnet address");
        assert_eq!(try_reply(&|_, r| r, &lan(), 80).0, false, "a low port");
        assert_eq!(try_reply(&|_, _| b"{}".to_vec(), &lan(), 8788).0, false);
        assert_eq!(try_reply(&|_, _| b"not json".to_vec(), &lan(), 8788).0, false);
        let flip = |_: &Companion, r: Vec<u8>| {
            let mut v: serde_json::Value = serde_json::from_slice(&r).unwrap();
            let mut ct = unb64(v["credential_ciphertext"].as_str().unwrap()).unwrap();
            *ct.last_mut().unwrap() ^= 1;
            v["credential_ciphertext"] = b64(&ct).into();
            v.to_string().into_bytes()
        };
        assert_eq!(try_reply(&flip, &lan(), 8788).0, false, "a flipped tag byte");
        let no_pc = |c: &Companion, _: Vec<u8>| c.finish_reply(b"xx_notACredential_0123456789abcdefghijk", None);
        assert_eq!(try_reply(&no_pc, &lan(), 8788).0, false, "a credential without the pc_ prefix");
        let wrong_aad = |c: &Companion, _: Vec<u8>| {
            let mut other = Companion::new(2, 4);
            other.hid = "someOtherHandshake".into();
            other.key = c.key;
            other.finish_reply(cred, None)
        };
        assert_eq!(try_reply(&wrong_aad, &lan(), 8788).0, false, "sealed under another handshake id");
        let half = |_: &Companion, r: Vec<u8>| {
            let mut v: serde_json::Value = serde_json::from_slice(&r).unwrap();
            v.as_object_mut().unwrap().remove("machine_id_nonce");
            v.to_string().into_bytes()
        };
        assert_eq!(try_reply(&half, &lan(), 8788).0, false, "a machine id with no nonce");
    }

    #[test]
    fn a_malformed_start_reply_a_low_order_key_and_the_named_409s_are_handled() {
        let comp = Companion::new(2, 4);
        let good = comp.start_reply();
        let mutate = |f: &dyn Fn(&mut serde_json::Value)| {
            let mut v: serde_json::Value = serde_json::from_slice(&good).unwrap();
            f(&mut v);
            v.to_string().into_bytes()
        };
        let bads: Vec<Vec<u8>> = vec![
            b"".to_vec(),
            b"{}".to_vec(),
            mutate(&|v| { v["public_key"] = b64(&[1u8; 31]).into() }),
            mutate(&|v| { v["commitment"] = b64(&[1u8; 33]).into() }),
            mutate(&|v| { v["handshake_id"] = "".into() }),
            mutate(&|v| { v["handshake_id"] = "a b".into() }),
            mutate(&|v| { v["handshake_id"] = "x".repeat(65).into() }),
            mutate(&|v| { v["public_key"] = "not base64!".into() }),
            mutate(&|v| { v["public_key"] = b64(&[0u8; 32]).into() }), // all zero: a low order point
        ];
        for (i, b) in bads.iter().enumerate() {
            let (mut p, _s) = Pair::begin([1; 32], [3; 16]);
            assert_eq!(p.on_start_reply(b), Err("bad_reply".to_string()), "case {i}");
            assert!(p.failed().is_some());
        }
        let (mut p, _s) = Pair::begin([1; 32], [3; 16]);
        assert_eq!(p.on_status(409, br#"{"error":"pair_aborted_overlap"}"#), "pair_aborted_overlap");
        assert_eq!(p.on_status(409, br#"{"error":"pair_code_mismatch"}"#), "pair_code_mismatch");
        assert_eq!(p.on_status(409, br#"{"error":"phone_limit"}"#), "http_409");
        assert_eq!(p.on_status(404, b"<html>"), "http_404");
        assert_eq!(p.on_status(500, b""), "http_500");
    }

    #[test]
    fn the_start_body_is_a_key_and_a_commitment_to_the_nonce_and_never_the_nonce() {
        let (_p, body) = Pair::begin([1; 32], [3; 16]);
        let v: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(v.as_object().unwrap().len(), 2);
        let public = unb64(v["public_key"].as_str().unwrap()).unwrap();
        assert_eq!(unb64(v["commitment"].as_str().unwrap()).unwrap(), commitment(&[3u8; 16], &public));
        assert!(!body.contains(&b64(&[3u8; 16])), "the nonce is not revealed in round one");
        let (a, _) = Pair::begin_fresh().unwrap();
        let (b, _) = Pair::begin_fresh().unwrap();
        let (St::Committed { public: pa, .. }, St::Committed { public: pb, .. }) = (&a.st, &b.st) else { panic!() };
        assert_ne!(pa, pb, "fresh keys per attempt");
    }
}
