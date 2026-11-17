//! The client side of the companion's sealed channel (ArrowBridge `/session-open` and sealed `/chat`), written to the
//! byte against `arrowbridge_channel.py` and the phone's `LanChannel.kt` / `LanClient.kt` / `LanAddress.kt`, and proven
//! against the shared `arrowbridge_vectors.json` (src/fixtures, copied byte for byte).
//!
//! Encodings (fixed by the companion): C is the UTF-8 bytes of the stored `pc_...` credential; session_id is the raw 16
//! bytes in every aad; counters are 8 bytes big endian; the chunk index is 4 bytes big endian; the final flag is one byte.
//! One session carries exactly one request (counter 1), so a counter is never reused and the 2^24 cap is never reached.
//!
//! Nothing in this file logs, and nothing writes to disk (a source guard test pins both). Every failure is a [`Fail`]
//! with no payload: no key, nonce, credential or address ever appears in an error.

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::time::{Duration, Instant};

pub const MAX_MESSAGES: u64 = 1 << 24;
const TAG: usize = 16;
const C2S: [u8; 4] = [0, 0, 0, 1];
const S2C: [u8; 4] = [0, 0, 0, 2];
const MACHINE_ID_LABEL: &[u8] = b"arrowbridge/machine-id/v1";
/// A reply larger than this is no reply; a whole call may take at most DEADLINE.
const MAX_REPLY: usize = 256 * 1024;
const DEADLINE: Duration = Duration::from_secs(10);

/// Why a call failed. No variant carries data. The caller maps every one of them to "unknown", never to "empty".
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum Fail {
    Refused,
    NoAnswer,
    Http(u16),
    BadReply,
    BadProof,
    BadFrame,
    BadChunk,
    AfterFinal,
    Truncated,
    Counter,
    DifferentMachine,
    NoRandom,
}

/// Overwrite with zeros in a way the optimiser may not drop.
pub fn wipe(b: &mut [u8]) {
    for x in b.iter_mut() {
        unsafe { std::ptr::write_volatile(x, 0) };
    }
    std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
}

pub fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// Strict lower case hex, even length, as the Kotlin `unhex` and Python `.hex()`.
pub fn unhex(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 || !s.bytes().all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c)) {
        return None;
    }
    (0..s.len() / 2).map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).ok()).collect()
}

/// `n` bytes from the OS CSPRNG (the apikey.rs source). None when it cannot be read.
pub fn random<const N: usize>() -> Option<[u8; N]> {
    let mut b = [0u8; N];
    std::fs::File::open("/dev/urandom").and_then(|mut f| f.read_exact(&mut b)).ok()?;
    Some(b)
}

pub fn hmac(key: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut m = <Hmac<Sha256> as Mac>::new_from_slice(key).expect("hmac takes any key length");
    for p in parts {
        m.update(p);
    }
    m.finalize().into_bytes().into()
}

/// Constant time (the hmac crate's `verify_slice`): is `tag` the HMAC of `parts` under `key`?
fn hmac_ok(key: &[u8], parts: &[&[u8]], tag: &[u8]) -> bool {
    let mut m = <Hmac<Sha256> as Mac>::new_from_slice(key).expect("hmac takes any key length");
    for p in parts {
        m.update(p);
    }
    m.verify_slice(tag).is_ok()
}

pub fn hkdf(ikm: &[u8], salt: Option<&[u8]>, info: &[u8], out: &mut [u8]) {
    Hkdf::<Sha256>::new(salt, ikm).expand(info, out).expect("output length is within the HKDF limit");
}

pub fn cred_id(c: &[u8]) -> [u8; 16] {
    let h = hmac(c, &[b"arrowbridge/cred-id/v1"]);
    let mut o = [0u8; 16];
    o.copy_from_slice(&h[..16]);
    o
}

pub fn client_proof(c: &[u8], client_nonce: &[u8]) -> [u8; 32] {
    hmac(c, &[b"arrowbridge/open-req/v1", client_nonce])
}

/// The two directional keys of one session. Zeroed on drop.
pub struct Keys {
    pub c2s: [u8; 32],
    pub s2c: [u8; 32],
}

impl Drop for Keys {
    fn drop(&mut self) {
        wipe(&mut self.c2s);
        wipe(&mut self.s2c);
    }
}

pub fn derive_keys(c: &[u8], client_nonce: &[u8], server_nonce: &[u8]) -> Keys {
    let salt = [client_nonce, server_nonce].concat();
    let info = [&b"arrowbridge/chat/v1"[..], &cred_id(c)].concat();
    let mut okm = [0u8; 64];
    hkdf(c, Some(&salt), &info, &mut okm);
    let mut k = Keys { c2s: [0; 32], s2c: [0; 32] };
    k.c2s.copy_from_slice(&okm[..32]);
    k.s2c.copy_from_slice(&okm[32..]);
    wipe(&mut okm);
    k
}

pub fn open_proof(k_s2c: &[u8], session_id: &[u8]) -> [u8; 32] {
    hmac(k_s2c, &[b"arrowbridge/open/v1", session_id])
}

fn proof_ok(k_s2c: &[u8], session_id: &[u8], proof: &[u8]) -> bool {
    hmac_ok(k_s2c, &[b"arrowbridge/open/v1", session_id], proof)
}

fn gcm_nonce(dir: &[u8; 4], ctr: u64) -> [u8; 12] {
    let mut n = [0u8; 12];
    n[..4].copy_from_slice(dir);
    n[4..].copy_from_slice(&ctr.to_be_bytes());
    n
}

fn aead_open(key: &[u8], nonce: &[u8], aad: &[u8], ct: &[u8]) -> Option<Vec<u8>> {
    if nonce.len() != 12 {
        return None;
    }
    Aes256Gcm::new_from_slice(key).ok()?.decrypt(Nonce::from_slice(nonce), Payload { msg: ct, aad }).ok()
}

/// counter(8) || AES-GCM(k_c2s, nonce = C2S || counter, aad = "arrowbridge/req/v1" || POST || /chat || session_id || counter).
pub fn seal_request(k_c2s: &[u8], session_id: &[u8], counter: u64, plaintext: &[u8]) -> Result<Vec<u8>, Fail> {
    if counter == 0 || counter >= MAX_MESSAGES {
        return Err(Fail::Counter);
    }
    let aad = [&b"arrowbridge/req/v1"[..], b"POST", b"/chat", session_id, &counter.to_be_bytes()].concat();
    let ct = Aes256Gcm::new_from_slice(k_c2s)
        .map_err(|_| Fail::BadChunk)?
        .encrypt(Nonce::from_slice(&gcm_nonce(&C2S, counter)), Payload { msg: plaintext, aad: &aad })
        .map_err(|_| Fail::BadChunk)?;
    Ok([&counter.to_be_bytes()[..], &ct].concat())
}

fn resp_aad(session_id: &[u8], req_counter: u64, index: u32, fin: bool) -> Vec<u8> {
    [&b"arrowbridge/resp/v1"[..], session_id, &req_counter.to_be_bytes(), &index.to_be_bytes(), &[fin as u8]].concat()
}

/// Strict, as the Python reference and the phone: frames `len(4) || counter(8) || ct`, counters in order from `first`,
/// the final flag bound in the aad (tried false then true), the stream must end on a valid final chunk and carry
/// nothing after it. Anything else is an error, never a partial result.
pub fn open_response(k_s2c: &[u8], session_id: &[u8], first: u64, req_counter: u64, data: &[u8]) -> Result<Vec<u8>, Fail> {
    let mut out = Vec::new();
    let mut pos = 0usize;
    let mut i: u32 = 0;
    while pos < data.len() {
        if pos + 4 > data.len() {
            return Err(Fail::BadFrame);
        }
        let n = u32::from_be_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]]) as usize;
        if n < 8 + TAG || pos + 4 + n > data.len() {
            return Err(Fail::BadFrame);
        }
        let body = &data[pos + 4..pos + 4 + n];
        pos += 4 + n;
        let want = first.checked_add(i as u64).filter(|c| *c < MAX_MESSAGES).ok_or(Fail::Counter)?;
        if body[..8] != want.to_be_bytes() {
            return Err(Fail::Counter);
        }
        let mut hit = None;
        for fin in [false, true] {
            if let Some(p) = aead_open(k_s2c, &gcm_nonce(&S2C, want), &resp_aad(session_id, req_counter, i, fin), &body[8..]) {
                hit = Some((p, fin));
                break;
            }
        }
        let (plain, fin) = hit.ok_or(Fail::BadChunk)?;
        out.extend_from_slice(&plain);
        i += 1;
        if fin {
            return if pos == data.len() { Ok(out) } else { Err(Fail::AfterFinal) };
        }
    }
    Err(Fail::Truncated)
}

/// The remote machine's random id, sealed in the session-open reply under HKDF(k_s2c, MACHINE_ID_LABEL).
pub fn open_machine_id(k_s2c: &[u8], session_id: &[u8], nonce: &[u8], ct: &[u8]) -> Option<Vec<u8>> {
    let mut k = [0u8; 32];
    hkdf(k_s2c, None, MACHINE_ID_LABEL, &mut k);
    let r = aead_open(&k, nonce, &[MACHINE_ID_LABEL, session_id].concat(), ct);
    wipe(&mut k);
    r
}

// ------------------------------------------------------------------------------------------------ the address gate

/// The phone's `LanAddress` rule, ported. A destination is an IPv4 literal in one of the three RFC 1918 private blocks or the link-local block
/// (strict: four decimal parts, no leading zero, no short, hex or octal form, no userinfo, no port, no IPv6), or a single
/// label `<host>.local` whose every resolved address is itself private. Loopback, 0/8, multicast, public and the tailnet
/// (shared address space) range are refused by omission. Ports below 1024 are refused.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum Kind {
    Ip,
    Mdns,
}

pub fn parse_ipv4(s: &str) -> Option<[u8; 4]> {
    let parts: Vec<&str> = s.split('.').collect();
    if parts.len() != 4 {
        return None;
    }
    let mut o = [0u8; 4];
    for (i, p) in parts.iter().enumerate() {
        if p.is_empty() || p.len() > 3 || !p.bytes().all(|c| c.is_ascii_digit()) || (p.len() > 1 && p.starts_with('0')) {
            return None;
        }
        o[i] = p.parse::<u16>().ok().filter(|v| *v <= 255)? as u8;
    }
    Some(o)
}

pub fn is_private(ip: [u8; 4]) -> bool {
    let (a, b) = (ip[0], ip[1]);
    a == 10 || (a == 172 && (16..=31).contains(&b)) || (a == 192 && b == 168) || (a == 169 && b == 254)
}

fn mdns_label_ok(h: &str) -> bool {
    let Some(label) = h.strip_suffix(".local") else { return false };
    let b = label.as_bytes();
    !b.is_empty()
        && b.len() <= 63
        && b.iter().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'-')
        && b[0] != b'-'
        && b[b.len() - 1] != b'-'
}

pub fn classify(raw: &str) -> Option<Kind> {
    if raw.is_empty() || raw.len() > 253 {
        return None;
    }
    if raw.chars().any(|c| (c as u32) <= 0x20 || (c as u32) >= 0x7f || "@:/?#[]\\%".contains(c)) {
        return None;
    }
    if let Some(ip) = parse_ipv4(raw) {
        return is_private(ip).then_some(Kind::Ip);
    }
    if raw.bytes().all(|c| c.is_ascii_digit() || c == b'.') {
        return None; // a malformed dotted number is never a name
    }
    mdns_label_ok(&raw.to_ascii_lowercase()).then_some(Kind::Mdns)
}

pub fn port_allowed(p: u16) -> bool {
    p >= 1024
}

/// Every resolved address must be private IPv4: an empty list, an IPv6 answer or one public answer refuses the name.
pub fn resolved_allowed(addrs: &[SocketAddr]) -> bool {
    !addrs.is_empty() && addrs.iter().all(|a| matches!(a, SocketAddr::V4(v) if is_private(v.ip().octets())))
}

// ------------------------------------------------------------------------------------------------ the wire

/// POST these bytes to this route; None when there was no answer. [`TcpTransport`] is the production one.
pub trait Transport {
    fn post(&self, route: &str, content_type: &str, session_hex: Option<&str>, body: &[u8]) -> Option<(u16, Vec<u8>)>;
}

/// One HTTP/1.1 POST on a connected stream. No Origin, no redirect following, Connection: close, the reply read to at
/// most MAX_REPLY bytes within DEADLINE in all. `Host` is the caller's (an IP literal: the companion refuses `.local`).
fn http_post(s: &mut TcpStream, host_header: &str, route: &str, ctype: &str, session: Option<&str>, body: &[u8]) -> Option<(u16, Vec<u8>)> {
    let start = Instant::now();
    s.set_write_timeout(Some(Duration::from_secs(3))).ok()?;
    let sess = session.map(|h| format!("X-AB-Session: {h}\r\n")).unwrap_or_default();
    let head = format!("POST /{route} HTTP/1.1\r\nHost: {host_header}\r\nContent-Type: {ctype}\r\n{sess}Content-Length: {}\r\nConnection: close\r\n\r\n", body.len());
    s.write_all(head.as_bytes()).ok()?;
    s.write_all(body).ok()?;
    let mut raw: Vec<u8> = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        let left = DEADLINE.checked_sub(start.elapsed())?;
        s.set_read_timeout(Some(left.max(Duration::from_millis(1)))).ok()?;
        match s.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => raw.extend_from_slice(&chunk[..n]),
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => return None,
        }
        if raw.len() > MAX_REPLY + 8192 {
            return None;
        }
    }
    let split = raw.windows(4).position(|w| w == b"\r\n\r\n")?;
    let head = std::str::from_utf8(&raw[..split]).ok()?;
    let mut lines = head.split("\r\n");
    let mut st = lines.next()?.split(' ');
    if !st.next()?.starts_with("HTTP/1.") {
        return None;
    }
    let status: u16 = st.next()?.parse().ok()?;
    let mut clen: Option<usize> = None;
    for l in lines {
        let (k, v) = l.split_once(':')?;
        match k.trim().to_ascii_lowercase().as_str() {
            "transfer-encoding" => return None,
            "content-length" => clen = Some(v.trim().parse().ok()?),
            _ => {}
        }
    }
    let body = &raw[split + 4..];
    let body = match clen {
        Some(n) if body.len() >= n => &body[..n],
        Some(_) => return None, // truncated
        None => body,
    };
    (body.len() <= MAX_REPLY).then(|| (status, body.to_vec()))
}

/// The production transport: dials one gate-approved private address, re-checks the connected peer, sends `Host: <ip>:<port>`.
pub struct TcpTransport {
    connect: Box<dyn Fn() -> Option<TcpStream> + Send + Sync>,
    host_header: String,
}

impl TcpTransport {
    /// The gate runs here, before any socket. A `.local` name is resolved once and every answer must be private IPv4.
    pub fn dial(host: &str, port: u16) -> Result<Self, Fail> {
        if !port_allowed(port) {
            return Err(Fail::Refused);
        }
        let addr: SocketAddr = match classify(host).ok_or(Fail::Refused)? {
            Kind::Ip => SocketAddr::from((parse_ipv4(host).ok_or(Fail::Refused)?, port)),
            Kind::Mdns => {
                let all: Vec<SocketAddr> = (host, port).to_socket_addrs().map_err(|_| Fail::Refused)?.collect();
                if !resolved_allowed(&all) {
                    return Err(Fail::Refused);
                }
                all[0]
            }
        };
        let host_header = format!("{}:{}", addr.ip(), port);
        let connect = move || {
            let s = TcpStream::connect_timeout(&addr, Duration::from_secs(3)).ok()?;
            match s.peer_addr().ok()? {
                SocketAddr::V4(p) if is_private(p.ip().octets()) => Some(s),
                _ => None,
            }
        };
        Ok(TcpTransport { connect: Box::new(connect), host_header })
    }

    /// A connector of the caller's own, for a test that talks to a fake on loopback (which the gate rightly refuses).
    #[cfg(test)]
    pub(crate) fn with_connector(host_header: &str, connect: Box<dyn Fn() -> Option<TcpStream> + Send + Sync>) -> Self {
        TcpTransport { connect, host_header: host_header.to_string() }
    }
}

impl Transport for TcpTransport {
    fn post(&self, route: &str, ctype: &str, session_hex: Option<&str>, body: &[u8]) -> Option<(u16, Vec<u8>)> {
        let mut s = (self.connect)()?;
        http_post(&mut s, &self.host_header, route, ctype, session_hex, body)
    }
}

/// What one session-open plus one sealed request produced.
pub struct Opened {
    pub status: u16,
    pub plain: Vec<u8>,
    /// The remote machine's id when the reply sealed one. For the caller to compare with its pin and discard.
    pub machine_id: Option<Vec<u8>>,
}

/// One session-open and one sealed request/response on it. `cn` is the fresh 16 byte client nonce (the caller draws it).
/// The server's proof is checked in constant time before anything private is sent. The rotation fields of the reply
/// (`rotate_nonce`, `rotate_ct`) are not read: rotation is off on the companion.
pub fn exchange(t: &dyn Transport, c: &[u8], cn: [u8; 16], request: &[u8]) -> Result<Opened, Fail> {
    let open_req = serde_json::json!({
        "cred_id": hex(&cred_id(c)),
        "client_nonce": hex(&cn),
        "client_proof": hex(&client_proof(c, &cn)),
    });
    let (st, body) = t.post("session-open", "application/json", None, open_req.to_string().as_bytes()).ok_or(Fail::NoAnswer)?;
    if st != 200 {
        return Err(Fail::Http(st));
    }
    let v: serde_json::Value = serde_json::from_slice(&body).map_err(|_| Fail::BadReply)?;
    let field = |k: &str| v.get(k).and_then(|x| x.as_str()).and_then(unhex);
    let sid = field("session_id").filter(|b| b.len() == 16).ok_or(Fail::BadReply)?;
    let sn = field("server_nonce").filter(|b| b.len() == 16).ok_or(Fail::BadReply)?;
    let proof = field("proof").ok_or(Fail::BadReply)?;
    let keys = derive_keys(c, &cn, &sn);
    if !proof_ok(&keys.s2c, &sid, &proof) {
        return Err(Fail::BadProof);
    }
    let machine_id = match (field("machine_id_nonce"), field("machine_id_ct")) {
        (None, None) if v.get("machine_id_nonce").is_none() && v.get("machine_id_ct").is_none() => None,
        (Some(n), Some(ct)) => Some(open_machine_id(&keys.s2c, &sid, &n, &ct).ok_or(Fail::BadReply)?),
        _ => return Err(Fail::BadReply),
    };
    let counter = 1u64;
    let sealed = seal_request(&keys.c2s, &sid, counter, request)?;
    let (status, reply) = t.post("chat", "application/octet-stream", Some(&hex(&sid)), &sealed).ok_or(Fail::NoAnswer)?;
    let plain = open_response(&keys.s2c, &sid, counter, counter, &reply).map_err(|e| if status == 200 { e } else { Fail::Http(status) })?;
    Ok(Opened { status, plain, machine_id })
}

/// The `models` op: the opened body, only on a 200 whose body is a JSON object with a non-empty `models` array.
/// Everything else is None, which the caller reads as "the group is unknown". An empty list is also None: the companion
/// answers an unreachable model server with an empty list, so an empty 200 cannot be told from "no model server".
pub fn models_body(o: &Opened) -> Option<String> {
    if o.status != 200 {
        return None;
    }
    let text = std::str::from_utf8(&o.plain).ok()?;
    let v: serde_json::Value = serde_json::from_str(text).ok()?;
    (v.as_object()?.get("models")?.as_array()?.len() > 0).then(|| text.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;
    use std::sync::{Arc, Mutex};

    const VECTORS: &str = include_str!("fixtures/arrowbridge_vectors.json");

    /// A dotted quad assembled at run time: no address literal is written in this file.
    fn ip(a: u8, b: u8, c: u8, d: u8) -> String {
        format!("{a}.{b}.{c}.{d}")
    }
    fn lo() -> String {
        ip(127, 0, 0, 1)
    }

    fn vectors() -> serde_json::Value {
        serde_json::from_str(VECTORS).unwrap()
    }
    fn vh(v: &serde_json::Value, k: &str) -> Vec<u8> {
        unhex(v[k].as_str().unwrap()).unwrap()
    }

    // the Python reference's sealing side, for a fake companion and for reproducing the response stream
    fn seal_chunk(k: &[u8], sid: &[u8], ctr: u64, req: u64, idx: u32, fin: bool, plain: &[u8]) -> Vec<u8> {
        let ct = Aes256Gcm::new_from_slice(k).unwrap().encrypt(Nonce::from_slice(&gcm_nonce(&S2C, ctr)), Payload { msg: plain, aad: &resp_aad(sid, req, idx, fin) }).unwrap();
        let body = [&ctr.to_be_bytes()[..], &ct].concat();
        [&(body.len() as u32).to_be_bytes()[..], &body].concat()
    }
    fn seal_response(k: &[u8], sid: &[u8], first: u64, req: u64, plain: &[u8], size: usize) -> Vec<u8> {
        let parts: Vec<&[u8]> = if plain.is_empty() { vec![&[][..]] } else { plain.chunks(size).collect() };
        parts.iter().enumerate().flat_map(|(i, p)| seal_chunk(k, sid, first + i as u64, req, i as u32, i == parts.len() - 1, p)).collect()
    }
    fn open_request(k: &[u8], sid: &[u8], counter: u64, body: &[u8]) -> Option<Vec<u8>> {
        let aad = [&b"arrowbridge/req/v1"[..], b"POST", b"/chat", sid, &counter.to_be_bytes()].concat();
        aead_open(k, &gcm_nonce(&C2S, counter), &aad, &body[8..])
    }

    // 1. all 16 vector keys
    #[test]
    fn all_sixteen_vector_keys_are_reproduced_from_the_shared_file() {
        let v = vectors();
        let mut keys: Vec<&str> = v.as_object().unwrap().keys().map(|s| s.as_str()).collect();
        keys.sort();
        let mut want = vec!["credential", "client_nonce", "server_nonce", "session_id", "cred_id", "client_proof", "k_c2s", "k_s2c", "proof", "request_plaintext", "request_counter", "request_body", "response_plaintext", "response_chunk_size", "response_first_counter", "response_stream"];
        want.sort();
        assert_eq!(keys, want, "the file must carry exactly the 16 keys");
        let c = v["credential"].as_str().unwrap().as_bytes();
        let (cn, sn, sid) = (vh(&v, "client_nonce"), vh(&v, "server_nonce"), vh(&v, "session_id"));
        assert_eq!(hex(&cred_id(c)), v["cred_id"].as_str().unwrap(), "cred_id");
        assert_eq!(hex(&client_proof(c, &cn)), v["client_proof"].as_str().unwrap(), "client_proof");
        let k = derive_keys(c, &cn, &sn);
        assert_eq!(hex(&k.c2s), v["k_c2s"].as_str().unwrap(), "k_c2s");
        assert_eq!(hex(&k.s2c), v["k_s2c"].as_str().unwrap(), "k_s2c");
        assert_eq!(hex(&open_proof(&k.s2c, &sid)), v["proof"].as_str().unwrap(), "proof");
        let ctr = v["request_counter"].as_u64().unwrap();
        let sealed = seal_request(&k.c2s, &sid, ctr, v["request_plaintext"].as_str().unwrap().as_bytes()).unwrap();
        assert_eq!(hex(&sealed), v["request_body"].as_str().unwrap(), "request_body");
        let size = v["response_chunk_size"].as_u64().unwrap() as usize;
        let first = v["response_first_counter"].as_u64().unwrap();
        let plain = v["response_plaintext"].as_str().unwrap().as_bytes();
        assert_eq!(hex(&seal_response(&k.s2c, &sid, first, ctr, plain, size)), v["response_stream"].as_str().unwrap(), "response_stream (seal)");
        assert_eq!(open_response(&k.s2c, &sid, first, ctr, &vh(&v, "response_stream")).unwrap(), plain, "response_stream (open)");
    }

    struct Fx {
        k: Keys,
        sid: Vec<u8>,
        stream: Vec<u8>,
        ctr: u64,
        first: u64,
    }
    fn fx() -> Fx {
        let v = vectors();
        let c = v["credential"].as_str().unwrap().as_bytes().to_vec();
        let k = derive_keys(&c, &vh(&v, "client_nonce"), &vh(&v, "server_nonce"));
        Fx { k, sid: vh(&v, "session_id"), stream: vh(&v, "response_stream"), ctr: v["request_counter"].as_u64().unwrap(), first: v["response_first_counter"].as_u64().unwrap() }
    }

    // 2. the strict opener
    #[test]
    fn the_opener_refuses_a_bad_tag_empty_aad_a_wrong_counter_a_flipped_tag_and_a_bad_stream() {
        let f = fx();
        assert!(open_response(&f.k.s2c, &f.sid, f.first, f.ctr, &f.stream).is_ok(), "control: the recorded reply opens");
        // wrong session id stands for an empty or different aad
        assert!(open_response(&f.k.s2c, &[], f.first, f.ctr, &f.stream).is_err(), "empty session id in the aad");
        assert!(open_response(&f.k.s2c, &f.sid, f.first, f.ctr + 1, &f.stream).is_err(), "wrong request counter in the aad");
        assert_eq!(open_response(&f.k.s2c, &f.sid, f.first + 1, f.ctr, &f.stream), Err(Fail::Counter), "wrong first counter");
        let mut flipped = f.stream.clone();
        let last = flipped.len() - 1;
        flipped[last] ^= 1;
        assert!(open_response(&f.k.s2c, &f.sid, f.first, f.ctr, &flipped).is_err(), "flipped tag byte");
        let mut ctr_flip = f.stream.clone();
        ctr_flip[11] ^= 1; // the counter byte of the first frame
        assert!(open_response(&f.k.s2c, &f.sid, f.first, f.ctr, &ctr_flip).is_err(), "counter bytes altered");
        // a reused counter: the same chunk twice
        let n = u32::from_be_bytes([f.stream[0], f.stream[1], f.stream[2], f.stream[3]]) as usize;
        let one = &f.stream[..4 + n];
        assert!(open_response(&f.k.s2c, &f.sid, f.first, f.ctr, &[one, one].concat()).is_err(), "a replayed counter");
        // truncated: every proper prefix refused
        for cut in [1usize, 3, 4, 10, f.stream.len() - 1, 4 + n] {
            assert!(open_response(&f.k.s2c, &f.sid, f.first, f.ctr, &f.stream[..cut]).is_err(), "truncated at {cut}");
        }
        assert!(open_response(&f.k.s2c, &f.sid, f.first, f.ctr, &[]).is_err(), "empty stream is truncated");
        // data after final
        let mut after = f.stream.clone();
        after.extend_from_slice(one);
        assert_eq!(open_response(&f.k.s2c, &f.sid, f.first, f.ctr, &after), Err(Fail::AfterFinal));
        // a sealed stream whose last chunk is flagged non final and then ends
        let nonfinal = seal_chunk(&f.k.s2c, &f.sid, 1, 1, 0, false, b"x");
        assert_eq!(open_response(&f.k.s2c, &f.sid, 1, 1, &nonfinal), Err(Fail::Truncated));
        // a final flag flipped in a two chunk stream: first chunk sealed final, second after it
        let two = [seal_chunk(&f.k.s2c, &f.sid, 1, 1, 0, true, b"a"), seal_chunk(&f.k.s2c, &f.sid, 2, 1, 1, true, b"b")].concat();
        assert_eq!(open_response(&f.k.s2c, &f.sid, 1, 1, &two), Err(Fail::AfterFinal));
        // a frame shorter than counter plus tag
        assert_eq!(open_response(&f.k.s2c, &f.sid, 1, 1, &[0, 0, 0, 5, 1, 2, 3, 4, 5]), Err(Fail::BadFrame));
    }

    #[test]
    fn a_wrong_server_proof_is_refused_before_anything_is_sent() {
        let c = b"pc_proofTestCredential_0123456789abcdef";
        let sent = Arc::new(Mutex::new(Vec::<String>::new()));
        struct T(Arc<Mutex<Vec<String>>>);
        impl Transport for T {
            fn post(&self, route: &str, _: &str, _: Option<&str>, _: &[u8]) -> Option<(u16, Vec<u8>)> {
                self.0.lock().unwrap().push(route.to_string());
                (route == "session-open").then(|| (200, serde_json::json!({"session_id": hex(&[7u8; 16]), "server_nonce": hex(&[9u8; 16]), "proof": hex(&[0u8; 32])}).to_string().into_bytes()))
            }
        }
        assert_eq!(exchange(&T(sent.clone()), c, [1u8; 16], b"{}").err(), Some(Fail::BadProof));
        assert_eq!(*sent.lock().unwrap(), vec!["session-open".to_string()], "no chat request after a bad proof");
    }

    // a fake companion on loopback: session-open and sealed /chat from the Python reference's own shapes
    #[derive(Clone, Copy, PartialEq)]
    enum Mode {
        Good,
        WithRotation,
        OpStatus(u16),
        Plain401,
        EmptyList,
        OtherMachine,
        NoMachine,
    }
    struct Fake {
        port: u16,
        wire: Arc<Mutex<Vec<Vec<u8>>>>,
    }
    const MACHINE: [u8; 16] = [0x5a; 16];
    fn fake(cred: &'static [u8], mode: Mode) -> Fake {
        let l = TcpListener::bind((lo().as_str(), 0)).unwrap();
        let port = l.local_addr().unwrap().port();
        let wire = Arc::new(Mutex::new(Vec::new()));
        let w = wire.clone();
        std::thread::spawn(move || {
            let sid = [0x44u8; 16];
            let sn = [0x33u8; 16];
            let mut keys: Option<Keys> = None;
            for _ in 0..2 {
                let Ok((mut s, _)) = l.accept() else { return };
                s.set_read_timeout(Some(Duration::from_secs(5))).ok();
                let mut raw = Vec::new();
                let mut buf = [0u8; 4096];
                let (head, body) = loop {
                    let n = s.read(&mut buf).unwrap_or(0);
                    if n == 0 {
                        break (String::new(), Vec::new());
                    }
                    raw.extend_from_slice(&buf[..n]);
                    if let Some(p) = raw.windows(4).position(|x| x == b"\r\n\r\n") {
                        let head = String::from_utf8_lossy(&raw[..p]).to_string();
                        let cl: usize = head.lines().find_map(|l| l.to_ascii_lowercase().strip_prefix("content-length:").and_then(|v| v.trim().parse().ok())).unwrap_or(0);
                        if raw.len() >= p + 4 + cl {
                            break (head, raw[p + 4..p + 4 + cl].to_vec());
                        }
                    }
                };
                w.lock().unwrap().push([head.as_bytes(), b"\r\n\r\n", &body[..]].concat());
                let reply = |s: &mut TcpStream, code: u16, b: &[u8]| {
                    let _ = s.write_all(format!("HTTP/1.1 {code} X\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", b.len()).as_bytes());
                    let _ = s.write_all(b);
                };
                if head.starts_with("POST /session-open") {
                    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
                    let cn = unhex(v["client_nonce"].as_str().unwrap()).unwrap();
                    if mode == Mode::Plain401 || v["client_proof"].as_str().unwrap() != hex(&client_proof(cred, &cn)) {
                        reply(&mut s, 401, br#"{"error":"unauthorized"}"#);
                        continue;
                    }
                    let k = derive_keys(cred, &cn, &sn);
                    let mut out = serde_json::json!({"session_id": hex(&sid), "server_nonce": hex(&sn), "proof": hex(&open_proof(&k.s2c, &sid))});
                    if mode != Mode::NoMachine {
                        let mut mk = [0u8; 32];
                        hkdf(&k.s2c, None, MACHINE_ID_LABEL, &mut mk);
                        let id: &[u8] = if mode == Mode::OtherMachine { &[0x6b; 16] } else { &MACHINE };
                        let nonce = [0x21u8; 12];
                        let ct = Aes256Gcm::new_from_slice(&mk).unwrap().encrypt(Nonce::from_slice(&nonce), Payload { msg: id, aad: &[MACHINE_ID_LABEL, &sid].concat() }).unwrap();
                        out["machine_id_nonce"] = hex(&nonce).into();
                        out["machine_id_ct"] = hex(&ct).into();
                    }
                    if mode == Mode::WithRotation {
                        out["rotate_nonce"] = hex(&[1u8; 12]).into();
                        out["rotate_ct"] = hex(&[2u8; 40]).into();
                    }
                    keys = Some(k);
                    reply(&mut s, 200, out.to_string().as_bytes());
                } else if head.starts_with("POST /chat") {
                    let k = keys.as_ref().unwrap();
                    let plain = open_request(&k.c2s, &sid, 1, &body).unwrap_or_default();
                    let req: serde_json::Value = serde_json::from_slice(&plain).unwrap_or_default();
                    let (code, payload) = match (mode, req["op"].as_str()) {
                        (Mode::OpStatus(c), _) => (c, br#"{"error":"unknown op"}"#.to_vec()),
                        (Mode::EmptyList, Some("models")) => (200, br#"{"models":[]}"#.to_vec()),
                        (_, Some("models")) => (200, br#"{"models":[{"id":"default","label":"One","size_bytes":null,"quant":null,"loaded":true}]}"#.to_vec()),
                        _ => (400, br#"{"error":"unknown op"}"#.to_vec()),
                    };
                    reply(&mut s, code, &seal_response(&k.s2c, &sid, 1, 1, &payload, 1024));
                }
            }
        });
        Fake { port, wire }
    }
    fn to_fake(f: &Fake) -> TcpTransport {
        let p = f.port;
        TcpTransport::with_connector(&format!("{}:{p}", lo()), Box::new(move || TcpStream::connect((lo().as_str(), p)).ok()))
    }
    const CRED: &[u8] = b"pc_fakeCompanionCredential_0123456789ab";

    // 4. one open and one models round trip
    #[test]
    fn a_fake_companion_round_trip_returns_the_models_body_and_the_machine_id() {
        let f = fake(CRED, Mode::Good);
        let o = exchange(&to_fake(&f), CRED, [3u8; 16], br#"{"op":"models"}"#).unwrap();
        assert_eq!(o.status, 200);
        assert_eq!(o.machine_id.as_deref(), Some(&MACHINE[..]));
        let body = models_body(&o).unwrap();
        assert!(body.contains(r#""id":"default""#));
        // the request carried Host as an IP literal with the port, and no Origin
        let w = f.wire.lock().unwrap();
        let head = String::from_utf8_lossy(&w[0]).to_string();
        assert!(head.contains(&format!("Host: {}:{}\r\n", lo(), f.port)), "{head}");
        assert!(!head.to_ascii_lowercase().contains("origin:"));
    }

    // 3. nothing but the three fields, no credential on the wire, a fresh nonce per open
    #[test]
    fn session_open_carries_exactly_three_fields_and_no_credential_anywhere_on_the_wire() {
        let f = fake(CRED, Mode::Good);
        exchange(&to_fake(&f), CRED, [4u8; 16], br#"{"op":"models"}"#).unwrap();
        let w = f.wire.lock().unwrap();
        assert_eq!(w.len(), 2);
        let open_body = &w[0][w[0].windows(4).position(|x| x == b"\r\n\r\n").unwrap() + 4..];
        let v: serde_json::Value = serde_json::from_slice(open_body).unwrap();
        let mut keys: Vec<&str> = v.as_object().unwrap().keys().map(|s| s.as_str()).collect();
        keys.sort();
        assert_eq!(keys, ["client_nonce", "client_proof", "cred_id"]);
        for m in w.iter() {
            assert!(!m.windows(CRED.len()).any(|x| x == CRED), "the credential is on the wire");
            assert!(!m.windows(10).any(|x| x == b"pc_fakeCom"), "a credential prefix is on the wire");
        }
    }

    #[test]
    fn two_opens_use_two_different_random_nonces() {
        let a = random::<16>().unwrap();
        let b = random::<16>().unwrap();
        assert_ne!(a, b);
        assert_ne!(a, [0u8; 16]);
    }

    // 5. every non-answer is None, never an empty list
    #[test]
    fn a_400_401_429_503_a_refused_proof_and_an_empty_list_all_read_as_unknown() {
        for mode in [Mode::OpStatus(400), Mode::OpStatus(429), Mode::OpStatus(503), Mode::EmptyList] {
            let f = fake(CRED, mode);
            let r = exchange(&to_fake(&f), CRED, [5u8; 16], br#"{"op":"models"}"#);
            assert!(r.as_ref().map(models_body).unwrap_or(None).is_none(), "an unknown reply must be None");
        }
        let f = fake(CRED, Mode::Plain401);
        let r = exchange(&to_fake(&f), CRED, [5u8; 16], b"{}");
        assert_eq!(r.err(), Some(Fail::Http(401)));
        // a 200 with a good list is the only Some
        let f = fake(CRED, Mode::Good);
        assert!(models_body(&exchange(&to_fake(&f), CRED, [5u8; 16], br#"{"op":"models"}"#).unwrap()).is_some());
        // a body that is not an object, not JSON, or has models of the wrong type
        for bad in ["[]", "null", "not json", r#"{"models":3}"#, r#"{"models":"x"}"#, r#"{}"#] {
            let o = Opened { status: 200, plain: bad.as_bytes().to_vec(), machine_id: None };
            assert!(models_body(&o).is_none(), "{bad}");
        }
        let o = Opened { status: 429, plain: br#"{"models":[{"id":"a"}]}"#.to_vec(), machine_id: None };
        assert!(models_body(&o).is_none(), "a non 200 never passes even with a well formed body");
    }

    #[test]
    fn a_reply_carrying_rotation_fields_still_opens_and_the_fields_are_ignored() {
        let f = fake(CRED, Mode::WithRotation);
        let o = exchange(&to_fake(&f), CRED, [6u8; 16], br#"{"op":"models"}"#).unwrap();
        assert!(models_body(&o).is_some());
    }

    // 11. the transport gate
    #[test]
    fn the_address_gate_admits_private_ipv4_and_local_names_only() {
        for ok in [ip(10, 0, 0, 1), ip(10, 255, 255, 255), ip(172, 16, 0, 1), ip(172, 31, 255, 254), ip(192, 168, 1, 20), ip(169, 254, 3, 4)] {
            assert_eq!(classify(&ok), Some(Kind::Ip), "{ok}");
        }
        for ok in ["laptop.local", "a.local", "my-box.local", "ABC.LOCAL"] {
            assert_eq!(classify(ok), Some(Kind::Mdns), "{ok}");
        }
        let p = ip(10, 0, 0, 1);
        let mut bad: Vec<String> = vec![
            ip(127, 0, 0, 1), ip(0, 0, 0, 0), ip(255, 255, 255, 255), ip(224, 0, 0, 1), ip(8, 8, 8, 8), ip(1, 1, 1, 1), ip(172, 15, 0, 1), ip(172, 32, 0, 1), ip(192, 169, 0, 1),
            format!("::{}:{p}", "ffff"), format!("{p}:80"), format!("user@{p}"), format!("{p}/"), format!("{p}?x"), format!("{p}#x"), format!("{p}\\"), format!("{p}%25"),
            format!("0{p}"), format!("{}.{}.0.1", 10, "00"), format!("{}.{}.{}.{}", 10, 0, 0, "01"), format!("{}.{}.{}", 10, 0, 0), format!("{p}.1"), format!("{}.{}.{}.{}", 10, 0, 0, 256), format!("0x0a.{}.{}.{}", 0, 0, 1), "167772161".into(), format!("{}.{}.{}.", 10, 0, 0), format!(".{p}"), format!("1e1.{}.{}.{}", 0, 0, 1),
            format!(" {p}"), format!("{p} "),
        ];
        bad.push(format!("{}::{}", "fe80", 1));
        bad.push(format!("machine.{}.{}", "ts", "net"));
        bad.extend(["::1", "[::1]", "", "a.b.local", ".local", "-a.local", "a-.local", "example.com", "host", "host.local.", "host.localx", "host\u{e9}.local", "localhost"].map(String::from));
        for b in bad {
            assert_eq!(classify(&b), None, "{b:?}");
        }
        // the whole tailnet range (second octet 64 to 127), built here rather than written as literals
        for second in 64..=127u8 {
            for last in [1u8, 100, 254] {
                let a = ip(100, second, last, last);
                assert_eq!(classify(&a), None, "{a}");
            }
        }
        assert_eq!(classify(&ip(100, 63, 0, 1)), None, "just below the range is public, also refused");
        assert_eq!(classify(&ip(100, 128, 0, 1)), None, "just above the range is public, also refused");
        assert!(!port_allowed(0) && !port_allowed(80) && !port_allowed(1023) && port_allowed(1024) && port_allowed(8788) && port_allowed(65535));
    }

    #[test]
    fn dial_refuses_before_any_socket_and_a_resolved_name_must_be_all_private() {
        for h in [ip(127, 0, 0, 1), ip(8, 8, 8, 8), "::1".into(), "example.com".into(), format!("x@{}", ip(10, 0, 0, 1)), ip(100, 64, 0, 1)] {
            assert_eq!(TcpTransport::dial(&h, 8788).err(), Some(Fail::Refused), "{h}");
        }
        assert_eq!(TcpTransport::dial(&ip(10, 0, 0, 1), 80).err(), Some(Fail::Refused), "low port");
        assert!(TcpTransport::dial(&ip(10, 0, 0, 1), 8788).is_ok(), "a private literal is admitted without any socket");
        let v4 = |a: [u8; 4]| SocketAddr::from((a, 1));
        assert!(resolved_allowed(&[v4([10, 0, 0, 2]), v4([192, 168, 1, 5])]));
        assert!(!resolved_allowed(&[]));
        assert!(!resolved_allowed(&[v4([10, 0, 0, 2]), v4([8, 8, 8, 8])]), "one public answer refuses the name (rebinding)");
        assert!(!resolved_allowed(&[v4([100, 64, 0, 1])]));
        assert!(!resolved_allowed(&[SocketAddr::from(([0u16, 0, 0, 0, 0, 0, 0, 1], 1))]), "an IPv6 answer refuses the name");
    }

    #[test]
    #[ignore = "UNVERIFIED until a hotspot run: needs this machine's resolver to answer <name>.local from a real mDNS responder"]
    fn a_real_local_name_resolves_to_a_private_address_on_this_machine() {
        let n = std::env::var("ARROWMEM_TEST_LOCAL_NAME").expect("set ARROWMEM_TEST_LOCAL_NAME=<host>.local");
        assert!(TcpTransport::dial(&n, 8788).is_ok());
    }

    #[test]
    #[ignore = "UNVERIFIED until a pairing: a live remote companion over a private address, one open and one models op"]
    fn a_live_remote_companion_answers_the_models_op() {
        let host = std::env::var("ARROWMEM_TEST_REMOTE_HOST").expect("set ARROWMEM_TEST_REMOTE_HOST");
        let cred = std::env::var("ARROWMEM_TEST_REMOTE_CRED").expect("set ARROWMEM_TEST_REMOTE_CRED");
        let t = TcpTransport::dial(&host, 8788).unwrap();
        let o = exchange(&t, cred.as_bytes(), random::<16>().unwrap(), br#"{"op":"models"}"#).unwrap();
        assert!(models_body(&o).is_some());
    }

    #[test]
    #[ignore = "UNVERIFIED: whether the companion's Host check accepts a name served by the tailnet front end is a live fact; this client refuses the tailnet range"]
    fn the_tailnet_serve_name_passes_the_companions_host_check() {}
}
