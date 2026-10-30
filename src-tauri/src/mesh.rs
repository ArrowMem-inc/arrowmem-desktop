//! Loopback client for the frozen arrowmesh v1 API (openapi/arrowmesh-v1.yaml, API.md).
//! The window never sees the bearer token and never makes a network request: it asks this one command, which only
//! speaks to an IP literal that is loopback, with a Host that is that IP literal, and only for the routes listed in
//! `route_allowed`. The token is read from its mode 600 file on every call and is never logged, returned or put in an error.
//! No streaming (v0.1): one request, one reply. No retry, no proxy, no redirect.

use std::io::Read;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

// The save dialog plugin is named only here: lib.rs is grepped for the substring of its path by the no-logging guard in pairing.rs.
pub use tauri_plugin_dialog as dlg;
pub fn dlg_init() -> tauri::plugin::TauriPlugin<tauri::Wry> {
    dlg::init()
}

const BODY_MAX: usize = 1 << 20; // the daemon refuses more than 1 MiB
const REPLY_MAX: u64 = 8 << 20;

#[derive(serde::Serialize, Debug, PartialEq)]
pub struct MeshReply {
    pub status: u16,
    /// Parsed JSON body, or null when the body was empty (the Host refusal) or not JSON.
    pub body: serde_json::Value,
}

#[derive(Debug, PartialEq)]
pub struct Target {
    pub addr: SocketAddr,
    pub token_file: PathBuf,
}

fn conf_value(text: &str, key: &str) -> Option<String> {
    for raw in text.lines() {
        let line = raw.split('#').next().unwrap_or("").trim();
        if let Some((k, v)) = line.split_once('=') {
            if k.trim() == key {
                return Some(v.trim().trim_matches('"').trim().to_string());
            }
        }
    }
    None
}

/// Where the daemon listens and where its token is. Same defaults as arrowmesh's config.rs; an environment
/// override wins, then the daemon's own config file, then the defaults. Anything not a loopback IP literal is refused.
pub fn resolve(env_addr: Option<&str>, env_token: Option<&str>, conf_text: Option<&str>, home: &Path) -> Result<Target, &'static str> {
    let addr_s = env_addr.map(str::to_string).or_else(|| conf_text.and_then(|t| conf_value(t, "chat_addr"))).unwrap_or_else(|| "127.0.0.1:8088".into());
    let addr: SocketAddr = addr_s.parse().map_err(|_| "bad_address")?; // a name does not parse: IP literals only
    if !addr.ip().is_loopback() {
        return Err("not_loopback");
    }
    let token_file = env_token.map(PathBuf::from).or_else(|| conf_text.and_then(|t| conf_value(t, "token_file")).map(PathBuf::from)).unwrap_or_else(|| home.join(".local/share/arrowmesh/api-token"));
    Ok(Target { addr, token_file })
}

/// The token file must be mode 600 (nothing for group or other) and hold hex; the daemon refuses a loose file too.
pub fn read_token(path: &Path) -> Result<String, &'static str> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let md = std::fs::metadata(path).map_err(|_| "no_token")?;
        if md.permissions().mode() & 0o077 != 0 {
            return Err("token_mode");
        }
    }
    let t = std::fs::read_to_string(path).map_err(|_| "no_token")?;
    let t = t.trim();
    if t.len() < 32 || !t.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("no_token");
    }
    Ok(t.to_string())
}

fn conv_ok(s: &str) -> bool {
    !s.is_empty() && s.len() <= 32 && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// The only requests the window may make. Anything else (export, gate check, install, add peer, openapi) is refused here.
pub fn route_allowed(method: &str, path_and_query: &str) -> bool {
    let (path, query) = match path_and_query.split_once('?') {
        Some((p, q)) => (p, Some(q)),
        None => (path_and_query, None),
    };
    match (method, path, query) {
        ("GET", "/v1/status" | "/v1/vault/conversations" | "/v1/sends", None) => true,
        ("POST", "/v1/chat" | "/v1/vault/unlock" | "/v1/vault/lock" | "/v1/send", None) => true,
        ("GET", "/v1/peers", None) => true,
        ("GET", "/v1/peers", Some("probe=1")) => true,
        ("GET", "/v1/history", None) => true,
        ("GET", "/v1/history", Some(q)) => q.strip_prefix("conv=").is_some_and(conv_ok),
        ("GET", p, None) => p.strip_prefix("/v1/chat/jobs/").is_some_and(|n| !n.is_empty() && n.len() <= 12 && n.bytes().all(|b| b.is_ascii_digit())),
        _ => false,
    }
}

pub fn call(t: &Target, method: &str, path: &str, body: Option<&serde_json::Value>) -> Result<MeshReply, &'static str> {
    if !route_allowed(method, path) {
        return Err("bad_route");
    }
    let payload = match body {
        Some(b) => Some(serde_json::to_vec(b).map_err(|_| "bad_body")?),
        None => None,
    };
    if payload.as_ref().is_some_and(|p| p.len() > BODY_MAX) || (method == "POST") != payload.is_some() {
        return Err("bad_body");
    }
    let (status, buf) = send(t, method, path, payload)?;
    let body = serde_json::from_slice(&buf).unwrap_or(serde_json::Value::Null);
    Ok(MeshReply { status, body })
}

/// The one route whose reply is sealed ciphertext. It is NOT in `route_allowed`, so the window's `mesh_call` can never fetch it;
/// only the Rust export command (after a native save dialog) reaches it, and the bytes go to a file, never to the window.
pub const EXPORT_PATH: &str = "/v1/vault/export";

pub fn export_allowed(method: &str, path_and_query: &str) -> bool {
    method == "GET" && path_and_query == EXPORT_PATH
}

/// GET the sealed export. Returns the status and the raw bytes (not parsed, not logged).
pub fn call_export(t: &Target) -> Result<(u16, Vec<u8>), &'static str> {
    if !export_allowed("GET", EXPORT_PATH) {
        return Err("bad_route");
    }
    send(t, "GET", EXPORT_PATH, None)
}

fn send(t: &Target, method: &str, path: &str, payload: Option<Vec<u8>>) -> Result<(u16, Vec<u8>), &'static str> {
    let token = read_token(&t.token_file)?;
    // ureq sets Host from the URL, and the URL holds the IP literal and port: never a name.
    let url = format!("http://{}{}", t.addr, path);
    let agent = ureq::AgentBuilder::new().redirects(0).timeout(Duration::from_secs(20)).build();
    let req = agent.request(method, &url).set("Authorization", &format!("Bearer {token}"));
    let res = match payload {
        Some(p) => req.set("Content-Type", "application/json").send_bytes(&p),
        None => req.call(),
    };
    let resp = match res {
        Ok(r) => r,
        Err(ureq::Error::Status(_, r)) => r,
        Err(_) => return Err("unreachable"),
    };
    let status = resp.status();
    let mut buf = Vec::new();
    resp.into_reader().take(REPLY_MAX).read_to_end(&mut buf).map_err(|_| "unreachable")?;
    Ok((status, buf))
}

/// Placeholder file name offered by the save dialog: only a date, no content, no user data.
pub fn export_filename(y: i32, m: u32, d: u32) -> String {
    format!("vault-export-{y:04}-{m:02}-{d:02}.sealed")
}

/// UTC calendar date from unix seconds (days-from-civil, Hinnant), so no date crate is needed.
pub fn civil_from_unix(secs: u64) -> (i32, u32, u32) {
    let z = (secs / 86400) as i64 + 719468;
    let era = z.div_euclid(146097);
    let doe = z.rem_euclid(146097);
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let y = (yoe + era * 400) as i32 + if m <= 2 { 1 } else { 0 };
    (y, m, d)
}

/// Write the bytes to the chosen path, owner only. Nothing else is written.
pub fn write_export(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    let mut o = std::fs::OpenOptions::new();
    o.write(true).create(true).truncate(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut o, 0o600);
    let mut f = o.open(path)?;
    f.write_all(bytes)?;
    f.sync_all()
}

pub fn target_from_env() -> Result<Target, &'static str> {
    let home = std::env::var("HOME").map_err(|_| "no_home")?;
    let conf = std::fs::read_to_string(Path::new(&home).join(".config/arrowmesh/config")).ok();
    resolve(std::env::var("ARROWMESH_CHAT_ADDR").ok().as_deref(), std::env::var("ARROWMESH_API_TOKEN_FILE").ok().as_deref(), conf.as_deref(), Path::new(&home))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::net::TcpListener;

    #[test]
    fn only_the_wired_routes_pass() {
        for (m, p) in [("GET", "/v1/status"), ("GET", "/v1/peers?probe=1"), ("GET", "/v1/history?conv=default"), ("GET", "/v1/chat/jobs/12"), ("POST", "/v1/chat"), ("POST", "/v1/vault/unlock"), ("POST", "/v1/vault/lock"), ("POST", "/v1/send"), ("GET", "/v1/sends"), ("GET", "/v1/vault/conversations")] {
            assert!(route_allowed(m, p), "{m} {p}");
        }
        for (m, p) in [("GET", "/v1/vault/export"), ("POST", "/v1/peers"), ("POST", "/v1/gate/check"), ("GET", "/v1/install"), ("GET", "/v1/openapi.yaml"), ("GET", "/v1/history?conv=../x"), ("GET", "/v1/history?conv="), ("GET", "/v1/chat/jobs/1a"), ("GET", "/v1/chat/jobs/"), ("GET", "/v1/status?x=1"), ("DELETE", "/v1/status"), ("GET", "/v1/peers?probe=2"), ("GET", "http://evil/v1/status"), ("GET", "/v1/status/../peers")] {
            assert!(!route_allowed(m, p), "{m} {p}");
        }
    }

    #[test]
    fn address_must_be_a_loopback_ip_literal() {
        let h = Path::new("/h");
        assert_eq!(resolve(None, None, None, h).unwrap().addr.to_string(), "127.0.0.1:8088");
        assert_eq!(resolve(Some("localhost:8088"), None, None, h), Err("bad_address"));
        assert_eq!(resolve(Some("192.168.1.2:8088"), None, None, h), Err("not_loopback"));
        assert_eq!(resolve(Some("0.0.0.0:8088"), None, None, h), Err("not_loopback"));
        let t = resolve(None, None, Some("chat_addr = 127.0.0.1:9999 # x\ntoken_file = /t/api-token\n"), h).unwrap();
        assert_eq!((t.addr.port(), t.token_file), (9999, PathBuf::from("/t/api-token")));
        assert_eq!(resolve(None, None, None, h).unwrap().token_file, PathBuf::from("/h/.local/share/arrowmesh/api-token"));
    }

    #[test]
    fn token_file_mode_and_shape() {
        use std::os::unix::fs::PermissionsExt;
        let d = std::env::temp_dir().join(format!("mesh-tok-{}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        let p = d.join("api-token");
        std::fs::write(&p, "ab".repeat(32)).unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert_eq!(read_token(&p), Err("token_mode"));
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(read_token(&p).unwrap().len(), 64);
        std::fs::write(&p, "zz").unwrap();
        assert_eq!(read_token(&p), Err("no_token"));
        assert_eq!(read_token(&d.join("none")), Err("no_token"));
        std::fs::remove_dir_all(&d).ok();
    }

    /// One request against a throwaway loopback server: the Host is the IP literal, the bearer is sent, the body arrives, a 401 is data not an error.
    #[test]
    fn request_carries_ip_host_and_bearer_and_errors_are_replies() {
        use std::os::unix::fs::PermissionsExt;
        let d = std::env::temp_dir().join(format!("mesh-req-{}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        let tf = d.join("api-token");
        std::fs::write(&tf, "cd".repeat(32)).unwrap();
        std::fs::set_permissions(&tf, std::fs::Permissions::from_mode(0o600)).unwrap();
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap();
        let h = std::thread::spawn(move || {
            let mut seen = Vec::new();
            for reply in ["HTTP/1.1 401 Unauthorized\r\nContent-Length: 24\r\nContent-Type: application/json\r\n\r\n{\"error\":\"unauthorized\"}", "HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n"] {
                let (mut s, _) = l.accept().unwrap();
                let mut got = Vec::new();
                let mut b = [0u8; 4096];
                // headers and body may arrive in separate reads: read until the head is complete and the declared body is in
                loop {
                    let n = s.read(&mut b).unwrap();
                    got.extend_from_slice(&b[..n]);
                    let txt = String::from_utf8_lossy(&got).to_string();
                    if let Some(i) = txt.find("\r\n\r\n") {
                        let cl = txt.to_lowercase().split("content-length:").nth(1).and_then(|r| r.trim_start().split("\r\n").next().and_then(|v| v.trim().parse::<usize>().ok())).unwrap_or(0);
                        if got.len() >= i + 4 + cl { break; }
                    }
                    if n == 0 { break; }
                }
                seen.push(String::from_utf8_lossy(&got).to_string());
                s.write_all(reply.as_bytes()).unwrap();
            }
            seen
        });
        let t = Target { addr, token_file: tf };
        let r = call(&t, "POST", "/v1/vault/unlock", Some(&serde_json::json!({"passphrase": "x"}))).unwrap();
        assert_eq!((r.status, r.body["error"].as_str()), (401, Some("unauthorized")));
        let r2 = call(&t, "GET", "/v1/status", None).unwrap();
        assert_eq!((r2.status, r2.body), (403, serde_json::Value::Null));
        let seen = h.join().unwrap();
        assert!(seen[0].contains(&format!("Host: {addr}\r\n")) || seen[0].to_lowercase().contains(&format!("host: {addr}\r\n")), "{}", seen[0]);
        assert!(seen[0].to_lowercase().contains(&format!("authorization: bearer {}", "cd".repeat(32))));
        assert!(seen[0].contains("{\"passphrase\":\"x\"}"));
        assert_eq!(call(&t, "GET", "/v1/vault/export", None), Err("bad_route")); // mesh_call still cannot fetch ciphertext
        assert_eq!(call(&t, "POST", "/v1/chat", None), Err("bad_body"));
        std::fs::remove_dir_all(&d).ok();
    }

    #[test]
    fn nothing_listening_is_unreachable() {
        use std::os::unix::fs::PermissionsExt;
        let d = std::env::temp_dir().join(format!("mesh-dead-{}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        let tf = d.join("api-token");
        std::fs::write(&tf, "ef".repeat(32)).unwrap();
        std::fs::set_permissions(&tf, std::fs::Permissions::from_mode(0o600)).unwrap();
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap();
        drop(l);
        assert_eq!(call(&Target { addr, token_file: tf }, "GET", "/v1/status", None), Err("unreachable"));
        std::fs::remove_dir_all(&d).ok();
    }

    #[test]
    fn export_route_is_one_exact_get_and_not_in_the_window_allowlist() {
        assert!(export_allowed("GET", "/v1/vault/export"));
        for (m, p) in [("POST", "/v1/vault/export"), ("GET", "/v1/vault/export?x=1"), ("GET", "/v1/vault/export/"), ("GET", "/v1/vault/exports"), ("GET", "http://evil/v1/vault/export"), ("DELETE", "/v1/vault/export")] {
            assert!(!export_allowed(m, p), "{m} {p}");
        }
        assert!(!route_allowed("GET", "/v1/vault/export"));
        assert_eq!(civil_from_unix(0), (1970, 1, 1));
        assert_eq!(civil_from_unix(1_782_777_600), (2026, 6, 30));
        assert_eq!(civil_from_unix(1_709_164_800), (2024, 2, 29));
        assert_eq!(export_filename(2026, 3, 9), "vault-export-2026-03-09.sealed");
    }

    /// Export against a throwaway daemon: 200 gives the raw bytes (non UTF-8 kept) and they land in a 0600 file; 423 is a status with no body.
    #[test]
    fn export_returns_raw_bytes_and_423_is_a_status() {
        use std::os::unix::fs::PermissionsExt;
        let d = std::env::temp_dir().join(format!("mesh-exp-{}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        let tf = d.join("api-token");
        std::fs::write(&tf, "ef".repeat(32)).unwrap();
        std::fs::set_permissions(&tf, std::fs::Permissions::from_mode(0o600)).unwrap();
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap();
        let cipher: Vec<u8> = vec![0, 255, 1, 254, 128, 10, 13, 0];
        let c2 = cipher.clone();
        let h = std::thread::spawn(move || {
            for i in 0..2 {
                let (mut s, _) = l.accept().unwrap();
                let mut b = [0u8; 4096];
                let n = s.read(&mut b).unwrap();
                assert!(String::from_utf8_lossy(&b[..n]).starts_with("GET /v1/vault/export HTTP/1.1"));
                if i == 0 {
                    s.write_all(format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\nContent-Type: application/octet-stream\r\n\r\n", c2.len()).as_bytes()).unwrap();
                    s.write_all(&c2).unwrap();
                } else {
                    s.write_all(b"HTTP/1.1 423 Locked\r\nContent-Length: 0\r\n\r\n").unwrap();
                }
            }
        });
        let t = Target { addr, token_file: tf };
        let (st, bytes) = call_export(&t).unwrap();
        assert_eq!((st, bytes.clone()), (200, cipher.clone()));
        let out = d.join("out.sealed");
        write_export(&out, &bytes).unwrap();
        assert_eq!(std::fs::read(&out).unwrap(), cipher);
        assert_eq!(std::fs::metadata(&out).unwrap().permissions().mode() & 0o777, 0o600);
        let (st2, b2) = call_export(&t).unwrap();
        assert_eq!((st2, b2.len()), (423, 0));
        h.join().unwrap();
        std::fs::remove_dir_all(&d).ok();
    }
}
