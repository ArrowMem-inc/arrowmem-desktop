//! The owner routes of the bridge: the one loopback listener a bar panel on this computer may talk to.
//! std only (hand written HTTP, three routes), bound to 127.0.0.1, nothing written to disk, nothing logged.
//!
//!   GET  /v1/models   rows {id,label,loaded,host}; host is exactly "local" or "remote"
//!   POST /v1/pause    {"model":"<listed id>"}  ->  {"state":"paused"} | {"state":"free"} | {"state":"unknown"}
//!   POST /v1/resume   {}                       ->  {"state":"free"} | {"state":"unknown"}
//!
//! Every request: Host must be 127.0.0.1:<port> or localhost:<port> (DNS rebinding); an Origin header of any
//! value is refused (cross origin); no CORS header is ever sent; X-ArrowBridge-Owner: 1 is required. Each route
//! admits one request per MIN_GAP. A pause is lifted by itself after AUTO_RESUME.
//! The llama key is read by `Upstream` for one request to the router and appears in no reply. A reply row
//! carries no machine name: a machine is mapped onto the two words and nothing else is copied from its listing.
//!
//! The router listing parse mirrors `crates/arrowbridge/src/picker.rs` (parse_listing, id_ok, parse_pause_reply):
//! the desktop crate does not depend on that crate, and a path dependency would change this Cargo.lock.
use serde_json::{json, Value};
use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

pub const DEFAULT_PORT: u16 = 8789;
pub const MAX_ROWS: usize = 64;
pub const MAX_LABEL: usize = 200;
/// One request per route per this long.
pub const MIN_GAP: Duration = Duration::from_secs(2);
/// A pause held by this listener is lifted after this long.
pub const AUTO_RESUME: Duration = Duration::from_secs(600);
const MAX_HEAD: usize = 8 * 1024;
const MAX_BODY: usize = 1024;
const REQUEST_DEADLINE: Duration = Duration::from_secs(3);
const UPSTREAM_DEADLINE: Duration = Duration::from_secs(4);
const MAX_UPSTREAM_REPLY: u64 = 64 * 1024;
const MAX_CONNS: usize = 8;
const OWNER_HEADER: &str = "x-arrowbridge-owner";

/// The port from the app config (the environment, like `ARROWMEM_COMPANION_PORT`). Unset, malformed or below 1024: the default.
pub fn owner_port(env: Option<&str>) -> u16 {
    env.and_then(|v| v.trim().parse::<u16>().ok()).filter(|p| *p >= 1024).unwrap_or(DEFAULT_PORT)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Host {
    Local,
    Remote,
}
impl Host {
    pub fn word(self) -> &'static str {
        match self {
            Host::Local => "local",
            Host::Remote => "remote",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Row {
    pub id: String,
    pub label: String,
    pub loaded: Option<bool>,
    pub host: Host,
}

/// A body that is not what the contract says. One value for every way to be wrong.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Unreadable;

fn id_ok(s: &str) -> bool {
    !s.is_empty() && s.len() <= MAX_LABEL && !s.chars().any(|c| c.is_control())
}
fn label_ok(s: &str) -> bool {
    !s.is_empty() && s.chars().count() <= MAX_LABEL && !s.chars().any(|c| c.is_control())
}

/// The router listing `{"data":[{"id","status":{"value":"loaded"}}]}`. The router has no label: the label is the id.
/// A single entry with no status is read as loaded. More than 64, empty, a duplicate id, a bad id: Unreadable.
pub fn parse_local(body: &str) -> Result<Vec<Row>, Unreadable> {
    let v: Value = serde_json::from_str(body).map_err(|_| Unreadable)?;
    let data = v.get("data").and_then(Value::as_array).ok_or(Unreadable)?;
    if data.is_empty() || data.len() > MAX_ROWS {
        return Err(Unreadable);
    }
    let mut out: Vec<Row> = Vec::with_capacity(data.len());
    for e in data {
        let id = e.get("id").and_then(Value::as_str).filter(|s| id_ok(s)).ok_or(Unreadable)?;
        if out.iter().any(|m| m.id == id) {
            return Err(Unreadable);
        }
        let loaded = match e.get("status").and_then(|s| s.get("value")).and_then(Value::as_str) {
            Some(s) => Some(s == "loaded"),
            None if data.len() == 1 => Some(true),
            None => None,
        };
        out.push(Row { id: id.into(), label: id.into(), loaded, host: Host::Local });
    }
    Ok(out)
}

/// The sealed `models` op `{"models":[{"id","label","size_bytes","quant","loaded"}]}`. Only id, label and loaded are read;
/// every other field (a machine name included) is dropped. `loaded` true, false or null.
pub fn parse_remote(body: &str) -> Result<Vec<Row>, Unreadable> {
    let v: Value = serde_json::from_str(body).map_err(|_| Unreadable)?;
    let data = v.get("models").and_then(Value::as_array).ok_or(Unreadable)?;
    if data.is_empty() || data.len() > MAX_ROWS {
        return Err(Unreadable);
    }
    let mut out: Vec<Row> = Vec::with_capacity(data.len());
    for e in data {
        let id = e.get("id").and_then(Value::as_str).filter(|s| id_ok(s)).ok_or(Unreadable)?;
        if out.iter().any(|m| m.id == id) {
            return Err(Unreadable);
        }
        let label = match e.get("label") {
            None | Some(Value::Null) => id,
            Some(l) => l.as_str().filter(|s| label_ok(s)).ok_or(Unreadable)?,
        };
        let loaded = match e.get("loaded") {
            Some(Value::Bool(b)) => Some(*b),
            None | Some(Value::Null) => None,
            _ => return Err(Unreadable),
        };
        out.push(Row { id: id.into(), label: label.into(), loaded, host: Host::Remote });
    }
    Ok(out)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    Paused,
    Free,
}
/// `{"state":"paused"}` or `{"state":"free"}`, as picker.rs `parse_pause_reply`; anything else is Unreadable.
fn parse_state(body: &str) -> Result<State, Unreadable> {
    let v: Value = serde_json::from_str(body).map_err(|_| Unreadable)?;
    match v.get("state").and_then(Value::as_str) {
        Some("paused") => Ok(State::Paused),
        Some("free") => Ok(State::Free),
        _ => Err(Unreadable),
    }
}

/// Where the data comes from. Each call returns the raw body or None (no answer, not 200, too big, too slow).
pub trait Upstream: Send + Sync {
    /// The home router's `GET /v1/models` body.
    fn local_listing(&self) -> Option<String>;
    /// The remote machine's `models` op body.
    fn remote_listing(&self) -> Option<String>;
    /// The coder side: the body is `{"action":"pause","model":"<id>"}` or `{"action":"resume"}`.
    fn coder(&self, body: &str) -> Option<String>;
}

/// One HTTP/1.1 call to a loopback port. Never sends Origin. The reply is read to at most 64 KiB and within `deadline`
/// in all (each read's timeout is the time left, so a trickling server cannot hold the caller). Not 200: None.
pub fn http_call(port: u16, method: &str, path: &str, extra: &str, body: &str, deadline: Duration) -> Option<String> {
    let start = Instant::now();
    let mut s = TcpStream::connect_timeout(&SocketAddr::from(([127, 0, 0, 1], port)), deadline.min(Duration::from_secs(2))).ok()?;
    s.set_write_timeout(Some(Duration::from_secs(2))).ok()?;
    let post = if method == "POST" { format!("X-ArrowBridge-Owner: 1\r\nContent-Type: application/json\r\nContent-Length: {}\r\n", body.len()) } else { String::new() };
    s.write_all(format!("{method} {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n{post}{extra}Connection: close\r\n\r\n{body}").as_bytes()).ok()?;
    let mut raw: Vec<u8> = Vec::new();
    let mut limited = (&mut s).take(MAX_UPSTREAM_REPLY + 1);
    let mut chunk = [0u8; 4096];
    loop {
        let left = deadline.checked_sub(start.elapsed())?;
        limited.get_ref().set_read_timeout(Some(left.max(Duration::from_millis(1)))).ok()?;
        match limited.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => raw.extend_from_slice(&chunk[..n]),
            Err(_) => return None,
        }
        if raw.len() as u64 > MAX_UPSTREAM_REPLY {
            return None;
        }
    }
    let raw = String::from_utf8(raw).ok()?;
    let status: u16 = raw.lines().next()?.split_whitespace().nth(1)?.parse().ok()?;
    if status != 200 {
        return None;
    }
    Some(raw.split_once("\r\n\r\n")?.1.to_string())
}

/// The desktop's own sources. The router needs the llama key (read per call, sent only in that one request).
/// There is no remote source in this process (no sealed channel is held here) and the coder pause service is not
/// built (picker.rs: "a separate service, not built here"): both answer None, which every route reads as unknown.
pub struct DesktopUpstream {
    pub llama_port: u16,
    pub key: Box<dyn Fn() -> Option<String> + Send + Sync>,
}
impl Upstream for DesktopUpstream {
    fn local_listing(&self) -> Option<String> {
        let auth = match (self.key)() {
            Some(k) if !k.is_empty() && !k.chars().any(|c| c.is_control()) => format!("Authorization: Bearer {k}\r\n"),
            Some(_) => return None,
            None => String::new(),
        };
        http_call(self.llama_port, "GET", "/v1/models", &auth, "", UPSTREAM_DEADLINE)
    }
    fn remote_listing(&self) -> Option<String> {
        None
    }
    fn coder(&self, _body: &str) -> Option<String> {
        None
    }
}

#[derive(Default)]
struct Gate {
    last: [Option<Instant>; 3],
    /// When a pause this listener made must be lifted.
    paused_until: Option<Instant>,
    retry_at: Option<Instant>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Route {
    Models = 0,
    Pause = 1,
    Resume = 2,
}

pub struct Owner<U: Upstream> {
    up: U,
    port: u16,
    gate: Mutex<Gate>,
}

type Reply = (u16, String);
fn err(code: u16, word: &str) -> Reply {
    (code, json!({ "error": word }).to_string())
}
fn state_reply(s: Option<State>) -> Reply {
    match s {
        Some(State::Paused) => (200, r#"{"state":"paused"}"#.into()),
        Some(State::Free) => (200, r#"{"state":"free"}"#.into()),
        None => (502, r#"{"state":"unknown"}"#.into()),
    }
}

impl<U: Upstream> Owner<U> {
    pub fn new(up: U, port: u16) -> Self {
        Owner { up, port, gate: Mutex::new(Gate::default()) }
    }

    /// A group that cannot be read is named in `unknown` and contributes no rows (never a guess, never kept stale).
    fn listing(&self) -> (Vec<Row>, Vec<Host>) {
        let mut rows = Vec::new();
        let mut unknown = Vec::new();
        match self.up.local_listing().as_deref().map(parse_local) {
            Some(Ok(r)) => rows.extend(r),
            _ => unknown.push(Host::Local),
        }
        match self.up.remote_listing().as_deref().map(parse_remote) {
            Some(Ok(r)) => rows.extend(r),
            _ => unknown.push(Host::Remote),
        }
        (rows, unknown)
    }

    /// One request, already read: the head text (request line and headers, no blank line) and the body.
    pub fn handle(&self, head: &str, body: &[u8], now: Instant) -> Reply {
        let mut lines = head.split("\r\n");
        let mut rl = lines.next().unwrap_or("").split(' ');
        let (method, path, ver) = (rl.next().unwrap_or(""), rl.next().unwrap_or(""), rl.next().unwrap_or(""));
        if method.is_empty() || !path.starts_with('/') || !(ver == "HTTP/1.1" || ver == "HTTP/1.0") || rl.next().is_some() {
            return err(400, "bad_request");
        }
        let mut hdr: Vec<(String, String)> = Vec::new();
        for l in lines {
            match l.split_once(':') {
                Some((n, v)) if !n.is_empty() && !n.starts_with([' ', '\t']) && !n.ends_with([' ', '\t']) => hdr.push((n.to_ascii_lowercase(), v.trim().to_string())),
                _ => return err(400, "bad_request"),
            }
        }
        fn pick<'a>(hdr: &'a [(String, String)], n: &'a str) -> impl Iterator<Item = &'a str> {
            hdr.iter().filter(move |(k, _)| k == n).map(|(_, v)| v.as_str())
        }
        let all = |n: &'static str| pick(&hdr, n);
        // 1. DNS rebinding: exactly one Host, an IP literal or localhost, with this port.
        let hosts: Vec<&str> = all("host").collect();
        let (a, b) = (format!("127.0.0.1:{}", self.port), format!("localhost:{}", self.port));
        if hosts.len() != 1 || !(hosts[0].eq_ignore_ascii_case(&a) || hosts[0].eq_ignore_ascii_case(&b)) {
            return err(403, "forbidden");
        }
        // 2. Cross origin: a browser sends Origin on a cross origin POST. Present, of any value, is refused.
        if all("origin").next().is_some() {
            return err(403, "forbidden");
        }
        let route = match (method, path) {
            ("GET", "/v1/models") => Route::Models,
            ("POST", "/v1/pause") => Route::Pause,
            ("POST", "/v1/resume") => Route::Resume,
            (_, "/v1/models" | "/v1/pause" | "/v1/resume") => return err(405, "method"),
            _ => return err(404, "not_found"),
        };
        // 3. The owner header (a browser simple request cannot set it).
        if all(OWNER_HEADER).count() != 1 || all(OWNER_HEADER).next() != Some("1") {
            return err(403, "forbidden");
        }
        if route != Route::Models {
            if all("transfer-encoding").next().is_some() {
                return err(400, "bad_request");
            }
            let cl: Vec<&str> = all("content-length").collect();
            if cl.len() != 1 || cl[0].parse::<usize>().ok() != Some(body.len()) {
                return err(400, "bad_request");
            }
            if body.len() > MAX_BODY {
                return err(413, "too_large");
            }
            if all("content-type").next().map(|c| c.split(';').next().unwrap_or("").trim().to_ascii_lowercase()).as_deref() != Some("application/json") {
                return err(415, "media_type");
            }
        }
        // 4. Rate limit, per route, only for a request that passed every gate above.
        {
            let mut g = self.gate.lock().unwrap();
            let slot = &mut g.last[route as usize];
            if slot.is_some_and(|t| now.saturating_duration_since(t) < MIN_GAP) {
                return err(429, "rate");
            }
            *slot = Some(now);
        }
        match route {
            Route::Models => {
                let (rows, unknown) = self.listing();
                let rows: Vec<Value> = rows.iter().map(|r| json!({"id": r.id, "label": r.label, "loaded": r.loaded, "host": r.host.word()})).collect();
                let unknown: Vec<&str> = unknown.iter().map(|h| h.word()).collect();
                (200, json!({"models": rows, "unknown": unknown}).to_string())
            }
            Route::Pause => self.pause(body, now),
            Route::Resume => self.resume(),
        }
    }

    fn pause(&self, body: &[u8], now: Instant) -> Reply {
        let model = std::str::from_utf8(body).ok().and_then(|b| serde_json::from_str::<Value>(b).ok()).and_then(|v| v.get("model").and_then(Value::as_str).map(str::to_string));
        let Some(model) = model.filter(|m| id_ok(m)) else { return err(400, "bad_request") };
        let (rows, unknown) = self.listing();
        if rows.is_empty() && !unknown.is_empty() {
            // The listing cannot be read, so the id cannot be checked: nothing is sent.
            return state_reply(None);
        }
        if !rows.iter().any(|r| r.id == model) {
            return err(400, "not_listed");
        }
        let reply = self.up.coder(&json!({"action": "pause", "model": model}).to_string()).as_deref().map(parse_state).and_then(Result::ok);
        let mut g = self.gate.lock().unwrap();
        match reply {
            Some(State::Paused) => {
                g.paused_until = Some(now + AUTO_RESUME);
                g.retry_at = None;
            }
            Some(State::Free) => g.paused_until = None,
            None => {}
        }
        state_reply(reply)
    }

    fn resume(&self) -> Reply {
        let reply = self.up.coder(r#"{"action":"resume"}"#).as_deref().map(parse_state).and_then(Result::ok).filter(|s| *s == State::Free);
        if reply.is_some() {
            self.gate.lock().unwrap().paused_until = None;
        }
        state_reply(reply)
    }

    /// The auto resume. Called often by the listener loop. A due resume that the coder does not confirm is retried every MIN_GAP.
    pub fn tick(&self, now: Instant) {
        {
            let g = self.gate.lock().unwrap();
            let due = g.paused_until.is_some_and(|t| now >= t);
            if !due || g.retry_at.is_some_and(|t| now < t) {
                return;
            }
        }
        let ok = self.up.coder(r#"{"action":"resume"}"#).as_deref().map(parse_state).and_then(Result::ok) == Some(State::Free);
        let mut g = self.gate.lock().unwrap();
        if ok {
            g.paused_until = None;
            g.retry_at = None;
        } else {
            g.retry_at = Some(now + MIN_GAP);
        }
    }

    pub fn is_held(&self) -> bool {
        self.gate.lock().unwrap().paused_until.is_some()
    }
}

fn reason(code: u16) -> &'static str {
    match code {
        200 => "OK",
        400 => "Bad Request",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        413 => "Payload Too Large",
        415 => "Unsupported Media Type",
        429 => "Too Many Requests",
        _ => "Bad Gateway",
    }
}

/// Reads one request: the head to the blank line (8 KiB at most) and a body of Content-Length (1 KiB at most), all within REQUEST_DEADLINE.
fn read_request(s: &mut TcpStream) -> Option<(String, Vec<u8>)> {
    let start = Instant::now();
    let mut buf: Vec<u8> = Vec::new();
    let mut chunk = [0u8; 1024];
    let end = loop {
        if let Some(p) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break p;
        }
        if buf.len() > MAX_HEAD {
            return None;
        }
        let left = REQUEST_DEADLINE.checked_sub(start.elapsed())?;
        s.set_read_timeout(Some(left.max(Duration::from_millis(1)))).ok()?;
        match s.read(&mut chunk) {
            Ok(0) | Err(_) => return None,
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
        }
    };
    let head = String::from_utf8(buf[..end].to_vec()).ok()?;
    let mut body = buf[end + 4..].to_vec();
    let want = head.split("\r\n").skip(1).filter_map(|l| l.split_once(':')).find(|(n, _)| n.eq_ignore_ascii_case("content-length")).and_then(|(_, v)| v.trim().parse::<usize>().ok()).unwrap_or(0);
    // More than the cap is not read: the handler answers 413 from the length it sees.
    while body.len() < want.min(MAX_BODY + 1) {
        let left = REQUEST_DEADLINE.checked_sub(start.elapsed())?;
        s.set_read_timeout(Some(left.max(Duration::from_millis(1)))).ok()?;
        match s.read(&mut chunk) {
            Ok(0) | Err(_) => return None,
            Ok(n) => body.extend_from_slice(&chunk[..n]),
        }
    }
    Some((head, body))
}

fn serve_one<U: Upstream>(o: &Owner<U>, mut s: TcpStream) {
    let (code, body) = match read_request(&mut s) {
        Some((head, body)) => o.handle(&head, &body, Instant::now()),
        None => err(400, "bad_request"),
    };
    // No CORS header, ever. No cache. Connection closes.
    let _ = s.set_write_timeout(Some(Duration::from_secs(2)));
    let _ = s.write_all(format!("HTTP/1.1 {code} {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nCache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\nConnection: close\r\n\r\n{body}", reason(code), body.len()).as_bytes());
}

pub struct Running {
    pub addr: SocketAddr,
    stop: Arc<AtomicBool>,
}
impl Running {
    pub fn stop(&self) {
        self.stop.store(true, Ordering::SeqCst);
    }
}

/// Binds 127.0.0.1:`port` (0 for any free port) and serves on a thread of its own. At most MAX_CONNS requests at once; the rest are dropped.
pub fn start<U: Upstream + 'static>(port: u16, up: U) -> std::io::Result<Running> {
    let l = TcpListener::bind((Ipv4Addr::LOCALHOST, port))?;
    l.set_nonblocking(true)?;
    let addr = l.local_addr()?;
    let o = Arc::new(Owner::new(up, addr.port()));
    let stop = Arc::new(AtomicBool::new(false));
    let (stop2, live) = (stop.clone(), Arc::new(AtomicUsize::new(0)));
    std::thread::spawn(move || {
        while !stop2.load(Ordering::SeqCst) {
            o.tick(Instant::now());
            match l.accept() {
                Ok((s, _)) => {
                    if live.fetch_add(1, Ordering::SeqCst) >= MAX_CONNS {
                        live.fetch_sub(1, Ordering::SeqCst);
                        continue;
                    }
                    let (o, live) = (o.clone(), live.clone());
                    std::thread::spawn(move || {
                        let _ = s.set_nonblocking(false);
                        serve_one(&o, s);
                        live.fetch_sub(1, Ordering::SeqCst);
                    });
                }
                Err(_) => std::thread::sleep(Duration::from_millis(100)),
            }
        }
    });
    Ok(Running { addr, stop })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;

    const ROUTER: &str = include_str!("fixtures/router_models.json");
    const REMOTE: &str = include_str!("fixtures/remote_models.json");
    const KEY: &str = "sk-test-llama-key-0123456789";

    #[derive(Default)]
    struct Fake {
        local: Option<String>,
        remote: Option<String>,
        coder: Mutex<VecDeque<Option<String>>>,
        posts: Mutex<Vec<String>>,
    }
    impl Upstream for Arc<Fake> {
        fn local_listing(&self) -> Option<String> {
            self.local.clone()
        }
        fn remote_listing(&self) -> Option<String> {
            self.remote.clone()
        }
        fn coder(&self, body: &str) -> Option<String> {
            self.posts.lock().unwrap().push(body.to_string());
            self.coder.lock().unwrap().pop_front().unwrap_or(None)
        }
    }
    fn fake(local: Option<&str>, remote: Option<&str>, coder: &[Option<&str>]) -> Arc<Fake> {
        Arc::new(Fake { local: local.map(Into::into), remote: remote.map(Into::into), coder: Mutex::new(coder.iter().map(|c| c.map(Into::into)).collect()), posts: Mutex::new(vec![]) })
    }
    const P: u16 = 8789;
    fn owner(f: &Arc<Fake>) -> Owner<Arc<Fake>> {
        Owner::new(f.clone(), P)
    }
    fn get(path: &str, extra: &str) -> String {
        format!("GET {path} HTTP/1.1\r\nHost: 127.0.0.1:{P}\r\nX-ArrowBridge-Owner: 1{extra}")
    }
    fn post(path: &str, body: &str, extra: &str) -> (String, Vec<u8>) {
        (format!("POST {path} HTTP/1.1\r\nHost: 127.0.0.1:{P}\r\nX-ArrowBridge-Owner: 1\r\nContent-Type: application/json\r\nContent-Length: {}{extra}", body.len()), body.as_bytes().to_vec())
    }
    fn nl(s: &str) -> String {
        s.to_string()
    }
    fn json_of(r: &Reply) -> Value {
        serde_json::from_str(&r.1).unwrap()
    }
    fn t0() -> Instant {
        Instant::now()
    }

    // ---- listings: fixture replay ----
    #[test]
    fn router_fixture_replay_gives_rows_with_label_id_and_host_local() {
        let rows = parse_local(ROUTER).unwrap();
        assert_eq!(rows.len(), 3);
        assert_eq!(rows.iter().map(|r| r.loaded).collect::<Vec<_>>(), vec![Some(true), Some(false), Some(false)]);
        assert!(rows.iter().all(|r| r.host == Host::Local && r.label == r.id));
    }
    #[test]
    fn remote_fixture_replay_keeps_id_label_loaded_and_drops_every_other_field() {
        let rows = parse_remote(REMOTE).unwrap();
        assert_eq!(rows.len(), 3);
        assert_eq!(rows.iter().map(|r| r.loaded).collect::<Vec<_>>(), vec![Some(true), Some(false), None]);
        assert_eq!(rows[0].label, "Remote Coder 7B");
        assert_eq!(rows[2].label, rows[2].id, "no label: the id");
        let f = fake(Some(ROUTER), Some(REMOTE), &[]);
        let r = owner(&f).handle(&get("/v1/models", ""), b"", t0());
        assert_eq!(r.0, 200);
        for leak in ["lab-mini-7", "hostname", "size_bytes", "quant", "machine"] {
            assert!(!r.1.contains(leak), "{leak} reached the reply: {}", r.1);
        }
    }
    #[test]
    fn host_is_exactly_local_or_remote_and_nothing_else_is_ever_emitted() {
        let f = fake(Some(ROUTER), Some(REMOTE), &[]);
        let v = json_of(&owner(&f).handle(&get("/v1/models", ""), b"", t0()));
        let rows = v["models"].as_array().unwrap();
        assert_eq!(rows.len(), 6);
        for r in rows {
            assert!(r["host"] == "local" || r["host"] == "remote", "{r}");
            assert_eq!(r.as_object().unwrap().keys().cloned().collect::<std::collections::BTreeSet<_>>(), ["host", "id", "label", "loaded"].iter().map(|s| s.to_string()).collect());
        }
        assert!(rows.iter().take(3).all(|r| r["host"] == "local") && rows.iter().skip(3).all(|r| r["host"] == "remote"));
        assert_eq!(v["unknown"], json!([]));
        assert!(rows.iter().any(|r| r["loaded"].is_null()), "null stays null, never a guess");
    }
    #[test]
    fn a_group_that_cannot_be_read_is_unknown_and_has_no_rows() {
        let f = fake(Some(ROUTER), Some("{garbage"), &[]);
        let v = json_of(&owner(&f).handle(&get("/v1/models", ""), b"", t0()));
        assert_eq!(v["unknown"], json!(["remote"]));
        assert!(v["models"].as_array().unwrap().iter().all(|r| r["host"] == "local"));
        let f = fake(None, None, &[]);
        let v = json_of(&owner(&f).handle(&get("/v1/models", ""), b"", t0()));
        assert_eq!((v["unknown"].clone(), v["models"].clone()), (json!(["local", "remote"]), json!([])));
    }

    // ---- caps ----
    fn local_n(n: usize) -> String {
        json!({"data": (0..n).map(|i| json!({"id": format!("m{i}"), "status": {"value": "loaded"}})).collect::<Vec<_>>()}).to_string()
    }
    #[test]
    fn rows_are_capped_at_64_a_group_over_the_cap_is_unreadable_not_truncated() {
        assert_eq!(parse_local(&local_n(64)).unwrap().len(), 64);
        assert_eq!(parse_local(&local_n(65)), Err(Unreadable));
        let r65 = json!({"models": (0..65).map(|i| json!({"id": format!("m{i}")})).collect::<Vec<_>>()}).to_string();
        assert_eq!(parse_remote(&r65), Err(Unreadable));
        assert_eq!(parse_local(r#"{"data":[]}"#), Err(Unreadable));
    }
    #[test]
    fn labels_and_ids_are_capped_at_200_and_carry_no_control_character_or_duplicate() {
        let rem = |l: &str| json!({"models": [{"id": "a", "label": l}]}).to_string();
        assert!(parse_remote(&rem(&"x".repeat(200))).is_ok());
        assert_eq!(parse_remote(&rem(&"x".repeat(201))), Err(Unreadable));
        assert_eq!(parse_remote(&rem("a\nb")), Err(Unreadable));
        assert_eq!(parse_remote(&rem("")), Err(Unreadable));
        assert_eq!(parse_remote(&rem("a\u{7}b")), Err(Unreadable));
        let loc = |id: &str| json!({"data": [{"id": id}, {"id": "z"}]}).to_string();
        assert!(parse_local(&loc(&"y".repeat(200))).is_ok());
        assert_eq!(parse_local(&loc(&"y".repeat(201))), Err(Unreadable));
        assert_eq!(parse_local(&loc("a\tb")), Err(Unreadable));
        assert_eq!(parse_local(r#"{"data":[{"id":"a"},{"id":"a"}]}"#), Err(Unreadable));
        assert_eq!(parse_remote(r#"{"models":[{"id":"a","loaded":"yes"}]}"#), Err(Unreadable));
    }
    #[test]
    fn plain_text_markup_in_an_id_is_data_inside_a_json_string_never_interpreted() {
        let f = fake(Some(r#"{"data":[{"id":"<img src=x onerror=1>"},{"id":"b"}]}"#), None, &[]);
        let r = owner(&f).handle(&get("/v1/models", ""), b"", t0());
        assert_eq!(json_of(&r)["models"][0]["id"], "<img src=x onerror=1>");
        assert!(r.1.starts_with('{'), "JSON body, served as application/json");
    }

    // ---- the llama key ----
    #[test]
    fn the_llama_key_reaches_the_router_in_one_header_and_no_reply_carries_it() {
        let (port, rx) = serve_with(200, ROUTER);
        let up = DesktopUpstream { llama_port: port, key: Box::new(|| Some(KEY.to_string())) };
        let body = up.local_listing().unwrap();
        let head = rx.recv().unwrap();
        assert!(head.contains(&format!("Authorization: Bearer {KEY}\r\n")), "{head}");
        let o = Owner::new(DesktopUpstream { llama_port: port, key: Box::new(|| Some(KEY.to_string())) }, P);
        let r = o.handle(&get("/v1/models", ""), b"", t0());
        assert!(!r.1.contains(KEY) && !body.contains(KEY));
        // a key that could split the header is not sent at all
        let bad = DesktopUpstream { llama_port: port, key: Box::new(|| Some("k\r\nX: y".into())) };
        assert!(bad.local_listing().is_none());
    }

    // ---- the gates ----
    #[test]
    fn host_must_be_127_0_0_1_or_localhost_with_this_port_exactly_once() {
        let f = fake(Some(ROUTER), None, &[]);
        let h = |host: &str| format!("GET /v1/models HTTP/1.1\r\nHost: {host}\r\nX-ArrowBridge-Owner: 1");
        let o = owner(&f);
        let mut now = t0();
        let mut step = |head: String| {
            now += MIN_GAP * 2;
            o.handle(&head, b"", now).0
        };
        assert_eq!(step(h("127.0.0.1:8789")), 200);
        assert_eq!(step(h("localhost:8789")), 200);
        assert_eq!(step(h("LOCALHOST:8789")), 200);
        for bad in ["127.0.0.1", "localhost", "127.0.0.1:8788", "evil.example:8789", "evil.example", "127.0.0.1.evil.example:8789", "[::1]:8789", "0.0.0.0:8789", "", "10.0.0.5:8789"] {
            assert_eq!(step(h(bad)), 403, "{bad}");
        }
        assert_eq!(step(format!("GET /v1/models HTTP/1.1\r\nX-ArrowBridge-Owner: 1")), 403, "no Host");
        assert_eq!(step(format!("{}\r\nHost: localhost:8789", h("127.0.0.1:8789"))), 403, "two Hosts");
    }
    #[test]
    fn an_origin_header_of_any_value_is_refused_and_no_cors_header_is_ever_sent() {
        let f = fake(Some(ROUTER), None, &[Some(r#"{"state":"free"}"#)]);
        let o = owner(&f);
        for (i, v) in ["https://evil.example", "null", "http://127.0.0.1:8789", ""].iter().enumerate() {
            let now = t0() + MIN_GAP * (i as u32 * 2 + 2);
            assert_eq!(o.handle(&get("/v1/models", &format!("\r\nOrigin: {v}")), b"", now).0, 403, "{v}");
            let (h, b) = post("/v1/resume", "{}", &format!("\r\nOrigin: {v}"));
            assert_eq!(o.handle(&h, &b, now).0, 403, "{v}");
        }
        assert!(f.posts.lock().unwrap().is_empty(), "a refused request reached the coder");
        assert_eq!(o.handle(&get("/v1/models", ""), b"", t0() + Duration::from_secs(100)).0, 200);
    }
    #[test]
    fn the_owner_header_is_required_on_all_three_routes() {
        let f = fake(Some(ROUTER), None, &[Some(r#"{"state":"free"}"#)]);
        let o = owner(&f);
        let now = t0();
        let nohdr = |l: String| l.replace("\r\nX-ArrowBridge-Owner: 1", "");
        assert_eq!(o.handle(&nohdr(get("/v1/models", "")), b"", now).0, 403);
        assert_eq!(o.handle(&get("/v1/models", "").replace("Owner: 1", "Owner: 0"), b"", now).0, 403);
        assert_eq!(o.handle(&get("/v1/models", "").replace("Owner: 1", "Owner: true"), b"", now).0, 403);
        assert_eq!(o.handle(&get("/v1/models", "\r\nX-ArrowBridge-Owner: 1"), b"", now).0, 403, "twice");
        for p in ["/v1/pause", "/v1/resume"] {
            let (h, b) = post(p, r#"{"model":"a"}"#, "");
            assert_eq!(o.handle(&nohdr(h), &b, now).0, 403, "{p}");
        }
        assert!(f.posts.lock().unwrap().is_empty());
    }
    #[test]
    fn other_paths_and_methods_are_refused_and_preflight_gets_no_cors() {
        let f = fake(Some(ROUTER), None, &[]);
        let o = owner(&f);
        let now = t0();
        assert_eq!(o.handle(&get("/pair-info", ""), b"", now).0, 404);
        assert_eq!(o.handle(&get("/v1/pause", ""), b"", now).0, 405);
        assert_eq!(o.handle(&get("/v1/models", "").replace("GET", "OPTIONS"), b"", now).0, 405);
        assert_eq!(o.handle(&get("/v1/models", "").replace("GET", "DELETE"), b"", now).0, 405);
        assert_eq!(o.handle("garbage", b"", now).0, 400);
        assert_eq!(o.handle(&get("/v1/models", "\r\nno colon here"), b"", now).0, 400);
    }
    #[test]
    fn post_needs_json_content_type_a_true_length_and_at_most_1_kib() {
        let f = fake(Some(ROUTER), None, &[]);
        let o = owner(&f);
        let now = t0();
        let (h, b) = post("/v1/resume", "{}", "");
        assert_eq!(o.handle(&h.replace("application/json", "text/plain"), &b, now).0, 415);
        assert_eq!(o.handle(&h.replace("Content-Length: 2", "Content-Length: 9"), &b, now).0, 400);
        assert_eq!(o.handle(&format!("{h}\r\nTransfer-Encoding: chunked"), &b, now).0, 400);
        let big = format!("{{\"model\":\"{}\"}}", "a".repeat(1100));
        let (h, b) = post("/v1/pause", &big, "");
        assert_eq!(o.handle(&h, &b, now).0, 413);
        assert!(f.posts.lock().unwrap().is_empty());
    }

    // ---- rate limit ----
    #[test]
    fn each_route_admits_one_request_per_two_seconds_independently() {
        let f = fake(Some(ROUTER), None, &[Some(r#"{"state":"free"}"#), Some(r#"{"state":"free"}"#), Some(r#"{"state":"free"}"#)]);
        let o = owner(&f);
        let now = t0();
        assert_eq!(o.handle(&get("/v1/models", ""), b"", now).0, 200);
        assert_eq!(o.handle(&get("/v1/models", ""), b"", now + Duration::from_millis(1999)).0, 429);
        let (h, b) = post("/v1/resume", "{}", "");
        assert_eq!(o.handle(&h, &b, now + Duration::from_millis(100)).0, 200, "another route is not limited by models");
        assert_eq!(o.handle(&h, &b, now + Duration::from_millis(1000)).0, 429);
        assert_eq!(o.handle(&get("/v1/models", ""), b"", now + Duration::from_millis(2000)).0, 200);
        assert_eq!(o.handle(&h, &b, now + Duration::from_millis(2100)).0, 200);
        assert_eq!(f.posts.lock().unwrap().len(), 2, "a limited request never reached the coder");
    }
    #[test]
    fn a_refused_request_does_not_spend_the_budget_of_the_owner() {
        let f = fake(Some(ROUTER), None, &[]);
        let o = owner(&f);
        let now = t0();
        assert_eq!(o.handle(&get("/v1/models", "").replace("Owner: 1", "Owner: 0"), b"", now).0, 403);
        assert_eq!(o.handle(&get("/v1/models", ""), b"", now).0, 200);
    }

    // ---- pause and resume ----
    #[test]
    fn pause_replies_exactly_paused_or_free_and_everything_else_is_unknown() {
        let cases: [(Option<&str>, u16, &str); 10] = [
            (Some(r#"{"state":"paused"}"#), 200, "paused"),
            (Some(r#"{"state":"free"}"#), 200, "free"),
            (Some(r#"{"state":"PAUSED"}"#), 502, "unknown"),
            (Some(r#"{"state":"busy"}"#), 502, "unknown"),
            (Some(r#"{"state":1}"#), 502, "unknown"),
            (Some(r#"[]"#), 502, "unknown"),
            (Some(""), 502, "unknown"),
            (Some("not json"), 502, "unknown"),
            (Some(r#"{"state":"paused"} trailing"#), 502, "unknown"),
            (None, 502, "unknown"),
        ];
        for (body, code, word) in cases {
            let f = fake(Some(ROUTER), None, &[body]);
            let (h, b) = post("/v1/pause", r#"{"model":"qwen-coder"}"#, "");
            let r = owner(&f).handle(&h, &b, t0());
            assert_eq!((r.0, r.1), (code, format!("{{\"state\":\"{word}\"}}")), "{body:?}");
        }
    }
    #[test]
    fn the_coder_gets_the_picker_bodies_byte_for_byte() {
        let f = fake(Some(ROUTER), None, &[Some(r#"{"state":"paused"}"#), Some(r#"{"state":"free"}"#)]);
        let o = owner(&f);
        let (h, b) = post("/v1/pause", r#"{"model":"qwen-coder","extra":1}"#, "");
        o.handle(&h, &b, t0());
        let (h, b) = post("/v1/resume", "{}", "");
        o.handle(&h, &b, t0());
        assert_eq!(*f.posts.lock().unwrap(), vec![nl(r#"{"action":"pause","model":"qwen-coder"}"#), nl(r#"{"action":"resume"}"#)]);
    }
    #[test]
    fn a_pause_for_an_unlisted_id_or_with_an_unreadable_listing_sends_nothing() {
        let f = fake(Some(ROUTER), Some(REMOTE), &[Some(r#"{"state":"paused"}"#)]);
        let o = owner(&f);
        let (h, b) = post("/v1/pause", r#"{"model":"not-in-any-listing"}"#, "");
        assert_eq!(o.handle(&h, &b, t0()).0, 400);
        for (i, body) in ["{}", r#"{"model":3}"#, r#"{"model":""}"#, "nope", r#"{"model":"a\nb"}"#].iter().enumerate() {
            let (h, b) = post("/v1/pause", body, "");
            assert_eq!(o.handle(&h, &b, t0() + MIN_GAP * (i as u32 * 2 + 2)).0, 400, "{body}");
        }
        assert!(f.posts.lock().unwrap().is_empty());
        let f = fake(Some("junk"), None, &[Some(r#"{"state":"paused"}"#)]);
        let (h, b) = post("/v1/pause", r#"{"model":"qwen-coder"}"#, "");
        let r = owner(&f).handle(&h, &b, t0());
        assert_eq!((r.0, r.1.as_str()), (502, r#"{"state":"unknown"}"#));
        assert!(f.posts.lock().unwrap().is_empty());
        // an id the remote lists is allowed
        let f = fake(Some(ROUTER), Some(REMOTE), &[Some(r#"{"state":"paused"}"#)]);
        let (h, b) = post("/v1/pause", r#"{"model":"remote-coder-7b"}"#, "");
        assert_eq!(owner(&f).handle(&h, &b, t0()).0, 200);
    }
    #[test]
    fn resume_answers_only_free_a_paused_or_garbage_answer_to_resume_is_unknown() {
        for (body, code) in [(Some(r#"{"state":"free"}"#), 200), (Some(r#"{"state":"paused"}"#), 502), (Some("x"), 502), (None, 502)] {
            let f = fake(Some(ROUTER), None, &[body]);
            let (h, b) = post("/v1/resume", "{}", "");
            assert_eq!(owner(&f).handle(&h, &b, t0()).0, code, "{body:?}");
        }
    }

    // ---- auto resume ----
    #[test]
    fn a_pause_is_lifted_after_the_bound_and_not_a_second_before() {
        let f = fake(Some(ROUTER), None, &[Some(r#"{"state":"paused"}"#), Some(r#"{"state":"free"}"#)]);
        let o = owner(&f);
        let now = t0();
        let (h, b) = post("/v1/pause", r#"{"model":"qwen-coder"}"#, "");
        assert_eq!(o.handle(&h, &b, now).0, 200);
        assert!(o.is_held());
        o.tick(now + AUTO_RESUME - Duration::from_secs(1));
        assert!(o.is_held() && f.posts.lock().unwrap().len() == 1, "lifted early");
        o.tick(now + AUTO_RESUME);
        assert!(!o.is_held());
        assert_eq!(f.posts.lock().unwrap().last().unwrap(), r#"{"action":"resume"}"#);
        o.tick(now + AUTO_RESUME * 2);
        assert_eq!(f.posts.lock().unwrap().len(), 2, "nothing held, nothing sent");
    }
    #[test]
    fn a_resume_the_coder_does_not_confirm_is_retried_every_two_seconds_until_it_is() {
        let f = fake(Some(ROUTER), None, &[Some(r#"{"state":"paused"}"#), None, Some("garbage"), Some(r#"{"state":"free"}"#)]);
        let o = owner(&f);
        let now = t0();
        let (h, b) = post("/v1/pause", r#"{"model":"qwen-coder"}"#, "");
        o.handle(&h, &b, now);
        let due = now + AUTO_RESUME;
        o.tick(due);
        o.tick(due + Duration::from_millis(500));
        assert_eq!(f.posts.lock().unwrap().len(), 2, "retry waits the gap");
        o.tick(due + MIN_GAP);
        assert!(o.is_held());
        o.tick(due + MIN_GAP * 2);
        assert!(!o.is_held());
        assert_eq!(f.posts.lock().unwrap().len(), 4);
    }
    #[test]
    fn a_manual_resume_clears_the_hold_and_free_never_sets_one() {
        let f = fake(Some(ROUTER), None, &[Some(r#"{"state":"free"}"#), Some(r#"{"state":"paused"}"#), Some(r#"{"state":"free"}"#)]);
        let o = owner(&f);
        let now = t0();
        let (h, b) = post("/v1/pause", r#"{"model":"qwen-coder"}"#, "");
        o.handle(&h, &b, now);
        assert!(!o.is_held());
        o.handle(&h, &b, now + MIN_GAP);
        assert!(o.is_held());
        let (h, b) = post("/v1/resume", "{}", "");
        o.handle(&h, &b, now + MIN_GAP * 2);
        assert!(!o.is_held());
    }

    // ---- real sockets ----
    fn serve_with(code: u16, body: &'static str) -> (u16, std::sync::mpsc::Receiver<String>) {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            for s in l.incoming() {
                let mut s = s.unwrap();
                let mut buf = [0u8; 4096];
                let n = s.read(&mut buf).unwrap_or(0);
                let _ = tx.send(String::from_utf8_lossy(&buf[..n]).into_owned());
                let _ = s.write_all(format!("HTTP/1.1 {code} X\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).as_bytes());
            }
        });
        (port, rx)
    }
    /// A server that sends `bytes` then waits `gap` between each byte (None: all at once), or never answers.
    fn serve_odd(mode: &'static str) -> u16 {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        std::thread::spawn(move || {
            for s in l.incoming() {
                let mut s = s.unwrap();
                std::thread::spawn(move || {
                    let mut buf = [0u8; 4096];
                    let _ = s.read(&mut buf);
                    match mode {
                        "hang" => std::thread::sleep(Duration::from_secs(9)),
                        "big" => {
                            let body = "x".repeat(64 * 1024 + 1);
                            let _ = s.write_all(format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{body}", body.len()).as_bytes());
                        }
                        _ => {
                            for b in b"HTTP/1.1 200 OK\r\n\r\n{\"state\":\"free\"}" {
                                if s.write_all(&[*b]).is_err() {
                                    return;
                                }
                                std::thread::sleep(Duration::from_millis(300));
                            }
                        }
                    }
                });
            }
        });
        port
    }
    #[test]
    fn upstream_calls_are_bounded_in_time_and_size_and_a_non_200_is_no_answer() {
        let t = Instant::now();
        assert!(http_call(serve_odd("hang"), "GET", "/", "", "", Duration::from_millis(700)).is_none());
        assert!(t.elapsed() < Duration::from_secs(2), "{:?}", t.elapsed());
        assert!(http_call(serve_odd("big"), "GET", "/", "", "", Duration::from_secs(4)).is_none(), "64 KiB plus one");
        let t = Instant::now();
        assert!(http_call(serve_odd("trickle"), "GET", "/", "", "", Duration::from_millis(900)).is_none());
        assert!(t.elapsed() < Duration::from_secs(2), "{:?}", t.elapsed());
        let (p, _rx) = serve_with(500, "{}");
        assert!(http_call(p, "GET", "/", "", "", Duration::from_secs(2)).is_none());
        let (p, rx) = serve_with(200, r#"{"state":"free"}"#);
        assert_eq!(http_call(p, "POST", "/x", "", "{}", Duration::from_secs(2)).as_deref(), Some(r#"{"state":"free"}"#));
        let head = rx.recv().unwrap();
        assert!(head.contains(&format!("Host: 127.0.0.1:{p}\r\n")) && head.contains("X-ArrowBridge-Owner: 1\r\n") && head.contains("Content-Length: 2\r\n"));
        assert!(!head.to_lowercase().contains("origin:"), "{head}");
        let dead = TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
        assert!(http_call(dead, "GET", "/", "", "", Duration::from_secs(2)).is_none(), "connection refused");
    }

    fn raw(addr: SocketAddr, req: &str) -> String {
        let mut s = TcpStream::connect(addr).unwrap();
        s.set_read_timeout(Some(Duration::from_secs(6))).unwrap();
        s.write_all(req.as_bytes()).unwrap();
        let mut out = String::new();
        let _ = s.read_to_string(&mut out);
        out
    }
    struct Hung;
    impl Upstream for Hung {
        fn local_listing(&self) -> Option<String> {
            Some(ROUTER.into())
        }
        fn remote_listing(&self) -> Option<String> {
            None
        }
        fn coder(&self, _b: &str) -> Option<String> {
            http_call(serve_odd("hang"), "POST", "/", "", "", Duration::from_millis(600))
        }
    }
    #[test]
    fn the_listener_binds_loopback_only_serves_the_three_routes_and_a_hung_coder_reads_unknown() {
        let run = start(0, Hung).unwrap();
        assert_eq!(run.addr.ip(), std::net::IpAddr::V4(Ipv4Addr::LOCALHOST));
        let port = run.addr.port();
        let r = raw(run.addr, &format!("GET /v1/models HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nX-ArrowBridge-Owner: 1\r\n\r\n"));
        assert!(r.starts_with("HTTP/1.1 200 OK\r\n") && r.contains("\"host\":\"local\""), "{r}");
        assert!(!r.to_lowercase().contains("access-control"), "{r}");
        let t = Instant::now();
        let body = r#"{"model":"qwen-coder"}"#;
        let r = raw(run.addr, &format!("POST /v1/pause HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nX-ArrowBridge-Owner: 1\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}", body.len()));
        assert!(r.starts_with("HTTP/1.1 502 ") && r.ends_with(r#"{"state":"unknown"}"#), "{r}");
        assert!(t.elapsed() < Duration::from_secs(3), "{:?}", t.elapsed());
        let r = raw(run.addr, &format!("POST /v1/pause HTTP/1.1\r\nHost: evil.example:{port}\r\nOrigin: https://evil.example\r\nContent-Length: 0\r\n\r\n"));
        assert!(r.starts_with("HTTP/1.1 403 ") && !r.to_lowercase().contains("access-control"), "{r}");
        run.stop();
    }
    #[test]
    fn a_client_that_trickles_or_stalls_is_dropped_at_the_request_deadline() {
        let run = start(0, Hung).unwrap();
        let t = Instant::now();
        let mut s = TcpStream::connect(run.addr).unwrap();
        s.set_read_timeout(Some(Duration::from_secs(6))).unwrap();
        s.write_all(b"GET /v1/models HTT").unwrap();
        let mut out = String::new();
        let _ = s.read_to_string(&mut out);
        assert!(t.elapsed() < Duration::from_secs(5), "{:?}", t.elapsed());
        assert!(out.starts_with("HTTP/1.1 400 "), "{out}");
        run.stop();
    }
    #[test]
    fn the_port_comes_from_the_config_with_a_safe_default() {
        assert_eq!(owner_port(None), 8789);
        assert_eq!(owner_port(Some("9100")), 9100);
        for bad in ["", "x", "0", "80", "70000", "-1"] {
            assert_eq!(owner_port(Some(bad)), 8789, "{bad}");
        }
    }

    // ---- nothing persisted, nothing logged ----
    fn write_calls(src: &str) -> Vec<&'static str> {
        let shipped = src.split("#[cfg(test)]").next().unwrap();
        ["File::create", "OpenOptions", "fs::write", "create_dir", "fs::File", "std::fs", "println!", "eprintln!", "dbg!", "log::", "tracing::"].into_iter().filter(|b| shipped.contains(b)).collect()
    }
    #[test]
    fn this_file_contains_no_write_to_disk_and_no_log_call_and_the_check_catches_a_planted_one() {
        assert_eq!(write_calls(include_str!("ownerroutes.rs")), Vec::<&str>::new());
        assert_eq!(write_calls("fn f(){ std::fs::write(\"x\", \"y\"); }\n#[cfg(test)]"), vec!["fs::write", "std::fs"]);
        assert_eq!(write_calls("fn f(){ eprintln!(\"x\"); }"), vec!["println!", "eprintln!"]);
    }
}
