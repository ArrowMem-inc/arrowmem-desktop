//! The bar panel helper. It speaks only to the bridge owner listener on 127.0.0.1 and prints ONE line of JSON.
//! std only. Writes no file, logs nothing, exits 0 on every path (main.rs): a failure is the word "unknown".
//!
//! The listener is not trusted (a process that binds the port first can pose as it). Every reply is held to
//! the listener's own caps: status 200, body at most 64 KiB, 3 s for the whole call, at most 64 rows per group,
//! id at most 200 bytes, label at most 200 characters, no control character, no duplicate id, the two host words only.
//!
//!   list   --owner-port N                -> {"groups":[{"host":"local"|"remote","state":"ok"|"unknown","rows":[{"id","loaded","paused"}]}]}
//!   pause  --owner-port N --model <id>   -> {"state":"paused"|"free"|"unknown"}
//!   resume --owner-port N                -> {"state":"free"|"unknown"}
use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpStream};
use std::time::{Duration, Instant};

pub const MAX_ROWS: usize = 64;
pub const MAX_ID: usize = 200;
pub const MAX_BODY: usize = 64 * 1024;
pub const MAX_HEAD: usize = 8 * 1024;
pub const DEADLINE: Duration = Duration::from_secs(3);
const CONNECT: Duration = Duration::from_secs(2);
const MAX_DEPTH: usize = 8;
pub const UNKNOWN_STATE: &str = r#"{"state":"unknown"}"#;
const UNKNOWN_LIST: &str = r#"{"groups":[{"host":"local","state":"unknown","rows":[]},{"host":"remote","state":"unknown","rows":[]}]}"#;
const HOSTS: [&str; 2] = ["local", "remote"];

// ---------------------------------------------------------------- JSON (strict, bounded)

#[derive(Debug)]
enum V {
    Null,
    Bool(bool),
    Num,
    Str(String),
    Arr(Vec<V>),
    Obj(Vec<(String, V)>),
}

impl V {
    fn get(&self, k: &str) -> Option<&V> {
        match self {
            V::Obj(o) => o.iter().find(|(n, _)| n == k).map(|(_, v)| v),
            _ => None,
        }
    }
    fn str(&self) -> Option<&str> {
        if let V::Str(s) = self { Some(s) } else { None }
    }
}

struct P<'a> {
    b: &'a [u8],
    i: usize,
}

fn parse(s: &str) -> Option<V> {
    let mut p = P { b: s.as_bytes(), i: 0 };
    let v = p.value(0)?;
    p.ws();
    (p.i == p.b.len()).then_some(v)
}

impl P<'_> {
    fn ws(&mut self) {
        while matches!(self.b.get(self.i), Some(b' ' | b'\t' | b'\n' | b'\r')) {
            self.i += 1;
        }
    }
    fn eat(&mut self, lit: &str) -> Option<()> {
        self.b[self.i..].starts_with(lit.as_bytes()).then(|| self.i += lit.len())
    }
    fn value(&mut self, depth: usize) -> Option<V> {
        if depth > MAX_DEPTH {
            return None;
        }
        self.ws();
        match *self.b.get(self.i)? {
            b'n' => self.eat("null").map(|_| V::Null),
            b't' => self.eat("true").map(|_| V::Bool(true)),
            b'f' => self.eat("false").map(|_| V::Bool(false)),
            b'"' => self.string().map(V::Str),
            b'[' => {
                self.i += 1;
                let mut a = Vec::new();
                loop {
                    self.ws();
                    if a.is_empty() && self.b.get(self.i) == Some(&b']') {
                        self.i += 1;
                        return Some(V::Arr(a));
                    }
                    a.push(self.value(depth + 1)?);
                    self.ws();
                    match self.b.get(self.i)? {
                        b',' => self.i += 1,
                        b']' => {
                            self.i += 1;
                            return Some(V::Arr(a));
                        }
                        _ => return None,
                    }
                }
            }
            b'{' => {
                self.i += 1;
                let mut o: Vec<(String, V)> = Vec::new();
                loop {
                    self.ws();
                    if o.is_empty() && self.b.get(self.i) == Some(&b'}') {
                        self.i += 1;
                        return Some(V::Obj(o));
                    }
                    let k = self.string()?;
                    self.ws();
                    self.eat(":")?;
                    let v = self.value(depth + 1)?;
                    if o.iter().any(|(n, _)| *n == k) {
                        return None;
                    }
                    o.push((k, v));
                    self.ws();
                    match self.b.get(self.i)? {
                        b',' => self.i += 1,
                        b'}' => {
                            self.i += 1;
                            return Some(V::Obj(o));
                        }
                        _ => return None,
                    }
                }
            }
            b'-' | b'0'..=b'9' => {
                let from = self.i;
                while matches!(self.b.get(self.i), Some(b'-' | b'+' | b'.' | b'e' | b'E' | b'0'..=b'9')) {
                    self.i += 1;
                }
                (self.i > from).then_some(V::Num)
            }
            _ => None,
        }
    }
    fn hex4(&mut self) -> Option<u32> {
        let h = std::str::from_utf8(self.b.get(self.i..self.i + 4)?).ok()?;
        self.i += 4;
        u32::from_str_radix(h, 16).ok().filter(|_| h.bytes().all(|c| c.is_ascii_hexdigit()))
    }
    fn string(&mut self) -> Option<String> {
        self.eat("\"")?;
        let mut out: Vec<u8> = Vec::new();
        loop {
            let c = *self.b.get(self.i)?;
            self.i += 1;
            match c {
                b'"' => return String::from_utf8(out).ok(),
                0..=0x1f => return None,
                b'\\' => {
                    let e = *self.b.get(self.i)?;
                    self.i += 1;
                    let ch = match e {
                        b'"' => '"',
                        b'\\' => '\\',
                        b'/' => '/',
                        b'b' => '\u{8}',
                        b'f' => '\u{c}',
                        b'n' => '\n',
                        b'r' => '\r',
                        b't' => '\t',
                        b'u' => {
                            let hi = self.hex4()?;
                            let cp = if (0xd800..0xdc00).contains(&hi) {
                                self.eat("\\u")?;
                                let lo = self.hex4()?;
                                if !(0xdc00..0xe000).contains(&lo) {
                                    return None;
                                }
                                0x10000 + ((hi - 0xd800) << 10) + (lo - 0xdc00)
                            } else {
                                hi
                            };
                            char::from_u32(cp)?
                        }
                        _ => return None,
                    };
                    let mut buf = [0u8; 4];
                    out.extend_from_slice(ch.encode_utf8(&mut buf).as_bytes());
                }
                _ => out.push(c),
            }
        }
    }
}

/// A JSON string literal, ASCII only: quote, backslash and everything outside 0x20..0x7e is escaped.
fn quote(s: &str) -> String {
    let mut o = String::from("\"");
    for c in s.chars() {
        match c {
            '"' => o.push_str("\\\""),
            '\\' => o.push_str("\\\\"),
            ' '..='~' => o.push(c),
            _ => {
                let mut u = [0u16; 2];
                for w in c.encode_utf16(&mut u) {
                    o.push_str(&format!("\\u{w:04x}"));
                }
            }
        }
    }
    o.push('"');
    o
}

// ---------------------------------------------------------------- the owner listener, one call

/// One request, one reply body. None on every failure: connect, deadline, non 200, framing, size, encoding.
fn call(port: u16, method: &str, path: &str, body: Option<&str>) -> Option<String> {
    let end = Instant::now() + DEADLINE;
    let left = || end.checked_duration_since(Instant::now()).filter(|d| !d.is_zero());
    let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, port));
    let mut s = TcpStream::connect_timeout(&addr, left()?.min(CONNECT)).ok()?;
    let mut req = format!("{method} {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nX-ArrowBridge-Owner: 1\r\nConnection: close\r\n");
    if let Some(b) = body {
        req.push_str(&format!("Content-Type: application/json\r\nContent-Length: {}\r\n", b.len()));
    }
    req.push_str("\r\n");
    req.push_str(body.unwrap_or(""));
    s.set_write_timeout(Some(left()?)).ok()?;
    s.write_all(req.as_bytes()).ok()?;
    let mut buf: Vec<u8> = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        if let Some((head_len, cl)) = frame(&buf)? {
            if cl.is_some_and(|n| buf.len() - head_len >= n) {
                break;
            }
        } else if buf.len() > MAX_HEAD {
            return None;
        }
        if buf.len() > MAX_HEAD + MAX_BODY + 1 {
            return None;
        }
        s.set_read_timeout(Some(left()?)).ok()?;
        match s.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
            Err(_) => return None,
        }
    }
    let (head_len, cl) = frame(&buf)??;
    let body = &buf[head_len..];
    if body.len() > MAX_BODY || cl.is_some_and(|n| n != body.len()) {
        return None;
    }
    String::from_utf8(body.to_vec()).ok()
}

/// Outer None: the head is unacceptable. Some(None): the head is not complete yet.
/// Some(Some((head length, Content-Length))): status 200, one Content-Length at most, no Transfer-Encoding.
#[allow(clippy::type_complexity)]
fn frame(buf: &[u8]) -> Option<Option<(usize, Option<usize>)>> {
    let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") else { return Some(None) };
    if pos > MAX_HEAD {
        return None;
    }
    let head = std::str::from_utf8(&buf[..pos]).ok()?;
    let mut lines = head.split("\r\n");
    let mut st = lines.next()?.split(' ');
    if !st.next()?.starts_with("HTTP/1.") || st.next()? != "200" {
        return None;
    }
    let mut cl = None;
    for l in lines {
        let (name, val) = l.split_once(':')?;
        match name.to_ascii_lowercase().as_str() {
            "transfer-encoding" => return None,
            "content-length" => {
                if cl.is_some() {
                    return None;
                }
                cl = Some(val.trim().parse::<usize>().ok()?);
            }
            _ => {}
        }
    }
    Some(Some((pos + 4, cl)))
}

// ---------------------------------------------------------------- the listing

/// Code points of categories Cf, Zl, Zp, Co and Cn (Cc is `is_control`). std has no category table, so this is
/// the Cf, Zl, Zp and Co ranges plus the noncharacters and every plane from 4 up; Model.js `BAD` holds the same list.
const BAD: &[(u32, u32)] = &[
    (0xAD, 0xAD), (0x600, 0x605), (0x61C, 0x61C), (0x6DD, 0x6DD), (0x70F, 0x70F), (0x890, 0x891), (0x8E2, 0x8E2),
    (0x180E, 0x180E), (0x200B, 0x200F), (0x2028, 0x202E), (0x2060, 0x2064), (0x2066, 0x206F), (0xE000, 0xF8FF),
    (0xFDD0, 0xFDEF), (0xFEFF, 0xFEFF), (0xFFF0, 0xFFFB), (0xFFFE, 0xFFFF), (0x110BD, 0x110BD), (0x110CD, 0x110CD),
    (0x13430, 0x1343F), (0x1BCA0, 0x1BCA3), (0x1D173, 0x1D17A), (0x1FFFE, 0x1FFFF), (0x2FFFE, 0x2FFFF),
    (0x3FFFE, 0x3FFFF), (0x40000, 0x10FFFF),
];

fn clean(s: &str) -> bool {
    !s.chars().any(|c| c.is_control() || BAD.iter().any(|&(a, b)| (a..=b).contains(&(c as u32))))
}

fn id_ok(s: &str) -> bool {
    !s.is_empty() && s.len() <= MAX_ID && s.bytes().all(|b| b.is_ascii_alphanumeric() || b".:_/-".contains(&b))
}

fn label_ok(s: &str) -> bool {
    !s.is_empty() && s.chars().count() <= MAX_ID && clean(s)
}

struct Row {
    id: String,
    loaded: Option<bool>,
    paused: bool,
}

/// One row as the listener builds it. Err: the row is unreadable (its group reads unknown).
fn row(r: &V) -> Result<Row, ()> {
    let id = r.get("id").and_then(V::str).filter(|s| id_ok(s)).ok_or(())?;
    match r.get("label") {
        None | Some(V::Null) => {}
        Some(l) => {
            l.str().filter(|s| label_ok(s)).ok_or(())?;
        }
    }
    let loaded = match r.get("loaded") {
        Some(V::Bool(b)) => Some(*b),
        None | Some(V::Null) => None,
        _ => return Err(()),
    };
    let paused = match r.get("paused") {
        Some(V::Bool(b)) => *b,
        _ => return Err(()),
    };
    Ok(Row { id: id.to_string(), loaded, paused })
}

/// `{"models":[{id,label,loaded,host,paused}],"unknown":["local"|"remote"]}` to the two output groups.
/// None: the reply is unreadable as a whole (not an object, a field missing, more than two groups' worth of rows).
fn listing(body: &str) -> Option<String> {
    let v = parse(body)?;
    let V::Arr(models) = v.get("models")? else { return None };
    let V::Arr(unk) = v.get("unknown")? else { return None };
    if models.len() > MAX_ROWS * HOSTS.len() {
        return None;
    }
    let mut bad = [false; 2];
    for u in unk {
        bad[HOSTS.iter().position(|h| Some(*h) == u.str())?] = true;
    }
    let mut rows: [Vec<Row>; 2] = [Vec::new(), Vec::new()];
    for m in models {
        // A host that is not one of the two words drops the row: nothing of it is ever shown.
        let Some(g) = m.get("host").and_then(V::str).and_then(|h| HOSTS.iter().position(|w| *w == h)) else { continue };
        match row(m) {
            Ok(r) if !rows[g].iter().any(|x| x.id == r.id) => rows[g].push(r),
            _ => bad[g] = true,
        }
    }
    let group = |g: usize| {
        if bad[g] || rows[g].len() > MAX_ROWS {
            return format!(r#"{{"host":"{}","state":"unknown","rows":[]}}"#, HOSTS[g]);
        }
        let list: Vec<String> = rows[g]
            .iter()
            .map(|r| format!(r#"{{"id":{},"loaded":{},"paused":{}}}"#, quote(&r.id), r.loaded.map_or("null".into(), |b| b.to_string()), r.paused))
            .collect();
        format!(r#"{{"host":"{}","state":"ok","rows":[{}]}}"#, HOSTS[g], list.join(","))
    };
    Some(format!(r#"{{"groups":[{},{}]}}"#, group(0), group(1)))
}

/// Exactly `{"state":"paused"}` or `{"state":"free"}`; a resume reply is held to `free`.
fn state(body: &str, only_free: bool) -> Option<&'static str> {
    let v = parse(body)?;
    let V::Obj(o) = &v else { return None };
    if o.len() != 1 {
        return None;
    }
    match v.get("state")?.str()? {
        "free" => Some(r#"{"state":"free"}"#),
        "paused" if !only_free => Some(r#"{"state":"paused"}"#),
        _ => None,
    }
}

// ---------------------------------------------------------------- entry

fn flag<'a>(args: &'a [String], name: &str) -> Option<&'a str> {
    args.iter().position(|a| a == name).and_then(|i| args.get(i + 1)).map(String::as_str)
}

/// The one line to print. Total: any failure is the unknown line for that verb.
pub fn run(args: &[String]) -> String {
    let verb = args.first().map(String::as_str).unwrap_or("");
    let port = flag(args, "--owner-port").and_then(|p| p.parse::<u16>().ok()).filter(|p| *p >= 1024);
    let out = match (verb, port) {
        ("list", Some(p)) => call(p, "GET", "/v1/models", None).and_then(|b| listing(&b)),
        ("resume", Some(p)) => call(p, "POST", "/v1/resume", Some("{}")).and_then(|b| state(&b, true).map(String::from)),
        ("pause", Some(p)) => flag(args, "--model").filter(|m| id_ok(m)).and_then(|m| {
            call(p, "POST", "/v1/pause", Some(&format!(r#"{{"model":{}}}"#, quote(m)))).and_then(|b| state(&b, false).map(String::from))
        }),
        _ => None,
    };
    out.unwrap_or_else(|| if verb == "list" { UNKNOWN_LIST } else { UNKNOWN_STATE }.to_string())
}
