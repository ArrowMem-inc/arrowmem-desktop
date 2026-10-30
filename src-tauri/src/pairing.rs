//! Release 11, S4: what the pair window and the status window show, and the first-install step that opens the
//! pair window after the single firewall prompt.
//!
//! The QR carries exactly the companion's LAN payload, address and name, nothing else. The pairing key is
//! never read by this module, never put in the QR, a window or a log: paired-or-not comes from the companion's
//! loopback owner route /pair-phones, which needs no key. (The companion's own GET /pair page encodes a
//! Tailscale address, not the LAN one, so the LAN payload is always built here, the same way: compact JSON with
//! sorted keys and ASCII escapes.)

use crate::firewall::{self, FwOutcome};
use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpStream};
use std::path::Path;
use std::time::{Duration, Instant};

pub const COMPANION_PORT: u16 = 8788;

/// Phone release 13 (vc17) types the code; the camera scan (F41) is NOT built. While true, the window shows the code and its lead line names the code and the paste only, never a scan. When false (a phone that cannot type), no code and the paste-only line. One line to flip, with a test that pins it (0.1.0-3 must not claim what vc16 cannot do).
pub const PHONE_CAN_TYPE_CODE: bool = true;

/// Decided: the QR STAYS on the window and the camera scan (F41) is built in the phone app for release 13.1. The flag exists so the picture can be hidden again if a
/// release ever has to go out before the scan does; it is true in 0.1.0-5.
pub const PHONE_CAN_SCAN: bool = true;

/// A companion reply larger than this is treated as no reply, and a whole request may take at most TOTAL_DEADLINE.
const MAX_REPLY_BYTES: u64 = 64 * 1024;
const TOTAL_DEADLINE: Duration = Duration::from_secs(10);
/// The only pairing protocol this client speaks; the companion echoes it on /pair-status and /pair-confirm.
const PAIR_PROTOCOL: &str = "typed6";
const MAX_HANDSHAKE_ID_LEN: usize = 64;

/// A handshake id: 1 to 64 printable ASCII characters (no space). Anything else is refused, never sent.
fn handshake_id_ok(h: &str) -> bool {
    !h.is_empty() && h.len() <= MAX_HANDSHAKE_ID_LEN && h.bytes().all(|b| b.is_ascii_graphic())
}

// The LAN rung is always http, never https: the desktop units never set ARROWBRIDGE_TLS_CERT, so the companion
// serves plain http and the scheme in the QR agrees with it.

/// json.dumps(..., ensure_ascii=True) string literal.
fn json_ascii(s: &str) -> String {
    let mut out = String::new();
    for c in serde_json::to_string(s).unwrap_or_default().chars() {
        if c.is_ascii() {
            out.push(c);
        } else {
            let mut b = [0u16; 2];
            for u in c.encode_utf16(&mut b) {
                out.push_str(&format!("\\u{:04x}", u));
            }
        }
    }
    out
}

/// The exact text the QR encodes: {"address":"http://<ip>:<port>","name":"<name>"}.
pub fn qr_payload(ip: Ipv4Addr, port: u16, name: &str) -> Result<String, String> {
    crate::userunit::private_lan_ip(&ip.to_string())?;
    Ok(format!("{{\"address\":{},\"name\":{}}}", json_ascii(&format!("http://{ip}:{port}")), json_ascii(name)))
}

/// SVG for `text` at error level M, 2-module border, 6px scale (the companion page's own settings).
pub fn qr_svg(text: &str) -> Result<String, String> {
    use qrcode::{Color, EcLevel, QrCode};
    let code = QrCode::with_error_correction_level(text.as_bytes(), EcLevel::M).map_err(|e| e.to_string())?;
    let w = code.width();
    let (border, scale) = (2usize, 6usize);
    let size = (w + 2 * border) * scale;
    let mut s = format!("<svg xmlns=\"http://www.w3.org/2000/svg\" width=\"{size}\" height=\"{size}\" viewBox=\"0 0 {size} {size}\"><rect width=\"{size}\" height=\"{size}\" fill=\"#FFFFFF\"/>");
    for (i, c) in code.to_colors().iter().enumerate() {
        if *c == Color::Dark {
            let (x, y) = ((i % w + border) * scale, (i / w + border) * scale);
            s.push_str(&format!("<rect x=\"{x}\" y=\"{y}\" width=\"{scale}\" height=\"{scale}\" fill=\"#10231A\"/>"));
        }
    }
    s.push_str("</svg>");
    Ok(s)
}

/// ARROWBRIDGE_DEVICE_NAME, else the OS hostname (the companion's own rule).
pub fn device_name() -> String {
    if let Ok(n) = std::env::var("ARROWBRIDGE_DEVICE_NAME") {
        if !n.trim().is_empty() {
            return n.trim().to_string();
        }
    }
    let mut buf = [0u8; 256];
    let ok = unsafe { libc::gethostname(buf.as_mut_ptr() as *mut libc::c_char, buf.len() - 1) } == 0;
    if ok {
        let end = buf.iter().position(|b| *b == 0).unwrap_or(buf.len());
        return String::from_utf8_lossy(&buf[..end]).into_owned();
    }
    String::new()
}

#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct PairView {
    /// False while the phone app that is out cannot type the code or scan: the window then says only "copy and paste"
    /// and shows no code. Flip with the release of the phone build that can. Never decided by the page.
    pub phone_can_type_code: bool,
    /// False while no phone release scans: the page draws no QR picture (the address is still in the code and the pairing text).
    pub phone_can_scan: bool,
    pub svg: String,
    pub address: String,
    pub name: String,
    /// The text inside the QR, for the window's copyable pairing text (address and name only, never a key).
    pub payload: String,
    /// The typed code (`ABCD-EFGH`); None on another port, where only the picture and the text are offered.
    pub code: Option<String>,
}

pub fn pair_view(ip: Ipv4Addr, name: &str) -> Result<PairView, String> {
    let payload = qr_payload(ip, COMPANION_PORT, name)?;
    Ok(PairView {
        svg: qr_svg(&payload)?,
        address: format!("http://{ip}:{COMPANION_PORT}"),
        name: name.to_string(),
        code: if PHONE_CAN_TYPE_CODE { crate::paircode::encode(ip, COMPANION_PORT) } else { None },
        phone_can_type_code: PHONE_CAN_TYPE_CODE,
        phone_can_scan: PHONE_CAN_SCAN,
        payload,
    })
}

/// The three status rows of the home window as machine states, never words (the page picks the words).
/// Unknown is never shown as the good state.
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct HomeRows {
    /// "loaded" | "idle" | "unknown"
    pub model: &'static str,
    /// "linked" | "none" | "unknown"
    pub phone: &'static str,
    /// "open" | "blocked" | "unknown"
    pub firewall: &'static str,
}

pub fn home_rows(s: &StatusView) -> HomeRows {
    HomeRows {
        model: match s.model_idle { Some(true) => "idle", Some(false) => "loaded", None => "unknown" },
        phone: match s.paired { Some(true) => "linked", Some(false) => "none", None => "unknown" },
        firewall: match s.lan_reachable { Some(true) => "open", Some(false) => "blocked", None => "unknown" },
    }
}

/// The companion answers its loopback owner route: up. Anything else, including a refused connection, is down.
pub fn service_state(companion_answers: bool) -> &'static str { if companion_answers { "up" } else { "down" } }

/// What the home window asks for about every two seconds: the pairing block (None when this computer has no
/// private address, which is its own state D) and the rows.
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct HomeView {
    /// "up" (the companion answers), "recovering" (it does not, a silent restart was just made: no card) or "down" (three restarts failed: the one card with Restart).
    pub service: &'static str,
    pub pair: Option<PairView>,
    pub rows: HomeRows,
    pub model: String,
    pub helper_missing: bool,
}

/// GET a loopback path on the companion. Host header is 127.0.0.1:<port>, as its owner routes require.
fn loopback_get(port: u16, path: &str) -> Option<(u16, String)> {
    loopback_get_with(port, path, "")
}

/// Same, with extra raw header lines (each ending in CRLF), for tests of the companion's gate.
fn loopback_get_with(port: u16, path: &str, extra: &str) -> Option<(u16, String)> {
    loopback_request(port, "GET", path, extra, "")
}

/// One HTTP/1.1 request to the companion on loopback. Never sends an Origin header. A POST carries the
/// content headers the companion's owner gate demands.
fn loopback_request(port: u16, method: &str, path: &str, extra: &str, body: &str) -> Option<(u16, String)> {
    let start = Instant::now();
    let mut s = TcpStream::connect_timeout(&SocketAddr::from(([127, 0, 0, 1], port)), Duration::from_secs(2)).ok()?;
    s.set_write_timeout(Some(Duration::from_secs(2))).ok()?;
    let post = if method == "POST" {
        format!("X-ArrowBridge-Owner: 1\r\nContent-Type: application/json\r\nContent-Length: {}\r\n", body.len())
    } else {
        String::new()
    };
    s.write_all(format!("{method} {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n{post}{extra}Connection: close\r\n\r\n{body}").as_bytes()).ok()?;
    // The read is bounded twice: by size (take of cap + 1, more than the cap is None) and by a total deadline
    // (each read's timeout shrinks to the time left, so a server that trickles bytes cannot hold the caller).
    let mut raw_bytes: Vec<u8> = Vec::new();
    let mut limited = (&mut s).take(MAX_REPLY_BYTES + 1);
    let mut chunk = [0u8; 4096];
    loop {
        let left = TOTAL_DEADLINE.checked_sub(start.elapsed())?;
        limited.get_ref().set_read_timeout(Some(left.min(Duration::from_secs(2)).max(Duration::from_millis(1)))).ok()?;
        match limited.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => raw_bytes.extend_from_slice(&chunk[..n]),
            Err(_) => return None,
        }
        if raw_bytes.len() as u64 > MAX_REPLY_BYTES {
            return None;
        }
    }
    let raw = String::from_utf8(raw_bytes).ok()?;
    let status: u16 = raw.lines().next()?.split_whitespace().nth(1)?.parse().ok()?;
    let body = raw.split("\r\n\r\n").nth(1).unwrap_or("").to_string();
    Some((status, body))
}

/// Why the companion stopped a pairing, from `last_abort` on GET /pair-status.
#[derive(Debug, Clone, Copy, PartialEq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AbortReason {
    Overlap,
    Mismatch,
    Unexpected,
}

/// What the pair window shows about the handshake. It never carries a code: the companion no longer sends one
/// (the owner types the six digits the phone shows), and nothing here could hold one.
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum PairState {
    /// No pairing window is open (the companion answers 404).
    Closed,
    /// Window open, the phone has not revealed yet: nothing to type.
    Waiting,
    /// The phone has revealed: the owner types the code it shows. The id is a handshake id, not a secret.
    Revealed { handshake_id: String },
    /// The owner's code was accepted; the phone has yet to finish.
    Confirmed,
    /// Both sides agreed and the phone is connected (the companion reports paired after the window closes).
    Paired,
    /// The companion stopped the pairing (window closed with a recorded reason).
    Aborted { reason: AbortReason },
    /// Could not be determined.
    Unknown,
}

fn abort_reason(v: &serde_json::Value) -> Option<AbortReason> {
    match v.get("last_abort").and_then(|a| a.as_str()) {
        Some("overlap") => Some(AbortReason::Overlap),
        Some("mismatch") => Some(AbortReason::Mismatch),
        Some("unexpected") => Some(AbortReason::Unexpected),
        _ => None,
    }
}

/// Parse the body of a 200 from GET /pair-status. `open:false` with a known `last_abort` is an abort; an open
/// window is Waiting until `revealed` is true with a handshake id. Anything else is Unknown.
pub fn parse_pair_status(body: &str) -> PairState {
    let Ok(v) = serde_json::from_str::<serde_json::Value>(body) else { return PairState::Unknown };
    // A companion that does not echo the typed-six protocol, or that still sends a code at all, is an older
    // shape this client must not drive: the owner would be shown a state it cannot trust.
    if v.get("pair_protocol").and_then(|p| p.as_str()) != Some(PAIR_PROTOCOL) || v.get("code").is_some() {
        return PairState::Unknown;
    }
    match v.get("open").and_then(|o| o.as_bool()) {
        Some(false) => match abort_reason(&v) {
            Some(reason) => PairState::Aborted { reason },
            // A finished pairing answers open:false with paired:true (the status text shows it).
            None if v.get("paired").and_then(|p| p.as_bool()) == Some(true) => PairState::Paired,
            None => PairState::Unknown,
        },
        Some(true) => {
            if v.get("machine_confirmed").and_then(|m| m.as_bool()) == Some(true) {
                return PairState::Confirmed;
            }
            if v.get("revealed").and_then(|r| r.as_bool()) == Some(true) {
                return match v.get("handshake_id").and_then(|h| h.as_str()) {
                    Some(h) if handshake_id_ok(h) => PairState::Revealed { handshake_id: h.to_string() },
                    _ => PairState::Unknown,
                };
            }
            PairState::Waiting
        }
        None => PairState::Unknown,
    }
}

/// Poll the companion's loopback owner route (no key, no Origin).
pub fn fetch_pair_state(port: u16) -> PairState {
    match loopback_get(port, "/pair-status") {
        Some((200, body)) => parse_pair_status(&body),
        Some((404, _)) => PairState::Closed,
        _ => PairState::Unknown,
    }
}

/// The six digits the owner typed. Holds a secret for as long as the pairing lasts: Debug redacts it, the type
/// has no Serialize, and nothing in this module logs.
pub struct TypedCode(String);

impl std::fmt::Debug for TypedCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "TypedCode(<redacted>)")
    }
}

impl TypedCode {
    /// Exactly six ASCII digits, nothing else (no whitespace, no other-script digits).
    pub fn parse(s: &str) -> Option<TypedCode> {
        if s.len() == 6 && s.bytes().all(|b| b.is_ascii_digit()) { Some(TypedCode(s.to_string())) } else { None }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ConfirmResult {
    /// 200 machine_confirmed.
    Confirmed,
    /// 409 pair_code_mismatch: the one try is spent and the window is closed.
    Mismatch,
    /// 409 pair_aborted_overlap.
    Overlap,
    /// Not six digits (refused here, or 400 code_format from the companion): not an attempt.
    CodeFormat,
    Failed,
}

/// The pair window's Connect: re-reads /pair-status first and posts the code only while that same handshake is
/// revealed by a companion that echoes the typed6 protocol (reviewed at 5f7d8d9). Anything else sends nothing.
pub fn confirm_if_revealed(port: u16, handshake_id: &str, code: &str) -> ConfirmResult {
    match fetch_pair_state(port) {
        PairState::Revealed { handshake_id: h } if h == handshake_id => confirm_pairing(port, handshake_id, code),
        _ => ConfirmResult::Failed,
    }
}

/// POST /pair-confirm {"handshake_id", "code"} through the owner route.
pub fn confirm_pairing(port: u16, handshake_id: &str, code: &str) -> ConfirmResult {
    let Some(code) = TypedCode::parse(code) else { return ConfirmResult::CodeFormat };
    if !handshake_id_ok(handshake_id) {
        return ConfirmResult::Failed;
    }
    let body = serde_json::json!({ "handshake_id": handshake_id, "code": code.0 }).to_string();
    match loopback_request(port, "POST", "/pair-confirm", "", &body) {
        // Confirmed only when the 200 body echoes machine_confirmed true AND the typed-six protocol.
        Some((200, b)) => match serde_json::from_str::<serde_json::Value>(&b) {
            Ok(v) if v.get("machine_confirmed").and_then(|m| m.as_bool()) == Some(true)
                && v.get("pair_protocol").and_then(|p| p.as_str()) == Some(PAIR_PROTOCOL) => ConfirmResult::Confirmed,
            _ => ConfirmResult::Failed,
        },
        Some((409, b)) => match serde_json::from_str::<serde_json::Value>(&b).ok().and_then(|v| v.get("error").and_then(|e| e.as_str().map(String::from))).as_deref() {
            Some("pair_code_mismatch") => ConfirmResult::Mismatch,
            Some("pair_aborted_overlap") => ConfirmResult::Overlap,
            _ => ConfirmResult::Failed,
        },
        Some((400, b)) if b.contains("code_format") => ConfirmResult::CodeFormat,
        _ => ConfirmResult::Failed,
    }
}

/// POST /pair-cancel, the owner's "Not me": the companion closes the window.
pub fn cancel_pairing(port: u16) -> bool {
    matches!(loopback_request(port, "POST", "/pair-cancel", "", "{}"), Some((200, _)))
}

#[derive(Debug, PartialEq)]
pub enum OpenResult {
    Opened,
    /// The companion's phone limit (409).
    PhoneLimit,
    Failed,
}

/// Open the pairing window through the companion's owner route POST /pair-open.
pub fn open_pairing(port: u16) -> OpenResult {
    match loopback_request(port, "POST", "/pair-open", "", "{}") {
        Some((200, _)) => OpenResult::Opened,
        Some((409, _)) => OpenResult::PhoneLimit,
        _ => OpenResult::Failed,
    }
}

/// `{"phones":[...]}` with at least one entry means paired. Anything else is unknown, never "not paired".
pub fn paired_from_body(body: &str) -> Option<bool> {
    let v: serde_json::Value = serde_json::from_str(body).ok()?;
    Some(!v.get("phones")?.as_array()?.is_empty())
}

pub fn fetch_paired(port: u16) -> Option<bool> {
    match loopback_get(port, "/pair-phones")? {
        (200, body) => paired_from_body(&body),
        _ => None,
    }
}

pub fn lan_reachable(ip: Ipv4Addr, port: u16) -> bool {
    TcpStream::connect_timeout(&SocketAddr::from((ip, port)), Duration::from_secs(2)).is_ok()
}

/// The three things the status window shows. None = could not be determined (never rendered as false).
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct StatusView {
    pub paired: Option<bool>,
    pub model: String,
    /// Some(true) = llama-server has unloaded the model (idle), Some(false) = loaded. None = unknown.
    pub model_idle: Option<bool>,
    pub lan_reachable: Option<bool>,
    /// The firewall helper from the package is not on this machine (AppImage run).
    pub helper_missing: bool,
    /// Which llama-server build runs ("vulkan" or "cpu"); None when not a packaged install or not started yet.
    pub llama_variant: Option<String>,
    /// The Vulkan build failed and the CPU build was switched in (once per app start).
    pub vulkan_failed: bool,
    /// Which slowness line to show: "specific" (a model above E4B runs), "generic" (tier unknown), or None.
    pub slowness: Option<String>,
}

/// llama-server's /props carries `is_sleeping` (bool). It stays answerable while the model is unloaded, unlike
/// the completion routes. Anything else (no answer, not 200, no such field, a non-bool) is unknown, never "loaded".
pub fn parse_is_sleeping(body: &str) -> Option<bool> {
    serde_json::from_str::<serde_json::Value>(body).ok()?.get("is_sleeping")?.as_bool()
}

/// `key` is llama-server's API key, read from its 0600 file by the caller; it goes only into the Authorization
/// header of this one request and is never logged or returned.
pub fn fetch_model_idle(llama_port: u16, key: Option<&str>) -> Option<bool> {
    let auth = key.map(|k| format!("Authorization: Bearer {k}\r\n")).unwrap_or_default();
    match loopback_get_with(llama_port, "/props", &auth)? {
        (200, body) => parse_is_sleeping(&body),
        _ => None,
    }
}

pub fn status_view(port: u16, llama_port: u16, llama_key: Option<&str>, lan: Option<Ipv4Addr>, model_note: &str, helper: &Path, llama_variant: Option<String>, vulkan_failed: bool) -> StatusView {
    StatusView {
        paired: fetch_paired(port),
        model: model_note.to_string(),
        model_idle: fetch_model_idle(llama_port, llama_key),
        lan_reachable: lan.map(|ip| lan_reachable(ip, port)),
        helper_missing: !helper.exists(),
        llama_variant,
        vulkan_failed,
        slowness: None,
    }
}

const STATUS_RAW: &str = include_str!("../strings/status.json");

#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct StatusLang {
    /// The home window's words (the drawn window). PENDING while a `pending` key is in it.
    pub home: std::collections::BTreeMap<String, String>,
    pub loaded: String,
    pub idle: String,
    pub first_answer: String,
    pub keep_awake_heading: String,
    pub keep_awake_body: String,
    pub helper_missing: String,
    pub above_command: String,
    pub open_pairing: String,
    pub retry_firewall: String,
    pub reachable_label: String,
    pub qr_alt: String,
    pub no_qr: String,
    pub note_preparing: String,
    pub note_starting: String,
    pub note_unavailable: String,
    pub tray_status_window: String,
    pub tray_paired: String,
    pub tray_unpaired: String,
    pub slowness_generic: String,
    pub unknown: String,
    pub unknown_detail: String,
    pub vulkan_failed: String,
    pub engine_vulkan: String,
    pub engine_cpu: String,
    pub low_memory: String,
    pub memory_unknown: String,
    pub no_fit: String,
    pub status_title: String,
    pub paired_label: String,
    pub paired_yes: String,
    pub paired_no: String,
    pub paired_unknown: String,
    pub model_label: String,
    pub model_loaded: String,
    pub model_idle: String,
    pub model_unknown: String,
    pub pair_title: String,
    pub pair_scan: String,
    pub pair_label: String,
    pub pair_p_code: String,
    pub pair_hint: String,
    pub pair_yes: String,
    pub pair_no: String,
    pub pair_why_h: String,
    pub pair_why_p: String,
    pub pair_mismatch: String,
    pub pair_overlap: String,
    pub pair_unexpected: String,
    pub pair_confirmed_h: String,
    pub pair_confirmed_p: String,
    pub pair_failed: String,
    pub pair_code_format: String,
    pub pair_paired_h: String,
    pub pair_paired_p: String,
    pub fw_cancelled: String,
    pub no_firewall: String,
    pub slowness: String,
}

#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct StatusTexts {
    pub en: StatusLang,
    pub fr: StatusLang,
    pub command_template: String,
}

/// The status and pair windows' words. `cidr` fills the untranslated command box (None: no private network).
pub fn status_texts(cidr: Option<&str>) -> (StatusTexts, Option<String>) {
    let t: StatusTexts = serde_json::from_str(STATUS_RAW).expect("strings/status.json is part of the build");
    let cmd = cidr.map(|c| t.command_template.replace("<cidr>", c));
    (t, cmd)
}

#[derive(Debug, PartialEq)]
pub struct FirstInstall {
    /// None: no prompt was shown (marker present, or no private address).
    pub firewall: Option<Result<FwOutcome, String>>,
    pub open_pair_window: bool,
}

const MARKER: &str = "first-install-done";

/// Ask for the firewall rule (the elevated prompt). The marker is written only when the prompt reached a
/// definite answer: the rule is in (Done) or there is no firewall to configure (NoFirewall). A cancel, a failure
/// or a bad mask leaves no marker, so the next start asks again.
fn apply_firewall(data_dir: &Path, lan: (Ipv4Addr, Ipv4Addr), pkexec: &Path, helper: &Path) -> Result<FwOutcome, String> {
    // The helper comes from the Arch package. Without it there is no prompt and no marker: the status says so.
    if !helper.exists() {
        return Ok(FwOutcome::HelperMissing);
    }
    let r = firewall::cidr_from(lan.0, lan.1).and_then(|c| firewall::allow(pkexec, helper, &c));
    if matches!(r, Ok(FwOutcome::Done) | Ok(FwOutcome::NoFirewall)) {
        let _ = std::fs::create_dir_all(data_dir);
        let _ = std::fs::write(data_dir.join(MARKER), b"1");
    }
    r
}

/// At the end of the first install: the one elevated prompt (firewall allow), then ask for the pair window.
/// Needs a private address (no address, no QR, nothing to allow): nothing happens. The pair window opens only
/// once the prompt has been answered.
pub fn first_install(data_dir: &Path, lan: Option<(Ipv4Addr, Ipv4Addr)>, pkexec: &Path, helper: &Path) -> FirstInstall {
    let none = FirstInstall { firewall: None, open_pair_window: false };
    if data_dir.join(MARKER).exists() {
        return none;
    }
    let Some(lan) = lan else { return none };
    let fw = apply_firewall(data_dir, lan, pkexec, helper);
    let open = data_dir.join(MARKER).exists();
    FirstInstall { firewall: Some(fw), open_pair_window: open }
}

/// The status window's retry button: ask for the firewall rule again.
pub fn retry_firewall(data_dir: &Path, lan: Option<(Ipv4Addr, Ipv4Addr)>, pkexec: &Path, helper: &Path) -> Result<FwOutcome, String> {
    apply_firewall(data_dir, lan.ok_or("no private network address")?, pkexec, helper)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;
    use std::process::Command;
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;

    fn ip(s: &str) -> Ipv4Addr { s.parse().unwrap() }
    fn tmp(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("pairing-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn payload_is_exactly_address_and_name() {
        assert_eq!(qr_payload(ip("192.168.1.20"), 8788, "box").unwrap(), r#"{"address":"http://192.168.1.20:8788","name":"box"}"#);
        let v: serde_json::Value = serde_json::from_str(&qr_payload(ip("10.0.0.5"), 8788, "n").unwrap()).unwrap();
        let mut keys: Vec<_> = v.as_object().unwrap().keys().cloned().collect();
        keys.sort();
        assert_eq!(keys, vec!["address", "name"]);
    }

    /// Byte-for-byte against the real companion: fixtures were produced by running json.dumps(
    /// companion_server._pairing_qr_payload(address, name), separators=(",",":"), sort_keys=True).
    #[test]
    fn payload_matches_the_real_companion_fixture_exactly() {
        let v: Vec<serde_json::Value> = serde_json::from_str(include_str!("fixtures/pair_payload.json")).unwrap();
        assert_eq!(v.len(), 2);
        for f in v {
            let got = qr_payload(ip(f["ip"].as_str().unwrap()), 8788, f["name"].as_str().unwrap()).unwrap();
            assert_eq!(got, f["payload"].as_str().unwrap());
        }
    }

    /// By hand only: needs COMPANION_DIR (the companion checkout), COMPANION_PYTHON, COMPANION_TEST_PORT and
    /// COMPANION_STATE_DIR. Starts a real companion on loopback and checks the /pair-phones gate.
    #[test]
    #[ignore]
    fn real_companion_pair_phones_gate() {
        let dir = std::env::var("COMPANION_DIR").unwrap();
        let py = std::env::var("COMPANION_PYTHON").unwrap();
        let port: u16 = std::env::var("COMPANION_TEST_PORT").unwrap().parse().unwrap();
        let state = std::env::var("COMPANION_STATE_DIR").unwrap();
        assert!(![8788, 8080, 11434].contains(&port));
        let mut child = Command::new(py).arg("-I").arg(format!("{dir}/companion_server.py"))
            .env("ARROWBRIDGE_PORT", port.to_string()).env("ARROWBRIDGE_BIND", "127.0.0.1")
            .env("ARROWBRIDGE_STATE_DIR", &state).env("ARROWBRIDGE_UPSTREAM_URL", "http://127.0.0.1:9")
            .env("ARROWBRIDGE_UPSTREAM_MODEL", "local").env("ARROWBRIDGE_PAIR_KEY", "throwaway-test-key-not-real")
            .stdin(std::process::Stdio::null()).stdout(std::process::Stdio::null()).stderr(std::process::Stdio::null())
            .spawn().unwrap();
        let mut up = false;
        for _ in 0..50 {
            if TcpStream::connect(("127.0.0.1", port)).is_ok() { up = true; break; }
            std::thread::sleep(Duration::from_millis(200));
        }
        let plain = loopback_get(port, "/pair-phones");
        let with_origin = loopback_get_with(port, "/pair-phones", "Origin: http://evil.example\r\n");
        let paired = fetch_paired(port);
        let closed_before = fetch_pair_state(port);
        let opened = open_pairing(port);
        let waiting = fetch_pair_state(port);
        let _ = child.kill();
        let _ = child.wait();
        let gone = TcpStream::connect(("127.0.0.1", port)).is_err();
        println!("up={up} plain={plain:?} origin={with_origin:?} paired={paired:?} closed_before={closed_before:?} opened={opened:?} waiting={waiting:?} process_gone={gone}");
        assert_eq!((closed_before, opened, waiting), (PairState::Closed, OpenResult::Opened, PairState::Waiting));
        assert!(up && gone);
        assert_eq!(plain.as_ref().map(|p| p.0), Some(200));
        assert_eq!(paired, Some(false));
        assert_eq!(with_origin.map(|p| p.0), Some(404));
    }

    // ---- release gate: this module's client against the REAL companion, phone played by tests/phone_side.py ----

    struct RealCompanion { child: std::process::Child, port: u16 }
    impl Drop for RealCompanion {
        fn drop(&mut self) { let _ = self.child.kill(); let _ = self.child.wait(); }
    }

    fn real_companion(port: u16) -> RealCompanion {
        let dir = std::env::var("COMPANION_DIR").unwrap();
        let py = std::env::var("COMPANION_PYTHON").unwrap();
        let state = format!("{}/p{port}", std::env::var("COMPANION_STATE_DIR").unwrap());
        let _ = std::fs::remove_dir_all(&state);
        std::fs::create_dir_all(&state).unwrap();
        std::fs::set_permissions(&state, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert!((18799..=18806).contains(&port));
        let child = Command::new(py).arg("-I").arg(format!("{dir}/companion_server.py"))
            .env("ARROWBRIDGE_PORT", port.to_string()).env("ARROWBRIDGE_BIND", "127.0.0.1")
            .env("ARROWBRIDGE_STATE_DIR", &state).env("ARROWBRIDGE_UPSTREAM_URL", "http://127.0.0.1:9")
            .env("ARROWBRIDGE_UPSTREAM_MODEL", "local").env("ARROWBRIDGE_PAIR_KEY", "throwaway-test-key-not-real")
            .stdin(std::process::Stdio::null()).stdout(std::process::Stdio::null()).stderr(std::process::Stdio::null())
            .spawn().unwrap();
        let c = RealCompanion { child, port };
        let mut up = false;
        for _ in 0..50 {
            if TcpStream::connect(("127.0.0.1", port)).is_ok() { up = true; break; }
            std::thread::sleep(Duration::from_millis(200));
        }
        assert!(up, "companion did not come up");
        c
    }

    /// Run the Python phone side; returns (handshake_id, code) (code None for start-only).
    fn phone(port: u16, mode: &str) -> (Option<String>, Option<String>, u64) {
        let py = std::env::var("COMPANION_PYTHON").unwrap();
        let script = format!("{}/../tests/phone_side.py", env!("CARGO_MANIFEST_DIR"));
        let out = Command::new(py).arg("-I").arg(script).arg(port.to_string()).arg(mode).output().unwrap();
        assert!(out.status.success(), "phone_side failed: {}", String::from_utf8_lossy(&out.stderr));
        let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
        (v["handshake_id"].as_str().map(String::from), v["code"].as_str().map(String::from), v["status"].as_u64().unwrap())
    }

    fn other_code(code: &str) -> String {
        let n: u32 = code.parse().unwrap();
        format!("{:06}", (n + 1) % 1_000_000)
    }

    fn port_env(n: u16) -> u16 { let _ = std::env::var("COMPANION_DIR").unwrap(); n }

    #[test]
    #[ignore]
    fn real_pair_right_digits_confirm() {
        let c = real_companion(port_env(18803));
        assert_eq!(open_pairing(c.port), OpenResult::Opened);
        let (hid, code, st) = phone(c.port, "start-reveal");
        let (hid, code) = (hid.unwrap(), code.unwrap());
        let revealed = fetch_pair_state(c.port);
        let result = confirm_pairing(c.port, &hid, &code);
        let after = fetch_pair_state(c.port);
        println!("case1 start_status={st} revealed={revealed:?} confirm={result:?} after={after:?}");
        assert_eq!(revealed, PairState::Revealed { handshake_id: hid.clone() });
        assert_eq!(result, ConfirmResult::Confirmed);
        assert_eq!(after, PairState::Confirmed);
    }

    #[test]
    #[ignore]
    fn real_pair_wrong_digits_mismatch_closes_window() {
        let c = real_companion(port_env(18804));
        assert_eq!(open_pairing(c.port), OpenResult::Opened);
        let (hid, code, _) = phone(c.port, "start-reveal");
        let (hid, code) = (hid.unwrap(), code.unwrap());
        let wrong = confirm_pairing(c.port, &hid, &other_code(&code));
        let state = fetch_pair_state(c.port);
        let right_after = confirm_pairing(c.port, &hid, &code);
        println!("case2 wrong={wrong:?} state={state:?} right_after={right_after:?}");
        assert_eq!(wrong, ConfirmResult::Mismatch);
        assert_eq!(state, PairState::Aborted { reason: AbortReason::Mismatch });
        assert_ne!(right_after, ConfirmResult::Confirmed);
    }

    #[test]
    #[ignore]
    fn real_pair_overlap_aborts_first_handshake() {
        let c = real_companion(port_env(18805));
        assert_eq!(open_pairing(c.port), OpenResult::Opened);
        let (hid, code, _) = phone(c.port, "start-reveal");
        let (hid, code) = (hid.unwrap(), code.unwrap());
        let (_, _, second_status) = phone(c.port, "start-only");
        let state = fetch_pair_state(c.port);
        let result = confirm_pairing(c.port, &hid, &code);
        println!("case3 second_start_status={second_status} state={state:?} confirm_first={result:?}");
        assert_eq!(state, PairState::Aborted { reason: AbortReason::Overlap });
        assert_ne!(result, ConfirmResult::Confirmed);
    }

    #[test]
    #[ignore]
    fn real_pair_non_ascii_digits_never_reach_the_companion() {
        let c = real_companion(port_env(18806));
        assert_eq!(open_pairing(c.port), OpenResult::Opened);
        let (hid, code, _) = phone(c.port, "start-reveal");
        let (hid, code) = (hid.unwrap(), code.unwrap());
        let arabic = "\u{0661}\u{0662}\u{0663}\u{0664}\u{0665}\u{0666}";
        let fullwidth = "\u{FF11}\u{FF12}\u{FF13}\u{FF14}\u{FF15}\u{FF16}";
        assert!(TypedCode::parse(arabic).is_none() && TypedCode::parse(fullwidth).is_none());
        let a = confirm_pairing(c.port, &hid, arabic);
        let f = confirm_pairing(c.port, &hid, fullwidth);
        let state = fetch_pair_state(c.port);
        let right = confirm_pairing(c.port, &hid, &code);
        println!("case4 arabic={a:?} fullwidth={f:?} state={state:?} right={right:?}");
        assert_eq!((a, f), (ConfirmResult::CodeFormat, ConfirmResult::CodeFormat));
        assert_eq!(state, PairState::Revealed { handshake_id: hid });
        assert_eq!(right, ConfirmResult::Confirmed);
    }

    #[test]
    fn payload_escapes_like_python_ensure_ascii() {
        assert_eq!(qr_payload(ip("10.0.0.5"), 8788, "caf\u{e9} \"x\"\\").unwrap(), r#"{"address":"http://10.0.0.5:8788","name":"caf\u00e9 \"x\"\\"}"#);
        assert!(qr_payload(ip("10.0.0.5"), 8788, "\u{1F600}").unwrap().contains(r"\ud83d\ude00"));
    }

    #[test]
    fn payload_refuses_a_non_private_address() {
        for a in ["8.8.8.8", "127.0.0.1", "0.0.0.0", "169.254.1.1"] { assert!(qr_payload(ip(a), 8788, "n").is_err(), "{a}"); }
    }

    #[test]
    fn svg_is_a_qr_of_the_payload_and_holds_no_key() {
        let p = qr_payload(ip("192.168.1.20"), 8788, "box").unwrap();
        let s = qr_svg(&p).unwrap();
        assert!(s.starts_with("<svg") && s.ends_with("</svg>") && s.matches("<rect").count() > 100);
        let v = pair_view(ip("192.168.1.20"), "box").unwrap();
        assert_eq!(v.address, "http://192.168.1.20:8788");
        assert_eq!(v.payload, p);
        // Phone release 13 (vc17) types the code: the flag is on and the view carries it (pinned here; flip back only with a review note).
        assert!(PHONE_CAN_TYPE_CODE && v.phone_can_type_code);
        assert!(PHONE_CAN_SCAN && v.phone_can_scan, "the QR stays on the window");
        assert_eq!(v.code, crate::paircode::encode(ip("192.168.1.20"), 8788));
        assert!(v.code.as_deref().is_some_and(|c| c.len() == 9 && c.as_bytes()[4] == b'-'));
        assert!(!v.svg.to_lowercase().contains("key") && !v.address.to_lowercase().contains("key"));
        assert_ne!(qr_svg("a").unwrap(), qr_svg("b").unwrap());
        // error level M for this payload is a 33-module (version 4) code: (33 + 2*2) * 6 = 222 px.
        assert!(s.contains("width=\"222\""), "{}", &s[..120]);
    }

    fn status(paired: Option<bool>, idle: Option<bool>, lan: Option<bool>) -> StatusView {
        StatusView { paired, model: "m".into(), model_idle: idle, lan_reachable: lan, helper_missing: false, llama_variant: None, vulkan_failed: false, slowness: None }
    }

    #[test]
    fn a_companion_that_does_not_answer_is_down_never_up() {
        assert_eq!(service_state(true), "up");
        assert_eq!(service_state(false), "down");
        // nothing listens on this port: the real probe says down
        assert_eq!(service_state(fetch_paired(1).is_some()), "down");
    }

    #[test]
    fn home_rows_never_show_unknown_as_the_good_state() {
        assert_eq!(home_rows(&status(Some(true), Some(false), Some(true))), HomeRows { model: "loaded", phone: "linked", firewall: "open" });
        assert_eq!(home_rows(&status(Some(false), Some(true), Some(false))), HomeRows { model: "idle", phone: "none", firewall: "blocked" });
        assert_eq!(home_rows(&status(None, None, None)), HomeRows { model: "unknown", phone: "unknown", firewall: "unknown" });
    }

    #[test]
    fn paired_body_parse_unknown_is_not_false() {
        assert_eq!(paired_from_body(r#"{"phones":[{"id":"x"}],"max":5}"#), Some(true));
        assert_eq!(paired_from_body(r#"{"phones":[],"max":5}"#), Some(false));
        for bad in ["", "{", r#"{"phones":"x"}"#, r#"{"error":"not found"}"#, "<html>"] { assert_eq!(paired_from_body(bad), None, "{bad}"); }
    }

    /// One-shot loopback server answering every request with `status` and `body`; records request heads.
    #[test]
    fn connect_posts_nothing_unless_the_same_handshake_is_revealed() {
        let other = r#"{"pair_protocol":"typed6","open":true,"handshake_id":"other","revealed":true}"#;
        let waiting = r#"{"pair_protocol":"typed6","open":true,"handshake_id":null,"revealed":false}"#;
        let old = r#"{"open":true,"handshake_id":"h1","revealed":true}"#;
        for body in [other, waiting, old] {
            let (p, rx) = serve(200, body);
            assert_eq!(confirm_if_revealed(p, "h1", "123456"), ConfirmResult::Failed, "{body}");
            let first = rx.recv_timeout(Duration::from_secs(2)).unwrap();
            assert!(first.starts_with("GET /pair-status "), "{first}");
            assert!(rx.recv_timeout(Duration::from_millis(300)).is_err(), "no POST may follow for {body}");
        }
    }

    fn serve(status: u16, body: &'static str) -> (u16, std::sync::mpsc::Receiver<String>) {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            for s in l.incoming() {
                let mut s = s.unwrap();
                let mut buf = [0u8; 2048];
                let n = s.read(&mut buf).unwrap_or(0);
                let _ = tx.send(String::from_utf8_lossy(&buf[..n]).into_owned());
                let _ = write!(s, "HTTP/1.1 {status} X\r\nContent-Length: {}\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n{body}", body.len());
            }
        });
        (port, rx)
    }

    #[test]
    fn fetch_paired_reads_the_loopback_route_with_no_credential() {
        let (p, rx) = serve(200, r#"{"phones":[{"a":1}],"max":5}"#);
        assert_eq!(fetch_paired(p), Some(true));
        let head = rx.recv().unwrap();
        assert!(head.starts_with("GET /pair-phones HTTP/1.1") && head.contains(&format!("Host: 127.0.0.1:{p}")), "{head}");
        let lower = head.to_lowercase();
        assert!(!lower.contains("authorization") && !lower.contains("x-arrowbridge-pair"), "{head}");
        let (p2, _r) = serve(200, r#"{"phones":[],"max":5}"#);
        assert_eq!(fetch_paired(p2), Some(false));
        let (p3, _r3) = serve(404, r#"{"error":"not found"}"#);
        assert_eq!(fetch_paired(p3), None);
        let (p4, _r4) = serve(403, r#"{"phones":[{"a":1}]}"#); // a refusal carrying a plausible body is not "paired"
        assert_eq!(fetch_paired(p4), None);
    }

    #[test]
    fn pair_status_states_and_no_code_is_ever_read() {
        assert_eq!(parse_pair_status(r#"{"pair_protocol":"typed6","open":true,"handshake_id":null,"revealed":false,"machine_confirmed":false,"phone_confirmed":false,"last_abort":null}"#), PairState::Waiting);
        assert_eq!(parse_pair_status(r#"{"pair_protocol":"typed6","open":true}"#), PairState::Waiting);
        assert_eq!(parse_pair_status(r#"{"pair_protocol":"typed6","open":true,"handshake_id":"h1","revealed":false}"#), PairState::Waiting);
        let rev = PairState::Revealed { handshake_id: "h1".into() };
        assert_eq!(parse_pair_status(r#"{"pair_protocol":"typed6","open":true,"handshake_id":"h1","revealed":true,"machine_confirmed":false}"#), rev);
        // a code key at all (an older companion) makes the whole status Unknown, and the state cannot carry one
        let with_code = parse_pair_status(r#"{"pair_protocol":"typed6","open":true,"handshake_id":"h1","revealed":true,"code":"482913"}"#);
        assert_eq!(with_code, PairState::Unknown);
        assert!(!format!("{with_code:?}").contains("482913") && !serde_json::to_string(&with_code).unwrap().contains("482913"));
        assert_eq!(serde_json::to_string(&rev).unwrap(), r#"{"state":"revealed","handshake_id":"h1"}"#);
        assert_eq!(parse_pair_status(r#"{"pair_protocol":"typed6","open":true,"handshake_id":"h1","revealed":true,"machine_confirmed":true}"#), PairState::Confirmed);
        assert_eq!(parse_pair_status(r#"{"pair_protocol":"typed6","open":false,"paired":true}"#), PairState::Paired);
    }

    #[test]
    fn old_shape_status_is_unknown() {
        // the 0a90eb5f shape, and one with neither code nor pair_protocol, and a wrong protocol value
        for old in [r#"{"open":true,"handshake_id":"h","code":"0482","revealed":true}"#, r#"{"open":true,"handshake_id":"h","revealed":true}"#,
                    r#"{"open":true,"handshake_id":null,"revealed":false}"#, r#"{"open":false,"paired":true}"#,
                    r#"{"pair_protocol":"typed4","open":true,"handshake_id":"h","revealed":true}"#, r#"{"pair_protocol":6,"open":true}"#,
                    r#"{"pair_protocol":"typed6","open":true,"handshake_id":"h","revealed":true,"code":null}"#] {
            assert_eq!(parse_pair_status(old), PairState::Unknown, "{old}");
        }
    }

    #[test]
    fn handshake_id_is_bounded_and_printable_ascii() {
        let long = "a".repeat(65);
        let ok64 = "a".repeat(64);
        let st = |h: &str| parse_pair_status(&serde_json::json!({"pair_protocol":"typed6","open":true,"handshake_id":h,"revealed":true}).to_string());
        assert_eq!(st(&ok64), PairState::Revealed { handshake_id: ok64.clone() });
        for bad in [long.as_str(), "", "a b", "h\u{e9}", "h\n", "h\u{0}"] { assert_eq!(st(bad), PairState::Unknown, "{bad:?}"); }
        let (p, rx) = serve(200, r#"{"machine_confirmed":true,"pair_protocol":"typed6"}"#);
        assert_eq!(confirm_pairing(p, &long, "482913"), ConfirmResult::Failed);
        assert_eq!(confirm_pairing(p, "h\u{e9}", "482913"), ConfirmResult::Failed);
        assert!(rx.recv_timeout(Duration::from_millis(300)).is_err(), "a request was sent for a bad handshake id");
        assert_eq!(confirm_pairing(p, &ok64, "482913"), ConfirmResult::Confirmed);
    }

    #[test]
    fn a_200_confirm_without_the_echo_is_failed() {
        for body in [r#"{"machine_confirmed":true}"#, r#"{"machine_confirmed":true,"pair_protocol":"typed4"}"#, r#"{"machine_confirmed":false,"pair_protocol":"typed6"}"#,
                     r#"{"pair_protocol":"typed6"}"#, "{}", "ok", ""] {
            let (p, _r) = serve(200, Box::leak(body.to_string().into_boxed_str()));
            assert_eq!(confirm_pairing(p, "h", "111111"), ConfirmResult::Failed, "{body}");
        }
    }

    #[test]
    fn an_oversized_reply_is_none() {
        let big: &'static str = Box::leak(format!("{{\"pad\":\"{}\"}}", "x".repeat(100_000)).into_boxed_str());
        let (p, _r) = serve(200, big);
        assert!(loopback_get(p, "/pair-status").is_none());
        // just under the cap still reads
        let ok: &'static str = Box::leak(format!("{{\"pad\":\"{}\"}}", "x".repeat(60_000)).into_boxed_str());
        let (p2, _r2) = serve(200, ok);
        assert_eq!(loopback_get(p2, "/pair-status").map(|r| r.0), Some(200));
    }

    #[test]
    fn a_server_that_trickles_past_the_total_deadline_is_none() {
        // ~11 s of wall time: one byte a second keeps every per-read timeout alive, only the total deadline stops it.
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        std::thread::spawn(move || {
            if let Some(Ok(mut s)) = l.incoming().next() {
                let mut buf = [0u8; 2048];
                let _ = s.read(&mut buf);
                for b in b"HTTP/1.1 200 X\r\nContent-Length: 999\r\n\r\n".iter().chain(std::iter::repeat(&b'x').take(30)) {
                    if s.write_all(&[*b]).is_err() { break; }
                    std::thread::sleep(Duration::from_millis(1000));
                }
            }
        });
        let t = Instant::now();
        assert!(loopback_get(port, "/pair-status").is_none());
        let took = t.elapsed();
        assert!(took >= Duration::from_secs(9) && took < Duration::from_secs(12), "{took:?}");
    }

    #[test]
    fn each_last_abort_maps_to_its_own_state() {
        for (w, r) in [("overlap", AbortReason::Overlap), ("mismatch", AbortReason::Mismatch), ("unexpected", AbortReason::Unexpected)] {
            assert_eq!(parse_pair_status(&format!(r#"{{"pair_protocol":"typed6","open":false,"last_abort":"{w}"}}"#)), PairState::Aborted { reason: r }, "{w}");
            assert_eq!(serde_json::to_string(&PairState::Aborted { reason: r }).unwrap(), format!(r#"{{"state":"aborted","reason":"{w}"}}"#));
        }
        // an open window that still names the last abort is a live window, not an abort
        assert_eq!(parse_pair_status(r#"{"pair_protocol":"typed6","open":true,"handshake_id":null,"revealed":false,"last_abort":"overlap"}"#), PairState::Waiting);
    }

    #[test]
    fn malformed_status_bodies_are_unknown() {
        for bad in [r#"{"pair_protocol":"typed6","open":false}"#, r#"{"pair_protocol":"typed6","open":false,"last_abort":"surprise"}"#, r#"{"pair_protocol":"typed6","open":false,"last_abort":null}"#, r#"{"pair_protocol":"typed6","open":false,"last_abort":3}"#,
                    r#"{"pair_protocol":"typed6","last_abort":"overlap"}"#, r#"{"pair_protocol":"typed6","open":"yes"}"#, r#"{"pair_protocol":"typed6","open":true,"revealed":true}"#, r#"{"pair_protocol":"typed6","open":true,"revealed":true,"handshake_id":""}"#,
                    r#"{"pair_protocol":"typed6","open":true,"revealed":true,"handshake_id":7}"#, "", "{", "[]", "<html>"] {
            assert_eq!(parse_pair_status(bad), PairState::Unknown, "{bad}");
        }
    }

    #[test]
    fn the_six_digit_validator_is_strict() {
        for ok in ["000000", "482913", "999999"] { assert!(TypedCode::parse(ok).is_some(), "{ok}"); }
        for bad in ["", "12345", "1234567", "12345a", "abcdef", " 12345", "12345 ", "123 456", "123456\n", "12.456", "+12345", "-12345",
                    "\u{661}\u{662}\u{663}\u{664}\u{665}\u{666}", "12345\u{666}", "\u{ff11}\u{ff12}\u{ff13}\u{ff14}\u{ff15}\u{ff16}", "1234\u{0}56"] {
            assert!(TypedCode::parse(bad).is_none(), "{bad:?}");
        }
        assert_eq!(format!("{:?}", TypedCode::parse("482913").unwrap()), "TypedCode(<redacted>)");
        assert!(!format!("{:#?}", TypedCode::parse("482913").unwrap()).contains("482913"));
    }

    #[test]
    fn confirm_is_an_owner_post_with_id_and_code_and_maps_the_answers() {
        let (p, rx) = serve(200, r#"{"machine_confirmed":true,"pair_protocol":"typed6"}"#);
        assert_eq!(confirm_pairing(p, "h-1_x", "482913"), ConfirmResult::Confirmed);
        let head = rx.recv().unwrap();
        assert!(head.starts_with("POST /pair-confirm HTTP/1.1\r\n"), "{head}");
        assert!(head.contains(&format!("Host: 127.0.0.1:{p}\r\n")));
        assert!(head.contains("X-ArrowBridge-Owner: 1\r\n") && head.contains("Content-Type: application/json\r\n"), "{head}");
        assert!(!head.to_lowercase().contains("origin:"));
        let body = head.split("\r\n\r\n").nth(1).unwrap();
        let v: serde_json::Value = serde_json::from_str(body).unwrap();
        assert_eq!(v, serde_json::json!({"handshake_id": "h-1_x", "code": "482913"}));
        assert!(head.contains(&format!("Content-Length: {}\r\n", body.len())), "{head}");
        let (p2, _r) = serve(409, r#"{"error":"pair_code_mismatch"}"#);
        assert_eq!(confirm_pairing(p2, "h", "111111"), ConfirmResult::Mismatch);
        let (p3, _r) = serve(409, r#"{"error":"pair_aborted_overlap"}"#);
        assert_eq!(confirm_pairing(p3, "h", "111111"), ConfirmResult::Overlap);
        let (p4, _r) = serve(400, r#"{"error":"code_format"}"#);
        assert_eq!(confirm_pairing(p4, "h", "111111"), ConfirmResult::CodeFormat);
        let (p5, _r) = serve(409, r#"{"error":"something_else"}"#);
        assert_eq!(confirm_pairing(p5, "h", "111111"), ConfirmResult::Failed);
        let (p6, _r) = serve(404, r#"{"error":"not found"}"#);
        assert_eq!(confirm_pairing(p6, "h", "111111"), ConfirmResult::Failed);
    }

    #[test]
    fn a_malformed_code_is_refused_before_any_request_is_sent() {
        let (p, rx) = serve(200, r#"{"machine_confirmed":true,"pair_protocol":"typed6"}"#);
        for bad in ["12345", "1234567", "12345a", " 12345", "\u{661}\u{662}\u{663}\u{664}\u{665}\u{666}"] {
            assert_eq!(confirm_pairing(p, "h", bad), ConfirmResult::CodeFormat, "{bad:?}");
        }
        assert!(rx.recv_timeout(Duration::from_millis(300)).is_err(), "a request was sent for a malformed code");
    }

    #[test]
    fn cancel_is_an_owner_post() {
        let (p, rx) = serve(200, r#"{"cancelled":true}"#);
        assert!(cancel_pairing(p));
        let head = rx.recv().unwrap();
        assert!(head.starts_with("POST /pair-cancel HTTP/1.1\r\n") && head.contains("X-ArrowBridge-Owner: 1\r\n"), "{head}");
        let (p2, _r) = serve(404, "{}");
        assert!(!cancel_pairing(p2));
    }

    #[test]
    fn nothing_that_handles_the_code_can_log_it() {
        // Static guard over the shipped (non-test) text of the modules that touch the code, and the page script.
        let strip = |s: &str| s.split("#[cfg(test)]").next().unwrap().to_string();
        for (name, text) in [("pairing.rs", strip(include_str!("pairing.rs"))), ("lib.rs", strip(include_str!("lib.rs")))] {
            for bad in ["println!", "eprintln!", "print!(", "dbg!", "log::", "tracing::", "info!(", "warn!(", "debug!("] {
                assert!(!text.contains(bad), "{name} contains {bad}");
            }
        }
        let js = include_str!("../../ui/home.js");
        for bad in ["console.", "localStorage", "sessionStorage", "indexedDB", "document.cookie", "title ="] {
            assert!(!js.contains(bad), "home.js contains {bad}");
        }
    }

    #[test]
    fn pair_status_request_has_the_loopback_host_and_no_origin() {
        let (p, rx) = serve(200, r#"{"pair_protocol":"typed6","open":true,"handshake_id":"h1","revealed":true}"#);
        assert_eq!(fetch_pair_state(p), PairState::Revealed { handshake_id: "h1".into() });
        let head = rx.recv().unwrap();
        assert!(head.starts_with("GET /pair-status HTTP/1.1\r\n"), "{head}");
        assert!(head.contains(&format!("Host: 127.0.0.1:{p}\r\n")));
        let lower = head.to_lowercase();
        assert!(!lower.contains("origin:") && !lower.contains("authorization") && !lower.contains("x-arrowbridge-pair") && !lower.contains("x-forwarded"), "{head}");
        let (p2, _r2) = serve(404, r#"{"error":"not found"}"#);
        assert_eq!(fetch_pair_state(p2), PairState::Closed);
        let (p3, _r3) = serve(500, "{}");
        assert_eq!(fetch_pair_state(p3), PairState::Unknown);
        let (p4, _r4) = serve(200, r#"{"pair_protocol":"typed6","open":false,"last_abort":"mismatch"}"#);
        assert_eq!(fetch_pair_state(p4), PairState::Aborted { reason: AbortReason::Mismatch });
    }

    #[test]
    fn open_pairing_is_an_owner_post_with_the_required_headers() {
        let (p, rx) = serve(200, r#"{"open":true,"expires_in":600}"#);
        assert_eq!(open_pairing(p), OpenResult::Opened);
        let head = rx.recv().unwrap();
        assert!(head.starts_with("POST /pair-open HTTP/1.1\r\n"), "{head}");
        assert!(head.contains(&format!("Host: 127.0.0.1:{p}\r\n")));
        assert!(head.contains("X-ArrowBridge-Owner: 1\r\n") && head.contains("Content-Type: application/json\r\n") && head.contains("Content-Length: 2\r\n"), "{head}");
        assert!(head.ends_with("\r\n\r\n{}"), "{head}");
        assert!(!head.to_lowercase().contains("origin:"));
        let (p2, _r) = serve(409, r#"{"error":"phone_limit","max":5}"#);
        assert_eq!(open_pairing(p2), OpenResult::PhoneLimit);
        let (p3, _r3) = serve(404, "{}");
        assert_eq!(open_pairing(p3), OpenResult::Failed);
        let dead = TcpListener::bind("127.0.0.1:0").unwrap();
        let dp = dead.local_addr().unwrap().port();
        drop(dead);
        assert_eq!(open_pairing(dp), OpenResult::Failed);
    }

    /// A port that is bound but not listening: connects to it are refused, and nothing else can take the port
    /// while the returned socket is alive (the old bind-then-drop version raced with parallel tests).
    fn closed_port() -> (socket2::Socket, u16) {
        let s = socket2::Socket::new(socket2::Domain::IPV4, socket2::Type::STREAM, None).unwrap();
        s.bind(&SocketAddr::from((Ipv4Addr::LOCALHOST, 0)).into()).unwrap();
        let p = s.local_addr().unwrap().as_socket().unwrap().port();
        (s, p)
    }

    #[test]
    fn unreachable_companion_is_unknown() {
        let (_hold, p) = closed_port();
        assert_eq!(fetch_paired(p), None);
    }

    #[test]
    fn lan_reachability_is_a_real_connect() {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        assert!(lan_reachable(ip("127.0.0.1"), l.local_addr().unwrap().port()));
        let (_hold, p) = closed_port();
        assert!(TcpListener::bind(("127.0.0.1", p)).is_err(), "the port must stay taken during the assertion");
        assert!(!lan_reachable(ip("127.0.0.1"), p));
    }

    #[test]
    fn is_sleeping_parse_unknown_stays_unknown() {
        assert_eq!(parse_is_sleeping(r#"{"is_sleeping":true,"x":1}"#), Some(true));
        assert_eq!(parse_is_sleeping(r#"{"is_sleeping":false}"#), Some(false));
        for bad in ["", "not json", "{}", r#"{"is_sleeping":"true"}"#, r#"{"is_sleeping":null}"#, "[]"] {
            assert_eq!(parse_is_sleeping(bad), None, "{bad}");
        }
    }

    /// The real pinned llama-server's /props, recorded awake and asleep (see record_real_props_awake_and_asleep).
    /// Only the model path was changed (the home directory is replaced); is_sleeping is the one field that differs.
    const PROPS_AWAKE: &str = include_str!("fixtures/props_awake.json");
    const PROPS_ASLEEP: &str = include_str!("fixtures/props_asleep.json");

    #[test]
    fn the_recorded_real_props_parse_awake_and_asleep() {
        assert_eq!(parse_is_sleeping(PROPS_AWAKE), Some(false));
        assert_eq!(parse_is_sleeping(PROPS_ASLEEP), Some(true));
        let (a, s): (serde_json::Value, serde_json::Value) = (serde_json::from_str(PROPS_AWAKE).unwrap(), serde_json::from_str(PROPS_ASLEEP).unwrap());
        let mut a2 = a.clone();
        a2["is_sleeping"] = serde_json::Value::Bool(true);
        assert_eq!(a2, s, "is_sleeping is the only field that differs between the two recordings");
        assert_eq!(a["build_info"], "b11840-36e36e63a");
        assert!(!PROPS_AWAKE.contains("/home/") && !PROPS_ASLEEP.contains("/home/"));
    }

    #[test]
    fn the_recorded_props_drive_the_status_read() {
        let (p, _r) = serve(200, PROPS_ASLEEP);
        assert_eq!(fetch_model_idle(p, Some("k")), Some(true));
        let (p2, _r2) = serve(200, PROPS_AWAKE);
        assert_eq!(fetch_model_idle(p2, Some("k")), Some(false));
    }

    #[test]
    fn model_idle_reads_props_on_loopback_and_non_200_is_unknown() {
        let (p, r) = serve(200, r#"{"is_sleeping":true}"#);
        assert_eq!(fetch_model_idle(p, None), Some(true));
        assert!(r.recv().unwrap().starts_with("GET /props "));
        let (p2, _r2) = serve(503, r#"{"is_sleeping":true}"#);
        assert_eq!(fetch_model_idle(p2, None), None, "a loading server must not be read as idle");
        let (_hold, closed) = closed_port();
        assert_eq!(fetch_model_idle(closed, None), None);
    }

    #[test]
    fn the_status_read_sends_the_key_as_a_bearer_header_and_only_when_it_has_one() {
        let key = "ab".repeat(32);
        let (p, r) = serve(200, r#"{"is_sleeping":false}"#);
        assert_eq!(fetch_model_idle(p, Some(&key)), Some(false));
        let req = r.recv().unwrap();
        assert!(req.contains(&format!("Authorization: Bearer {key}\r\n")), "{req}");
        assert!(req.starts_with("GET /props HTTP/1.1\r\nHost: 127.0.0.1:") && !req.to_lowercase().contains("origin:"));
        let (p2, r2) = serve(401, r#"{"error":"no key"}"#);
        assert_eq!(fetch_model_idle(p2, None), None, "a refused read is unknown");
        assert!(!r2.recv().unwrap().contains("Authorization"));
    }

    /// By hand only. Needs HAND_LLAMA_BIN (the pinned llama-server), HAND_MODEL (a gguf) and HAND_PORT (a spare
    /// port, never 8080). Starts the real server exactly as the unit does (key file, no web UI, localhost-only CORS),
    /// then checks /props answers 401 with no key, 401 with a wrong key and 200 with the right one, that a foreign
    /// Origin is not allowed, and that the status read works with the key. Stops it by PID and checks the port is free.
    #[test]
    #[ignore]
    fn real_llama_server_refuses_without_the_key() {
        let bin = std::env::var("HAND_LLAMA_BIN").unwrap();
        let model = std::env::var("HAND_MODEL").unwrap();
        let port: u16 = std::env::var("HAND_PORT").unwrap().parse().unwrap();
        assert!(![8080, 8788, 11434].contains(&port));
        let d = tmp("hand");
        crate::apikey::rotate(&d).unwrap();
        let key = crate::apikey::read_key(&d).unwrap();
        let mut child = Command::new(&bin)
            .args(["--host", "127.0.0.1", "--port", &port.to_string(), "--models-max", "1", "--sleep-idle-seconds", "600"])
            .arg("--api-key-file").arg(d.join("llama-api-key"))
            .args(["--no-webui", "--cors-origins", "localhost", "--no-cors-credentials", "-m", &model])
            .stdin(std::process::Stdio::null()).stdout(std::process::Stdio::null()).stderr(std::process::Stdio::null())
            .spawn().unwrap();
        let pid = child.id();
        let mut ready = false;
        for _ in 0..240 {
            if loopback_get(port, "/health").map(|r| r.0) == Some(200) { ready = true; break; }
            std::thread::sleep(Duration::from_secs(1));
        }
        let none = loopback_get(port, "/props").map(|r| r.0);
        let wrong = loopback_get_with(port, "/props", "Authorization: Bearer wrong\r\n").map(|r| r.0);
        let right = loopback_get_with(port, "/props", &format!("Authorization: Bearer {key}\r\n")).map(|r| r.0);
        let webui = loopback_get(port, "/").map(|r| r.0);
        let evil = {
            let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
            write!(s, "GET /props HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nOrigin: http://evil.example\r\nAuthorization: Bearer {key}\r\nConnection: close\r\n\r\n").unwrap();
            let mut raw = String::new();
            let _ = s.read_to_string(&mut raw);
            raw.to_lowercase().contains("access-control-allow-origin: http://evil.example") || raw.to_lowercase().contains("access-control-allow-origin: *")
        };
        let idle = fetch_model_idle(port, Some(&key));
        let idle_nokey = fetch_model_idle(port, None);
        let _ = child.kill();
        let _ = child.wait();
        std::thread::sleep(Duration::from_millis(500));
        let free = TcpListener::bind(("127.0.0.1", port)).is_ok();
        println!("pid={pid} ready={ready} no_key={none:?} wrong_key={wrong:?} right_key={right:?} webui_root={webui:?} evil_origin_allowed={evil} idle_with_key={idle:?} idle_no_key={idle_nokey:?} port_free_after={free}");
        assert!(ready);
        assert_eq!((none, wrong, right), (Some(401), Some(401), Some(200)));
        assert!(!evil);
        assert_eq!(idle_nokey, None);
        assert!(idle.is_some());
        assert!(free);
    }

    /// By hand only: records /props awake and asleep from the real pinned server into HAND_FIXTURE_DIR. Needs
    /// HAND_LLAMA_BIN, HAND_MODEL, HAND_PORT (never 8080). Starts it with --sleep-idle-seconds 10 and a key file,
    /// reads /props, sends one tiny completion, waits 20 s, reads /props again, stops it by PID, checks the port.
    #[test]
    #[ignore]
    fn record_real_props_awake_and_asleep() {
        let bin = std::env::var("HAND_LLAMA_BIN").unwrap();
        let model = std::env::var("HAND_MODEL").unwrap();
        let port: u16 = std::env::var("HAND_PORT").unwrap().parse().unwrap();
        let out = std::path::PathBuf::from(std::env::var("HAND_FIXTURE_DIR").unwrap());
        assert!(![8080, 8788, 11434].contains(&port));
        let d = tmp("record");
        crate::apikey::rotate(&d).unwrap();
        let key = crate::apikey::read_key(&d).unwrap();
        let mut child = Command::new(&bin)
            .args(["--host", "127.0.0.1", "--port", &port.to_string(), "--models-max", "1", "--sleep-idle-seconds", "10"])
            .arg("--api-key-file").arg(d.join("llama-api-key"))
            .args(["--no-webui", "--cors-origins", "localhost", "--no-cors-credentials", "-m", &model])
            .stdin(std::process::Stdio::null()).stdout(std::process::Stdio::null()).stderr(std::process::Stdio::null())
            .spawn().unwrap();
        let pid = child.id();
        for _ in 0..240 {
            if loopback_get(port, "/health").map(|r| r.0) == Some(200) { break; }
            std::thread::sleep(Duration::from_secs(1));
        }
        let auth = format!("Authorization: Bearer {key}\r\n");
        let awake = loopback_get_with(port, "/props", &auth);
        let body = r#"{"model":"local","messages":[{"role":"user","content":"hi"}],"max_tokens":1}"#;
        let comp = {
            let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
            s.set_read_timeout(Some(Duration::from_secs(120))).unwrap();
            write!(s, "POST /v1/chat/completions HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n{auth}Content-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).unwrap();
            let mut raw = String::new();
            let _ = s.read_to_string(&mut raw);
            raw.lines().next().unwrap_or("").to_string()
        };
        std::thread::sleep(Duration::from_secs(20));
        let asleep = loopback_get_with(port, "/props", &auth);
        let health_asleep = loopback_get(port, "/health").map(|r| r.0);
        let _ = child.kill();
        let _ = child.wait();
        std::thread::sleep(Duration::from_millis(500));
        let free = TcpListener::bind(("127.0.0.1", port)).is_ok();
        let (a, s) = (awake.clone().unwrap(), asleep.clone().unwrap());
        std::fs::create_dir_all(&out).unwrap();
        std::fs::write(out.join("props_awake.json"), &a.1).unwrap();
        std::fs::write(out.join("props_asleep.json"), &s.1).unwrap();
        println!("pid={pid} awake_status={} asleep_status={} completion={comp:?} health_asleep={health_asleep:?} port_free_after={free} awake_len={} asleep_len={} key_in_bodies={}",
            a.0, s.0, a.1.len(), s.1.len(), a.1.contains(&key) || s.1.contains(&key));
        assert!(free);
    }

    #[test]
    fn status_texts_fill_the_untranslated_command_and_hold_the_tmk_lines() {
        let (t, cmd) = status_texts(Some("192.168.1.0/24"));
        assert_eq!(cmd.as_deref(), Some("sudo ufw allow from 192.168.1.0/24 to any port 8788 proto tcp"));
        assert_eq!(status_texts(None).1, None);
        assert_eq!(t.en.loaded, "Model loaded. Ready to answer.");
        assert_eq!(t.en.idle, "Model idle. It was unloaded after 10 minutes without a question, and it loads again on the next one.");
        assert_eq!(t.en.first_answer, "Loading the model. The first answer can take a moment.");
        assert_eq!(t.en.keep_awake_heading, "Keep your computer awake");
        assert!(t.en.keep_awake_body.starts_with("ArrowBridge answers only while this computer is on"));
        assert!(t.en.helper_missing.contains("the network this computer is connected to"));
        assert!(t.en.above_command.contains("the network this computer is connected to"));
        for l in [&t.en, &t.fr] {
            assert!(!l.loaded.is_empty() && !l.idle.is_empty() && !l.keep_awake_body.is_empty() && !l.helper_missing.is_empty());
        }
        assert_eq!(t.fr.paired_label, "Jumelé :");
        assert_eq!(t.en.pair_label, "Code from your phone");
        assert_eq!(t.en.pair_yes, "Connect");
        assert_eq!(t.en.pair_no, "Not me");
        assert_eq!(t.fr.pair_why_h, "Pourquoi saisir un code ?");
        assert_eq!(t.fr.pair_no, "Ce n'est pas moi");
        for l in [&t.en, &t.fr] {
            for w in [&l.pair_label, &l.pair_p_code, &l.pair_hint, &l.pair_yes, &l.pair_no, &l.pair_why_h, &l.pair_why_p, &l.pair_mismatch, &l.pair_overlap, &l.pair_unexpected] {
                assert!(!w.is_empty() && !w.contains("{code}") && !w.contains("four") && !w.contains("quatre"));
            }
        }
        assert_eq!(t.en.vulkan_failed, "The graphics (Vulkan) build could not start, so ArrowBridge is using the processor (CPU) build instead. It still works, but answers are slower.");
        assert_eq!(t.en.open_pairing, "Open pairing");
        assert_eq!(t.en.retry_firewall, "Retry firewall");
    }

    #[test]
    fn status_has_three_fields_and_none_without_lan() {
        let (p, _r) = serve(200, r#"{"phones":[],"max":5}"#);
        let s = status_view(p, 9, None, None, "model note", Path::new("/nonexistent/helper"), Some("cpu".into()), false);
        assert_eq!(s, StatusView { paired: Some(false), model: "model note".into(), model_idle: None, lan_reachable: None, helper_missing: true, llama_variant: Some("cpu".into()), vulkan_failed: false, slowness: None });
        let s2 = status_view(p, 9, None, Some(ip("127.0.0.1")), "m", Path::new("/"), None, true);
        assert!(s2.vulkan_failed);
        assert!(!s2.helper_missing);
        assert_eq!(s2.lan_reachable, Some(true));
    }

    /// A helper path that exists (so the app calls it directly).
    fn helper_file(d: &Path) -> PathBuf {
        let h = d.join("helper");
        std::fs::write(&h, "x").unwrap();
        h
    }

    fn pkexec(d: &Path, code: i32) -> PathBuf {
        let p = d.join("pkexec");
        std::fs::write(&p, format!("#!/bin/sh\necho \"$@\" >> {}/pk.log\nexit {code}\n", d.display())).unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
        p
    }

    #[test]
    fn first_install_prompts_once_and_opens_pair_window() {
        let d = tmp("fi");
        let h = helper_file(&d);
        let pk = pkexec(&d, 0);
        let lan = Some((ip("192.168.1.77"), ip("255.255.255.0")));
        let r = first_install(&d, lan, &pk, &h);
        assert_eq!(r, FirstInstall { firewall: Some(Ok(FwOutcome::Done)), open_pair_window: true });
        assert_eq!(std::fs::read_to_string(d.join("pk.log")).unwrap(), format!("{} allow 192.168.1.0/24\n", h.display()));
        let r2 = first_install(&d, lan, &pk, &h);
        assert_eq!(r2, FirstInstall { firewall: None, open_pair_window: false });
        assert_eq!(std::fs::read_to_string(d.join("pk.log")).unwrap().lines().count(), 1);
    }

    #[test]
    fn first_install_with_no_helper_records_status_writes_no_marker_and_shows_no_prompt() {
        let d = tmp("onep");
        let pk = pkexec(&d, 0);
        let lan = Some((ip("192.168.1.77"), ip("255.255.255.0")));
        let r = first_install(&d, lan, &pk, &d.join("not-installed-yet"));
        assert_eq!(r, FirstInstall { firewall: Some(Ok(FwOutcome::HelperMissing)), open_pair_window: false });
        assert!(!d.join("pk.log").exists(), "pkexec must not run");
        assert!(!d.join("first-install-done").exists());
        assert_eq!(retry_firewall(&d, lan, &pk, &d.join("nope")).unwrap(), FwOutcome::HelperMissing);
    }

    #[test]
    fn first_install_without_address_does_nothing_and_retries_later() {
        let d = tmp("fi0");
        let h = helper_file(&d);
        let pk = pkexec(&d, 0);
        let r = first_install(&d, None, &pk, &h);
        assert_eq!(r, FirstInstall { firewall: None, open_pair_window: false });
        assert!(!d.join("pk.log").exists() && !d.join("first-install-done").exists());
        assert!(first_install(&d, Some((ip("10.0.0.2"), ip("255.255.0.0"))), &pk, &h).open_pair_window);
    }

    #[test]
    fn declined_prompt_leaves_no_marker_and_asks_again() {
        let d = tmp("fid");
        let h = helper_file(&d);
        let pk = pkexec(&d, 126);
        let lan = Some((ip("10.0.0.2"), ip("255.255.255.0")));
        let r = first_install(&d, lan, &pk, &h);
        assert_eq!(r.firewall, Some(Ok(FwOutcome::Failed(126))));
        assert!(!r.open_pair_window && !d.join("first-install-done").exists());
        assert_eq!(first_install(&d, lan, &pk, &h).firewall, Some(Ok(FwOutcome::Failed(126))));
        assert_eq!(std::fs::read_to_string(d.join("pk.log")).unwrap().lines().count(), 2);
    }

    #[test]
    fn helper_failure_leaves_no_marker() {
        let d = tmp("fi4");
        let h = helper_file(&d);
        let r = first_install(&d, Some((ip("10.0.0.2"), ip("255.255.255.0"))), &pkexec(&d, 4), &h);
        assert_eq!(r.firewall, Some(Ok(FwOutcome::Failed(4))));
        assert!(!d.join("first-install-done").exists());
    }

    #[test]
    fn retry_runs_the_prompt_again_and_a_success_writes_the_marker() {
        let d = tmp("retry");
        let h = helper_file(&d);
        let lan = Some((ip("192.168.1.9"), ip("255.255.255.0")));
        assert_eq!(retry_firewall(&d, lan, &pkexec(&d, 126), &h).unwrap(), FwOutcome::Failed(126));
        assert!(!d.join("first-install-done").exists());
        assert_eq!(retry_firewall(&d, lan, &pkexec(&d, 0), &h).unwrap(), FwOutcome::Done);
        assert!(d.join("first-install-done").exists());
        assert!(retry_firewall(&d, None, &pkexec(&d, 0), &h).is_err());
    }

    #[test]
    fn no_firewall_is_a_recorded_outcome() {
        let d = tmp("fin");
        let h = helper_file(&d);
        let r = first_install(&d, Some((ip("10.0.0.2"), ip("255.255.255.0"))), &pkexec(&d, 3), &h);
        assert_eq!(r.firewall, Some(Ok(FwOutcome::NoFirewall)));
    }

    #[test]
    fn bad_mask_skips_the_rule_and_leaves_no_marker() {
        let d = tmp("fib");
        let h = helper_file(&d);
        let r = first_install(&d, Some((ip("10.0.0.2"), ip("255.0.255.0"))), &pkexec(&d, 0), &h);
        assert!(matches!(r.firewall, Some(Err(_))));
        assert!(!d.join("pk.log").exists());
        assert!(!r.open_pair_window && !d.join("first-install-done").exists());
    }
}
