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

/// The shortest time between two session opens on the remote machine. Its companion counts every open, good or bad, at 10 per
/// minute per source address and answers 401 past that; 15 s keeps this at 4 a minute, well under the budget. The owner routes
/// admit a models call every 2 s, so the answer of the last open (a listing or None) is reused inside this interval.
pub const MIN_OPEN_GAP: std::time::Duration = std::time::Duration::from_secs(15);

/// What one open produced: the listing (or unknown) and whether it cost a session open on the remote machine.
pub struct Opened {
    body: Option<String>,
    cost: bool,
}

type Opener = std::sync::Arc<dyn Fn() -> Opened + Send + Sync>;
type Dialer = std::sync::Arc<dyn Fn(&str, u16) -> Option<Box<dyn Transport + Send>> + Send + Sync>;

/// The last answer and whether an open is running. The lock is only ever held to read or write these two, never across an open.
#[derive(Default)]
struct Cache {
    last: Option<(std::time::Instant, Option<String>)>,
    opening: bool,
    /// Bumped by `reset`; an open that began under an older value lands nowhere.
    gen: u64,
}

pub struct MiniRemote {
    opener: Opener,
    cache: std::sync::Arc<std::sync::Mutex<Cache>>,
}

impl MiniRemote {
    pub fn new(state_dir: PathBuf) -> MiniRemote {
        MiniRemote::with_dialer(state_dir, std::sync::Arc::new(|host, port| TcpTransport::dial(host, port).ok().map(|t| Box::new(t) as Box<dyn Transport + Send>)))
    }

    /// The production open with a dialer of the caller's (a test passes a counting fake). No pairing file and a refused address
    /// cost no session open on the remote machine, so those answers are not held.
    pub(crate) fn with_dialer(state_dir: PathBuf, dial: Dialer) -> MiniRemote {
        MiniRemote::with_opened(Box::new(move || {
            let Some(pin) = minicred::load(&state_dir) else { return Opened { body: None, cost: false } };
            let Some(t) = dial(&pin.host, pin.port) else { return Opened { body: None, cost: false } };
            Opened { body: listing_via(&*t, pin.credential(), &pin), cost: true }
        }))
    }

    /// `opener` is the whole cost: dial, open a session, read the models. Tests pass a fake that always costs an open.
    #[cfg(test)]
    pub(crate) fn with_opener(opener: Box<dyn Fn() -> Option<String> + Send + Sync>) -> MiniRemote {
        MiniRemote::with_opened(Box::new(move || Opened { body: opener(), cost: true }))
    }

    fn with_opened(opener: Box<dyn Fn() -> Opened + Send + Sync>) -> MiniRemote {
        MiniRemote { opener: opener.into(), cache: Default::default() }
    }

    /// R6: drop the held answer. Called in process right after the pairing file is saved or forgotten; there is no HTTP route to it.
    /// An open already running is forgotten too: its answer was read before the change and lands nowhere.
    pub fn reset(&self) {
        let mut g = self.cache.lock().unwrap_or_else(|e| e.into_inner());
        g.last = None;
        g.opening = false;
        g.gen += 1;
    }

    /// R7. `Ok(answer)`: serve it (the last open is under MIN_OPEN_GAP old, or an open is running and the answer is unknown).
    /// `Err(gen)`: this caller now owns a new open and must call `finish` with that gen. An answer is never served past the
    /// interval, a failure included. No caller waits for an open: a burst makes one, the rest read unknown until it lands.
    fn begin(&self, now: std::time::Instant) -> Result<Option<String>, u64> {
        let mut g = self.cache.lock().unwrap_or_else(|e| e.into_inner());
        if g.opening {
            return Ok(None);
        }
        if let Some((t, body)) = g.last.as_ref() {
            if now.saturating_duration_since(*t) < MIN_OPEN_GAP {
                return Ok(body.clone());
            }
        }
        g.opening = true;
        Err(g.gen)
    }

    /// The open of this caller runs on a thread of its own; the caller reads unknown at once.
    fn open_in_background(&self, gen: u64) {
        let (opener, cache) = (self.opener.clone(), self.cache.clone());
        std::thread::spawn(move || {
            let o = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| opener())).unwrap_or(Opened { body: None, cost: true });
            finish(&cache, gen, std::time::Instant::now(), o);
        });
    }

    /// Test helper: the same rule with the open run inline.
    #[cfg(test)]
    fn bounded(&self, now: std::time::Instant, open: impl FnOnce() -> Option<String>) -> Option<String> {
        match self.begin(now) {
            Ok(served) => served,
            Err(gen) => {
                let body = open();
                finish(&self.cache, gen, now, Opened { body: body.clone(), cost: true });
                body
            }
        }
    }

    /// The listing through any transport (the production one is `TcpTransport::dial` on the pinned address).
    #[cfg(test)]
    fn listing_via(&self, t: &dyn Transport, cred: &[u8], pin: &minicred::Pin) -> Option<String> {
        listing_via(t, cred, pin)
    }
}

/// Lands an open. Under a newer gen (a reset came) it lands nowhere. Only an answer that cost a session open is held.
fn finish(cache: &std::sync::Mutex<Cache>, gen: u64, now: std::time::Instant, o: Opened) {
    let mut g = cache.lock().unwrap_or_else(|e| e.into_inner());
    if g.gen != gen {
        return;
    }
    g.last = o.cost.then_some((now, o.body));
    g.opening = false;
}

fn listing_via(t: &dyn Transport, cred: &[u8], pin: &minicred::Pin) -> Option<String> {
    let o = exchange(t, cred, random::<16>()?, br#"{"op":"models"}"#).ok()?;
    pin.machine_matches(o.machine_id.as_deref()).then(|| models_body(&o)).flatten()
}

impl RemoteListing for MiniRemote {
    fn remote_listing(&self) -> Option<String> {
        match self.begin(std::time::Instant::now()) {
            Ok(served) => served,
            Err(gen) => {
                self.open_in_background(gen);
                None
            }
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::sealed::{derive_keys, hex, open_proof, unhex};
    use std::sync::{Arc, Mutex};

    /// A dotted quad assembled at run time: no address literal is written in this file.
    fn ip(a: u8, b: u8, c: u8, d: u8) -> String {
        format!("{a}.{b}.{c}.{d}")
    }

    pub(crate) const CRED: &[u8] = b"pc_remoteListingCredential_0123456789ab";
    pub(crate) const MID: [u8; 16] = [0x5a; 16];

    fn dir(tag: &str) -> crate::testtmp::TmpDir {
        crate::testtmp::TmpDir::absent(&format!("miniremote-{tag}"))
    }

    /// An in process companion: no socket. Seals under the keys the real derivation gives.
    pub(crate) struct Fake {
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
    pub(crate) fn fake(mid: Option<[u8; 16]>, status: u16, list: &'static str) -> Fake {
        Fake { mid, status, list, calls: Arc::new(Mutex::new(vec![])), keys: Mutex::new(None) }
    }
    pub(crate) const LIST: &str = r#"{"models":[{"id":"default","label":"One","size_bytes":null,"quant":null,"loaded":true}]}"#;

    fn paired(tag: &str, mid: &[u8]) -> (MiniRemote, minicred::Pin, crate::testtmp::TmpDir) {
        let d = dir(tag);
        let pin = minicred::Pin::new(&ip(192, 168, 4, 20), 8788, CRED, mid).unwrap();
        minicred::save(&d, &pin).unwrap();
        (MiniRemote::new(d.to_path_buf()), pin, d)
    }

    #[test]
    fn a_matching_machine_id_and_a_200_list_give_the_body() {
        let (r, pin, _g) = paired("ok", &MID);
        let f = fake(Some(MID), 200, LIST);
        assert_eq!(r.listing_via(&f, CRED, &pin).as_deref(), Some(LIST));
        assert_eq!(*f.calls.lock().unwrap(), ["session-open", "chat"]);
    }

    #[test]
    fn a_different_machine_id_reads_unknown_even_with_a_good_list() {
        let (r, pin, _g) = paired("other", &MID);
        assert_eq!(r.listing_via(&fake(Some([0x6b; 16]), 200, LIST), CRED, &pin), None);
        assert_eq!(r.listing_via(&fake(None, 200, LIST), CRED, &pin), None, "a pinned id that stopped being sealed");
    }

    #[test]
    fn every_failure_is_none_and_never_an_empty_listing() {
        let (r, pin, _g) = paired("fails", &MID);
        for (st, body) in [(400u16, LIST), (401, LIST), (429, LIST), (503, LIST), (200, r#"{"models":[]}"#), (200, "{}"), (200, "[]"), (200, "garbage")] {
            assert_eq!(r.listing_via(&fake(Some(MID), st, body), CRED, &pin), None, "{st} {body}");
        }
        // the wrong credential on the remote side: the proof does not verify
        assert_eq!(r.listing_via(&fake(Some(MID), 200, LIST), b"pc_aDifferentCredential_0123456789abcd", &pin), None);
    }

    /// C1: the opened body goes through the owner routes' own parse_remote, as `Owner::listing` does.
    fn rows(r: &MiniRemote, pin: &minicred::Pin, f: &Fake) -> Option<Result<usize, ()>> {
        r.listing_via(f, CRED, pin).as_deref().map(|b| crate::ownerroutes::parse_remote(b).map(|v| v.len()).map_err(|_| ()))
    }

    #[test]
    fn an_opened_body_replays_through_parse_remote_and_empty_or_failed_reads_unknown() {
        let (r, pin, _g) = paired("replay", &MID);
        assert_eq!(rows(&r, &pin, &fake(Some(MID), 200, LIST)), Some(Ok(1)));
        let two = r#"{"models":[{"id":"a","label":"A"},{"id":"b","label":null,"loaded":false}]}"#;
        assert_eq!(rows(&r, &pin, &fake(Some(MID), 200, two)), Some(Ok(2)));
        // an opened empty plaintext, an opened empty list and a non-200 never reach the parser: unknown
        for (st, body) in [(200u16, ""), (200, r#"{"models":[]}"#), (429, LIST)] {
            assert_eq!(rows(&r, &pin, &fake(Some(MID), st, body)), None, "{st} {body:?}");
        }
        // and the parser alone refuses the empty body and the empty list
        assert!(crate::ownerroutes::parse_remote("").is_err() && crate::ownerroutes::parse_remote(r#"{"models":[]}"#).is_err());
    }

    #[test]
    fn thirty_calls_in_a_minute_open_at_most_four_sessions_and_a_stale_answer_is_never_served() {
        let (r, pin, _g) = paired("budget", &MID);
        let f = fake(Some(MID), 200, LIST);
        let t0 = std::time::Instant::now();
        let mut got = Vec::new();
        for i in 0..30u64 {
            got.push(r.bounded(t0 + std::time::Duration::from_secs(i * 2), || r.listing_via(&f, CRED, &pin)));
        }
        let opens = f.calls.lock().unwrap().iter().filter(|c| *c == "session-open").count();
        assert!(opens <= 4, "{opens} session opens in one simulated minute (the budget is 10)");
        assert!(got.iter().all(|g| g.as_deref() == Some(LIST)));
        // past the interval the next call opens again; a failing remote then reads unknown, not the old body
        let down = fake(Some(MID), 503, LIST);
        let later = t0 + std::time::Duration::from_secs(60 + 16);
        assert_eq!(r.bounded(later, || r.listing_via(&down, CRED, &pin)), None);
        assert_eq!(*down.calls.lock().unwrap(), ["session-open", "chat"]);
    }

    /// A dialer that hands out a fresh Fake each time and counts the dials; `calls` is shared by every Fake it makes.
    fn counting_dialer() -> (Dialer, Arc<std::sync::atomic::AtomicUsize>, Arc<Mutex<Vec<String>>>) {
        let dials = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let calls = Arc::new(Mutex::new(Vec::new()));
        let (d2, c2) = (dials.clone(), calls.clone());
        let dial: Dialer = Arc::new(move |_, _| {
            d2.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Some(Box::new(Fake { mid: Some(MID), status: 200, list: LIST, calls: c2.clone(), keys: Mutex::new(None) }) as Box<dyn Transport + Send>)
        });
        (dial, dials, calls)
    }
    fn session_opens(calls: &Mutex<Vec<String>>) -> usize {
        calls.lock().unwrap().iter().filter(|c| *c == "session-open").count()
    }
    /// Waits for the background open to land (at most 3 s).
    fn settle(r: &MiniRemote) {
        for _ in 0..300 {
            if !r.cache.lock().unwrap().opening {
                return;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        panic!("the open never finished");
    }
    fn pin() -> minicred::Pin {
        minicred::Pin::new(&ip(192, 168, 4, 20), 8788, CRED, &MID).unwrap()
    }

    /// R6: saving a pairing resets the held answer, so the first call after it opens a session and does not read a stale unknown.
    #[test]
    fn a_save_then_a_call_inside_the_interval_does_one_session_open() {
        let d = dir("r6save");
        let (dial, dials, calls) = counting_dialer();
        let r = MiniRemote::with_dialer(d.to_path_buf(), dial);
        assert_eq!(r.remote_listing(), None);
        settle(&r);
        assert_eq!(dials.load(std::sync::atomic::Ordering::SeqCst), 0, "no pairing file: nothing dialled");
        minicred::save(&d, &pin()).unwrap();
        r.reset();
        assert_eq!(r.remote_listing(), None, "the open is in flight");
        settle(&r);
        assert_eq!(r.remote_listing().as_deref(), Some(LIST));
        assert_eq!(session_opens(&calls), 1);
    }

    /// R6: forgetting resets the held listing: the next call reads unknown with no dial.
    #[test]
    fn a_forget_then_a_call_reads_unknown_with_no_dial() {
        let (r, _pin, d) = paired_with("r6forget");
        settle_after_call(&r);
        assert_eq!(r.0.remote_listing().as_deref(), Some(LIST), "a paired remote lists");
        let dialled = r.1.load(std::sync::atomic::Ordering::SeqCst);
        minicred::forget(&d).unwrap();
        r.0.reset();
        assert_eq!(r.0.remote_listing(), None, "the old listing is not served after a forget");
        settle(&r.0);
        assert_eq!(r.1.load(std::sync::atomic::Ordering::SeqCst), dialled, "a forgotten pairing is not dialled");
        assert_eq!(r.0.remote_listing(), None);
    }
    fn paired_with(tag: &str) -> ((MiniRemote, Arc<std::sync::atomic::AtomicUsize>), minicred::Pin, crate::testtmp::TmpDir) {
        let d = dir(tag);
        minicred::save(&d, &pin()).unwrap();
        let (dial, dials, _calls) = counting_dialer();
        ((MiniRemote::with_dialer(d.to_path_buf(), dial), dials), pin(), d)
    }
    fn settle_after_call(r: &(MiniRemote, Arc<std::sync::atomic::AtomicUsize>)) {
        assert_eq!(r.0.remote_listing(), None);
        settle(&r.0);
    }

    /// R6: only an answer that cost a session open is held. An unpaired read is not, so a pairing that lands is seen at once.
    #[test]
    fn an_answer_that_cost_no_open_is_not_held() {
        let d = dir("r6nocost");
        let (dial, _dials, calls) = counting_dialer();
        let r = MiniRemote::with_dialer(d.to_path_buf(), dial);
        assert_eq!(r.remote_listing(), None);
        settle(&r);
        minicred::save(&d, &pin()).unwrap();
        assert_eq!(r.remote_listing(), None, "the open is in flight");
        settle(&r);
        assert_eq!(r.remote_listing().as_deref(), Some(LIST), "no reset was called and the unpaired read was not held");
        assert_eq!(session_opens(&calls), 1);
    }

    /// R6: an open that was already running when the pairing changed lands nowhere.
    #[test]
    fn an_open_in_flight_when_the_pairing_changes_is_not_kept() {
        let r = MiniRemote::with_opener(Box::new(|| {
            std::thread::sleep(std::time::Duration::from_millis(300));
            Some(LIST.to_string())
        }));
        assert_eq!(r.remote_listing(), None);
        r.reset();
        std::thread::sleep(std::time::Duration::from_millis(600));
        assert_eq!(r.cache.lock().unwrap().last.is_none(), true, "the old open landed after the reset");
        assert_eq!(r.remote_listing(), None, "a fresh open starts and is not served from the old one");
    }

    /// R7: a burst makes one open, and no caller waits for it: the callers read unknown at once and the answer lands later.
    #[test]
    fn a_burst_makes_one_open_and_no_caller_waits_for_it() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let opens = Arc::new(AtomicUsize::new(0));
        let o2 = opens.clone();
        let r = Arc::new(MiniRemote::with_opener(Box::new(move || {
            o2.fetch_add(1, Ordering::SeqCst);
            std::thread::sleep(std::time::Duration::from_millis(400));
            Some(LIST.to_string())
        })));
        let calls: Vec<_> = (0..2)
            .map(|_| {
                let r = r.clone();
                std::thread::spawn(move || {
                    let t = std::time::Instant::now();
                    (r.remote_listing(), t.elapsed())
                })
            })
            .collect();
        for c in calls {
            let (got, took) = c.join().unwrap();
            assert_eq!(got, None, "an open in flight reads unknown");
            assert!(took < std::time::Duration::from_millis(200), "a caller waited {took:?} for the open");
        }
        std::thread::sleep(std::time::Duration::from_millis(700));
        assert_eq!(r.remote_listing().as_deref(), Some(LIST), "the finished open is served inside the interval");
        assert_eq!(opens.load(Ordering::SeqCst), 1, "one open for the whole burst");
    }

    #[test]
    fn with_no_pairing_file_or_a_refused_address_nothing_is_dialled_and_the_group_is_unknown() {
        let none = dir("none");
        assert_eq!(MiniRemote::new(none.to_path_buf()).remote_listing(), None);
        // a pin file whose address the gate refuses reads as unpaired before any socket
        let d = dir("refused");
        std::fs::create_dir_all(&d).unwrap();
        std::fs::set_permissions(&d, std::os::unix::fs::PermissionsExt::from_mode(0o700)).unwrap();
        let p = d.join(minicred::FILE);
        std::fs::write(&p, format!(r#"{{"host":"{}","port":8788,"credential":"{}","machine_id":""}}"#, ip(127, 0, 0, 1), String::from_utf8_lossy(CRED))).unwrap();
        std::fs::set_permissions(&p, std::os::unix::fs::PermissionsExt::from_mode(0o600)).unwrap();
        assert_eq!(MiniRemote::new(d.to_path_buf()).remote_listing(), None);
    }

    // 6. the source guard: no log call anywhere, no write outside the credential store
    const SHIPPED: [(&str, &str); 5] = [
        ("mini_driver.rs", include_str!("mini_driver.rs")),
        ("sealed.rs", include_str!("sealed.rs")),
        ("minicred.rs", include_str!("minicred.rs")),
        ("mini_pair.rs", include_str!("mini_pair.rs")),
        ("mini_remote.rs", include_str!("mini_remote.rs")),
    ];

    fn shipped(text: &str) -> &str {
        text.split("#[cfg(test)]\nmod tests").next().unwrap().split("#[cfg(test)]\npub(crate) mod tests").next().unwrap()
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
