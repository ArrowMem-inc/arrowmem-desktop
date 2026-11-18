//! The pairing driver for the remote machine (round 2 of the sealed client): it runs the `mini_pair` state machine over a
//! [`Transport`], hands back the six digits for the person to type on the remote machine, and on their confirmation stores the
//! pin and resets the answer held by the remote group (R6).
//!
//! No UI and no words here: the window that shows the digits and the button that confirms are the caller's. Every failure is
//! one short fixed word from `mini_pair` (never a key, nonce, credential or address). The routes are the companion's own
//! `pair-start`, `pair-reveal` and `pair-finish`.

use crate::mini_pair::Pair;
use crate::mini_remote::MiniRemote;
use crate::minicred;
use crate::sealed::Transport;
use std::path::Path;

const JSON: &str = "application/json";

/// A pairing between "digits shown" and "digits confirmed". Dropping it abandons the pairing (the state machine wipes its keys).
pub struct Driving {
    pair: Pair,
    transport: Box<dyn Transport + Send>,
    host: String,
    port: u16,
    digits: String,
}

fn post(t: &dyn Transport, pair: &mut Pair, route: &str, body: &str) -> Result<Vec<u8>, String> {
    match t.post(route, JSON, None, body.as_bytes()) {
        None => Err("no_answer".into()),
        Some((200, b)) => Ok(b),
        Some((status, b)) => Err(pair.on_status(status, &b)),
    }
}

/// Rounds one and two against the remote companion. On success the six digits are in [`Driving::digits`].
pub fn start(transport: Box<dyn Transport + Send>, host: &str, port: u16) -> Result<Driving, String> {
    let (mut pair, start_body) = Pair::begin_fresh().ok_or_else(|| "no_random".to_string())?;
    let reply = post(&*transport, &mut pair, "pair-start", &start_body)?;
    let reveal = pair.on_start_reply(&reply)?;
    let reply = post(&*transport, &mut pair, "pair-reveal", &reveal)?;
    let digits = pair.on_reveal_reply(&reply)?;
    Ok(Driving { pair, transport, host: host.to_string(), port, digits })
}

impl Driving {
    /// The six digits to type on the remote machine.
    pub fn digits(&self) -> &str {
        &self.digits
    }

    /// The person typed the digits: finish, store the pin atomically, then reset the remote group's held answer.
    pub fn confirm(mut self, state_dir: &Path, remote: &MiniRemote) -> Result<(), String> {
        self.pair.confirm()?;
        let body = self.pair.finish_request()?;
        let reply = post(&*self.transport, &mut self.pair, "pair-finish", &body)?;
        let pin = self.pair.on_finish_reply(&reply, &self.host, self.port)?;
        save_pairing(state_dir, &pin, remote)
    }
}

/// Store the pin, then reset the held answer so the first call after a pairing opens a session (R6).
pub fn save_pairing(state_dir: &Path, pin: &minicred::Pin, remote: &MiniRemote) -> Result<(), String> {
    let r = minicred::save(state_dir, pin);
    remote.reset();
    r
}

/// Forget the pairing, then reset the held answer so a stale listing is never served after it (R6).
pub fn forget_pairing(state_dir: &Path, remote: &MiniRemote) -> Result<(), String> {
    let r = minicred::forget(state_dir);
    remote.reset();
    r
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mini_pair::tests::Companion;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};

    const CRED: &[u8] = b"pc_driverTestCredential_0123456789";
    const MID: [u8; 16] = [0x5a; 16];

    fn lan() -> String {
        format!("{}.{}.{}.{}", 192, 168, 4, 20)
    }

    /// The remote companion in process. A `finish_status` other than 200 makes `pair-finish` answer that status.
    struct Remote {
        comp: Mutex<Companion>,
        start_body: Mutex<String>,
        routes: Arc<Mutex<Vec<String>>>,
        finish_status: u16,
        silent: bool,
    }
    impl Transport for Remote {
        fn post(&self, route: &str, _: &str, _: Option<&str>, body: &[u8]) -> Option<(u16, Vec<u8>)> {
            self.routes.lock().unwrap().push(route.to_string());
            if self.silent {
                return None;
            }
            let body = String::from_utf8_lossy(body).to_string();
            let mut c = self.comp.lock().unwrap();
            match route {
                "pair-start" => {
                    *self.start_body.lock().unwrap() = body;
                    Some((200, c.start_reply()))
                }
                "pair-reveal" => Some((200, c.reveal_reply(&self.start_body.lock().unwrap(), &body))),
                "pair-finish" if self.finish_status != 200 => Some((self.finish_status, br#"{"error":"pair_code_mismatch"}"#.to_vec())),
                "pair-finish" => Some((200, c.finish_reply(CRED, Some(&MID)))),
                _ => Some((404, Vec::new())),
            }
        }
    }
    fn remote(finish_status: u16, silent: bool) -> (Box<dyn Transport + Send>, Arc<Mutex<Vec<String>>>) {
        let routes = Arc::new(Mutex::new(Vec::new()));
        let r = Remote { comp: Mutex::new(Companion::new(2, 4)), start_body: Mutex::new(String::new()), routes: routes.clone(), finish_status, silent };
        (Box::new(r), routes)
    }
    /// A MiniRemote whose open always costs one and counts them; it reads unknown. A reset shows as one more open.
    fn counting_remote() -> (MiniRemote, Arc<AtomicUsize>) {
        let n = Arc::new(AtomicUsize::new(0));
        let n2 = n.clone();
        (MiniRemote::with_opener(Box::new(move || { n2.fetch_add(1, Ordering::SeqCst); None })), n)
    }
    /// One call, then a pause for the background open to land.
    fn call_and_settle(r: &MiniRemote) {
        let _ = crate::mini_remote::RemoteListing::remote_listing(r);
        std::thread::sleep(std::time::Duration::from_millis(100));
    }

    #[test]
    fn a_full_pairing_shows_six_digits_then_stores_the_pin_and_resets_the_remote_group() {
        let d = crate::testtmp::TmpDir::absent("driver-full");
        let (t, routes) = remote(200, false);
        let (rem, opens) = counting_remote();
        call_and_settle(&rem);
        call_and_settle(&rem);
        assert_eq!(opens.load(Ordering::SeqCst), 1, "an answer that cost an open is held inside the interval");
        let driving = start(t, &lan(), 8788).unwrap();
        assert!(driving.digits().len() == 6 && driving.digits().bytes().all(|c| c.is_ascii_digit()));
        assert_eq!(*routes.lock().unwrap(), ["pair-start", "pair-reveal"], "nothing is finished before the person confirms");
        assert!(minicred::load(&d).is_none());
        driving.confirm(&d, &rem).unwrap();
        assert_eq!(*routes.lock().unwrap(), ["pair-start", "pair-reveal", "pair-finish"]);
        let pin = minicred::load(&d).expect("the pin is stored");
        assert_eq!((pin.host.as_str(), pin.port, pin.credential()), (lan().as_str(), 8788, CRED));
        call_and_settle(&rem);
        assert_eq!(opens.load(Ordering::SeqCst), 2, "the save reset the held answer: the next call opened a session");
    }

    #[test]
    fn no_answer_and_a_refused_finish_store_nothing_and_name_the_reason() {
        let d = crate::testtmp::TmpDir::absent("driver-fail");
        let (t, _) = remote(200, true);
        assert_eq!(start(t, &lan(), 8788).err().as_deref(), Some("no_answer"));
        let (t, _) = remote(409, false);
        let (rem, _) = counting_remote();
        let driving = start(t, &lan(), 8788).unwrap();
        assert_eq!(driving.confirm(&d, &rem).err().as_deref(), Some("pair_code_mismatch"));
        assert!(minicred::load(&d).is_none(), "a refused finish stores no pin");
    }

    #[test]
    fn forgetting_resets_the_remote_group_and_removes_the_pin() {
        let d = crate::testtmp::TmpDir::absent("driver-forget");
        let (t, _) = remote(200, false);
        let (rem, opens) = counting_remote();
        start(t, &lan(), 8788).unwrap().confirm(&d, &rem).unwrap();
        call_and_settle(&rem);
        call_and_settle(&rem);
        assert_eq!(opens.load(Ordering::SeqCst), 1);
        forget_pairing(&d, &rem).unwrap();
        assert!(minicred::load(&d).is_none());
        call_and_settle(&rem);
        assert_eq!(opens.load(Ordering::SeqCst), 2, "the forget reset the held answer");
    }
}
