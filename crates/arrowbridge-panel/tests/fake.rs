//! Every cap against a fake owner listener on an ephemeral loopback port (the reply is untrusted).
use arrowbridge_panel::{run, MAX_BODY, UNKNOWN_STATE};
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::Command;
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

const BOTH_UNKNOWN: &str = r#"{"groups":[{"host":"local","state":"unknown","rows":[]},{"host":"remote","state":"unknown","rows":[]}]}"#;

fn http(status: &str, body: &str) -> Vec<u8> {
    format!("HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).into_bytes()
}

/// Serves one connection with `f`; the join handle yields the request bytes the client sent.
fn serve(f: impl FnOnce(&mut TcpStream) + Send + 'static) -> (u16, JoinHandle<String>) {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    let h = thread::spawn(move || {
        let (mut s, _) = l.accept().unwrap();
        let mut req = Vec::new();
        let mut b = [0u8; 1024];
        loop {
            let n = s.read(&mut b).unwrap();
            req.extend_from_slice(&b[..n]);
            let t = String::from_utf8_lossy(&req).to_string();
            if let Some(p) = t.find("\r\n\r\n") {
                let cl = t[..p].lines().find_map(|l| l.strip_prefix("Content-Length: ")).and_then(|v| v.parse::<usize>().ok()).unwrap_or(0);
                if req.len() >= p + 4 + cl {
                    break;
                }
            }
        }
        f(&mut s);
        String::from_utf8_lossy(&req).to_string()
    });
    (port, h)
}

fn reply(bytes: Vec<u8>) -> (u16, JoinHandle<String>) {
    serve(move |s| {
        let _ = s.write_all(&bytes);
    })
}

fn args(verb: &str, port: u16, extra: &[&str]) -> Vec<String> {
    let mut a = vec![verb.to_string(), "--owner-port".into(), port.to_string()];
    a.extend(extra.iter().map(|s| s.to_string()));
    a
}

fn list_of(body: &str) -> String {
    let (port, _h) = reply(http("200 OK", body));
    run(&args("list", port, &[]))
}

fn row(id: &str, host: &str) -> String {
    format!(r#"{{"id":"{id}","label":"{id}","loaded":true,"host":"{host}","paused":false}}"#)
}

fn rows(n: usize, host: &str) -> Vec<String> {
    (0..n).map(|i| row(&format!("m{i}"), host)).collect()
}

fn body(models: &[String], unknown: &str) -> String {
    format!(r#"{{"models":[{}],"unknown":[{unknown}]}}"#, models.join(","))
}

fn local_state(out: &str) -> &str {
    let g = &out[..out.find(r#"{"host":"remote""#).unwrap()];
    if g.contains(r#""state":"ok""#) { "ok" } else { "unknown" }
}

fn remote_state(out: &str) -> &str {
    if out[out.find(r#"{"host":"remote""#).unwrap()..].contains(r#""state":"ok""#) { "ok" } else { "unknown" }
}

#[test]
fn a_good_listing_is_printed_in_the_shape_the_panel_reads() {
    let b = r#"{"models":[{"id":"a","label":"A","loaded":true,"host":"local","paused":true},{"id":"b","label":"b","loaded":null,"host":"local","paused":false},{"id":"c","loaded":false,"host":"remote","paused":false}],"unknown":[]}"#;
    assert_eq!(
        list_of(b),
        r#"{"groups":[{"host":"local","state":"ok","rows":[{"id":"a","loaded":true,"paused":true},{"id":"b","loaded":null,"paused":false}]},{"host":"remote","state":"ok","rows":[{"id":"c","loaded":false,"paused":false}]}]}"#
    );
}

#[test]
fn an_empty_group_is_ok_and_empty_not_unknown() {
    assert_eq!(list_of(&body(&[], "")), r#"{"groups":[{"host":"local","state":"ok","rows":[]},{"host":"remote","state":"ok","rows":[]}]}"#);
}

#[test]
fn sixty_four_rows_pass_and_sixty_five_make_that_group_unknown_not_truncated() {
    let mut m = rows(64, "local");
    m.extend(rows(1, "remote"));
    let out = list_of(&body(&m, ""));
    assert_eq!((local_state(&out), remote_state(&out)), ("ok", "ok"));
    assert_eq!(out.matches(r#""id":"#).count(), 65);
    let mut m = rows(65, "local");
    m.extend(rows(1, "remote"));
    let out = list_of(&body(&m, ""));
    assert_eq!((local_state(&out), remote_state(&out)), ("unknown", "ok"));
    assert_eq!(out.matches(r#""id":"#).count(), 1);
}

#[test]
fn an_id_of_200_passes_and_201_makes_the_group_unknown() {
    // The label is short on purpose: the label cap must not be what rejects the long id.
    let with = |n: usize| format!(r#"{{"id":"{}","label":"a","loaded":true,"host":"local","paused":false}}"#, "x".repeat(n));
    assert_eq!(local_state(&list_of(&body(&[with(200)], ""))), "ok");
    assert_eq!(local_state(&list_of(&body(&[with(201)], ""))), "unknown");
}

#[test]
fn a_label_over_200_characters_makes_the_group_unknown() {
    let r = format!(r#"{{"id":"a","label":"{}","loaded":true,"host":"local","paused":false}}"#, "y".repeat(201));
    assert_eq!(local_state(&list_of(&body(&[r], ""))), "unknown");
}

#[test]
fn control_characters_empty_ids_and_duplicates_make_the_group_unknown() {
    for id in ["a\\u0007b", "a\\nb", "a\\u007fb", ""] {
        let out = list_of(&body(&[row(id, "local")], ""));
        assert_eq!(local_state(&out), "unknown", "id {id:?}");
    }
    let out = list_of(&body(&[row("a", "remote"), row("a", "remote")], ""));
    assert_eq!((local_state(&out), remote_state(&out)), ("ok", "unknown"));
}

#[test]
fn a_row_of_the_wrong_shape_makes_its_group_unknown() {
    for r in [
        r#"{"id":"a","label":"a","loaded":"yes","host":"local","paused":false}"#,
        r#"{"id":"a","label":"a","loaded":true,"host":"local","paused":"no"}"#,
        r#"{"id":"a","label":"a","loaded":true,"host":"local"}"#,
        r#"{"id":1,"label":"a","loaded":true,"host":"local","paused":false}"#,
    ] {
        assert_eq!(local_state(&list_of(&body(&[r.to_string()], ""))), "unknown", "{r}");
    }
}

#[test]
fn a_machine_name_never_reaches_the_output() {
    let weird = r#"{"id":"a","label":"a","loaded":true,"host":"lab-box-7","paused":false,"hostname":"lab-box-7"}"#;
    let ok = r#"{"id":"b","label":"b","loaded":true,"host":"local","paused":false,"hostname":"lab-box-7"}"#;
    let out = list_of(&body(&[weird.to_string(), ok.to_string()], ""));
    assert!(!out.contains("lab-box") && !out.contains(r#""id":"a""#), "{out}");
    assert_eq!((local_state(&out), remote_state(&out)), ("ok", "ok"));
}

#[test]
fn a_host_named_unknown_is_unknown_even_when_rows_carry_it_and_a_bad_word_there_fails_the_reply() {
    let out = list_of(&body(&rows(2, "remote"), r#""remote""#));
    assert_eq!((local_state(&out), remote_state(&out)), ("ok", "unknown"));
    assert_eq!(out.matches(r#""id":"#).count(), 0);
    assert_eq!(list_of(&body(&[], r#""elsewhere""#)), BOTH_UNKNOWN);
    assert_eq!(list_of(&body(&[], "1")), BOTH_UNKNOWN);
}

#[test]
fn ten_thousand_rows_and_markup_render_nothing() {
    let m = rows(10_000, "local");
    assert_eq!(list_of(&body(&m, "")), BOTH_UNKNOWN);
    // 129 rows fit the body cap and still fail as a whole.
    let mut m = rows(100, "local");
    m.extend(rows(29, "remote"));
    assert_eq!(list_of(&body(&m, "")), BOTH_UNKNOWN);
    // Markup is data: it stays a JSON string, ASCII, never interpreted here.
    // An id takes an ASCII allow list, so the markup rides in the label.
    let label = format!(r#"<img src=\"https://example.invalid/x\">{}"#, '\u{e9}');
    let r = format!(r#"{{"id":"a","label":"{label}","loaded":true,"host":"local","paused":false}}"#);
    let out = list_of(&body(&[r], ""));
    assert!(out.contains(r#""id":"a""#) && !out.contains("img") && !out.contains("example"), "{out}");
    assert!(out.is_ascii());
}

#[test]
fn the_body_cap_is_64_kib_exactly() {
    let good = body(&rows(1, "local"), "");
    let pad = |n: usize| format!("{good}{}", " ".repeat(n - good.len()));
    assert_eq!(local_state(&list_of(&pad(MAX_BODY))), "ok");
    assert_eq!(list_of(&pad(MAX_BODY + 1)), BOTH_UNKNOWN);
}

#[test]
fn garbage_empty_trailing_text_and_deep_nesting_are_unknown() {
    let good = body(&rows(1, "local"), "");
    let deep = format!("{}{}", "[".repeat(40), "]".repeat(40));
    for b in ["", "not json", "[]", "{}", r#"{"models":[]}"#, &format!("{good} x"), &deep, r#"{"models":[],"models":[],"unknown":[]}"#] {
        assert_eq!(list_of(b), BOTH_UNKNOWN, "{b}");
    }
}

#[test]
fn non_200_and_bad_framing_are_unknown() {
    let good = body(&rows(1, "local"), "");
    for status in ["429 Too Many Requests", "502 Bad Gateway", "500 X", "403 Forbidden", "204 No Content"] {
        let (port, _h) = reply(http(status, &good));
        assert_eq!(run(&args("list", port, &[])), BOTH_UNKNOWN, "{status}");
    }
    let framings = [
        format!("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n{}\r\n{good}\r\n0\r\n\r\n", good.len()),
        format!("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Length: {}\r\n\r\n{good}", good.len()),
        format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{good}", good.len() + 5),
        format!("HTTP/1.1 200 OK\r\nContent-Length: 1\r\nContent-Length: {}\r\n\r\n{good}", good.len()),
        format!("HTTP/1.1 200 OK\r\nbroken header\r\n\r\n{good}"),
        "GARBAGE\r\n\r\n".to_string(),
    ];
    for f in framings {
        let (port, _h) = reply(f.clone().into_bytes());
        assert_eq!(run(&args("list", port, &[])), BOTH_UNKNOWN, "{f}");
    }
}

#[test]
fn a_reply_with_no_content_length_is_read_to_close() {
    let good = body(&rows(1, "local"), "");
    let (port, _h) = reply(format!("HTTP/1.0 200 OK\r\n\r\n{good}").into_bytes());
    assert_eq!(local_state(&run(&args("list", port, &[]))), "ok");
}

#[test]
fn a_reply_delayed_past_the_deadline_is_unknown_at_about_three_seconds() {
    let good = http("200 OK", &body(&rows(1, "local"), ""));
    let (port, _h) = serve(move |s| {
        thread::sleep(Duration::from_millis(4500));
        let _ = s.write_all(&good);
    });
    let t = Instant::now();
    assert_eq!(run(&args("list", port, &[])), BOTH_UNKNOWN);
    let e = t.elapsed();
    assert!(e >= Duration::from_millis(2900) && e < Duration::from_millis(3600), "{e:?}");
}

#[test]
fn a_trickle_cannot_extend_the_deadline() {
    let good = http("200 OK", &body(&rows(1, "local"), ""));
    let (port, _h) = serve(move |s| {
        for b in good {
            if s.write_all(&[b]).is_err() {
                return;
            }
            thread::sleep(Duration::from_millis(100));
        }
    });
    let t = Instant::now();
    assert_eq!(run(&args("list", port, &[])), BOTH_UNKNOWN);
    let e = t.elapsed();
    assert!(e < Duration::from_millis(3600), "{e:?}");
}

#[test]
fn a_refused_connection_and_a_bad_port_are_unknown() {
    let port = TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
    assert_eq!(run(&args("list", port, &[])), BOTH_UNKNOWN);
    assert_eq!(run(&args("resume", port, &[])), UNKNOWN_STATE);
    for a in [vec!["list"], vec!["list", "--owner-port", "80"], vec!["list", "--owner-port", "x"], vec!["frobnicate", "--owner-port", "8789"], vec![]] {
        let a: Vec<String> = a.into_iter().map(String::from).collect();
        let out = run(&a);
        assert!(out == BOTH_UNKNOWN || out == UNKNOWN_STATE, "{a:?}");
    }
}

#[test]
fn the_request_bytes_carry_the_owner_header_and_one_exact_host_and_no_origin() {
    let (port, h) = reply(http("200 OK", &body(&[], "")));
    run(&args("list", port, &[]));
    let req = h.join().unwrap();
    assert!(req.starts_with("GET /v1/models HTTP/1.1\r\n"), "{req}");
    assert_eq!(req.matches("Host: ").count(), 1);
    assert!(req.contains(&format!("\r\nHost: 127.0.0.1:{port}\r\n")));
    assert_eq!(req.matches("X-ArrowBridge-Owner: 1\r\n").count(), 1);
    assert!(!req.to_ascii_lowercase().contains("origin") && !req.contains("Content-Length"), "{req}");

    let (port, h) = reply(http("200 OK", r#"{"state":"paused"}"#));
    assert_eq!(run(&args("pause", port, &["--model", "org/llama.v2_1:x"])), r#"{"state":"paused"}"#);
    let req = h.join().unwrap();
    let b = r#"{"model":"org/llama.v2_1:x"}"#;
    assert!(req.starts_with("POST /v1/pause HTTP/1.1\r\n"), "{req}");
    assert!(req.contains("Content-Type: application/json\r\n") && req.contains(&format!("Content-Length: {}\r\n", b.len())), "{req}");
    assert!(req.ends_with(&format!("\r\n\r\n{b}")), "{req}");
    assert_eq!((req.matches("Host: ").count(), req.matches("X-ArrowBridge-Owner: 1\r\n").count()), (1, 1));
    assert!(!req.to_ascii_lowercase().contains("origin"));

    let (port, h) = reply(http("200 OK", r#"{"state":"free"}"#));
    assert_eq!(run(&args("resume", port, &[])), r#"{"state":"free"}"#);
    let req = h.join().unwrap();
    assert!(req.starts_with("POST /v1/resume HTTP/1.1\r\n") && req.ends_with("\r\n\r\n{}") && req.contains("Content-Length: 2\r\n"), "{req}");
}

#[test]
fn pause_and_resume_replies_are_exactly_paused_or_free() {
    for (b, want) in [
        (r#"{"state":"paused"}"#, r#"{"state":"paused"}"#),
        (r#"{"state":"free"}"#, r#"{"state":"free"}"#),
        (r#"{"state":"PAUSED"}"#, UNKNOWN_STATE),
        (r#"{"state":"busy"}"#, UNKNOWN_STATE),
        (r#"{"state":1}"#, UNKNOWN_STATE),
        (r#"{"state":"paused","extra":1}"#, UNKNOWN_STATE),
        (r#"{"state":"unknown"}"#, UNKNOWN_STATE),
        ("[]", UNKNOWN_STATE),
        ("", UNKNOWN_STATE),
        (r#"{"state":"paused"} trailing"#, UNKNOWN_STATE),
    ] {
        let (port, _h) = reply(http("200 OK", b));
        assert_eq!(run(&args("pause", port, &["--model", "a"])), want, "{b}");
    }
    let (port, _h) = reply(http("200 OK", r#"{"state":"paused"}"#));
    assert_eq!(run(&args("resume", port, &[])), UNKNOWN_STATE, "a paused answer to resume is not free");
    let (port, _h) = reply(http("502 Bad Gateway", r#"{"state":"free"}"#));
    assert_eq!(run(&args("pause", port, &["--model", "a"])), UNKNOWN_STATE);
}

#[test]
fn a_bad_model_id_sends_nothing() {
    for id in ["", &"x".repeat(201), "a\nb", "a\u{7}b", "a\u{301}b", "a\u{378}b", "a b"] {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        l.set_nonblocking(true).unwrap();
        let port = l.local_addr().unwrap().port();
        assert_eq!(run(&args("pause", port, &["--model", id])), UNKNOWN_STATE);
        assert_eq!(l.accept().unwrap_err().kind(), std::io::ErrorKind::WouldBlock, "id {id:?} reached the socket");
    }
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    l.set_nonblocking(true).unwrap();
    assert_eq!(run(&args("pause", l.local_addr().unwrap().port(), &[])), UNKNOWN_STATE);
    assert!(l.accept().is_err());
}

#[test]
fn the_binary_prints_one_line_exits_zero_and_creates_no_file() {
    /// Removes the folder on drop, also while a failing assertion unwinds (this crate cannot reach the desktop's testtmp guard).
    struct Dir(std::path::PathBuf);
    impl Drop for Dir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    let guard = Dir(std::env::temp_dir().join(format!("abp-nofile-{}", std::process::id())));
    let dir = guard.0.clone();
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let port = TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port().to_string();
    for a in [vec!["list", "--owner-port", &port], vec!["pause", "--owner-port", &port, "--model", "a"], vec![]] {
        let o = Command::new(env!("CARGO_BIN_EXE_arrowbridge-panel")).args(&a).current_dir(&dir).output().unwrap();
        assert!(o.status.success(), "{a:?}");
        let out = String::from_utf8(o.stdout).unwrap();
        assert!(out == format!("{BOTH_UNKNOWN}\n") || out == format!("{UNKNOWN_STATE}\n"), "{out}");
        assert!(o.stderr.is_empty());
    }
    assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 0);
}

fn writes_to_disk(src: &str) -> bool {
    let code = src.split("\n#[cfg(test)]").next().unwrap();
    ["File::create", "OpenOptions", "fs::write", "std::fs", "create_dir", "println!", "eprint", "agents/usage", "llama", "machine"].iter().any(|p| code.contains(p))
}

#[test]
fn the_crate_source_holds_no_write_call_and_the_guard_proves_itself() {
    for f in ["src/lib.rs", "src/main.rs"] {
        let src = std::fs::read_to_string(format!("{}/{f}", env!("CARGO_MANIFEST_DIR"))).unwrap();
        let code = if f == "src/main.rs" { src.replace("println!(\"{out}\");", "") } else { src };
        assert!(!writes_to_disk(&code), "{f}");
    }
    assert!(writes_to_disk("fn x() { std::fs::write(\"a\", \"b\").unwrap(); }"));
    assert!(writes_to_disk("fn x() { let _ = File::create(\"a\"); }"));
    assert!(writes_to_disk("fn x() { eprintln!(\"a\"); }"));
}

#[test]
fn nine_nested_arrays_in_an_ignored_field_read_unknown() {
    let nest = |n: usize| format!(r#"{{"models":[],"unknown":[],"x":{}{}}}"#, "[".repeat(n), "]".repeat(n));
    assert_eq!(list_of(&nest(9)), BOTH_UNKNOWN);
    assert_ne!(list_of(&nest(7)), BOTH_UNKNOWN);
}

fn binary(a: &[std::ffi::OsString]) -> (std::process::ExitStatus, String, usize) {
    let o = Command::new(env!("CARGO_BIN_EXE_arrowbridge-panel")).args(a).output().unwrap();
    (o.status, String::from_utf8(o.stdout).unwrap(), o.stderr.len())
}

#[test]
fn a_32000_deep_array_gives_exit_zero_and_the_unknown_line_not_an_abort() {
    let b = format!(r#"{{"models":[],"unknown":[],"x":{}{}}}"#, "[".repeat(32_000), "]".repeat(32_000));
    assert!(b.len() < MAX_BODY);
    let (port, _h) = reply(http("200 OK", &b));
    let a: Vec<_> = args("list", port, &[]).into_iter().map(Into::into).collect();
    assert_eq!(binary(&a), (std::process::ExitStatus::default(), format!("{BOTH_UNKNOWN}\n"), 0));
}

#[test]
fn format_private_and_unassigned_characters_in_an_id_or_label_make_the_group_unknown() {
    for c in ["\\u202e", "\\u200b", "\\u2028", "\\u2029", "\\ue000", "\\ufffe", "\\ud83d\\ude00", "\\udb40\\udc01"] {
        // An id now takes an ASCII allow list, so an emoji there is refused; a label keeps the category list.
        let ok = c == "\\ud83d\\ude00";
        for (id, label) in [(format!("a{c}b"), "a".to_string()), ("a".to_string(), format!("a{c}b"))] {
            let r = format!(r#"{{"id":"{id}","label":"{label}","loaded":true,"host":"local","paused":false}}"#);
            let want = ok && id == "a";
            assert_eq!(local_state(&list_of(&body(&[r], ""))), if want { "ok" } else { "unknown" }, "{c} {id} {label}");
        }
    }
}

#[test]
fn an_id_takes_an_ascii_allow_list_and_a_label_keeps_the_category_list() {
    let id_row = |id: &str| format!(r#"{{"id":"{id}","label":"a","loaded":true,"host":"local","paused":false}}"#);
    for id in ["a\\u0301b", "a\\u0378b", "a b", "a\\u00e9b", "a\\ud83d\\ude00b", &"x".repeat(201), ""] {
        assert_eq!(local_state(&list_of(&body(&[id_row(id)], ""))), "unknown", "id {id:?}");
    }
    for id in ["qwen3-coder:30b", "org/model.v2_1", &"x".repeat(200)] {
        assert_eq!(local_state(&list_of(&body(&[id_row(id)], ""))), "ok", "id {id:?}");
    }
    // A label with a combining mark or an emoji still passes: labels render as plain text.
    for label in ["a\\u0301b", "a b", "a\\ud83d\\ude00b"] {
        let r = format!(r#"{{"id":"a","label":"{label}","loaded":true,"host":"local","paused":false}}"#);
        assert_eq!(local_state(&list_of(&body(&[r], ""))), "ok", "label {label:?}");
    }
}

#[cfg(unix)]
#[test]
fn a_non_utf8_argument_gives_exit_zero_and_the_unknown_line() {
    use std::os::unix::ffi::OsStringExt;
    let (st, out, err) = binary(&[std::ffi::OsString::from_vec(vec![0xff])]);
    assert_eq!((st.code(), out, err), (Some(0), format!("{UNKNOWN_STATE}\n"), 0));
}
