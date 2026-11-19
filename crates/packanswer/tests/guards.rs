//! Source and dependency guards, and the zero retention proof.
use std::fs;
use std::path::Path;

fn src_files() -> Vec<(String, String)> {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    fs::read_dir(dir).unwrap().map(|e| e.unwrap().path()).map(|p| (p.display().to_string(), fs::read_to_string(&p).unwrap())).collect()
}

/// The code of a source file without its comment lines (comments may name what the code must never do).
fn code(s: &str) -> String {
    s.lines().filter(|l| !l.trim_start().starts_with("//")).collect::<Vec<_>>().join("\n")
}

/// The crisis answer is built in one place, turn.rs, from the gate's closed `CrisisLine`. No other source file of this crate builds one.
#[test]
fn f6_answer_crisis_is_built_only_in_turn_rs_from_the_gates_line() {
    for (name, s) in src_files() {
        let c = code(&s);
        let builds = c.matches("Answer::Crisis {").count();
        if name.ends_with("turn.rs") {
            assert_eq!(builds, 1, "{name}");
            assert!(c.contains("Answer::Crisis { line: r.line,"), "the line must be the gate's own, unmodified");
        } else {
            assert_eq!(builds, 0, "{name} builds Answer::Crisis");
        }
    }
}

#[test]
fn t13_no_network_or_async_crate_is_in_the_lock_and_no_std_net_in_the_source() {
    let lock = fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("Cargo.lock")).unwrap();
    for banned in ["reqwest", "ureq", "hyper", "tokio", "async-std", "socket2", "mio"] {
        assert!(!lock.contains(&format!("name = \"{banned}\"")), "{banned} is in Cargo.lock");
    }
    // a tripwire on top of clippy.toml: a socket type is caught however the `use` is spelled
    for (name, s) in src_files() {
        let c = code(&s);
        for w in ["std::net", "net::", "TcpStream", "TcpListener", "UdpSocket", "UnixStream", "UnixListener", "UnixDatagram"] {
            assert!(!c.contains(w), "{name} contains {w}");
        }
    }
}

#[test]
fn d2_the_crate_forbids_unsafe_code_so_libc_is_constants_only() {
    let lib = fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("src/lib.rs")).unwrap();
    assert!(code(&lib).lines().any(|l| l.trim() == "#![forbid(unsafe_code)]"));
}

#[test]
fn d8_clippy_toml_carries_the_socket_process_and_write_bans() {
    let c = fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("clippy.toml")).unwrap();
    for p in [
        "std::net::TcpStream",
        "std::net::TcpListener",
        "std::net::UdpSocket",
        "std::os::unix::net::UnixStream",
        "std::os::unix::net::UnixListener",
        "std::os::unix::net::UnixDatagram",
        "std::process::Command::new",
        "std::fs::write",
        "std::fs::File::create",
        "std::io::stdout",
        "std::io::stderr",
        "std::fs::copy",
        "std::fs::hard_link",
        "std::os::unix::fs::symlink",
        "std::fs::OpenOptions::write",
        "std::fs::OpenOptions::append",
        "std::fs::OpenOptions::create",
        "std::fs::OpenOptions::create_new",
        "std::fs::OpenOptions::truncate",
        "std::fs::File::create_new",
        "std::fs::rename",
        "std::fs::remove_file",
        "std::fs::create_dir_all",
        "std::fs::create_dir",
        "std::fs::remove_dir",
        "std::fs::remove_dir_all",
        "std::fs::set_permissions",
    ] {
        assert!(c.contains(&format!("path = \"{p}\"")), "{p}");
    }
    // the assert and unreachable family: its panic message, with the question formatted in, is written to stderr by the default hook
    let macros = c.split("disallowed-macros").nth(1).expect("disallowed-macros");
    for m in ["assert", "assert_eq", "assert_ne", "debug_assert", "debug_assert_eq", "debug_assert_ne", "unreachable"] {
        assert!(macros.contains(&format!("path = \"std::{m}\"")), "{m}");
    }
    // clippy's own print lints, denied in the library root: a question can never reach stdout or stderr
    let lib = fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("src/lib.rs")).unwrap();
    // and the panic family: the default panic hook writes its message to stderr, so a question formatted into a panic would reach the journal
    for l in ["#![deny(clippy::print_stdout, clippy::print_stderr, clippy::dbg_macro)]", "#![deny(clippy::panic, clippy::unwrap_used, clippy::expect_used, clippy::todo, clippy::unimplemented)]"] {
        assert!(code(&lib).lines().any(|x| x.trim() == l), "{l}");
    }
}

#[test]
fn t14_no_write_call_exists_in_the_crate_source() {
    for (name, s) in src_files() {
        let c = code(&s);
        for w in ["fs::write", "File::create", "process::", "Command::new", ".create(", ".append(", ".write(", "create_dir", "remove_", "rename(", "println!", "eprintln!", "dbg!", "log::"] {
            assert!(!c.contains(w), "{name} contains {w}");
        }
    }
}

#[test]
fn t19_no_fixed_string_names_an_ai_model_or_a_region() {
    for (name, s) in src_files() {
        let c = code(&s).to_lowercase();
        for w in ["llama", "qwen", "gpt", "claude", "anthropic", "mistral", "gemma", "ca-central", "montreal", "aws", "region"] {
            assert!(!c.contains(w), "{name} contains {w}");
        }
    }
}
