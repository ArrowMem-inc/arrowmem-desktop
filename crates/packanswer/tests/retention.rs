//! The behavioural half. A single test in its own binary, so it may point HOME, TMPDIR, XDG_* and the working directory at empty folders
//! without racing another test. (The source test in guards.rs covers a write to a hard coded absolute path.)
mod common;
use common::*;
use packanswer::answer;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

fn entries(dir: &Path) -> usize {
    fs::read_dir(dir).unwrap().count()
}

#[test]
fn t14_a_hundred_turns_over_a_read_only_pack_create_no_file() {
    let p = pack("r-pack");
    let pack_dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join("r-pack");
    let watched = Path::new(env!("CARGO_TARGET_TMPDIR")).join("r-watch");
    let _ = fs::remove_dir_all(&watched);
    fs::create_dir_all(&watched).unwrap();
    for k in ["HOME", "TMPDIR", "XDG_CACHE_HOME", "XDG_DATA_HOME", "XDG_STATE_HOME", "XDG_CONFIG_HOME"] {
        std::env::set_var(k, &watched);
    }
    std::env::set_current_dir(&watched).unwrap();
    let before = entries(&pack_dir);
    fs::set_permissions(&pack_dir, fs::Permissions::from_mode(0o555)).unwrap();
    for i in 0..100 {
        let q = ["water", "ginger", "I want to kill myself", "qzxv", "tent pegs"][i % 5];
        answer(Some(&p), q, "en", None);
    }
    fs::set_permissions(&pack_dir, fs::Permissions::from_mode(0o755)).unwrap();
    assert_eq!(entries(&pack_dir), before);
    assert_eq!(entries(&watched), 0);
}
