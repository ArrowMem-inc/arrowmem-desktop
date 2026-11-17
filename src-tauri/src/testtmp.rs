//! Test-only temp folders that remove themselves. Created under `std::env::temp_dir()` so TMPDIR is honoured.
use std::ops::Deref;
use std::path::PathBuf;

/// A fresh folder, removed on drop (also while a failing test unwinds).
pub struct TmpDir(PathBuf);

impl TmpDir {
    pub fn new(name: &str) -> TmpDir {
        let d = std::env::temp_dir().join(format!("{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        TmpDir(d)
    }

    /// Same name and removal, but the folder is not created: the code under test makes it.
    pub fn absent(name: &str) -> TmpDir {
        let d = std::env::temp_dir().join(format!("{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        TmpDir(d)
    }
}

impl Deref for TmpDir {
    type Target = PathBuf;
    fn deref(&self) -> &PathBuf { &self.0 }
}

impl AsRef<std::path::Path> for TmpDir {
    fn as_ref(&self) -> &std::path::Path { &self.0 }
}

impl Drop for TmpDir {
    fn drop(&mut self) { let _ = std::fs::remove_dir_all(&self.0); }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;

    /// Runs this very test binary on the modelpick and follow tests with TMPDIR pointed at a fresh folder; nothing may be left in it.
    #[test]
    fn the_guarded_modules_leave_their_temp_folder_empty() {
        let scratch = TmpDir::new("testtmp-scratch");
        let out = Command::new(std::env::current_exe().unwrap())
            .args(["modelpick::tests::", "follow::tests::", "apikey::tests::", "minicred::tests::", "firstrun::tests::", "firewall::tests::",
                   "userunit::tests::", "uninstall::tests::", "linuxrun::tests::", "pairing::tests::", "--test-threads=4"])
            .env("TMPDIR", &*scratch)
            .output()
            .unwrap();
        let text = String::from_utf8_lossy(&out.stdout);
        assert!(out.status.success(), "inner run failed: {text}");
        assert!(text.contains("test result: ok.") && !text.contains(" 0 passed"), "inner run ran nothing: {text}");
        let left: Vec<_> = std::fs::read_dir(&*scratch).unwrap().map(|e| e.unwrap().file_name()).collect();
        assert!(left.is_empty(), "temp folders left behind: {left:?}");
    }

    #[test]
    fn a_dropped_guard_removes_the_folder_and_its_content() {
        let p = {
            let t = TmpDir::new("testtmp-drop");
            std::fs::write(t.join("f"), b"x").unwrap();
            t.to_path_buf()
        };
        assert!(!p.exists());
    }
}
