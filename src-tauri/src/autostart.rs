//! XDG autostart for Linux: a .desktop file in ~/.config/autostart. The content and file writing are pure and
//! tested on any OS (against a temp dir); only `autostart_dir()` is Linux-specific, and nothing here is called on
//! other platforms.
use std::io;
use std::path::{Path, PathBuf};

pub const FILE_NAME: &str = "arrowmem-desktop.desktop";

/// Quote an Exec path per the Desktop Entry spec: wrap in double quotes when it has reserved characters and
/// escape `"`, backslash, backtick and `$` with a backslash.
pub(crate) fn exec_quote(path: &str) -> String {
    let reserved = " \t\n\"'\\><~|&;$*?#()`";
    if !path.chars().any(|c| reserved.contains(c)) {
        return path.to_string();
    }
    let mut out = String::from("\"");
    for c in path.chars() {
        if matches!(c, '"' | '\\' | '`' | '$') {
            out.push('\\');
        }
        out.push(c);
    }
    out.push('"');
    out
}

pub fn desktop_entry(exec_path: &str) -> String {
    format!(
        "[Desktop Entry]\nType=Application\nName=ArrowMem\nExec={} --background\nIcon=arrowmem-desktop\n\
         Terminal=false\nCategories=Utility;\nX-GNOME-Autostart-enabled=true\n",
        exec_quote(exec_path)
    )
}

pub fn write_autostart(dir: &Path, exec_path: &str) -> io::Result<PathBuf> {
    std::fs::create_dir_all(dir)?;
    let p = dir.join(FILE_NAME);
    std::fs::write(&p, desktop_entry(exec_path))?;
    Ok(p)
}

pub fn remove_autostart(dir: &Path) -> io::Result<()> {
    match std::fs::remove_file(dir.join(FILE_NAME)) {
        Err(e) if e.kind() != io::ErrorKind::NotFound => Err(e),
        _ => Ok(()),
    }
}

#[cfg(target_os = "linux")]
pub fn autostart_dir() -> Option<PathBuf> {
    let base = std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .filter(|p| p.is_absolute())
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".config")))?;
    Some(base.join("autostart"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entry_content_is_exact() {
        let e = desktop_entry("/usr/bin/arrowmem-desktop");
        assert_eq!(
            e,
            "[Desktop Entry]\nType=Application\nName=ArrowMem\nExec=/usr/bin/arrowmem-desktop --background\n\
             Icon=arrowmem-desktop\nTerminal=false\nCategories=Utility;\nX-GNOME-Autostart-enabled=true\n"
        );
    }

    #[test]
    fn exec_with_space_and_dollar_is_quoted_and_escaped() {
        let e = desktop_entry("/opt/My App/a$b");
        assert!(e.contains("Exec=\"/opt/My App/a\\$b\" --background\n"), "{e}");
    }

    #[test]
    fn write_and_remove_in_temp_dir() {
        let d = std::env::temp_dir().join(format!("amd-autostart-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        let dir = d.join("autostart");
        let p = write_autostart(&dir, "/usr/bin/arrowmem-desktop").unwrap();
        assert_eq!(p, dir.join("arrowmem-desktop.desktop"));
        assert!(std::fs::read_to_string(&p).unwrap().starts_with("[Desktop Entry]\n"));
        remove_autostart(&dir).unwrap();
        assert!(!p.exists());
        remove_autostart(&dir).unwrap(); // idempotent
        let _ = std::fs::remove_dir_all(&d);
    }
}
