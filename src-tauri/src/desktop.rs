//! Release 11, S5: the launcher entry. An AppImage installs nothing by itself, so on first run from one the app
//! writes a .desktop file and its icon into the user's XDG data dir (no root). The words are the product name only.

use std::io;
use std::path::{Path, PathBuf};

pub const FILE_NAME: &str = "arrowmem-desktop.desktop";
pub const ICON_NAME: &str = "arrowmem-desktop.png";
const ICON_PNG: &[u8] = include_bytes!("../icons/icon.png");

pub fn launcher_entry(exec_path: &str) -> String {
    format!(
        "[Desktop Entry]\nType=Application\nName=ArrowMem\nExec={}\nIcon=arrowmem-desktop\nTerminal=false\nCategories=Utility;Network;\n",
        crate::autostart::exec_quote(exec_path)
    )
}

pub fn install_launcher(apps_dir: &Path, icons_dir: &Path, exec_path: &str) -> io::Result<()> {
    std::fs::create_dir_all(apps_dir)?;
    std::fs::create_dir_all(icons_dir)?;
    std::fs::write(apps_dir.join(FILE_NAME), launcher_entry(exec_path))?;
    std::fs::write(icons_dir.join(ICON_NAME), ICON_PNG)
}

pub fn remove_launcher(apps_dir: &Path, icons_dir: &Path) -> io::Result<()> {
    for p in [apps_dir.join(FILE_NAME), icons_dir.join(ICON_NAME)] {
        match std::fs::remove_file(p) {
            Err(e) if e.kind() != io::ErrorKind::NotFound => return Err(e),
            _ => {}
        }
    }
    Ok(())
}

/// (applications dir, icon dir) under XDG_DATA_HOME or ~/.local/share.
pub fn data_dirs(xdg_data_home: Option<&str>, home: &str) -> (PathBuf, PathBuf) {
    let base = match xdg_data_home {
        Some(x) if x.starts_with('/') => PathBuf::from(x),
        _ => PathBuf::from(home).join(".local/share"),
    };
    (base.join("applications"), base.join("icons/hicolor/128x128/apps"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entry_fields_are_exact() {
        let e = launcher_entry("/home/u/Apps/ArrowMem.AppImage");
        let lines: Vec<&str> = e.lines().collect();
        assert_eq!(lines, vec![
            "[Desktop Entry]", "Type=Application", "Name=ArrowMem", "Exec=/home/u/Apps/ArrowMem.AppImage",
            "Icon=arrowmem-desktop", "Terminal=false", "Categories=Utility;Network;",
        ]);
    }

    #[test]
    fn exec_with_a_space_is_quoted() {
        assert!(launcher_entry("/home/u/My Apps/a.AppImage").contains("Exec=\"/home/u/My Apps/a.AppImage\"\n"));
    }

    #[test]
    fn install_and_remove_round_trip() {
        let d = std::env::temp_dir().join(format!("desk-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        let (a, i) = data_dirs(Some(d.to_str().unwrap()), "/nope");
        assert_eq!(a, d.join("applications"));
        install_launcher(&a, &i, "/x/app").unwrap();
        assert!(std::fs::read_to_string(a.join(FILE_NAME)).unwrap().contains("Exec=/x/app"));
        assert_eq!(&std::fs::read(i.join(ICON_NAME)).unwrap()[..4], b"\x89PNG");
        remove_launcher(&a, &i).unwrap();
        assert!(!a.join(FILE_NAME).exists() && !i.join(ICON_NAME).exists());
        remove_launcher(&a, &i).unwrap(); // idempotent
        assert_eq!(data_dirs(None, "/h").0, PathBuf::from("/h/.local/share/applications"));
    }
}
