//! Per-configuration GUI preferences (kill-switch, auto-connect), persisted to a
//! GKeyFile at `$XDG_CONFIG_HOME/warrenvpn/settings.ini`, grouped by config id.

use std::path::PathBuf;

use gtk::glib;

pub const KILLSWITCH: &str = "killswitch";
pub const AUTOCONNECT: &str = "autoconnect";

fn path() -> PathBuf {
    let dir = glib::user_config_dir().join("warrenvpn");
    let _ = std::fs::create_dir_all(&dir);
    dir.join("settings.ini")
}

fn load() -> glib::KeyFile {
    let kf = glib::KeyFile::new();
    let _ = kf.load_from_file(path(), glib::KeyFileFlags::NONE);
    kf
}

/// Read a per-config boolean preference (default `false`).
pub fn get_bool(config_id: &str, key: &str) -> bool {
    load().boolean(config_id, key).unwrap_or(false)
}

/// Persist a per-config boolean preference.
pub fn set_bool(config_id: &str, key: &str, value: bool) {
    let kf = load();
    kf.set_boolean(config_id, key, value);
    let _ = kf.save_to_file(path());
}
