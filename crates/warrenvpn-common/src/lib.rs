//! WarrenVPN identity — the single source of truth.
//!
//! Every namespace the product exposes (app-id, binary names, D-Bus bus/interface
//! names, polkit action ids, filesystem locations, the Unix group) is derived from
//! the constants here. Rebranding the product is, by design, an edit of this one
//! file plus the matching packaging templates under `packaging/` (which embed the
//! same strings). Keeping it centralized is a Phase-0 requirement so the privilege
//! contract stays internally consistent.

#![forbid(unsafe_code)]

/// Human-facing product name.
pub const PRODUCT_NAME: &str = "WarrenVPN";

/// Reverse-DNS application id (also the GApplication / session bus name).
pub const APP_ID: &str = "net.warrenvpn.WarrenVPN";

/// Installed binary names.
pub const DAEMON_BINARY: &str = "warrenvpnd";
pub const APP_BINARY: &str = "warrenvpn";

// ----------------------------------------------------------------- D-Bus ---

/// Privileged system-bus service (the daemon). Calls are authorized per-method via
/// polkit; this name is owned only by the root daemon.
pub const DBUS_SYSTEM_NAME: &str = "net.warrenvpn.WarrenVPN1";
pub const DBUS_SYSTEM_PATH: &str = "/net/warrenvpn/WarrenVPN1";
/// Top-level manager interface on the system bus.
pub const DBUS_MANAGER_IFACE: &str = "net.warrenvpn.WarrenVPN1.Manager";
/// Per-connection object interface on the system bus.
pub const DBUS_CONNECTION_IFACE: &str = "net.warrenvpn.WarrenVPN1.Connection";
/// Object path prefix for per-connection objects.
pub const DBUS_CONNECTION_PATH_PREFIX: &str = "/net/warrenvpn/WarrenVPN1/connection/";

/// Session-bus automation/scripting surface; served by the GUI agent and driven by
/// the CLI. The session bus name equals [`APP_ID`].
pub const DBUS_SESSION_NAME: &str = APP_ID;
pub const DBUS_SESSION_PATH: &str = "/net/warrenvpn/WarrenVPN";
pub const DBUS_CONTROL_IFACE: &str = "net.warrenvpn.WarrenVPN.Control";

// ----------------------------------------------------------------- polkit ---

/// Prefix for every polkit action id.
pub const POLKIT_PREFIX: &str = "net.warrenvpn";

/// polkit action ids. The authorization defaults live in the `.policy` file under
/// `packaging/polkit/`; these constants are what the daemon passes to
/// `CheckAuthorization`.
pub mod actions {
    /// Start/stop a VPN connection from a *safe* configuration. Default: allowed
    /// for any active local session (no prompt).
    pub const CONNECT: &str = "net.warrenvpn.connect";
    /// Start a connection from an *unsafe* configuration (one whose options can run
    /// code as root). Default: admin. This is the connect-time defense in depth so
    /// an unsafe config can never reach a passwordless root path.
    pub const CONNECT_UNSAFE: &str = "net.warrenvpn.connect-unsafe";
    /// Install / move / remove a configuration. Default: admin (kept briefly).
    pub const INSTALL_CONFIG: &str = "net.warrenvpn.install-config";
    /// Install/reload the daemon, change forced preferences. Default: admin.
    pub const MANAGE_DAEMON: &str = "net.warrenvpn.manage-daemon";
    /// Apply a self-update (AppImage path only). Default: admin.
    pub const UPDATE_INSTALL: &str = "net.warrenvpn.update-install";
    /// Configure connect-at-boot (before login). Default: admin.
    pub const CONNECT_AT_BOOT: &str = "net.warrenvpn.connect-at-boot";
    /// Arm/disarm the kill-switch and restore connectivity. Default: lenient
    /// (any active session) so a user can always recover their own network.
    pub const KILLSWITCH: &str = "net.warrenvpn.killswitch";
}

// ------------------------------------------------------------ filesystem ---

/// Unix group that owns shared/managed config files and shadow copies.
pub const SYSTEM_GROUP: &str = "warrenvpn";

/// Runtime directory (tmpfs): per-connection state, management sockets, password
/// files. Created 0700 root. Wiped on reboot.
pub const RUNTIME_DIR: &str = "/run/warrenvpn";
/// Persistent state: root-owned shadow copies, crash-recovery snapshots.
pub const STATE_DIR: &str = "/var/lib/warrenvpn";
/// System configuration: forced (admin) preferences and shared configurations.
pub const CONFIG_DIR: &str = "/etc/warrenvpn";
/// Bundled/deployed (rebranded enterprise) configurations.
pub const DEPLOY_DIR: &str = "/usr/share/warrenvpn/deploy";

/// Per-user data subdirectory name (under `$XDG_DATA_HOME` and `$XDG_CONFIG_HOME`).
pub const USER_DIR_NAME: &str = "warrenvpn";

/// The D-Bus object path for the connection identified by `id`.
pub fn connection_path(id: &str) -> String {
    format!("{DBUS_CONNECTION_PATH_PREFIX}{id}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_is_internally_consistent() {
        // The session bus name is the app-id.
        assert_eq!(DBUS_SESSION_NAME, APP_ID);
        // D-Bus names use the reverse-DNS app-id stem.
        assert!(DBUS_SYSTEM_NAME.starts_with("net.warrenvpn."));
        assert!(DBUS_MANAGER_IFACE.starts_with(DBUS_SYSTEM_NAME));
        assert!(DBUS_CONNECTION_IFACE.starts_with(DBUS_SYSTEM_NAME));
        // Object paths are the dotted names with '.' -> '/'.
        assert_eq!(DBUS_SYSTEM_PATH, "/net/warrenvpn/WarrenVPN1");
    }

    #[test]
    fn all_polkit_actions_share_the_prefix() {
        for action in [
            actions::CONNECT,
            actions::CONNECT_UNSAFE,
            actions::INSTALL_CONFIG,
            actions::MANAGE_DAEMON,
            actions::UPDATE_INSTALL,
            actions::CONNECT_AT_BOOT,
            actions::KILLSWITCH,
        ] {
            assert!(action.starts_with(POLKIT_PREFIX), "{action} lacks prefix");
        }
    }

    #[test]
    fn system_paths_are_absolute() {
        for p in [RUNTIME_DIR, STATE_DIR, CONFIG_DIR, DEPLOY_DIR] {
            assert!(p.starts_with('/'), "{p} is not absolute");
        }
    }

    #[test]
    fn connection_path_is_well_formed() {
        let p = connection_path("abc123");
        assert_eq!(p, "/net/warrenvpn/WarrenVPN1/connection/abc123");
        assert!(p.starts_with(DBUS_SYSTEM_PATH));
    }
}
