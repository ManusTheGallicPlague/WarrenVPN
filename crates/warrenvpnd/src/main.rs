//! warrenvpnd — the WarrenVPN privileged daemon.
//!
//! A D-Bus system-bus service (`net.warrenvpn.WarrenVPN1`) that owns the product's
//! entire privilege boundary. This MVP implements the `Manager` configuration and
//! capability surface — every privileged method is polkit-gated and the daemon
//! classifies configurations safe/unsafe itself via `warrenvpn-core`. Launching
//! OpenVPN and the live per-connection objects (management relay + state signals)
//! are the next increment; the building blocks (`warrenvpn_core::openvpn`,
//! `warrenvpn_core::management`) are already implemented and unit-tested.
//!
//! Development: set `WARRENVPND_BUS=session` to run on the session bus (no root),
//! `WARRENVPND_STATE_DIR` / `WARRENVPND_RUNTIME_DIR` to relocate state, and
//! `WARRENVPND_INSECURE_ALLOW_ALL=1` to bypass polkit (insecure; for smoke tests).

mod connection;
mod dns;
mod killswitch;
mod logind;
mod polkit;

use std::collections::HashMap;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use tokio::sync::Mutex;
use zbus::message::Header;
use zbus::zvariant::{OwnedObjectPath, OwnedValue, Value};
use zbus::connection::Builder as ConnBuilder;
use zbus::{fdo, interface, Connection};

use ovpn_config::Config;
use warrenvpn_common::{actions, DBUS_SYSTEM_NAME, DBUS_SYSTEM_PATH, RUNTIME_DIR, STATE_DIR};
use warrenvpn_core::store::ConfigStore;

/// The Manager object served at [`DBUS_SYSTEM_PATH`].
struct Manager {
    /// Root of the persistent state tree; each user's shadow store lives under
    /// `<state_dir>/users/<caller-uid>`.
    state_dir: PathBuf,
    /// Where management sockets / runtime state live.
    runtime_dir: PathBuf,
    /// Resolved path to the `openvpn` binary, if present.
    openvpn_path: Option<PathBuf>,
    /// Resolved path to the trusted up/down DNS helper, if installed.
    updown_path: Option<PathBuf>,
    /// Daemon-level kill-switch manager (shared across all connections).
    killswitch: Arc<killswitch::KillSwitch>,
    /// Live connections as `(owner uid, object path)`.
    active: Arc<Mutex<Vec<(u32, OwnedObjectPath)>>>,
}

impl Manager {
    /// The shadow store scoped to a specific user.
    fn store_for(&self, uid: u32) -> ConfigStore {
        ConfigStore::new(self.state_dir.join("users").join(uid.to_string()))
    }
}

/// Resolve the uid of the authenticated D-Bus caller via the bus daemon, rather
/// than trusting anything the caller asserts. Used to scope every per-user
/// operation to the caller's own store.
pub(crate) async fn caller_uid(conn: &Connection, hdr: &Header<'_>) -> fdo::Result<u32> {
    let sender = hdr
        .sender()
        .ok_or_else(|| fdo::Error::Failed("message has no sender".into()))?;
    let dbus = fdo::DBusProxy::new(conn)
        .await
        .map_err(|e| fdo::Error::Failed(format!("D-Bus proxy: {e}")))?;
    dbus.get_connection_unix_user(sender.to_owned().into())
        .await
        .map_err(|e| fdo::Error::Failed(format!("caller uid lookup: {e}")))
}

#[interface(name = "net.warrenvpn.WarrenVPN1.Manager")]
impl Manager {
    /// Daemon version, for staleness detection. No authorization required.
    async fn get_version(&self) -> String {
        env!("CARGO_PKG_VERSION").to_string()
    }

    /// Runtime capabilities. No authorization required.
    async fn probe(&self) -> HashMap<String, OwnedValue> {
        let mut caps: HashMap<String, OwnedValue> = HashMap::new();
        caps.insert("version".into(), ov(Value::from(env!("CARGO_PKG_VERSION"))));
        caps.insert(
            "tun_available".into(),
            ov(Value::from(Path::new("/dev/net/tun").exists())),
        );
        caps.insert(
            "resolved_available".into(),
            ov(Value::from(Path::new("/run/systemd/resolve").exists())),
        );
        caps.insert(
            "openvpn_path".into(),
            ov(Value::from(
                self.openvpn_path
                    .as_ref()
                    .map(|p| p.to_string_lossy().into_owned())
                    .unwrap_or_default(),
            )),
        );
        caps.insert(
            "runtime_dir".into(),
            ov(Value::from(self.runtime_dir.to_string_lossy().into_owned())),
        );
        caps.insert(
            "killswitch_available".into(),
            ov(Value::from(killswitch::nft_available())),
        );
        caps
    }

    /// Install a configuration from its `contents` (the unprivileged client reads
    /// the file as the user and sends the bytes, so the daemon never opens a
    /// caller-controlled path as root). The daemon computes the safe/unsafe verdict
    /// server-side and stores a root-owned shadow copy under the caller's own
    /// store. Authorized by `install-config`. Returns the immutable config id.
    async fn install_config(
        &self,
        name: String,
        contents: String,
        _scope: String,
        _options: HashMap<String, OwnedValue>,
        #[zbus(header)] hdr: Header<'_>,
        #[zbus(connection)] conn: &Connection,
    ) -> fdo::Result<String> {
        let sender = sender_of(&hdr)?;
        polkit::require(
            polkit::check(conn, &sender, actions::INSTALL_CONFIG).await,
            actions::INSTALL_CONFIG,
        )?;

        let uid = caller_uid(conn, &hdr).await?;
        let display = if name.trim().is_empty() {
            "configuration".to_string()
        } else {
            name
        };

        let installed = self
            .store_for(uid)
            .install_contents(&contents, &display)
            .map_err(io_to_fdo)?;
        eprintln!(
            "warrenvpnd: uid {uid} installed config {} ({}) safe={}",
            installed.id, installed.name, installed.safe
        );
        Ok(installed.id)
    }

    /// List the calling user's configurations as `(id, name, safe)` tuples.
    async fn list_configs(
        &self,
        #[zbus(header)] hdr: Header<'_>,
        #[zbus(connection)] conn: &Connection,
    ) -> fdo::Result<Vec<(String, String, bool)>> {
        let uid = caller_uid(conn, &hdr).await?;
        let list = self.store_for(uid).list().map_err(io_to_fdo)?;
        Ok(list.into_iter().map(|c| (c.id, c.name, c.safe)).collect())
    }

    /// Return one of the calling user's configurations with secrets removed.
    async fn get_sanitized_config(
        &self,
        id: String,
        #[zbus(header)] hdr: Header<'_>,
        #[zbus(connection)] conn: &Connection,
    ) -> fdo::Result<String> {
        let uid = caller_uid(conn, &hdr).await?;
        self.store_for(uid).sanitized(&id).map_err(io_to_fdo)
    }

    /// Remove one of the calling user's configurations. Authorized by
    /// `install-config` (config management).
    async fn remove_config(
        &self,
        id: String,
        #[zbus(header)] hdr: Header<'_>,
        #[zbus(connection)] conn: &Connection,
    ) -> fdo::Result<()> {
        let sender = sender_of(&hdr)?;
        polkit::require(
            polkit::check(conn, &sender, actions::INSTALL_CONFIG).await,
            actions::INSTALL_CONFIG,
        )?;
        let uid = caller_uid(conn, &hdr).await?;
        self.store_for(uid).remove(&id).map_err(io_to_fdo)?;
        eprintln!("warrenvpnd: uid {uid} removed config {id}");
        Ok(())
    }

    /// Start a connection from an installed configuration. Authorized by `connect`.
    /// Launches OpenVPN under our control and returns the live connection object.
    async fn start_connection(
        &self,
        config_id: String,
        options: HashMap<String, OwnedValue>,
        #[zbus(header)] hdr: Header<'_>,
        #[zbus(connection)] conn: &Connection,
    ) -> fdo::Result<OwnedObjectPath> {
        let sender = sender_of(&hdr)?;
        let uid = caller_uid(conn, &hdr).await?;

        // Resolve the config within the CALLER's own store (rejects malformed ids).
        let cfg = self
            .store_for(uid)
            .get(&config_id)
            .map_err(io_to_fdo)?
            .ok_or_else(|| fdo::Error::FileNotFound(format!("no such configuration: {config_id}")))?;

        // Re-derive the safe/unsafe verdict from the exact bytes we are about to run
        // as root — the config bytes, not the stored metadata, are the authority for
        // the privilege decision.
        let bytes = std::fs::read_to_string(&cfg.path).map_err(io_to_fdo)?;
        let safe = Config::parse(&bytes).is_safe();

        // Defense in depth: connecting a safe config is passwordless for an active
        // session; an unsafe config (which can run code as root) requires admin.
        let action = if safe {
            actions::CONNECT
        } else {
            actions::CONNECT_UNSAFE
        };
        polkit::require(polkit::check(conn, &sender, action).await, action)?;

        let openvpn = self
            .openvpn_path
            .clone()
            .ok_or_else(|| fdo::Error::Failed("the openvpn binary was not found".into()))?;

        // DNS management uses a trusted up/down helper, which needs script-security 2.
        // We only enable it for SAFE configs (which by classification have no user
        // scripts of their own, so the only script that runs is ours). For an unsafe
        // (admin-approved) config we inject nothing and leave its own settings alone;
        // for a safe config with no helper installed we force script-security 1.
        let (up_script, script_security) = match (safe, self.updown_path.as_deref()) {
            (true, Some(updown)) => (Some(updown), Some(2)),
            (true, None) => (None, Some(1)),
            (false, _) => (None, None),
        };

        let killswitch = options
            .get("killswitch")
            .and_then(|v| bool::try_from(v.clone()).ok())
            .unwrap_or(false);

        // Fail closed up front: refuse a kill-switch connect we could never arm.
        if killswitch && !killswitch::nft_available() {
            return Err(fdo::Error::NotSupported(
                "kill-switch requested but nftables (nft) is not available".into(),
            ));
        }

        // Resolve the server endpoint(s) so the connect-phase kill-switch can
        // whitelist them before OpenVPN starts.
        let remote_ips = if killswitch {
            resolve_remotes(&cfg.path).await
        } else {
            Vec::new()
        };

        connection::launch_and_attach(connection::LaunchParams {
            zconn: conn,
            openvpn: &openvpn,
            runtime_dir: &self.runtime_dir,
            config_id: &config_id,
            config_path: &cfg.path,
            script_security,
            up_script,
            killswitch,
            killswitch_mgr: self.killswitch.clone(),
            owner_uid: uid,
            remote_ips,
            active: self.active.clone(),
        })
        .await
    }

    /// Restore network connectivity by tearing down the kill-switch. Authorized by
    /// `killswitch` (lenient — a user can always recover their own network). Works
    /// even with no active connection (e.g. after an unexpected disconnect).
    async fn recover_network(
        &self,
        #[zbus(header)] hdr: Header<'_>,
        #[zbus(connection)] conn: &Connection,
    ) -> fdo::Result<()> {
        let sender = sender_of(&hdr)?;
        polkit::require(
            polkit::check(conn, &sender, actions::KILLSWITCH).await,
            actions::KILLSWITCH,
        )?;
        self.killswitch.recover().await;
        eprintln!("warrenvpnd: network restored (kill-switch torn down)");
        Ok(())
    }

    /// Object paths of the caller's own live connections.
    async fn list_connections(
        &self,
        #[zbus(header)] hdr: Header<'_>,
        #[zbus(connection)] conn: &Connection,
    ) -> fdo::Result<Vec<OwnedObjectPath>> {
        let uid = caller_uid(conn, &hdr).await?;
        Ok(self
            .active
            .lock()
            .await
            .iter()
            .filter(|(owner, _)| *owner == uid)
            .map(|(_, path)| path.clone())
            .collect())
    }
}

/// Wrap a [`Value`] into an [`OwnedValue`] for an `a{sv}` reply.
fn ov(v: Value<'_>) -> OwnedValue {
    v.try_to_owned().expect("value is ownable")
}

/// Extract the caller's unique bus name from the message header.
fn sender_of(hdr: &Header<'_>) -> fdo::Result<String> {
    hdr.sender()
        .map(|n| n.to_string())
        .ok_or_else(|| fdo::Error::Failed("message has no sender".into()))
}

fn io_to_fdo(e: std::io::Error) -> fdo::Error {
    if e.kind() == std::io::ErrorKind::NotFound {
        fdo::Error::FileNotFound(e.to_string())
    } else {
        fdo::Error::Failed(e.to_string())
    }
}

/// Locate the `openvpn` binary: an explicit `WARRENVPND_OPENVPN_PATH` override (used
/// for testing and for selecting a bundled build) wins, otherwise search `PATH`.
fn find_openvpn() -> Option<PathBuf> {
    if let Some(p) = std::env::var_os("WARRENVPND_OPENVPN_PATH") {
        let p = PathBuf::from(p);
        if p.is_file() {
            return Some(p);
        }
    }
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .map(|d| d.join("openvpn"))
        .find(|p| p.is_file())
}

/// Resolve the candidate server IPs from a configuration's `remote` lines, so the
/// connect-phase kill-switch can whitelist them before OpenVPN starts. Literal IPs
/// are used directly; hostnames are resolved. Best-effort (returns what it can).
async fn resolve_remotes(config_path: &Path) -> Vec<IpAddr> {
    let contents = match tokio::fs::read_to_string(config_path).await {
        Ok(c) => c,
        Err(_) => return Vec::new(),
    };
    let cfg = Config::parse(&contents);
    let mut ips: Vec<IpAddr> = Vec::new();
    for entry in cfg.entries_with_option("remote") {
        let Some(host) = entry.get(1) else { continue };
        let host = host.trim_matches('"');
        if let Ok(ip) = host.parse::<IpAddr>() {
            if !ips.contains(&ip) {
                ips.push(ip);
            }
        } else if let Ok(addrs) = tokio::net::lookup_host(format!("{host}:0")).await {
            for a in addrs {
                let ip = a.ip();
                if !ips.contains(&ip) {
                    ips.push(ip);
                }
            }
        }
    }
    ips
}

/// Locate the trusted up/down DNS helper. `WARRENVPND_UPDOWN_PATH` overrides the
/// installed location. Returns `None` if absent (DNS management is then skipped).
fn find_updown() -> Option<PathBuf> {
    let candidate = std::env::var_os("WARRENVPND_UPDOWN_PATH")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/usr/lib/warrenvpn/warrenvpn-updown"));
    candidate.is_file().then_some(candidate)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let use_session = std::env::var("WARRENVPND_BUS").as_deref() == Ok("session");

    let state_dir = std::env::var_os("WARRENVPND_STATE_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(STATE_DIR));
    let runtime_dir = std::env::var_os("WARRENVPND_RUNTIME_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(RUNTIME_DIR));

    let active = Arc::new(Mutex::new(Vec::new()));
    let manager = Manager {
        state_dir,
        runtime_dir,
        openvpn_path: find_openvpn(),
        updown_path: find_updown(),
        killswitch: Arc::new(killswitch::KillSwitch::new()),
        active: active.clone(),
    };

    eprintln!(
        "warrenvpnd {} starting on {} bus, name {}",
        env!("CARGO_PKG_VERSION"),
        if use_session { "session" } else { "system" },
        DBUS_SYSTEM_NAME,
    );

    let builder = if use_session {
        ConnBuilder::session()?
    } else {
        ConnBuilder::system()?
    };

    let conn = builder
        .name(DBUS_SYSTEM_NAME)?
        .serve_at(DBUS_SYSTEM_PATH, manager)?
        .build()
        .await?;

    eprintln!("warrenvpnd: serving {DBUS_SYSTEM_PATH}");

    // Disconnect cleanly on system shutdown.
    logind::spawn(conn.clone(), active);

    // Run until terminated. (D-Bus activation + idle-exit is added with the
    // connection lifecycle increment.)
    std::future::pending::<()>().await;
    Ok(())
}
