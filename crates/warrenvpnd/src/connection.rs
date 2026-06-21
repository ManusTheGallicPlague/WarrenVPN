//! The live per-connection D-Bus object and the OpenVPN management relay.
//!
//! `launch_and_attach` starts an OpenVPN process under our control, connects to its
//! management socket, registers a [`VpnConnection`] object on the bus, and spawns a
//! task that translates management-channel notifications into typed D-Bus signals.
//! Unprivileged clients drive the tunnel through this object and never see the raw
//! socket.

use std::collections::HashMap;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::unix::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::UnixStream;
use tokio::process::Child;
use tokio::sync::Mutex;

use zbus::message::Header;
use zbus::object_server::SignalEmitter;
use zbus::zvariant::{OwnedObjectPath, OwnedValue};
use zbus::{fdo, interface, Connection as ZConnection};

use warrenvpn_common::connection_path;
use crate::killswitch::KillSwitch;
use warrenvpn_core::dns::{interface_index, parse_foreign_options};
use warrenvpn_core::killswitch::{Endpoint, Proto};
use warrenvpn_core::management::{
    command, crv1_password, is_browser_url, parse_management_line, parse_password_request,
    scrv1_password, ManagementMessage,
};
use warrenvpn_core::openvpn::{build_openvpn_args, LaunchSpec};
use warrenvpn_core::util::random_id;

/// Mutable per-connection state, shared between the D-Bus object and the relay task.
#[derive(Default)]
pub struct ConnState {
    pub state: String,
    pub detail: String,
    pub bytes_in: u64,
    pub bytes_out: u64,
    /// Details of the most recent, unanswered `>PASSWORD:` request, so
    /// `ProvideCredentials` knows how to reply.
    pub pending_auth: Option<PendingAuth>,
    /// Set by `Disconnect` so the relay can distinguish an expected teardown (where
    /// the kill-switch is disarmed) from an unexpected drop (where it stays armed).
    pub expected_disconnect: bool,
}

/// What the daemon needs to remember between an auth prompt and the reply.
#[derive(Clone)]
pub struct PendingAuth {
    pub realm: String,
    pub needs_username: bool,
    /// True if the prompt carried a static challenge (reply password must be SCRV1).
    pub has_static_challenge: bool,
    /// `(state_id, username)` if a dynamic challenge (CRV1) is pending; the reply
    /// password must be `CRV1::<state_id>::<response>`.
    pub dynamic: Option<(String, String)>,
}

/// A live VPN connection exposed at `/net/warrenvpn/WarrenVPN1/connection/<id>`.
pub struct VpnConnection {
    config_id: String,
    /// uid of the user that started this connection; only they may control it.
    owner_uid: u32,
    state: Arc<Mutex<ConnState>>,
    writer: Arc<Mutex<OwnedWriteHalf>>,
}

#[interface(name = "net.warrenvpn.WarrenVPN1.Connection")]
impl VpnConnection {
    #[zbus(property)]
    async fn config_id(&self) -> String {
        self.config_id.clone()
    }

    #[zbus(property)]
    async fn state(&self) -> String {
        self.state.lock().await.state.clone()
    }

    #[zbus(property)]
    async fn state_detail(&self) -> String {
        self.state.lock().await.detail.clone()
    }

    #[zbus(property)]
    async fn bytes_in(&self) -> u64 {
        self.state.lock().await.bytes_in
    }

    #[zbus(property)]
    async fn bytes_out(&self) -> u64 {
        self.state.lock().await.bytes_out
    }

    /// Orderly disconnect via the management channel (`signal SIGTERM`). Only the
    /// user that started the connection may do this.
    async fn disconnect(
        &self,
        #[zbus(header)] hdr: Header<'_>,
        #[zbus(connection)] conn: &ZConnection,
    ) -> fdo::Result<()> {
        self.authorize(conn, &hdr).await?;
        self.shutdown().await;
        Ok(())
    }

    /// Provide credentials in response to an [`Self::auth_request`]. `fields` may
    /// contain `username` and/or `password` (string variants). The daemon replies
    /// to OpenVPN's management channel for the realm recorded from the prompt.
    async fn provide_credentials(
        &self,
        _kind: String,
        fields: HashMap<String, OwnedValue>,
        #[zbus(header)] hdr: Header<'_>,
        #[zbus(connection)] conn: &ZConnection,
    ) -> fdo::Result<()> {
        self.authorize(conn, &hdr).await?;
        let pending = {
            let mut s = self.state.lock().await;
            s.pending_auth
                .take()
                .ok_or_else(|| fdo::Error::Failed("no pending authentication request".into()))?
        };

        // A dynamic challenge (CRV1) re-sends the original username and a
        // CRV1::state::response password; nothing else is needed.
        if let Some((state_id, username)) = &pending.dynamic {
            let response = str_field(&fields, "challenge")
                .or_else(|| str_field(&fields, "password"))
                .unwrap_or_default();
            let pass = crv1_password(state_id, &response);
            let mut w = self.writer.lock().await;
            w.write_all(command::username(&pending.realm, username).as_bytes())
                .await
                .map_err(write_err)?;
            w.write_all(command::password(&pending.realm, &pass).as_bytes())
                .await
                .map_err(write_err)?;
            w.flush().await.map_err(write_err)?;
            return Ok(());
        }

        // A static challenge folds the extra response into the password as SCRV1.
        let mut pass = str_field(&fields, "password")
            .ok_or_else(|| fdo::Error::InvalidArgs("password field required".into()))?;
        if pending.has_static_challenge {
            let response = str_field(&fields, "challenge").unwrap_or_default();
            pass = scrv1_password(&pass, &response);
        }

        let mut w = self.writer.lock().await;
        if pending.needs_username {
            let user = str_field(&fields, "username")
                .ok_or_else(|| fdo::Error::InvalidArgs("username field required".into()))?;
            w.write_all(command::username(&pending.realm, &user).as_bytes())
                .await
                .map_err(write_err)?;
        }
        w.write_all(command::password(&pending.realm, &pass).as_bytes())
            .await
            .map_err(write_err)?;
        w.flush().await.map_err(write_err)?;
        Ok(())
    }

    // State / StateDetail / BytesIn / BytesOut changes are delivered via the
    // standard org.freedesktop.DBus.Properties `PropertiesChanged` signal (emitted
    // by the property notifiers the `#[zbus(property)]` attribute generates).
    // Only events without a property backing get explicit signals:

    #[zbus(signal)]
    async fn auth_request(
        emitter: &SignalEmitter<'_>,
        kind: &str,
        realm: &str,
        prompt: &str,
        challenge: &str,
        echo: bool,
    ) -> zbus::Result<()>;

    #[zbus(signal)]
    async fn log_line(emitter: &SignalEmitter<'_>, line: &str) -> zbus::Result<()>;

    /// The server requires single-sign-on: the user must open `url` in a browser.
    #[zbus(signal)]
    async fn web_auth(emitter: &SignalEmitter<'_>, url: &str) -> zbus::Result<()>;
}

/// Extract a string field from a D-Bus `a{sv}` credential map.
fn str_field(fields: &HashMap<String, OwnedValue>, key: &str) -> Option<String> {
    let v = fields.get(key)?;
    <&str>::try_from(v).ok().map(str::to_owned)
}

/// Map a management-socket write error to a D-Bus error.
fn write_err(e: std::io::Error) -> fdo::Error {
    fdo::Error::Failed(format!("management write failed: {e}"))
}

impl VpnConnection {
    /// Mark the disconnect as expected and signal OpenVPN to exit (best-effort).
    /// Used by the `Disconnect` D-Bus method and by the logind shutdown handler.
    pub async fn shutdown(&self) {
        self.state.lock().await.expected_disconnect = true;
        send_sigterm(&self.writer).await;
    }

    /// Reject a caller that is not the user who started this connection. Enforced
    /// in-process (the system D-Bus policy intentionally lets any local user send;
    /// this is the real authorization boundary for per-connection control).
    async fn authorize(&self, conn: &ZConnection, hdr: &Header<'_>) -> fdo::Result<()> {
        let uid = crate::caller_uid(conn, hdr).await?;
        if uid == self.owner_uid {
            Ok(())
        } else {
            Err(fdo::Error::AccessDenied(
                "only the user that started this connection may control it".into(),
            ))
        }
    }
}

/// Inputs needed to start a connection.
pub struct LaunchParams<'a> {
    pub zconn: &'a ZConnection,
    pub openvpn: &'a Path,
    pub runtime_dir: &'a Path,
    pub config_id: &'a str,
    pub config_path: &'a Path,
    /// `--script-security` level to force, or `None` to leave it to the config.
    pub script_security: Option<u8>,
    /// Trusted up/down helper for DNS capture (safe configs only); `None` disables
    /// daemon-managed DNS for this connection.
    pub up_script: Option<&'a Path>,
    /// Arm the nftables kill-switch once connected (kept active on unexpected drop).
    pub killswitch: bool,
    /// The daemon-level kill-switch manager (shared across all connections).
    pub killswitch_mgr: Arc<KillSwitch>,
    /// uid of the user starting this connection (only they may control it).
    pub owner_uid: u32,
    /// Resolved candidate server IPs, used to arm the connect-phase kill-switch
    /// before OpenVPN is even spawned (empty when the kill-switch is off).
    pub remote_ips: Vec<IpAddr>,
    pub active: Arc<Mutex<Vec<(u32, OwnedObjectPath)>>>,
}

/// Launch OpenVPN, attach to its management socket, register a [`VpnConnection`]
/// object, and start relaying notifications. Returns the new object's path.
pub async fn launch_and_attach(p: LaunchParams<'_>) -> fdo::Result<OwnedObjectPath> {
    let connid = random_id().map_err(|e| fdo::Error::Failed(e.to_string()))?;

    tokio::fs::create_dir_all(p.runtime_dir).await.ok();
    let sock = p.runtime_dir.join(format!("{connid}.sock"));
    let _ = tokio::fs::remove_file(&sock).await; // clear any stale socket

    // When DNS is managed, the trusted up/down helper writes the pushed options here.
    let env_file = p.up_script.map(|_| p.runtime_dir.join(format!("{connid}.env")));

    let spec = LaunchSpec {
        config_path: p.config_path,
        management_socket: &sock,
        verb: 3,
        management_hold: true,
        script_security: p.script_security,
        up_script: p.up_script,
        env_file: env_file.as_deref(),
    };
    let args = build_openvpn_args(&spec);

    // Arm the connect-phase kill-switch BEFORE spawning OpenVPN, so the connect
    // window (DNS + handshake) is never unprotected and a connection that never
    // reaches CONNECTED is still fail-closed. Refuse to start if it can't be armed.
    if p.killswitch
        && !p
            .killswitch_mgr
            .arm_connecting(&connid, p.remote_ips.clone())
            .await
    {
        return Err(fdo::Error::Failed(
            "could not arm the kill-switch — refusing to connect (fail-closed)".into(),
        ));
    }

    // TODO(scope): launch inside a transient systemd scope so the tunnel survives a
    // daemon idle-exit. Direct spawn is sufficient for the MVP path.
    let child = tokio::process::Command::new(p.openvpn)
        .args(&args)
        .kill_on_drop(true) // never leak the root openvpn on an error path before the relay owns it
        .spawn()
        .map_err(|e| fdo::Error::Failed(format!("failed to launch openvpn: {e}")))?;
    let child = Arc::new(Mutex::new(child));

    wait_for_socket(&sock, &child).await?;

    let stream = UnixStream::connect(&sock)
        .await
        .map_err(|e| fdo::Error::Failed(format!("management connect failed: {e}")))?;
    let (read_half, write_half) = stream.into_split();

    let state = Arc::new(Mutex::new(ConnState::default()));
    let writer = Arc::new(Mutex::new(write_half));

    let path = OwnedObjectPath::try_from(connection_path(&connid))
        .map_err(|e| fdo::Error::Failed(format!("bad object path: {e}")))?;

    let iface = VpnConnection {
        config_id: p.config_id.to_string(),
        owner_uid: p.owner_uid,
        state: state.clone(),
        writer: writer.clone(),
    };
    p.zconn
        .object_server()
        .at(&path, iface)
        .await
        .map_err(|e| fdo::Error::Failed(format!("register connection object: {e}")))?;
    p.active.lock().await.push((p.owner_uid, path.clone()));

    let zconn = p.zconn.clone();
    let relay_path = path.clone();
    let active = p.active.clone();
    let killswitch = p.killswitch;
    let killswitch_mgr = p.killswitch_mgr.clone();
    let connid_for_relay = connid.clone();
    tokio::spawn(async move {
        relay(RelayCtx {
            read: read_half,
            writer,
            state,
            child,
            zconn,
            path: relay_path,
            active,
            env_file,
            sock,
            killswitch,
            killswitch_mgr,
            conn_id: connid_for_relay,
        })
        .await;
    });

    Ok(path)
}

/// Wait for OpenVPN to create its management socket, failing fast if it exits.
async fn wait_for_socket(sock: &Path, child: &Arc<Mutex<Child>>) -> fdo::Result<()> {
    for _ in 0..200 {
        if sock.exists() {
            return Ok(());
        }
        if let Ok(Some(status)) = child.lock().await.try_wait() {
            return Err(fdo::Error::Failed(format!(
                "openvpn exited before opening its management socket ({status})"
            )));
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    Err(fdo::Error::Failed(
        "timed out waiting for the management socket".into(),
    ))
}

/// Inputs for the management relay task.
struct RelayCtx {
    read: OwnedReadHalf,
    writer: Arc<Mutex<OwnedWriteHalf>>,
    state: Arc<Mutex<ConnState>>,
    child: Arc<Mutex<Child>>,
    zconn: ZConnection,
    path: OwnedObjectPath,
    active: Arc<Mutex<Vec<(u32, OwnedObjectPath)>>>,
    env_file: Option<PathBuf>,
    sock: PathBuf,
    killswitch: bool,
    killswitch_mgr: Arc<KillSwitch>,
    conn_id: String,
}

/// Drive the management channel: enable notifications, release the hold, then relay
/// each line as a typed signal until the socket closes.
async fn relay(ctx: RelayCtx) {
    let RelayCtx {
        read,
        writer,
        state,
        child,
        zconn,
        path,
        active,
        env_file,
        sock,
        killswitch,
        killswitch_mgr,
        conn_id,
    } = ctx;
    {
        let mut w = writer.lock().await;
        let _ = w.write_all(command::STATE_ON.as_bytes()).await;
        let _ = w.write_all(command::bytecount(1).as_bytes()).await;
        let _ = w.write_all(command::HOLD_RELEASE.as_bytes()).await;
        let _ = w.flush().await;
    }

    // Per-connection post-connect side effects, undone on teardown.
    let mut dns_ifindex: Option<u32> = None;
    let mut killswitch_armed = false;

    // Resolve the registered interface so we can both emit property-change
    // notifications (PropertiesChanged) and our explicit signals.
    let iface_ref = match zconn
        .object_server()
        .interface::<_, VpnConnection>(&path)
        .await
    {
        Ok(r) => r,
        Err(_) => return,
    };

    let mut reader = BufReader::new(read);
    while let Some(line) = read_capped_line(&mut reader, MAX_MGMT_LINE).await {
        match parse_management_line(&line) {
            ManagementMessage::State { name, detail, .. } => {
                let is_connected = name == "CONNECTED";
                {
                    let mut s = state.lock().await;
                    s.state = name;
                    s.detail = detail;
                }
                {
                    let guard = iface_ref.get().await;
                    let _ = guard.state_changed(iface_ref.signal_emitter()).await;
                    let _ = guard.state_detail_changed(iface_ref.signal_emitter()).await;
                }

                // Re-assert DNS + kill-switch on EVERY CONNECTED so a reconnect to a
                // different server IP or tun device self-heals.
                if is_connected {
                    let env = match &env_file {
                        Some(ef) => Some(read_env_map(ef).await),
                        None => None,
                    };
                    if let Some(env) = &env {
                        match apply_dns_from_env(&zconn, env).await {
                            Ok(Some(idx)) => dns_ifindex = Some(idx),
                            Ok(None) => {}
                            Err(()) if killswitch => {
                                // With the kill-switch on, unconfined DNS would leak
                                // to the pre-VPN resolver — fail closed instead.
                                eprintln!(
                                    "warrenvpnd: DNS apply failed with kill-switch on — \
                                     tearing down the connection (fail-closed)"
                                );
                                send_sigterm(&writer).await;
                            }
                            Err(()) => {}
                        }
                    }
                    if killswitch {
                        let armed = match env.as_ref().and_then(endpoint_from_env) {
                            Some(ep) => killswitch_mgr.arm_connected(&conn_id, ep).await,
                            None => false,
                        };
                        killswitch_armed = armed;
                        if armed {
                            eprintln!("warrenvpnd: kill-switch tunnel-locked for {conn_id}");
                        } else {
                            // Fail closed: never run a kill-switch tunnel unprotected.
                            eprintln!(
                                "warrenvpnd: kill-switch requested but could not be armed — \
                                 tearing down the connection (fail-closed)"
                            );
                            send_sigterm(&writer).await;
                        }
                    }
                }
            }
            ManagementMessage::ByteCount {
                bytes_in,
                bytes_out,
            } => {
                {
                    let mut s = state.lock().await;
                    s.bytes_in = bytes_in;
                    s.bytes_out = bytes_out;
                }
                let guard = iface_ref.get().await;
                let _ = guard.bytes_in_changed(iface_ref.signal_emitter()).await;
                let _ = guard.bytes_out_changed(iface_ref.signal_emitter()).await;
            }
            ManagementMessage::PasswordRequest { prompt } => {
                if let Some(p) = parse_password_request(&prompt) {
                    let plain_kind = if p.needs_username {
                        "auth-user-pass"
                    } else {
                        "passphrase"
                    };
                    let (kind, challenge, echo, needs_username, dynamic) =
                        if let Some(dc) = &p.dynamic_challenge {
                            (
                                "dynamic-challenge",
                                dc.text.clone(),
                                dc.echo,
                                false,
                                Some((dc.state_id.clone(), dc.username.clone())),
                            )
                        } else if let Some(sc) = &p.static_challenge {
                            (plain_kind, sc.text.clone(), sc.echo, p.needs_username, None)
                        } else {
                            (plain_kind, String::new(), false, p.needs_username, None)
                        };
                    state.lock().await.pending_auth = Some(PendingAuth {
                        realm: p.realm.clone(),
                        needs_username,
                        has_static_challenge: p.static_challenge.is_some(),
                        dynamic,
                    });
                    let _ = VpnConnection::auth_request(
                        iface_ref.signal_emitter(),
                        kind,
                        &p.realm,
                        &prompt,
                        &challenge,
                        echo,
                    )
                    .await;
                }
            }
            ManagementMessage::Log(l) => {
                let _ = VpnConnection::log_line(iface_ref.signal_emitter(), &l).await;
            }
            ManagementMessage::WebAuthUrl(url) => {
                if is_browser_url(&url) {
                    eprintln!("warrenvpnd: web-auth (SSO) URL: {url}");
                    let _ = VpnConnection::web_auth(iface_ref.signal_emitter(), &url).await;
                } else {
                    eprintln!("warrenvpnd: refusing non-http(s) web-auth URL from server: {url}");
                }
            }
            _ => {}
        }
    }

    // Socket closed: OpenVPN exited.
    let expected = state.lock().await.expected_disconnect;
    if let Some(ifindex) = dns_ifindex {
        if let Err(e) = crate::dns::revert(&zconn, ifindex).await {
            eprintln!("warrenvpnd: DNS revert (link {ifindex}) failed: {e}");
        }
    }
    if killswitch_armed && !expected {
        // Unexpected drop: keep this connection's allowances in the union so egress
        // stays blocked (no leak) until the user reconnects or calls RecoverNetwork.
        eprintln!(
            "warrenvpnd: kill-switch KEPT ACTIVE after an unexpected disconnect — \
             egress stays blocked until you reconnect or RecoverNetwork"
        );
    } else {
        // Expected disconnect (or never armed): drop this connection's allowances;
        // the manager tears the table down only when the last tunnel is gone.
        killswitch_mgr.disarm(&conn_id).await;
        if killswitch_armed {
            eprintln!("warrenvpnd: kill-switch disarmed (expected disconnect)");
        }
    }
    let _ = child.lock().await.wait().await;
    let _ = zconn
        .object_server()
        .remove::<VpnConnection, _>(&path)
        .await;
    active.lock().await.retain(|(_, p)| p != &path);

    // Clean up the per-connection runtime files (the management socket and the
    // captured env, which held the endpoint/DNS info).
    let _ = tokio::fs::remove_file(&sock).await;
    if let Some(ef) = &env_file {
        let _ = tokio::fs::remove_file(ef).await;
    }
}

/// Maximum length of a single OpenVPN management line we buffer. They are tiny; a
/// generous cap prevents an unbounded allocation from a flood with no newline.
const MAX_MGMT_LINE: usize = 64 * 1024;

/// Read one newline-terminated management line, capping its length. Returns the line
/// (an empty string for an over-long line that is discarded) or `None` at EOF.
async fn read_capped_line(reader: &mut BufReader<OwnedReadHalf>, max: usize) -> Option<String> {
    let mut buf: Vec<u8> = Vec::new();
    let mut overflow = false;
    loop {
        let chunk = match reader.fill_buf().await {
            Ok(c) => c,
            Err(_) => return None,
        };
        if chunk.is_empty() {
            return if buf.is_empty() && !overflow {
                None
            } else {
                Some(String::from_utf8_lossy(&buf).into_owned())
            };
        }
        if let Some(pos) = chunk.iter().position(|&b| b == b'\n') {
            if !overflow && buf.len() + pos <= max {
                buf.extend_from_slice(&chunk[..pos]);
            } else {
                overflow = true;
            }
            reader.consume(pos + 1);
            if overflow {
                eprintln!("warrenvpnd: dropped an over-long management line");
                return Some(String::new());
            }
            return Some(String::from_utf8_lossy(&buf).into_owned());
        }
        let len = chunk.len();
        if !overflow && buf.len() + len <= max {
            buf.extend_from_slice(chunk);
        } else {
            overflow = true;
            buf = Vec::new();
        }
        reader.consume(len);
    }
}

/// Read the `key=value` lines the trusted up helper wrote into a map.
async fn read_env_map(env_file: &Path) -> HashMap<String, String> {
    let mut map = HashMap::new();
    if let Ok(contents) = tokio::fs::read_to_string(env_file).await {
        for line in contents.lines() {
            if let Some((k, v)) = line.split_once('=') {
                // First-write-wins: the helper writes the authoritative keys
                // (dev/trusted_*/proto) first, so an injected duplicate later in the
                // file (e.g. a crafted foreign_option) can never override them.
                map.entry(k.to_string()).or_insert_with(|| v.to_string());
            }
        }
    }
    map
}

/// Apply the pushed DNS via systemd-resolved. `Ok(Some(ifindex))` = applied (revert
/// on teardown); `Ok(None)` = nothing to apply (no dev / no pushed DNS); `Err(())` =
/// DNS was expected but could not be applied (the caller fails closed when the
/// kill-switch is on, so queries can't fall back to the pre-VPN resolver).
async fn apply_dns_from_env(
    zconn: &ZConnection,
    env: &HashMap<String, String>,
) -> Result<Option<u32>, ()> {
    let Some(dev) = env.get("dev").filter(|d| !d.is_empty()) else {
        return Ok(None);
    };
    let options: Vec<&String> = env
        .iter()
        .filter(|(k, _)| k.starts_with("foreign_option_"))
        .map(|(_, v)| v)
        .collect();
    let dns = parse_foreign_options(options.iter().map(|s| s.as_str()));
    if dns.is_empty() {
        return Ok(None);
    }
    let ifindex = match interface_index(dev) {
        Ok(i) => i,
        Err(e) => {
            eprintln!("warrenvpnd: could not resolve interface {dev}: {e}");
            return Err(());
        }
    };
    match crate::dns::apply(zconn, ifindex, &dns).await {
        Ok(()) => {
            eprintln!(
                "warrenvpnd: applied DNS on {dev} (link {ifindex}): {} server(s), {} domain(s)",
                dns.servers.len(),
                dns.search_domains.len()
            );
            Ok(Some(ifindex))
        }
        Err(e) => {
            eprintln!("warrenvpnd: DNS apply on {dev} failed: {e}");
            Err(())
        }
    }
}

/// Build the kill-switch [`Endpoint`] from the captured up-helper environment.
fn endpoint_from_env(env: &HashMap<String, String>) -> Option<Endpoint> {
    let tun_dev = env.get("dev").filter(|d| !d.is_empty())?.clone();
    let server_ip = env
        .get("trusted_ip")
        .or_else(|| env.get("trusted_ip6"))
        .and_then(|s| s.parse::<IpAddr>().ok())?;
    let server_port = env.get("trusted_port").and_then(|s| s.parse::<u16>().ok())?;
    let proto = match env.get("proto").map(String::as_str) {
        Some(p) if p.starts_with("tcp") => Proto::Tcp,
        _ => Proto::Udp,
    };
    Some(Endpoint {
        tun_dev,
        server_ip,
        server_port,
        proto,
    })
}

/// Send `signal SIGTERM` over the management channel (used to fail closed).
async fn send_sigterm(writer: &Arc<Mutex<OwnedWriteHalf>>) {
    let mut w = writer.lock().await;
    let _ = w.write_all(command::SIGTERM.as_bytes()).await;
    let _ = w.flush().await;
}
