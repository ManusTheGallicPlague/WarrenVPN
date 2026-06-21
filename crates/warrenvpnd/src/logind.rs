//! React to systemd-logind power events.
//!
//! On `PrepareForShutdown(true)` we disconnect every active tunnel cleanly, so the
//! kill-switch is torn down and DNS reverted before the machine powers off (rather
//! than leaving an orphaned OpenVPN / a stale nftables table for the boot-time
//! recovery unit to mop up).
//!
//! Sleep/wake is intentionally not handled here: OpenVPN's own `ping-restart`
//! re-establishes the tunnel after resume, and the relay re-applies DNS and re-arms
//! the kill-switch on each CONNECTED — so the kill-switch stays armed across suspend
//! (no leak) and self-heals on wake.

use std::sync::Arc;

use futures_util::StreamExt;
use tokio::sync::Mutex;
use zbus::zvariant::OwnedObjectPath;
use zbus::Connection;

use crate::connection::VpnConnection;

/// Subscribe to logind and disconnect all tunnels on shutdown. Best-effort: if
/// logind is unavailable the daemon simply runs without this integration.
pub fn spawn(conn: Connection, active: Arc<Mutex<Vec<(u32, OwnedObjectPath)>>>) {
    tokio::spawn(async move {
        let proxy = match zbus::Proxy::new(
            &conn,
            "org.freedesktop.login1",
            "/org/freedesktop/login1",
            "org.freedesktop.login1.Manager",
        )
        .await
        {
            Ok(p) => p,
            Err(e) => {
                eprintln!("warrenvpnd: logind unavailable, power-event handling off: {e}");
                return;
            }
        };

        let mut shutdown = match proxy.receive_signal("PrepareForShutdown").await {
            Ok(s) => s,
            Err(e) => {
                eprintln!("warrenvpnd: could not subscribe to PrepareForShutdown: {e}");
                return;
            }
        };

        while let Some(msg) = shutdown.next().await {
            if msg.body().deserialize::<bool>().unwrap_or(false) {
                eprintln!("warrenvpnd: system shutting down — disconnecting all VPNs");
                let paths = active.lock().await.clone();
                for (_uid, path) in paths {
                    if let Ok(iref) = conn
                        .object_server()
                        .interface::<_, VpnConnection>(&path)
                        .await
                    {
                        iref.get().await.shutdown().await;
                    }
                }
            }
        }
    });
}
