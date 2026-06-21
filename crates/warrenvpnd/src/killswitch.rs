//! Daemon-level kill-switch manager.
//!
//! The `inet warrenvpn` nftables table is a process-wide singleton, so arming/disarming
//! must be coordinated across all connections rather than driven per-connection.
//! This manager keeps the set of currently-armed connections (by id) and their
//! endpoints, and always installs the UNION ruleset. Disarming one connection
//! rebuilds the union (and only tears the table down when the last armed connection
//! is gone), so it can never open another live tunnel's leak protection.

use std::collections::HashMap;
use std::net::IpAddr;
use std::path::Path;
use std::process::Stdio;

use tokio::io::AsyncWriteExt;
use tokio::process::Command;
use tokio::sync::Mutex;

use warrenvpn_core::killswitch::{build_ruleset, teardown_ruleset, Allowance, Endpoint};

/// Coordinates the singleton kill-switch table across all connections.
#[derive(Default)]
pub struct KillSwitch {
    /// conn id -> the connection's current allowance (connecting or connected).
    active: Mutex<HashMap<String, Allowance>>,
}

impl KillSwitch {
    pub fn new() -> Self {
        Self::default()
    }

    async fn rebuild(active: &HashMap<String, Allowance>) -> bool {
        let allowances: Vec<Allowance> = active.values().cloned().collect();
        match build_ruleset(&allowances) {
            Some(rs) => apply(&rs).await,
            None => false,
        }
    }

    /// Arm the connect-phase lockdown for `conn_id` (allow DNS + the candidate
    /// server IPs only) and install the union ruleset. Call BEFORE launching
    /// OpenVPN so the connect window is never unprotected.
    pub async fn arm_connecting(&self, conn_id: &str, remote_ips: Vec<IpAddr>) -> bool {
        let mut active = self.active.lock().await;
        active.insert(conn_id.to_string(), Allowance::Connecting { remote_ips });
        Self::rebuild(&active).await
    }

    /// Switch `conn_id` to the connected (tunnel-locked) allowance and reinstall the
    /// union. Returns whether the table is now correctly installed.
    pub async fn arm_connected(&self, conn_id: &str, endpoint: Endpoint) -> bool {
        let mut active = self.active.lock().await;
        active.insert(conn_id.to_string(), Allowance::Connected(endpoint));
        Self::rebuild(&active).await
    }

    /// Remove `conn_id`'s allowances: rebuild the union, or tear the table down when
    /// no armed connection remains. No-op if it was not armed.
    pub async fn disarm(&self, conn_id: &str) {
        let mut active = self.active.lock().await;
        if active.remove(conn_id).is_none() {
            return;
        }
        if active.is_empty() {
            apply(&teardown_ruleset()).await;
        } else {
            Self::rebuild(&active).await;
        }
    }

    /// Tear everything down (the user's "restore connectivity").
    pub async fn recover(&self) {
        let mut active = self.active.lock().await;
        active.clear();
        apply(&teardown_ruleset()).await;
    }
}

/// Whether the `nft` binary is available; a kill-switch is impossible without it.
pub fn nft_available() -> bool {
    for dir in ["/usr/sbin", "/sbin", "/usr/bin", "/bin"] {
        if Path::new(dir).join("nft").is_file() {
            return true;
        }
    }
    std::env::var_os("PATH")
        .map(|p| std::env::split_paths(&p).any(|d| d.join("nft").is_file()))
        .unwrap_or(false)
}

/// Absolute path to the `nft` binary (root daemon shouldn't trust $PATH).
fn nft_bin() -> &'static str {
    for p in ["/usr/sbin/nft", "/sbin/nft", "/usr/bin/nft"] {
        if Path::new(p).is_file() {
            return p;
        }
    }
    "nft"
}

/// Apply a `nft -f -` script as a single kernel transaction. Returns success.
async fn apply(script: &str) -> bool {
    let mut child = match Command::new(nft_bin())
        .arg("-f")
        .arg("-")
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
    {
        Ok(c) => c,
        Err(e) => {
            eprintln!("warrenvpnd: could not run nft: {e}");
            return false;
        }
    };
    if let Some(mut stdin) = child.stdin.take() {
        if stdin.write_all(script.as_bytes()).await.is_err() {
            return false;
        }
        let _ = stdin.flush().await;
        drop(stdin);
    }
    match child.wait_with_output().await {
        Ok(out) if out.status.success() => true,
        Ok(out) => {
            eprintln!(
                "warrenvpnd: nft failed: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            );
            false
        }
        Err(e) => {
            eprintln!("warrenvpnd: nft wait failed: {e}");
            false
        }
    }
}
