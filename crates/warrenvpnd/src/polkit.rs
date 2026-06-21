//! polkit authorization. Every privileged daemon method calls [`check`] with the
//! D-Bus caller as the subject before acting.
//!
//! A development bypass exists (`WARRENVPND_INSECURE_ALLOW_ALL=1`) so the daemon can be
//! exercised on a session bus without a polkit agent. It is INSECURE and logs a
//! loud warning; it must never be set in production.

use std::collections::HashMap;

use zbus::zvariant::Value;
use zbus::Connection;

#[cfg(debug_assertions)]
const INSECURE_ENV: &str = "WARRENVPND_INSECURE_ALLOW_ALL";

/// Result of an authorization check.
pub enum Authz {
    Allowed,
    Denied,
    /// polkit or its agent could not be reached.
    Unavailable(String),
}

/// Check whether `sender` (a D-Bus unique name) is authorized for `action`.
pub async fn check(conn: &Connection, sender: &str, action: &str) -> Authz {
    // The bypass is compiled out of release builds, so a shipped binary can never
    // skip polkit regardless of the environment.
    #[cfg(debug_assertions)]
    if std::env::var(INSECURE_ENV).as_deref() == Ok("1") {
        eprintln!("warrenvpnd: WARNING: {INSECURE_ENV}=1 — bypassing polkit for `{action}` (INSECURE, dev only)");
        return Authz::Allowed;
    }

    // Subject = ("system-bus-name", {"name": <sender>})
    let mut subject_details: HashMap<&str, Value> = HashMap::new();
    subject_details.insert("name", Value::from(sender));
    let subject = ("system-bus-name", subject_details);

    let details: HashMap<&str, &str> = HashMap::new();
    // flags bit 0 = AllowUserInteraction (let the agent prompt for admin actions).
    let flags: u32 = 1;
    let cancellation_id = "";

    let proxy = match zbus::Proxy::new(
        conn,
        "org.freedesktop.PolicyKit1",
        "/org/freedesktop/PolicyKit1/Authority",
        "org.freedesktop.PolicyKit1.Authority",
    )
    .await
    {
        Ok(p) => p,
        Err(e) => return Authz::Unavailable(format!("polkit proxy: {e}")),
    };

    let reply: Result<(bool, bool, HashMap<String, String>), _> = proxy
        .call(
            "CheckAuthorization",
            &(subject, action, details, flags, cancellation_id),
        )
        .await;

    match reply {
        Ok((authorized, _challenge, _details)) => {
            if authorized {
                Authz::Allowed
            } else {
                Authz::Denied
            }
        }
        Err(e) => Authz::Unavailable(format!("CheckAuthorization: {e}")),
    }
}

/// Convert an [`Authz`] into a D-Bus error for the non-allowed cases.
pub fn require(authz: Authz, action: &str) -> Result<(), zbus::fdo::Error> {
    match authz {
        Authz::Allowed => Ok(()),
        Authz::Denied => Err(zbus::fdo::Error::AccessDenied(format!(
            "not authorized for {action}"
        ))),
        Authz::Unavailable(why) => Err(zbus::fdo::Error::AuthFailed(format!(
            "authorization unavailable for {action}: {why}"
        ))),
    }
}
