//! Credential persistence via the freedesktop Secret Service (libsecret).
//!
//! Credentials are keyed by the immutable configuration id and a field name
//! (`username` / `password` / `passphrase`), so a renamed configuration keeps its
//! saved secrets. All operations are best-effort: if no Secret Service is running
//! (headless box, no keyring), they log and return `None`/do nothing rather than
//! failing the connection.

use std::collections::HashMap;

use gtk::gio;
use libsecret::{Schema, SchemaAttributeType, SchemaFlags};
use warrenvpn_common::APP_ID;

const ATTR_CONFIG: &str = "config-id";
const ATTR_FIELD: &str = "field";

fn schema() -> Schema {
    let mut attrs = HashMap::new();
    attrs.insert(ATTR_CONFIG, SchemaAttributeType::String);
    attrs.insert(ATTR_FIELD, SchemaAttributeType::String);
    Schema::new(APP_ID, SchemaFlags::NONE, attrs)
}

fn attrs<'a>(config_id: &'a str, field: &'a str) -> HashMap<&'a str, &'a str> {
    let mut m = HashMap::new();
    m.insert(ATTR_CONFIG, config_id);
    m.insert(ATTR_FIELD, field);
    m
}

/// Store (or replace) a secret for a configuration field.
pub fn store(config_id: &str, field: &str, value: &str) {
    let label = format!("WarrenVPN VPN — {field} ({config_id})");
    if let Err(e) = libsecret::password_store_sync(
        Some(&schema()),
        attrs(config_id, field),
        Some(libsecret::COLLECTION_DEFAULT),
        &label,
        value,
        gio::Cancellable::NONE,
    ) {
        eprintln!("warrenvpn: could not save {field} to keyring: {e}");
    }
}

/// Look up a saved secret, or `None` if absent / unavailable.
pub fn lookup(config_id: &str, field: &str) -> Option<String> {
    match libsecret::password_lookup_sync(Some(&schema()), attrs(config_id, field), gio::Cancellable::NONE)
    {
        Ok(opt) => opt.map(|g| g.to_string()),
        Err(e) => {
            eprintln!("warrenvpn: keyring lookup failed: {e}");
            None
        }
    }
}

/// Forget a saved secret.
pub fn clear(config_id: &str, field: &str) {
    let _ = libsecret::password_clear_sync(Some(&schema()), attrs(config_id, field), gio::Cancellable::NONE);
}
