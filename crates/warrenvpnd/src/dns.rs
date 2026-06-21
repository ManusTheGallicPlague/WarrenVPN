//! Apply / revert DNS for a tunnel link via systemd-resolved's D-Bus API
//! (`org.freedesktop.resolve1.Manager`). The daemon owns DNS — it does not let a
//! script reconfigure `/etc/resolv.conf` behind its back.
//!
//! NOTE: end-to-end behavior requires a real tun link and a running
//! systemd-resolved, so it cannot be exercised by the in-repo smoke tests. The
//! pushed-option parsing ([`warrenvpn_core::dns`]) and the interface-index lookup are
//! unit-tested; the D-Bus calls here are compile-checked and modeled on the
//! documented resolve1 interface. When resolved is absent the calls fail and are
//! logged, leaving the tunnel up (a DNS-leak tradeoff to revisit with the
//! resolvconf/raw fallback).

use std::net::IpAddr;

use warrenvpn_core::dns::DnsSettings;
use zbus::Connection;

const DEST: &str = "org.freedesktop.resolve1";
const PATH: &str = "/org/freedesktop/resolve1";
const IFACE: &str = "org.freedesktop.resolve1.Manager";

/// resolve1 expects each address as `(family, raw-bytes)`.
fn address_tuple(ip: &IpAddr) -> (i32, Vec<u8>) {
    match ip {
        IpAddr::V4(a) => (libc_af_inet(), a.octets().to_vec()),
        IpAddr::V6(a) => (libc_af_inet6(), a.octets().to_vec()),
    }
}

// AF_INET / AF_INET6 are stable across Linux; hard-coded to avoid a libc dep.
fn libc_af_inet() -> i32 {
    2
}
fn libc_af_inet6() -> i32 {
    10
}

/// Configure DNS servers + search domains on `ifindex`, and route all DNS through
/// this link (full-tunnel default).
pub async fn apply(conn: &Connection, ifindex: u32, dns: &DnsSettings) -> zbus::Result<()> {
    let proxy = zbus::Proxy::new(conn, DEST, PATH, IFACE).await?;
    let ifi = ifindex as i32;

    let addresses: Vec<(i32, Vec<u8>)> = dns.servers.iter().map(address_tuple).collect();
    let _: () = proxy.call("SetLinkDNS", &(ifi, addresses)).await?;

    let domains: Vec<(String, bool)> = dns
        .search_domains
        .iter()
        .map(|d| (d.clone(), false)) // routing_only = false -> a search domain
        .collect();
    let _: () = proxy.call("SetLinkDomains", &(ifi, domains)).await?;

    let _: () = proxy.call("SetLinkDefaultRoute", &(ifi, true)).await?;
    Ok(())
}

/// Undo all per-link DNS configuration set via [`apply`].
pub async fn revert(conn: &Connection, ifindex: u32) -> zbus::Result<()> {
    let proxy = zbus::Proxy::new(conn, DEST, PATH, IFACE).await?;
    let _: () = proxy.call("RevertLink", &(ifindex as i32,)).await?;
    Ok(())
}
