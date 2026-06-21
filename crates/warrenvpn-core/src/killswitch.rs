//! Build the nftables ruleset for the kill-switch.
//!
//! When armed, **all** locally-generated and **forwarded** traffic is dropped
//! except: loopback, the tunnel device(s), and the VPN server endpoint(s) over the
//! physical link (so OpenVPN can establish/maintain/re-establish the tunnel). DHCP
//! is permitted so the physical link can renew. Because the table is `inet` and the
//! default policy is `drop`, non-tunnel IPv6 is dropped too — closing the IPv6 leak.
//!
//! Blast radius (intentional): an nftables base-chain `drop` is final across all
//! tables, so while armed **every** non-tunnel egress dies — including
//! Docker/Podman/libvirt/LXC guest traffic (the `forward` chain) and host services
//! to non-tunnel destinations. That is the point of a kill-switch; `RecoverNetwork`
//! is the explicit unblock path. The table is independent, so a `firewalld`/`ufw`
//! reload does not touch it (and cannot clear it — that is the recovery unit's job).
//!
//! The ruleset supports MULTIPLE simultaneous tunnels: the daemon arms a UNION of
//! every active tunnel's device + endpoint, so tearing one down never opens the
//! others. It is applied atomically via a single `nft -f -` stream (one kernel
//! transaction — never an empty-table window); splitting that into multiple `nft`
//! calls would briefly strand even tunnel traffic.

use std::collections::BTreeSet;
use std::net::IpAddr;

/// The dedicated table name. Kept distinct so we never touch other firewall rules.
pub const TABLE: &str = "warrenvpn";

/// Transport protocol of the VPN server connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Proto {
    Udp,
    Tcp,
}

impl Proto {
    fn keyword(self) -> &'static str {
        match self {
            Proto::Udp => "udp",
            Proto::Tcp => "tcp",
        }
    }
}

/// One active tunnel's allowances: its device and the server endpoint it uses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Endpoint {
    /// The tunnel device name (e.g. `tun0`). MUST be a validated interface name.
    pub tun_dev: String,
    /// The actual VPN server address OpenVPN connected to (`trusted_ip`).
    pub server_ip: IpAddr,
    /// The server port (`trusted_port`).
    pub server_port: u16,
    /// The server transport protocol.
    pub proto: Proto,
}

/// What one connection is allowed to reach, depending on its phase. The daemon arms
/// the UNION of all connections' allowances.
#[derive(Debug, Clone)]
pub enum Allowance {
    /// Before the tunnel is up: allow DNS resolution + the candidate server IP(s)
    /// over the physical link (so OpenVPN can resolve `remote` and handshake), but
    /// block all other egress. Closes the connect-window leak.
    Connecting { remote_ips: Vec<IpAddr> },
    /// Once connected: allow the tunnel device + the actual server endpoint only.
    Connected(Endpoint),
}

/// True if `dev` is a plausible network interface name (defensive: it is
/// interpolated into the nft script).
pub fn is_valid_ifname(dev: &str) -> bool {
    !dev.is_empty()
        && dev.len() <= 15
        && dev
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'.')
}

fn daddr_line(ip: &IpAddr, suffix: &str) -> String {
    let fam = match ip {
        IpAddr::V4(_) => "ip",
        IpAddr::V6(_) => "ip6",
    };
    format!("\t\t{fam} daddr {ip}{suffix} accept\n")
}

/// Build the `nft -f` script that atomically (re)installs the kill-switch for the
/// UNION of all `allowances`. Returns `None` if `allowances` is empty or any
/// connected interface name is invalid (we never build an injectable/partial set).
pub fn build_ruleset(allowances: &[Allowance]) -> Option<String> {
    if allowances.is_empty() {
        return None;
    }
    // Validate connected interface names (interpolated into the script).
    for a in allowances {
        if let Allowance::Connected(e) = a {
            if !is_valid_ifname(&e.tun_dev) {
                return None;
            }
        }
    }

    let connecting = allowances
        .iter()
        .any(|a| matches!(a, Allowance::Connecting { .. }));
    // Distinct connected tunnel devices.
    let devs: BTreeSet<&str> = allowances
        .iter()
        .filter_map(|a| match a {
            Allowance::Connected(e) => Some(e.tun_dev.as_str()),
            _ => None,
        })
        .collect();

    let mut s = String::new();
    s.push_str(&format!("table inet {TABLE} {{}}\n"));
    s.push_str(&format!("delete table inet {TABLE}\n"));
    s.push_str(&format!("table inet {TABLE} {{\n"));

    // --- output: locally-generated traffic ---
    s.push_str("\tchain output {\n");
    s.push_str("\t\ttype filter hook output priority filter; policy drop;\n");
    s.push_str("\t\toifname \"lo\" accept\n");
    s.push_str("\t\tudp sport 68 udp dport 67 accept\n");
    s.push_str("\t\tudp sport 546 udp dport 547 accept\n");
    // During any connect phase, DNS must resolve so OpenVPN can reach `remote`.
    if connecting {
        s.push_str("\t\tudp dport 53 accept\n");
        s.push_str("\t\ttcp dport 53 accept\n");
    }
    for dev in &devs {
        s.push_str(&format!("\t\toifname \"{dev}\" accept\n"));
    }
    for a in allowances {
        match a {
            Allowance::Connecting { remote_ips } => {
                for ip in remote_ips {
                    s.push_str(&daddr_line(ip, ""));
                }
            }
            Allowance::Connected(e) => {
                s.push_str(&daddr_line(
                    &e.server_ip,
                    &format!(" {} dport {}", e.proto.keyword(), e.server_port),
                ));
            }
        }
    }
    s.push_str("\t}\n");

    // --- forward: routed traffic (containers / VMs / downstream clients) ---
    s.push_str("\tchain forward {\n");
    s.push_str("\t\ttype filter hook forward priority filter; policy drop;\n");
    s.push_str("\t\tct state established,related accept\n");
    for dev in &devs {
        s.push_str(&format!("\t\toifname \"{dev}\" accept\n"));
    }
    s.push_str("\t}\n");

    s.push_str("}\n");
    Some(s)
}

/// An idempotent `nft -f` script that tears the kill-switch down (disarm/recovery).
/// The create-then-delete idiom tolerates the table not existing.
pub fn teardown_ruleset() -> String {
    format!("table inet {TABLE} {{}}\ndelete table inet {TABLE}\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ep(dev: &str, ip: &str, port: u16, proto: Proto) -> Endpoint {
        Endpoint {
            tun_dev: dev.into(),
            server_ip: ip.parse().unwrap(),
            server_port: port,
            proto,
        }
    }

    fn conn(dev: &str, ip: &str, port: u16, proto: Proto) -> Allowance {
        Allowance::Connected(ep(dev, ip, port, proto))
    }

    #[test]
    fn builds_udp_v4_ruleset_with_both_chains() {
        let r = build_ruleset(&[conn("tun0", "203.0.113.7", 1194, Proto::Udp)]).unwrap();
        assert!(r.contains("table inet warrenvpn {}"));
        assert!(r.contains("delete table inet warrenvpn"));
        assert!(r.contains("chain output {"));
        assert!(r.contains("chain forward {"));
        assert!(r.contains("type filter hook output priority filter; policy drop;"));
        assert!(r.contains("type filter hook forward priority filter; policy drop;"));
        assert!(r.contains("oifname \"lo\" accept"));
        assert!(r.contains("oifname \"tun0\" accept"));
        assert!(r.contains("ip daddr 203.0.113.7 udp dport 1194 accept"));
        assert!(r.contains("ct state established,related accept"));
        assert!(!r.contains("ip6 daddr")); // v6 endpoint absent -> dropped by policy
    }

    #[test]
    fn builds_tcp_v6_ruleset() {
        let r = build_ruleset(&[conn("tun1", "2001:db8::1", 443, Proto::Tcp)]).unwrap();
        assert!(r.contains("ip6 daddr 2001:db8::1 tcp dport 443 accept"));
    }

    #[test]
    fn unions_multiple_tunnels() {
        let r = build_ruleset(&[
            conn("tun0", "203.0.113.7", 1194, Proto::Udp),
            conn("tun1", "198.51.100.9", 443, Proto::Tcp),
        ])
        .unwrap();
        assert!(r.contains("oifname \"tun0\" accept"));
        assert!(r.contains("oifname \"tun1\" accept"));
        assert!(r.contains("ip daddr 203.0.113.7 udp dport 1194 accept"));
        assert!(r.contains("ip daddr 198.51.100.9 tcp dport 443 accept"));
    }

    #[test]
    fn connect_phase_allows_dns_and_remotes_but_no_tunnel() {
        let r = build_ruleset(&[Allowance::Connecting {
            remote_ips: vec!["203.0.113.7".parse().unwrap(), "2001:db8::9".parse().unwrap()],
        }])
        .unwrap();
        assert!(r.contains("policy drop;"));
        assert!(r.contains("udp dport 53 accept")); // DNS allowed while connecting
        assert!(r.contains("tcp dport 53 accept"));
        assert!(r.contains("ip daddr 203.0.113.7 accept")); // candidate server, any port
        assert!(r.contains("ip6 daddr 2001:db8::9 accept"));
        assert!(!r.contains("oifname \"tun")); // no tunnel device yet
    }

    #[test]
    fn empty_or_invalid_yields_none() {
        assert!(build_ruleset(&[]).is_none());
        assert!(build_ruleset(&[conn("bad dev", "1.2.3.4", 1, Proto::Udp)]).is_none());
        assert!(is_valid_ifname("tun0"));
        assert!(!is_valid_ifname("tun0\"; drop"));
        assert!(!is_valid_ifname("waaaaaaaaytoolong"));
    }
}
