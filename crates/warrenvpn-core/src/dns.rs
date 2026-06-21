//! Parse the DNS settings OpenVPN pushes to its up/down script.
//!
//! OpenVPN hands pushed `dhcp-option` directives to the up script as environment
//! variables `foreign_option_1`, `foreign_option_2`, … each holding a string like
//! `dhcp-option DNS 10.8.0.1` or `dhcp-option DOMAIN-SEARCH corp.example.com`. The
//! daemon collects those values and turns them into a [`DnsSettings`] which it then
//! applies to the tun link via systemd-resolved.

use std::net::IpAddr;

/// DNS configuration extracted from OpenVPN's pushed options.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DnsSettings {
    /// DNS server addresses, in push order.
    pub servers: Vec<IpAddr>,
    /// Search domains (from DOMAIN / DOMAIN-SEARCH / ADAPTER_DOMAIN_SUFFIX).
    pub search_domains: Vec<String>,
}

impl DnsSettings {
    /// True if nothing DNS-related was pushed.
    pub fn is_empty(&self) -> bool {
        self.servers.is_empty() && self.search_domains.is_empty()
    }
}

/// Parse a list of `foreign_option_*` values (the part after `foreign_option_N=`)
/// into [`DnsSettings`]. Unknown or malformed entries are ignored.
pub fn parse_foreign_options<I, S>(values: I) -> DnsSettings
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let mut out = DnsSettings::default();
    for value in values {
        let v = value.as_ref();
        // Expect: "dhcp-option <TYPE> <ARG>"
        let mut it = v.split_whitespace();
        if it.next() != Some("dhcp-option") {
            continue;
        }
        let kind = match it.next() {
            Some(k) => k.to_ascii_uppercase(),
            None => continue,
        };
        let arg = match it.next() {
            Some(a) => a,
            None => continue,
        };
        match kind.as_str() {
            "DNS" | "DNS6" => {
                if let Ok(ip) = arg.parse::<IpAddr>() {
                    if !out.servers.contains(&ip) {
                        out.servers.push(ip);
                    }
                }
            }
            "DOMAIN" | "DOMAIN-SEARCH" | "ADAPTER_DOMAIN_SUFFIX" => {
                let d = arg.trim_end_matches('.').to_string();
                if !d.is_empty() && !out.search_domains.contains(&d) {
                    out.search_domains.push(d);
                }
            }
            _ => {}
        }
    }
    out
}

/// Read the kernel interface index for a network device (e.g. `tun0`) from
/// `/sys/class/net/<dev>/ifindex`. Avoids pulling libc just for `if_nametoindex`.
pub fn interface_index(dev: &str) -> std::io::Result<u32> {
    // Reject anything that is not a bare interface name (no path components).
    if dev.is_empty() || dev.contains('/') || dev.contains("..") {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "invalid interface name",
        ));
    }
    let raw = std::fs::read_to_string(format!("/sys/class/net/{dev}/ifindex"))?;
    raw.trim()
        .parse::<u32>()
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidData, "bad ifindex"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_dns_servers_and_domains() {
        let opts = [
            "dhcp-option DNS 10.8.0.1",
            "dhcp-option DNS 10.8.0.2",
            "dhcp-option DOMAIN-SEARCH corp.example.com",
            "dhcp-option DOMAIN example.org.",
        ];
        let s = parse_foreign_options(opts);
        assert_eq!(
            s.servers,
            vec![
                "10.8.0.1".parse::<IpAddr>().unwrap(),
                "10.8.0.2".parse::<IpAddr>().unwrap()
            ]
        );
        assert_eq!(s.search_domains, vec!["corp.example.com", "example.org"]);
        assert!(!s.is_empty());
    }

    #[test]
    fn parses_ipv6_dns() {
        let s = parse_foreign_options(["dhcp-option DNS6 2001:db8::1"]);
        assert_eq!(s.servers, vec!["2001:db8::1".parse::<IpAddr>().unwrap()]);
    }

    #[test]
    fn ignores_unknown_and_malformed() {
        let s = parse_foreign_options([
            "dhcp-option WINS 10.0.0.1",   // not DNS/DOMAIN -> ignored
            "dhcp-option DNS not-an-ip",   // bad address -> ignored
            "route 10.0.0.0 255.0.0.0",    // not a dhcp-option -> ignored
            "dhcp-option DNS",             // missing arg -> ignored
            "",
        ]);
        assert!(s.is_empty());
    }

    #[test]
    fn deduplicates() {
        let s = parse_foreign_options([
            "dhcp-option DNS 1.1.1.1",
            "dhcp-option DNS 1.1.1.1",
            "dhcp-option DOMAIN x.test",
            "dhcp-option DOMAIN x.test",
        ]);
        assert_eq!(s.servers.len(), 1);
        assert_eq!(s.search_domains.len(), 1);
    }

    #[test]
    fn rejects_bad_interface_names() {
        assert!(interface_index("../../etc/passwd").is_err());
        assert!(interface_index("eth0/foo").is_err());
        assert!(interface_index("").is_err());
    }
}
