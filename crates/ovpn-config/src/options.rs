//! Static knowledge about OpenVPN option names. These lists drive two distinct
//! decisions:
//!
//! * **Reject** — options the privileged daemon must own, or that don't apply to
//!   this OS.
//! * **Safe vs unsafe** — whether a configuration may be installed/run *without*
//!   an administrator authorization. "Unsafe" options can run arbitrary code (as
//!   root, in our daemon model), so this classification is **security-critical**.
//!
//! IMPORTANT (maintenance notes):
//!
//! 1. The SAFE list is maintained by hand: take care that adjacent entries are not
//!    accidentally concatenated (for example `ifconfig-pool` and
//!    `ifconfig-push-constraint` must stay two separate entries).
//!
//! 2. The WINDOWS_ONLY list collects options that do not apply on this OS. It MUST
//!    be audited against the actual OpenVPN-on-Linux option set before being used
//!    to reject configs. See `TODO(linux-audit)`.

use std::collections::HashSet;
use std::sync::LazyLock;

/// Whitespace characters recognised inside an OpenVPN configuration file.
pub const WHITESPACE: &[char] = &['\t', '\n', '\r', ' '];

/// Options the privileged daemon must control exclusively; a user config is not
/// allowed to set them (they would let a config redirect logging or pull in a
/// second configuration file).
pub const RESERVED: &[&str] = &["log", "log-append", "syslog", "config"];

/// Options that only apply to OpenVPN on Windows, and so are not valid on Linux.
///
/// TODO(linux-audit): replace with the set that is invalid specifically on
/// OpenVPN-for-Linux before wiring this into config rejection.
pub const WINDOWS_ONLY: &[&str] = &[
    "allow-nonadmin",
    "cryptoapicert",
    "dhcp-release",
    "dhcp-renew",
    "pause-exit",
    "register-dns",
    "service",
    "show-adapters",
    "show-net",
    "show-net-up",
    "show-valid-subnets",
    "tap-sleep",
    "win-sys",
    "windows-driver",
];

/// Options that cannot appear in a "safe" configuration: each can cause arbitrary
/// code execution (scripts/plugins) which, in our model, runs with root privilege.
/// Mirrors `OPENVPN_OPTIONS_THAT_ARE_UNSAFE`.
///
/// NOTE: `dns-updown` is intentionally NOT in this list — it is handled specially
/// (`dns-updown force` / `dns-updown disable` are safe; `dns-updown <command>` is
/// unsafe). See [`crate::Config::is_safe`].
pub const UNSAFE: &[&str] = &[
    "auth-user-pass-verify",
    "client-connect",
    "client-crresponse",
    "client-disconnect",
    "config",
    "dns-script",
    "down",
    "ipchange",
    "iproute",
    "learn-address",
    "plugin",
    "route-pre-down",
    "route-up",
    "tls-verify",
    "up",
];

/// The `dns-updown` parameters that keep a configuration safe. Any other first
/// parameter (or none) means a user-supplied command, which is unsafe.
pub const DNS_UPDOWN_SAFE_PARAMS: &[&str] = &["force", "disable"];

/// Options that may appear in a "safe" configuration. Mirrors
/// `OPENVPN_OPTIONS_THAT_ARE_SAFE` (with the missing-comma bug fixed; see module
/// docs). Currently used only for "unknown option" diagnostics, not for the
/// privilege gate, so a mistake here cannot weaken security — but keep it faithful.
pub const SAFE: &[&str] = &[
    "allow-compression", "allow-nonadmin", "allow-pull-fqdn", "allow-recursive-routing", "askpass",
    "auth-gen-token", "auth-nocache", "auth-retry", "auth-token", "auth-token-user", "auth-user-pass-optional",
    "auth-user-pass", "auth", "auth-gen-token-secret",
    "bcast-buffers", "bind", "bind-dev", "block-ipv6", "block-outside-dns",
    "ca", "capath", "ccd-exclusive", "cd", "cert", "chroot", "cipher", "client-cert-not-required",
    "client-config-dir",
    "client-nat", "client-to-client", "client", "comp-lzo", "comp-noadapt", "compat-names",
    "compress",
    "connect-freq", "connect-retry-max", "connect-retry", "connect-timeout", "connection",
    "crl-verify", "cryptoapicert", "daemon", "data-ciphers", "data-ciphers-fallback",
    "dev-node", "dev-type", "dev", "dh", "dhcp-internal", "dhcp-option", "dhcp-pre-release",
    "dhcp-release", "dhcp-renew", "disable-occ", "disable",
    "down-pre",
    "duplicate-cn",
    "ecdh-curve", "echo", "engine", "errors-to-stderr", "explicit-exit-notify", "extra-certs",
    "fast-io", "float", "force-tls-key-material-export", "foreign-option", "fragment",
    "genkey", "gremlin", "group",
    "hand-window", "hash-size", "help", "http-proxy-option", "http-proxy-override",
    "http-proxy-retry", "http-proxy-timeout", "http-proxy-user-pass", "http-proxy",
    "ifconfig-ipv6-pool", "ifconfig-ipv6-push", "ifconfig-ipv6", "ifconfig-noexec",
    "ifconfig-nowarn", "ifconfig-pool-linear", "ifconfig-pool-persist",
    // Upstream missing-comma bug fixed: these two were concatenated.
    "ifconfig-pool", "ifconfig-push-constraint",
    "ifconfig-push", "ifconfig",
    "inactive", "inetd", "ip-remote-hint", "ip-win32",
    "iroute-ipv6", "iroute",
    "keepalive", "key-direction", "key-method", "key", "key-derivation",
    "keying-material-exporter", "keysize",
    "link-mtu", "lladdr", "local", "log-append", "log", "lport",
    "machine-readable-output", "management-client-auth", "management-client-group",
    "management-client-pf", "management-client-user", "management-client",
    "management-external-cert", "management-external-key", "management-forget-disconnect",
    "management-hold", "management-log-cache", "management-query-passwords", "management-query-proxy",
    "management-query-remote", "management-signal", "management-up-down", "management", "mark",
    "max-clients", "max-routes-per-client", "max-routes", "memstats", "mktun", "mlock", "mode",
    "msg-channel", "mssfix", "mtu-disc", "mtu-dynamic", "mtu-test", "multihome",
    "mute-replay-warnings", "mute",
    "ncp-ciphers", "ncp-disable", "nice", "no-iv", "no-name-remapping", "no-replay",
    "nobind", "ns-cert-type",
    "opt-verify",
    "parameter", "passtos", "pause-exit", "peer-fingerprint", "peer-id", "persist-key",
    "persist-local-ip", "persist-remote-ip", "persist-tun", "ping-exit", "ping-restart",
    "ping-timer-rem", "ping", "pkcs11-cert-private", "pkcs11-id-management", "pkcs11-id",
    "pkcs11-pin-cache", "pkcs11-private-mode", "pkcs11-protected-authentication",
    "pkcs11-providers", "pkcs12",
    "port-share", "port", "preresolve", "prng", "proto-force", "proto", "pull",
    "push-continuation", "pull-filter", "push-peer-info", "push-remove", "push-reset", "push",
    "rcvbuf", "rdns-internal", "redirect-gateway", "redirect-private", "register-dns",
    "remap-usr1", "remote-cert-eku", "remote-cert-ku", "remote-cert-tls", "remote-random-hostname",
    "remote-random", "remote", "reneg-bytes", "reneg-pkts", "reneg-sec", "replay-persist",
    "replay-window", "resolv-retry", "rmtun", "route-delay", "route-gateway", "route-ipv6",
    "route-ipv6-gateway", "route-method", "route-metric", "route-noexec", "route-nopull",
    "route", "rport",
    "scramble", "script-security", "secret", "server-bridge", "server-ipv6", "server-poll-timeout",
    "server", "service", "setcon", "setenv-safe", "setenv", "shaper", "show-adapters",
    "show-ciphers", "show-curves", "show-digests", "show-engines", "show-gateway", "show-groups",
    "show-net-up", "show-net", "show-pkcs11-ids", "show-tls", "show-valid-subnets",
    "single-session", "sndbuf", "socket-flags", "socks-proxy-retry", "socks-proxy",
    "stale-routes-check", "static-challenge", "status-version", "status", "suppress-timestamps",
    "syslog",
    "tap-sleep", "tcp-nodelay", "tcp-queue-limit", "test-crypto", "tls-auth", "tls-cert-profile",
    "tls-cipher", "tls-ciphersuites", "tls-client", "tls-crypt", "tls-crypt-v2",
    "tls-crypt-v2-verify", "tls-exit", "tls-export-cert", "tls-groups", "tls-remote",
    "tls-server", "tls-timeout",
    "tls-version-max", "tls-version-min", "tmp-dir", "topology", "tran-window", "tun-ipv6",
    "tun-mtu-extra", "tun-mtu", "txqueuelen", "udp-mtu",
    "up-delay", "up-restart", "use-prediction-resistance", "user", "username-as-common-name",
    "verb", "verify-client-cert", "verify-hash", "verify-x509-name", "version", "vlan-accept",
    "vlan-pvid", "vlan-tagging",
    "windows-driver", "win-sys", "writepid",
    "x509-track", "x509-username-field",
];

static UNSAFE_SET: LazyLock<HashSet<&'static str>> = LazyLock::new(|| UNSAFE.iter().copied().collect());
static RESERVED_SET: LazyLock<HashSet<&'static str>> = LazyLock::new(|| RESERVED.iter().copied().collect());
static WINDOWS_ONLY_SET: LazyLock<HashSet<&'static str>> =
    LazyLock::new(|| WINDOWS_ONLY.iter().copied().collect());
static SAFE_SET: LazyLock<HashSet<&'static str>> = LazyLock::new(|| SAFE.iter().copied().collect());

/// True if `name` is an option that, on its own, makes a configuration unsafe.
pub fn is_unsafe_option(name: &str) -> bool {
    UNSAFE_SET.contains(name)
}

/// True if `name` is reserved for exclusive use by the application.
pub fn is_reserved_option(name: &str) -> bool {
    RESERVED_SET.contains(name)
}

/// True if `name` is in the (macOS) Windows-only list. See `TODO(linux-audit)`.
pub fn is_windows_only_option(name: &str) -> bool {
    WINDOWS_ONLY_SET.contains(name)
}

/// True if `name` is a known, safe option.
pub fn is_known_safe_option(name: &str) -> bool {
    SAFE_SET.contains(name)
}
