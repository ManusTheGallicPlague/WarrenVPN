//! Construction of the OpenVPN command line. The daemon launches OpenVPN inside a
//! transient systemd scope; this module builds the argument vector. Keeping it
//! pure and tested guards against option-injection regressions.

use std::path::Path;

/// Everything needed to launch one OpenVPN client process under our control.
#[derive(Debug, Clone)]
pub struct LaunchSpec<'a> {
    /// Path to the root-owned shadow configuration.
    pub config_path: &'a Path,
    /// Path to the management unix socket the daemon will create/connect to.
    pub management_socket: &'a Path,
    /// OpenVPN `--verb` logging level.
    pub verb: u8,
    /// If true, start held (`--management-hold`) so the daemon can drive auth and
    /// release the hold explicitly.
    pub management_hold: bool,
    /// If `Some(n)`, force `--script-security n` on the command line. The daemon
    /// sets this to `Some(1)` for configurations it classified as *safe*, so that a
    /// stray or overlooked script-enabling directive cannot cause root code
    /// execution even if the unsafe-option classifier missed something. For configs
    /// the daemon already deemed unsafe (and gated behind admin authorization), it
    /// passes `None` to let the configuration's own setting stand.
    pub script_security: Option<u8>,
    /// Trusted up/down helper to invoke (shipped, root-owned). When set, the daemon
    /// uses it to learn the pushed DNS so it can configure systemd-resolved. Only
    /// injected for *safe* configurations (which by classification contain no user
    /// up/down scripts of their own).
    pub up_script: Option<&'a Path>,
    /// File the up/down helper writes the captured environment to (passed to it via
    /// `--setenv WARRENVPN_ENVFILE`).
    pub env_file: Option<&'a Path>,
}

impl Default for LaunchSpec<'_> {
    fn default() -> Self {
        LaunchSpec {
            config_path: Path::new(""),
            management_socket: Path::new(""),
            verb: 3,
            management_hold: true,
            script_security: Some(1),
            up_script: None,
            env_file: None,
        }
    }
}

/// Build the OpenVPN argument vector (excluding the `openvpn` program name itself).
///
/// Notes on the fixed flags:
/// * `--management <sock> unix` — listen on a unix-domain management socket (we
///   prefer this to a TCP loopback port to shrink the local attack surface).
/// * `--management-query-passwords` — route credential prompts through the channel
///   so we can answer them from the GUI/secret store.
/// * `--management-hold` — do not connect until the daemon releases the hold.
///
/// The config itself is passed via `--config`; the daemon has already tokenized,
/// classified and shadow-copied it, and forbids reserved options, so we do not add
/// `--script-security` here (no user scripts run in the MVP path).
pub fn build_openvpn_args(spec: &LaunchSpec) -> Vec<String> {
    let mut args: Vec<String> = vec![
        "--config".into(),
        spec.config_path.to_string_lossy().into_owned(),
        "--management".into(),
        spec.management_socket.to_string_lossy().into_owned(),
        "unix".into(),
        "--management-query-passwords".into(),
    ];

    if spec.management_hold {
        args.push("--management-hold".into());
    }

    if let Some(up) = spec.up_script {
        let up = up.to_string_lossy().into_owned();
        args.push("--up".into());
        args.push(up.clone());
        args.push("--down".into());
        args.push(up);
        if let Some(env) = spec.env_file {
            args.push("--setenv".into());
            args.push("WARRENVPN_ENVFILE".into());
            args.push(env.to_string_lossy().into_owned());
        }
    }

    if let Some(level) = spec.script_security {
        args.push("--script-security".into());
        args.push(level.to_string());
    }

    args.push("--verb".into());
    args.push(spec.verb.to_string());

    args
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn builds_expected_args() {
        let spec = LaunchSpec {
            config_path: Path::new("/var/lib/warrenvpn/users/1000/abc/config.ovpn"),
            management_socket: Path::new("/run/warrenvpn/abc.sock"),
            verb: 4,
            management_hold: true,
            script_security: Some(1),
            up_script: None,
            env_file: None,
        };
        let args = build_openvpn_args(&spec);
        assert_eq!(
            args,
            vec![
                "--config",
                "/var/lib/warrenvpn/users/1000/abc/config.ovpn",
                "--management",
                "/run/warrenvpn/abc.sock",
                "unix",
                "--management-query-passwords",
                "--management-hold",
                "--script-security",
                "1",
                "--verb",
                "4",
            ]
        );
    }

    #[test]
    fn up_script_adds_up_down_and_envfile() {
        let spec = LaunchSpec {
            config_path: Path::new("/c"),
            management_socket: Path::new("/s"),
            verb: 3,
            management_hold: true,
            script_security: Some(2),
            up_script: Some(Path::new("/usr/lib/warrenvpn/warrenvpn-updown")),
            env_file: Some(Path::new("/run/warrenvpn/abc.env")),
        };
        let args = build_openvpn_args(&spec);
        let pos = |needle: &str| args.iter().position(|a| a == needle);
        assert!(pos("--up").is_some() && pos("--down").is_some());
        assert!(args.contains(&"/usr/lib/warrenvpn/warrenvpn-updown".to_string()));
        assert!(pos("--setenv").is_some());
        assert!(args.contains(&"WARRENVPN_ENVFILE".to_string()));
        assert!(args.contains(&"/run/warrenvpn/abc.env".to_string()));
    }

    #[test]
    fn hold_can_be_disabled() {
        let spec = LaunchSpec {
            config_path: Path::new("/c"),
            management_socket: Path::new("/s"),
            verb: 3,
            management_hold: false,
            script_security: Some(1),
            up_script: None,
            env_file: None,
        };
        let args = build_openvpn_args(&spec);
        assert!(!args.iter().any(|a| a == "--management-hold"));
    }

    #[test]
    fn script_security_omitted_when_none() {
        let spec = LaunchSpec {
            config_path: Path::new("/c"),
            management_socket: Path::new("/s"),
            verb: 3,
            management_hold: true,
            script_security: None,
            up_script: None,
            env_file: None,
        };
        let args = build_openvpn_args(&spec);
        assert!(!args.iter().any(|a| a == "--script-security"));
    }
}
