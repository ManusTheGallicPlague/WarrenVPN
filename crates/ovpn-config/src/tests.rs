use super::*;

fn opt(c: &Config, i: usize) -> &str {
    c.entries()[i].first().unwrap().as_str()
}

// ---------------------------------------------------------------- tokenizer ---

#[test]
fn basic_option_and_params() {
    let c = Config::parse("remote example.com 1194\ndev tun\nclient\n");
    assert_eq!(c.entries().len(), 3);
    assert_eq!(c.entries()[0], vec!["remote", "example.com", "1194"]);
    assert_eq!(c.entries()[1], vec!["dev", "tun"]);
    assert_eq!(c.entries()[2], vec!["client"]);
}

#[test]
fn blank_and_comment_lines_are_dropped() {
    let c = Config::parse("\n   \n# a hash comment\n; a semicolon comment\nclient\n");
    assert_eq!(c.entries().len(), 1);
    assert_eq!(opt(&c, 0), "client");
}

#[test]
fn inline_comment_after_whitespace() {
    let c = Config::parse("client # trailing comment\nverb 3 ; also\n");
    assert_eq!(c.entries()[0], vec!["client"]);
    assert_eq!(c.entries()[1], vec!["verb", "3"]);
}

#[test]
fn slash_star_is_treated_as_line_comment() {
    // Upstream quirk: `/*` (like `//`) comments to end of line.
    let c = Config::parse("/* whole line ignored */ client\n");
    assert!(c.entries().is_empty());
}

#[test]
fn double_slash_line_comment() {
    let c = Config::parse("// ignored\ndev tun\n");
    assert_eq!(c.entries().len(), 1);
    assert_eq!(opt(&c, 0), "dev");
}

#[test]
fn double_quoted_token_keeps_quotes_raw() {
    let c = Config::parse("setenv FORWARD_COMPATIBLE \"a value with spaces\"\n");
    assert_eq!(
        c.entries()[0],
        vec!["setenv", "FORWARD_COMPATIBLE", "\"a value with spaces\""]
    );
}

#[test]
fn single_quoted_token() {
    let c = Config::parse("echo 'hello there'\n");
    assert_eq!(c.entries()[0], vec!["echo", "'hello there'"]);
}

#[test]
fn backslash_escapes_whitespace_inside_token() {
    // Backslash makes the next char part of the token (here, a space).
    let c = Config::parse("echo a\\ b\n");
    assert_eq!(c.entries()[0], vec!["echo", "a\\ b"]);
}

#[test]
fn line_continuation_merges_lines() {
    let c = Config::parse("remote example.com \\\n1194\n");
    assert_eq!(c.entries()[0], vec!["remote", "example.com", "1194"]);
}

#[test]
fn carriage_returns_are_whitespace() {
    let c = Config::parse("client\r\ndev\ttun\r\n");
    assert_eq!(c.entries()[0], vec!["client"]);
    assert_eq!(c.entries()[1], vec!["dev", "tun"]);
}

#[test]
fn leading_slash_path_is_a_token_when_followed_by_close_comment_marker_absent() {
    // A token like `/etc/openvpn/ca.crt` as a *parameter* survives intact.
    let c = Config::parse("ca /etc/openvpn/ca.crt\n");
    assert_eq!(c.entries()[0], vec!["ca", "/etc/openvpn/ca.crt"]);
}

#[test]
fn sanitized_placeholder_is_ignored() {
    let c = Config::parse("client\n[Security-related line(s) omitted]\ndev tun\n");
    assert_eq!(c.entries().len(), 2);
    assert_eq!(opt(&c, 0), "client");
    assert_eq!(opt(&c, 1), "dev");
}

// ----------------------------------------------------------- lookups/helpers ---

#[test]
fn entries_with_option_lookup() {
    let c = Config::parse("remote a 1\nremote b 2\ndev tun\n");
    let remotes: Vec<_> = c.entries_with_option("remote").collect();
    assert_eq!(remotes.len(), 2);
    assert_eq!(remotes[0][1], "a");
    assert_eq!(remotes[1][1], "b");
}

#[test]
fn entries_with_option_and_first_param_lookup() {
    let c = Config::parse("dns-updown force\ndns-updown other\n");
    let forced: Vec<_> = c
        .entries_with_option_and_first_param("dns-updown", "force")
        .collect();
    assert_eq!(forced.len(), 1);
}

// ------------------------------------------------------ safe/unsafe gate ---

#[test]
fn plain_safe_config_is_safe() {
    let c = Config::parse("client\ndev tun\nproto udp\nremote vpn.example.com 1194\nca ca.crt\ncert client.crt\nkey client.key\nauth-user-pass\n");
    assert!(c.is_safe());
    assert!(!c.contains_unsafe_options());
}

#[test]
fn each_unsafe_option_makes_config_unsafe() {
    for unsafe_opt in options::UNSAFE {
        let cfg = format!("client\n{unsafe_opt} /some/arg\n");
        let c = Config::parse(&cfg);
        assert!(
            !c.is_safe(),
            "option `{unsafe_opt}` should make the config unsafe"
        );
    }
}

#[test]
fn up_script_is_unsafe() {
    let c = Config::parse("client\nup /home/user/evil.sh\n");
    assert!(!c.is_safe());
}

// -------------------------------------- security hardening: quoting evasion ---

#[test]
fn double_quoted_unsafe_option_name_does_not_evade() {
    // OpenVPN would parse `"up"` as the `up` option and run the script as root.
    let c = Config::parse("client\n\"up\" /home/user/evil.sh\n");
    assert_eq!(opt(&c, 1), "\"up\"", "tokenizer keeps the raw quoted token");
    assert!(!c.is_safe(), "quoted unsafe option must still be flagged");
}

#[test]
fn single_quoted_unsafe_option_name_does_not_evade() {
    let c = Config::parse("client\n'plugin' /lib/evil.so\n");
    assert!(!c.is_safe());
}

#[test]
fn backslash_escaped_unsafe_option_name_does_not_evade() {
    // `u\p` is `up` to OpenVPN (backslash escapes the following char).
    let c = Config::parse("client\nu\\p /home/user/evil.sh\n");
    assert_eq!(opt(&c, 1), "u\\p");
    assert!(!c.is_safe());
}

#[test]
fn unquote_matches_openvpn_style_normalization() {
    assert_eq!(unquote("\"up\""), "up");
    assert_eq!(unquote("'up'"), "up");
    assert_eq!(unquote("u\\p"), "up");
    assert_eq!(unquote("up"), "up");
    assert_eq!(unquote("\"a b\""), "a b");
    // Backslash is literal inside single quotes (OpenVPN semantics).
    assert_eq!(unquote("'a\\b'"), "a\\b");
}

// ------------------------------------------------ dns-updown special-casing ---

#[test]
fn dns_updown_force_is_safe() {
    let c = Config::parse("client\ndns-updown force\n");
    assert!(c.is_safe());
    assert!(c.contains_dns_updown_force());
    assert!(!c.contains_dns_updown_command());
}

#[test]
fn dns_updown_disable_is_safe() {
    let c = Config::parse("client\ndns-updown disable\n");
    assert!(c.is_safe());
    assert!(c.contains_dns_updown_disable());
}

#[test]
fn dns_updown_command_is_unsafe() {
    let c = Config::parse("client\ndns-updown /usr/local/bin/myhook\n");
    assert!(!c.is_safe());
    assert!(c.contains_dns_updown_command());
}

#[test]
fn bare_dns_updown_is_unsafe() {
    let c = Config::parse("client\ndns-updown\n");
    assert!(!c.is_safe());
    assert!(c.contains_dns_updown_command());
}

#[test]
fn dns_script_option_is_unsafe() {
    let c = Config::parse("client\ndns-script /usr/local/bin/dns\n");
    assert!(!c.is_safe());
    assert!(c.contains_dns_script());
}

// ------------------------------------------------------------ reserved opts ---

#[test]
fn reserved_options_are_detected() {
    let c = Config::parse("client\nconfig other.conf\nlog /tmp/x.log\n");
    let mut reserved = c.reserved_options_present();
    reserved.sort();
    assert_eq!(reserved, vec!["config", "log"]);
    // `config` is also unsafe.
    assert!(!c.is_safe());
}

#[test]
fn empty_input_is_safe_and_empty() {
    let c = Config::parse("");
    assert!(c.entries().is_empty());
    assert!(c.is_safe());
}
