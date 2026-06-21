//! Parser for OpenVPN's [management interface] real-time notifications and command
//! replies. The daemon connects to each OpenVPN process's management socket, parses
//! the lines here, and relays them to clients as typed D-Bus signals — clients
//! never see the raw socket.
//!
//! [management interface]: https://github.com/OpenVPN/openvpn/blob/master/doc/management-notes.txt

/// One parsed line from the management channel.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ManagementMessage {
    /// `>STATE:` real-time notification. `name` is the OpenVPN state
    /// (`CONNECTING`, `WAIT`, `AUTH`, `GET_CONFIG`, `ASSIGN_IP`, `ADD_ROUTES`,
    /// `CONNECTED`, `RECONNECTING`, `EXITING`, …).
    State {
        name: String,
        detail: String,
        local_ip: String,
        remote_ip: String,
    },
    /// `>BYTECOUNT:` (global) — total bytes in/out since connect.
    ByteCount { bytes_in: u64, bytes_out: u64 },
    /// `>PASSWORD:` — OpenVPN needs a credential. `prompt` is the raw text after
    /// the marker (e.g. `Need 'Auth' username/password`).
    PasswordRequest { prompt: String },
    /// `>INFO:` informational real-time message.
    Info(String),
    /// A single-sign-on web-auth URL the user must open in a browser
    /// (`>INFO:OPEN_URL:` / `WEB_AUTH:`).
    WebAuthUrl(String),
    /// `>LOG:` log line (timestamp/flags stripped to the message).
    Log(String),
    /// `>HOLD:` the daemon is in a management hold and awaits `hold release`.
    Hold(String),
    /// A `SUCCESS: …` command reply.
    Success(String),
    /// An `ERROR: …` command reply.
    Error(String),
    /// The `END` terminator of a multi-line command reply.
    End,
    /// Anything not recognised (kept verbatim for logging/debugging).
    Other(String),
}

/// Parse a single management line (trailing CR/LF tolerated).
pub fn parse_management_line(raw: &str) -> ManagementMessage {
    let line = raw.trim_end_matches(['\r', '\n']);

    if let Some(rest) = line.strip_prefix(">STATE:") {
        // time,name,detail,local_ip,remote_ip[,...]
        let f: Vec<&str> = rest.split(',').collect();
        let get = |i: usize| f.get(i).copied().unwrap_or("").to_string();
        return ManagementMessage::State {
            name: get(1),
            detail: get(2),
            local_ip: get(3),
            remote_ip: get(4),
        };
    }

    if let Some(rest) = line.strip_prefix(">BYTECOUNT:") {
        let mut it = rest.split(',');
        let bytes_in = it.next().and_then(|s| s.trim().parse().ok()).unwrap_or(0);
        let bytes_out = it.next().and_then(|s| s.trim().parse().ok()).unwrap_or(0);
        return ManagementMessage::ByteCount {
            bytes_in,
            bytes_out,
        };
    }

    if let Some(rest) = line.strip_prefix(">PASSWORD:") {
        return ManagementMessage::PasswordRequest {
            prompt: rest.to_string(),
        };
    }
    if let Some(rest) = line.strip_prefix(">INFO:") {
        if let Some(url) = rest.strip_prefix("OPEN_URL:") {
            return ManagementMessage::WebAuthUrl(url.to_string());
        }
        // WEB_AUTH:<flags>:<url>
        if let Some(spec) = rest.strip_prefix("WEB_AUTH:") {
            if let Some((_flags, url)) = spec.split_once(':') {
                return ManagementMessage::WebAuthUrl(url.to_string());
            }
        }
        return ManagementMessage::Info(rest.to_string());
    }
    if let Some(rest) = line.strip_prefix(">HOLD:") {
        return ManagementMessage::Hold(rest.to_string());
    }
    if let Some(rest) = line.strip_prefix(">LOG:") {
        // Format: time,flags,message — keep the message.
        let msg = rest.splitn(3, ',').nth(2).unwrap_or(rest);
        return ManagementMessage::Log(msg.to_string());
    }

    if let Some(rest) = line.strip_prefix("SUCCESS: ") {
        return ManagementMessage::Success(rest.to_string());
    }
    if let Some(rest) = line.strip_prefix("ERROR: ") {
        return ManagementMessage::Error(rest.to_string());
    }
    if line == "END" {
        return ManagementMessage::End;
    }

    ManagementMessage::Other(line.to_string())
}

/// A static challenge (`static-challenge`) attached to an auth prompt: the user
/// must supply an extra response (e.g. a token PIN) alongside the password.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StaticChallenge {
    /// True if the response may be echoed on screen (not secret).
    pub echo: bool,
    /// The prompt text shown to the user.
    pub text: String,
}

/// A parsed `>PASSWORD:` request from OpenVPN.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PasswordPrompt {
    /// The realm OpenVPN is asking about (e.g. `Auth`, `Private Key`), echoed back
    /// verbatim in the `username`/`password` reply commands.
    pub realm: String,
    /// True if a username is also required (`Need '...' username/password`); false
    /// for a password-only prompt (e.g. a private-key passphrase).
    pub needs_username: bool,
    /// True if this is a re-prompt after a failed verification.
    pub failed: bool,
    /// Set when the prompt carries a static challenge (`SC:<echo>,<text>`).
    pub static_challenge: Option<StaticChallenge>,
    /// Set when the prompt carries a dynamic challenge (`CRV1:...`).
    pub dynamic_challenge: Option<DynamicChallenge>,
}

/// Standard base64 encoding (with padding). Used to build the SCRV1/CRV1 reply
/// strings without pulling an external crate into the TCB.
pub fn base64_encode(input: &[u8]) -> String {
    const ALPHABET: &[u8; 64] =
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let b0 = chunk[0];
        let b1 = *chunk.get(1).unwrap_or(&0);
        let b2 = *chunk.get(2).unwrap_or(&0);
        let n = ((b0 as u32) << 16) | ((b1 as u32) << 8) | (b2 as u32);
        out.push(ALPHABET[((n >> 18) & 63) as usize] as char);
        out.push(ALPHABET[((n >> 12) & 63) as usize] as char);
        out.push(if chunk.len() > 1 {
            ALPHABET[((n >> 6) & 63) as usize] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            ALPHABET[(n & 63) as usize] as char
        } else {
            '='
        });
    }
    out
}

/// Build the SCRV1 password value for a static-challenge response:
/// `SCRV1:base64(password):base64(response)`.
pub fn scrv1_password(password: &str, response: &str) -> String {
    format!(
        "SCRV1:{}:{}",
        base64_encode(password.as_bytes()),
        base64_encode(response.as_bytes())
    )
}

/// Standard base64 decoding (ignores padding/whitespace). `None` on invalid input.
pub fn base64_decode(input: &str) -> Option<Vec<u8>> {
    fn val(c: u8) -> Option<u32> {
        match c {
            b'A'..=b'Z' => Some((c - b'A') as u32),
            b'a'..=b'z' => Some((c - b'a' + 26) as u32),
            b'0'..=b'9' => Some((c - b'0' + 52) as u32),
            b'+' => Some(62),
            b'/' => Some(63),
            _ => None,
        }
    }
    let cleaned: Vec<u8> = input
        .bytes()
        .filter(|&c| c != b'=' && !c.is_ascii_whitespace())
        .collect();
    let mut out = Vec::new();
    for chunk in cleaned.chunks(4) {
        if chunk.len() < 2 {
            return None;
        }
        let mut buf = 0u32;
        for &c in chunk {
            buf = (buf << 6) | val(c)?;
        }
        buf <<= 6 * (4 - chunk.len());
        out.push((buf >> 16) as u8);
        if chunk.len() >= 3 {
            out.push((buf >> 8) as u8);
        }
        if chunk.len() >= 4 {
            out.push(buf as u8);
        }
    }
    Some(out)
}

/// A dynamic challenge (CRV1) the server sent in an auth-failure reason. The client
/// re-authenticates with the original username and password
/// `CRV1::<state_id>::<response>`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DynamicChallenge {
    pub flags: String,
    pub state_id: String,
    /// The username (base64-decoded from the challenge) to re-send.
    pub username: String,
    /// Prompt text shown to the user.
    pub text: String,
    /// Response may be echoed on screen ('E' flag).
    pub echo: bool,
    /// A response is required ('R' flag).
    pub response_required: bool,
}

/// Parse a `CRV1:flags:state_id:base64(username):text` dynamic challenge (tolerating
/// surrounding `[`...`]` / quotes).
pub fn parse_dynamic_challenge(s: &str) -> Option<DynamicChallenge> {
    let start = s.find("CRV1:")?;
    let rest = &s[start + 5..];
    // The text (last field) may contain ':'; keep it whole.
    let mut it = rest.splitn(4, ':');
    let flags = it.next()?.to_string();
    let state_id = it.next()?.to_string();
    let b64user = it.next()?;
    let text_raw = it.next().unwrap_or("");
    // Trim a trailing ] or ' from the challenge text.
    let text = text_raw.trim_end_matches([']', '\'']).to_string();
    let username = base64_decode(b64user)
        .and_then(|b| String::from_utf8(b).ok())
        .unwrap_or_default();
    Some(DynamicChallenge {
        echo: flags.contains('E'),
        response_required: flags.contains('R'),
        flags,
        state_id,
        username,
        text,
    })
}

/// Build the CRV1 dynamic-challenge response password: `CRV1::<state_id>::<response>`.
pub fn crv1_password(state_id: &str, response: &str) -> String {
    format!("CRV1::{state_id}::{response}")
}

/// True if `url` is safe to hand to the desktop's URL opener for SSO: only `http`/
/// `https`. The web-auth URL is server-controlled (and arrives before the tunnel is
/// up, so it can be MITM'd), so we must never launch `file:`, `smb:` or any other
/// registered protocol handler.
pub fn is_browser_url(url: &str) -> bool {
    let u = url.trim();
    (u.len() > "https://".len())
        && (u.to_ascii_lowercase().starts_with("https://")
            || u.to_ascii_lowercase().starts_with("http://"))
}

/// Extract the text between the first pair of single quotes.
fn first_quoted(s: &str) -> Option<String> {
    let start = s.find('\'')? + 1;
    let rest = &s[start..];
    let end = rest.find('\'')?;
    Some(rest[..end].to_string())
}

/// Parse the text following `>PASSWORD:` into a [`PasswordPrompt`].
///
/// Recognised forms:
/// * `Need 'Auth' username/password`
/// * `Need 'Private Key' password`
/// * `Verification Failed: 'Auth'`
pub fn parse_password_request(text: &str) -> Option<PasswordPrompt> {
    let realm = first_quoted(text)?;
    let failed = text.starts_with("Verification Failed");
    let needs_username = text.contains("username/password");
    let static_challenge = text.find("SC:").and_then(|i| {
        let (echo_s, ch_text) = text[i + 3..].split_once(',')?;
        Some(StaticChallenge {
            echo: echo_s.trim() == "1",
            text: ch_text.trim().to_string(),
        })
    });
    let dynamic_challenge = if text.contains("CRV1:") {
        parse_dynamic_challenge(text)
    } else {
        None
    };
    Some(PasswordPrompt {
        realm,
        needs_username,
        failed,
        static_challenge,
        dynamic_challenge,
    })
}

/// Escape and quote a value for the OpenVPN management protocol, which lexes lines
/// with `parse_line()` (double quotes group a token; `\"` and `\\` are literal `"`
/// and `\`). Returns the value wrapped in double quotes.
///
/// This is a security-relevant invariant: an unescaped quote or backslash in a
/// password could otherwise inject additional management arguments.
pub fn escape_mgmt_value(value: &str) -> String {
    let mut out = String::with_capacity(value.len() + 2);
    out.push('"');
    for c in value.chars() {
        if c == '"' || c == '\\' {
            out.push('\\');
        }
        out.push(c);
    }
    out.push('"');
    out
}

/// Commands the daemon sends to OpenVPN. Centralised so the wire format lives in
/// one place. Each includes the trailing newline OpenVPN expects.
pub mod command {
    use super::escape_mgmt_value;

    /// Enable real-time state notifications.
    pub const STATE_ON: &str = "state on\n";
    /// Enable byte-count notifications every `n` seconds.
    pub fn bytecount(seconds: u32) -> String {
        format!("bytecount {seconds}\n")
    }
    /// Request an orderly shutdown of the OpenVPN process.
    pub const SIGTERM: &str = "signal SIGTERM\n";
    /// Release a management hold so OpenVPN proceeds to connect.
    pub const HOLD_RELEASE: &str = "hold release\n";

    /// `username "<realm>" "<user>"` — answer a queried username.
    pub fn username(realm: &str, user: &str) -> String {
        format!(
            "username {} {}\n",
            escape_mgmt_value(realm),
            escape_mgmt_value(user)
        )
    }
    /// `password "<realm>" "<pass>"` — answer a queried password/passphrase.
    pub fn password(realm: &str, pass: &str) -> String {
        format!(
            "password {} {}\n",
            escape_mgmt_value(realm),
            escape_mgmt_value(pass)
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_connected_state() {
        let m = parse_management_line(">STATE:1700000000,CONNECTED,SUCCESS,10.8.0.2,203.0.113.7,1194,,\r\n");
        assert_eq!(
            m,
            ManagementMessage::State {
                name: "CONNECTED".into(),
                detail: "SUCCESS".into(),
                local_ip: "10.8.0.2".into(),
                remote_ip: "203.0.113.7".into(),
            }
        );
    }

    #[test]
    fn parses_state_with_missing_trailing_fields() {
        let m = parse_management_line(">STATE:1700000000,CONNECTING,,,");
        assert_eq!(
            m,
            ManagementMessage::State {
                name: "CONNECTING".into(),
                detail: String::new(),
                local_ip: String::new(),
                remote_ip: String::new(),
            }
        );
    }

    #[test]
    fn parses_bytecount() {
        assert_eq!(
            parse_management_line(">BYTECOUNT:12345,67890"),
            ManagementMessage::ByteCount {
                bytes_in: 12345,
                bytes_out: 67890
            }
        );
    }

    #[test]
    fn parses_password_request() {
        assert_eq!(
            parse_management_line(">PASSWORD:Need 'Auth' username/password"),
            ManagementMessage::PasswordRequest {
                prompt: "Need 'Auth' username/password".into()
            }
        );
    }

    #[test]
    fn parses_log_keeps_message() {
        assert_eq!(
            parse_management_line(">LOG:1700000000,I,OpenVPN 2.6.0 starting"),
            ManagementMessage::Log("OpenVPN 2.6.0 starting".into())
        );
    }

    #[test]
    fn parses_success_error_end() {
        assert_eq!(
            parse_management_line("SUCCESS: real-time state notification set to ON"),
            ManagementMessage::Success("real-time state notification set to ON".into())
        );
        assert_eq!(
            parse_management_line("ERROR: could not parse"),
            ManagementMessage::Error("could not parse".into())
        );
        assert_eq!(parse_management_line("END"), ManagementMessage::End);
    }

    #[test]
    fn unknown_line_is_other() {
        assert_eq!(
            parse_management_line(">FOO:bar"),
            ManagementMessage::Other(">FOO:bar".into())
        );
    }

    #[test]
    fn commands_are_well_formed() {
        assert_eq!(command::STATE_ON, "state on\n");
        assert_eq!(command::bytecount(1), "bytecount 1\n");
        assert_eq!(command::SIGTERM, "signal SIGTERM\n");
    }

    #[test]
    fn parses_password_prompts() {
        assert_eq!(
            parse_password_request("Need 'Auth' username/password"),
            Some(PasswordPrompt {
                realm: "Auth".into(),
                needs_username: true,
                failed: false,
                static_challenge: None,
                dynamic_challenge: None,
            })
        );
        assert_eq!(
            parse_password_request("Need 'Private Key' password"),
            Some(PasswordPrompt {
                realm: "Private Key".into(),
                needs_username: false,
                failed: false,
                static_challenge: None,
                dynamic_challenge: None,
            })
        );
        let failed = parse_password_request("Verification Failed: 'Auth'").unwrap();
        assert!(failed.failed);
        assert_eq!(failed.realm, "Auth");
        assert!(parse_password_request("no quotes here").is_none());
    }

    #[test]
    fn parses_static_challenge() {
        let p = parse_password_request("Need 'Auth' username/password SC:1,Enter token PIN")
            .unwrap();
        assert_eq!(p.realm, "Auth");
        assert!(p.needs_username);
        assert_eq!(
            p.static_challenge,
            Some(StaticChallenge {
                echo: true,
                text: "Enter token PIN".into()
            })
        );
        // Non-echo challenge.
        let p2 =
            parse_password_request("Need 'Auth' username/password SC:0,PIN").unwrap();
        assert_eq!(
            p2.static_challenge,
            Some(StaticChallenge {
                echo: false,
                text: "PIN".into()
            })
        );
    }

    #[test]
    fn base64_matches_known_vectors() {
        assert_eq!(base64_encode(b""), "");
        assert_eq!(base64_encode(b"f"), "Zg==");
        assert_eq!(base64_encode(b"fo"), "Zm8=");
        assert_eq!(base64_encode(b"foo"), "Zm9v");
        assert_eq!(base64_encode(b"foobar"), "Zm9vYmFy");
    }

    #[test]
    fn builds_scrv1_password() {
        // password "foo", response "bar" -> SCRV1:Zm9v:YmFy
        assert_eq!(scrv1_password("foo", "bar"), "SCRV1:Zm9v:YmFy");
    }

    #[test]
    fn base64_decode_roundtrip() {
        assert_eq!(base64_decode("Zg==").unwrap(), b"f");
        assert_eq!(base64_decode("Zm8=").unwrap(), b"fo");
        assert_eq!(base64_decode("Zm9v").unwrap(), b"foo");
        assert_eq!(base64_decode("Zm9vYmFy").unwrap(), b"foobar");
        for s in ["", "alice", "user@example.com", "OpenVPN!"] {
            let enc = base64_encode(s.as_bytes());
            assert_eq!(base64_decode(&enc).unwrap(), s.as_bytes());
        }
        assert!(base64_decode("not base64 !!!").is_none());
    }

    #[test]
    fn parses_dynamic_challenge_crv1() {
        // username "alice" -> base64 "YWxpY2U="
        let line = "Verification Failed: 'Auth' [CRV1:R,E:Sn9w:YWxpY2U=:Enter your token code]";
        let p = parse_password_request(line).unwrap();
        assert!(p.failed);
        let dc = p.dynamic_challenge.unwrap();
        assert_eq!(dc.state_id, "Sn9w");
        assert_eq!(dc.username, "alice");
        assert_eq!(dc.text, "Enter your token code");
        assert!(dc.echo && dc.response_required);
        assert_eq!(crv1_password(&dc.state_id, "123456"), "CRV1::Sn9w::123456");
    }

    #[test]
    fn web_url_scheme_allow_list() {
        assert!(is_browser_url("https://vpn.example.com/sso"));
        assert!(is_browser_url("http://10.0.0.1/auth"));
        assert!(!is_browser_url("file:///etc/passwd"));
        assert!(!is_browser_url("smb://server/share"));
        assert!(!is_browser_url("javascript:alert(1)"));
        assert!(!is_browser_url(""));
    }

    #[test]
    fn parses_web_auth_url() {
        assert_eq!(
            parse_management_line(">INFO:OPEN_URL:https://vpn.example.com/sso?token=abc"),
            ManagementMessage::WebAuthUrl("https://vpn.example.com/sso?token=abc".into())
        );
        assert_eq!(
            parse_management_line(">INFO:WEB_AUTH:1:https://vpn.example.com/auth"),
            ManagementMessage::WebAuthUrl("https://vpn.example.com/auth".into())
        );
    }

    #[test]
    fn escapes_mgmt_values() {
        assert_eq!(escape_mgmt_value("hunter2"), "\"hunter2\"");
        // A quote and a backslash must be escaped (injection prevention).
        assert_eq!(escape_mgmt_value("a\"b\\c"), "\"a\\\"b\\\\c\"");
        assert_eq!(escape_mgmt_value(""), "\"\"");
    }

    #[test]
    fn builds_auth_commands() {
        assert_eq!(command::username("Auth", "alice"), "username \"Auth\" \"alice\"\n");
        assert_eq!(
            command::password("Auth", "p@ss \"x\""),
            "password \"Auth\" \"p@ss \\\"x\\\"\"\n"
        );
        assert_eq!(
            command::password("Private Key", "secret"),
            "password \"Private Key\" \"secret\"\n"
        );
    }
}
