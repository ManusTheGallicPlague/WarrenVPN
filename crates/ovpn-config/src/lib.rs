//! OpenVPN configuration tokenizer, parser and safe/unsafe classifier.
//!
//! The tokenizer reproduces OpenVPN's own `parse_line()` lexing so the classifier
//! sees option names exactly as OpenVPN would. It is shared by both the GUI and the
//! privileged daemon: the daemon re-runs it server-side and never trusts the GUI's
//! verdict, so both sides must agree byte-for-byte — hence the deliberate fidelity
//! to OpenVPN's lexer.
//!
//! # The privilege gate
//!
//! In our model the daemon launches OpenVPN as root. A configuration is "safe"
//! (installable / connectable without an admin prompt) only if it cannot cause
//! arbitrary code execution. [`Config::is_safe`] implements that gate.
//!
//! # Why the option name is normalized
//!
//! A naive classifier that keeps quote and backslash characters *inside* the token
//! and compares the raw token against the unsafe-option list can be bypassed:
//! OpenVPN strips quotes/backslashes, so a line like `"up" /evil` is parsed by
//! OpenVPN as the `up` option (running `/evil` as root) while the raw token `"up"`
//! would NOT match the unsafe list — an authorization bypass. To close that gap,
//! the classifier compares the **normalized** option name (quotes and backslash
//! escapes removed, the way OpenVPN does) against the unsafe list.
//!
//! [`unquote`] is an approximation of OpenVPN's `parse_line()` lexing and MUST be
//! cross-checked against OpenVPN's actual implementation as part of the TCB audit
//! before the verdict is trusted for a real privilege decision. See the project
//! risk register (shadow-copy + classifier is the highest-risk component).

pub mod options;

pub use options::{is_reserved_option, is_unsafe_option, is_windows_only_option, WHITESPACE};

/// The placeholder line substituted for security-sensitive content when a
/// configuration is sanitized for display/logging. It must never parse as an option.
const SANITIZED_PLACEHOLDER: &str = "[Security-related line(s) omitted]";

fn is_ws(c: char) -> bool {
    WHITESPACE.contains(&c)
}

/// Find the start index of the two-character sequence `*/` in `line[from..]`,
/// returning its absolute index, or `None`.
fn find_close_comment(line: &[char], from: usize) -> Option<usize> {
    if line.len() < 2 {
        return None;
    }
    (from..line.len() - 1).find(|&i| line[i] == '*' && line[i + 1] == '/')
}

/// Port of `-skipWhitespaceAndCommentsInLine:fromIndexPtr:`.
///
/// Advances `*ix` past whitespace and comments. Returns `Ok(())` (upstream `TRUE`)
/// normally, or `Err(())` (upstream `FALSE`) on an unterminated `/*…` error. The
/// caller only checks the result for the *first* skip of a line; subsequent skips
/// ignore it (faithfully reproducing upstream control flow).
fn skip_ws_and_comments(line: &[char], ix: &mut usize) -> Result<(), ()> {
    while *ix < line.len() {
        let ch1 = line[*ix];

        if is_ws(ch1) {
            *ix += 1;
            continue;
        }

        if ch1 == ';' || ch1 == '#' {
            // Comment to end of line.
            *ix = line.len();
            return Ok(());
        }

        if *ix == line.len() - 1 {
            // Last character of the line: cannot start a comment.
            return Ok(());
        }

        if ch1 != '/' {
            return Ok(());
        }

        let ch2 = line[*ix + 1];

        if ch2 == '/' || ch2 == '*' {
            // `//` or `/*`: upstream treats both as comment-to-end-of-line.
            *ix = line.len();
            return Ok(());
        }

        // `/X` where X is neither `/` nor `*`: upstream then scans for a closing
        // `*/`. Reachable but quirky; preserved for byte-for-byte equivalence.
        match find_close_comment(line, *ix) {
            Some(loc) => *ix = loc + 2,
            None => return Err(()),
        }
    }
    Ok(())
}

/// Port of `-nextTokenInLine:fromIndexPtr:`.
///
/// Returns the next raw token (quotes and backslashes preserved, exactly as
/// upstream) starting at `*ix`, advancing `*ix` to the following whitespace or end
/// of line. Returns `None` if there is no token.
fn next_token(line: &[char], ix: &mut usize) -> Option<String> {
    let start = *ix;

    let mut in_backslash = false;
    let mut in_single_quote = false;
    let mut in_double_quote = false;

    while *ix < line.len() {
        let ch = line[*ix];
        *ix += 1;

        if in_backslash {
            in_backslash = false;
            continue;
        }
        if in_single_quote {
            if ch == '\'' {
                in_single_quote = false;
            }
            continue;
        }
        if in_double_quote {
            if ch == '"' {
                in_double_quote = false;
            }
            continue;
        }
        if ch == '\\' {
            in_backslash = true;
            continue;
        }
        if ch == '\'' {
            in_single_quote = true;
            continue;
        }
        if ch == '"' {
            in_double_quote = true;
            continue;
        }
        if is_ws(ch) {
            // End of token; leave `*ix` pointing at the whitespace.
            *ix -= 1;
            break;
        }
    }

    if *ix == start {
        return None;
    }
    Some(line[start..*ix].iter().collect())
}

/// Port of `-parseOpenVPNConfigurationLine:`.
///
/// Returns the option and its parameters for one physical line, or `None` for a
/// blank/comment-only line, the sanitized placeholder, or an unterminated-comment
/// error at the start of the line.
fn parse_line(line: &str) -> Option<Vec<String>> {
    if line == SANITIZED_PLACEHOLDER {
        return None;
    }

    let chars: Vec<char> = line.chars().collect();
    let mut arr: Vec<String> = Vec::new();

    let mut ix = 0usize;
    // Only the first skip's error is honoured (upstream returns nil on FALSE here).
    if skip_ws_and_comments(&chars, &mut ix).is_err() {
        return None;
    }

    while ix < chars.len() {
        if let Some(tok) = next_token(&chars, &mut ix) {
            arr.push(tok);
        }
        // Result deliberately ignored, matching upstream.
        let _ = skip_ws_and_comments(&chars, &mut ix);
    }

    if arr.is_empty() {
        None
    } else {
        Some(arr)
    }
}

/// Normalize a raw token into the value OpenVPN would use, by removing quoting and
/// processing backslash escapes. Used by the privilege gate so that quoted/escaped
/// option names (e.g. `"up"`, `u\p`) cannot evade the unsafe-option check.
///
/// This approximates OpenVPN's `parse_line()` semantics:
/// * single quotes are literal (no escape processing inside them),
/// * double quotes allow backslash escapes,
/// * a backslash outside quotes escapes the next character.
///
/// TODO(tcb-audit): verify against OpenVPN's real `parse_line()` (`options.c`).
pub fn unquote(token: &str) -> String {
    let mut out = String::with_capacity(token.len());

    let mut in_backslash = false;
    let mut in_single_quote = false;
    let mut in_double_quote = false;

    for ch in token.chars() {
        if in_backslash {
            out.push(ch);
            in_backslash = false;
            continue;
        }
        if in_single_quote {
            if ch == '\'' {
                in_single_quote = false;
            } else {
                out.push(ch);
            }
            continue;
        }
        if in_double_quote {
            if ch == '\\' {
                in_backslash = true;
            } else if ch == '"' {
                in_double_quote = false;
            } else {
                out.push(ch);
            }
            continue;
        }
        match ch {
            '\\' => in_backslash = true,
            '\'' => in_single_quote = true,
            '"' => in_double_quote = true,
            _ => out.push(ch),
        }
    }
    out
}

/// A parsed OpenVPN configuration: one entry per non-empty line, each entry being
/// the option name followed by its raw parameters.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Config {
    lines: Vec<Vec<String>>,
}

impl Config {
    /// Parse configuration `contents`. Mirrors
    /// `+parsedConfigurationWithString:`: merges backslash-LF continuations, then
    /// parses each line. Never fails (malformed lines are simply dropped), matching
    /// upstream — callers needing strictness should validate the resulting entries.
    pub fn parse(contents: &str) -> Config {
        // Merge a backslash immediately followed by LF (line continuation).
        let merged = contents.replace("\\\n", "");

        let mut lines = Vec::new();
        // Upstream appends a trailing LF, guaranteeing the last line is processed;
        // splitting on '\n' and dropping a trailing empty segment is equivalent.
        for raw in merged.split('\n') {
            if let Some(entry) = parse_line(raw) {
                lines.push(entry);
            }
        }
        Config { lines }
    }

    /// All entries (option + parameters), in file order.
    pub fn entries(&self) -> &[Vec<String>] {
        &self.lines
    }

    /// Entries whose option name equals `name`.
    pub fn entries_with_option<'a>(&'a self, name: &str) -> impl Iterator<Item = &'a Vec<String>> {
        let name = name.to_owned();
        self.lines
            .iter()
            .filter(move |e| e.first().map(String::as_str) == Some(name.as_str()))
    }

    /// Entries whose option name equals `name` and whose first parameter equals
    /// `first`.
    pub fn entries_with_option_and_first_param<'a>(
        &'a self,
        name: &str,
        first: &str,
    ) -> impl Iterator<Item = &'a Vec<String>> {
        let first = first.to_owned();
        self.entries_with_option(name)
            .filter(move |e| e.get(1).map(String::as_str) == Some(first.as_str()))
    }

    /// True if a `dns-script` option is present.
    pub fn contains_dns_script(&self) -> bool {
        self.entries_with_option("dns-script").next().is_some()
    }

    /// True if `dns-updown force` is present.
    pub fn contains_dns_updown_force(&self) -> bool {
        self.entries_with_option_and_first_param("dns-updown", "force")
            .next()
            .is_some()
    }

    /// True if `dns-updown disable` is present.
    pub fn contains_dns_updown_disable(&self) -> bool {
        self.entries_with_option_and_first_param("dns-updown", "disable")
            .next()
            .is_some()
    }

    /// True if a `dns-updown` directive specifies a user command (anything other
    /// than `force`/`disable`, including a missing parameter), which is unsafe.
    ///
    /// NOTE: this implements upstream's *documented intent* (check the first
    /// parameter). Upstream's shipped code has a bug that compares the whole entry
    /// against a string and so flags every `dns-updown` as a command. Our version
    /// is the intended behavior and is still safe (any genuine command is flagged);
    /// it merely avoids forcing an admin prompt for the legitimate `force`/`disable`
    /// forms. Covered by tests.
    pub fn contains_dns_updown_command(&self) -> bool {
        self.entries_with_option("dns-updown").any(|e| {
            match e.get(1).map(|p| unquote(p)) {
                Some(param) => !options::DNS_UPDOWN_SAFE_PARAMS.contains(&param.as_str()),
                None => true, // bare `dns-updown` with no parameter: treat as unsafe.
            }
        })
    }

    /// The security gate. True iff the configuration contains no option that could
    /// run arbitrary code (which, in our model, would run as root). Mirrors
    /// `-doesNotContainAnyUnsafeOptions`, hardened to compare the *normalized*
    /// option name so quoted/escaped names cannot evade detection.
    pub fn is_safe(&self) -> bool {
        for entry in &self.lines {
            if let Some(raw_name) = entry.first() {
                if is_unsafe_option(&unquote(raw_name)) {
                    return false;
                }
            }
        }
        !self.contains_dns_updown_command()
    }

    /// Convenience inverse of [`Config::is_safe`].
    pub fn contains_unsafe_options(&self) -> bool {
        !self.is_safe()
    }

    /// Normalized option names that are reserved for exclusive application use
    /// (must be rejected if present in a user config).
    pub fn reserved_options_present(&self) -> Vec<String> {
        self.lines
            .iter()
            .filter_map(|e| e.first())
            .map(|raw| unquote(raw))
            .filter(|n| is_reserved_option(n))
            .collect()
    }
}

#[cfg(test)]
mod tests;
