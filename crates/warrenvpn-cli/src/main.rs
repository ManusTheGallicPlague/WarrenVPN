//! warrenvpnctl — command-line client for the WarrenVPN VPN daemon.
//!
//! Talks to `warrenvpnd` over D-Bus (system bus, or the session bus when
//! `WARRENVPN_BUS=session`). Usable headless / for scripting; no GUI required.
//!
//!   warrenvpnctl list
//!   warrenvpnctl status
//!   warrenvpnctl import <file.ovpn> [name]
//!   warrenvpnctl connect <name|id> [--killswitch]
//!   warrenvpnctl disconnect <name|id>
//!   warrenvpnctl recover

use std::collections::HashMap;
use std::io::Write;
use std::process::ExitCode;

use zbus::blocking;
use zbus::zvariant::{OwnedObjectPath, OwnedValue, Value};

use warrenvpn_common::{
    DBUS_CONNECTION_IFACE, DBUS_MANAGER_IFACE, DBUS_SYSTEM_NAME, DBUS_SYSTEM_PATH,
};

fn connect_bus() -> zbus::Result<blocking::Connection> {
    if std::env::var("WARRENVPN_BUS").as_deref() == Ok("session")
        || std::env::var("WARRENVPND_BUS").as_deref() == Ok("session")
    {
        blocking::Connection::session()
    } else {
        blocking::Connection::system()
    }
}

fn manager(bus: &blocking::Connection) -> zbus::Result<blocking::Proxy<'static>> {
    blocking::Proxy::new(bus, DBUS_SYSTEM_NAME, DBUS_SYSTEM_PATH, DBUS_MANAGER_IFACE)
}

fn list_configs(bus: &blocking::Connection) -> zbus::Result<Vec<(String, String, bool)>> {
    manager(bus)?.call("ListConfigs", &())
}

/// `(config_id, state, object_path)` for each live connection.
fn connection_states(bus: &blocking::Connection) -> Vec<(String, String, String)> {
    let paths: Vec<OwnedObjectPath> =
        match manager(bus).and_then(|p| p.call("ListConnections", &())) {
            Ok(v) => v,
            Err(_) => return Vec::new(),
        };
    let mut out = Vec::new();
    for p in paths {
        if let Ok(pr) =
            blocking::Proxy::new(bus, DBUS_SYSTEM_NAME, p.as_str(), DBUS_CONNECTION_IFACE)
        {
            let cid = pr.get_property::<String>("ConfigId").unwrap_or_default();
            let st = pr.get_property::<String>("State").unwrap_or_default();
            out.push((cid, st, p.as_str().to_owned()));
        }
    }
    out
}

/// Resolve a user-supplied name or id to a config id.
fn resolve(bus: &blocking::Connection, needle: &str) -> Option<(String, String)> {
    let configs = list_configs(bus).ok()?;
    configs
        .iter()
        .find(|(id, name, _)| id == needle || name == needle)
        .map(|(id, name, _)| (id.clone(), name.clone()))
}

fn read_line(prompt: &str) -> String {
    print!("{prompt}");
    let _ = std::io::stdout().flush();
    let mut s = String::new();
    let _ = std::io::stdin().read_line(&mut s);
    s.trim_end_matches(['\r', '\n']).to_string()
}

// --------------------------------------------------------------- commands ---

fn cmd_list(bus: &blocking::Connection) -> ExitCode {
    let configs = match list_configs(bus) {
        Ok(c) => c,
        Err(e) => return fail(&format!("could not reach warrenvpnd: {e}")),
    };
    if configs.is_empty() {
        println!("No configurations. Import one with: warrenvpnctl import <file.ovpn>");
        return ExitCode::SUCCESS;
    }
    let active = connection_states(bus);
    println!("{:<10}  {:<28}  SAFE", "STATE", "NAME");
    for (id, name, safe) in configs {
        let state = active
            .iter()
            .find(|(cid, _, _)| cid == &id)
            .map(|(_, s, _)| s.as_str())
            .unwrap_or("-");
        println!(
            "{:<10}  {:<28}  {}",
            state,
            name,
            if safe { "yes" } else { "UNSAFE" }
        );
    }
    ExitCode::SUCCESS
}

fn cmd_status(bus: &blocking::Connection) -> ExitCode {
    let active = connection_states(bus);
    if active.is_empty() {
        println!("No active connections.");
        return ExitCode::SUCCESS;
    }
    let configs = list_configs(bus).unwrap_or_default();
    for (cid, state, _path) in active {
        let name = configs
            .iter()
            .find(|(id, _, _)| id == &cid)
            .map(|(_, n, _)| n.as_str())
            .unwrap_or(&cid);
        println!("{name}: {state}");
    }
    ExitCode::SUCCESS
}

fn cmd_import(bus: &blocking::Connection, args: &[String]) -> ExitCode {
    let Some(path) = args.first() else {
        return fail("usage: warrenvpnctl import <file.ovpn> [name]");
    };
    let contents = match std::fs::read_to_string(path) {
        Ok(c) => c,
        Err(e) => return fail(&format!("could not read {path}: {e}")),
    };
    let name = args.get(1).cloned().unwrap_or_else(|| {
        std::path::Path::new(path)
            .file_stem()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_else(|| "configuration".to_string())
    });
    let opts: HashMap<String, OwnedValue> = HashMap::new();
    match manager(bus).and_then(|m| m.call::<_, _, String>("InstallConfig", &(name.as_str(), contents.as_str(), "private", opts))) {
        Ok(id) => {
            println!("Imported '{name}' (id {id}).");
            ExitCode::SUCCESS
        }
        Err(e) => fail(&format!("import failed: {e}")),
    }
}

fn cmd_connect(bus: &blocking::Connection, args: &[String]) -> ExitCode {
    let killswitch = args.iter().any(|a| a == "--killswitch" || a == "-k");
    let Some(needle) = args.iter().find(|a| !a.starts_with('-')) else {
        return fail("usage: warrenvpnctl connect <name|id> [--killswitch]");
    };
    let Some((id, name)) = resolve(bus, needle) else {
        return fail(&format!("no such configuration: {needle}"));
    };

    let mut opts: HashMap<&str, Value> = HashMap::new();
    if killswitch {
        opts.insert("killswitch", Value::from(true));
    }

    // Subscribe to the daemon's signals BEFORE starting, so we can never miss the
    // first AuthRequest (the relay releases the management hold as soon as the
    // socket is up, which can be before StartConnection even returns).
    let rule = match zbus::MatchRule::builder()
        .msg_type(zbus::message::Type::Signal)
        .sender(DBUS_SYSTEM_NAME)
    {
        Ok(b) => b.build(),
        Err(e) => return fail(&format!("subscribe failed: {e}")),
    };
    let iter = match blocking::MessageIterator::for_match_rule(rule, bus, None) {
        Ok(i) => i,
        Err(e) => return fail(&format!("subscribe failed: {e}")),
    };

    let cpath: OwnedObjectPath = match manager(bus)
        .and_then(|m| m.call("StartConnection", &(id.as_str(), opts)))
    {
        Ok(p) => p,
        Err(e) => return fail(&format!("connect failed: {e}")),
    };
    println!("Connecting '{name}'{}...", if killswitch { " (kill-switch)" } else { "" });
    follow_connection(bus, cpath.as_str(), iter)
}

/// Follow a connection: print state transitions and answer auth prompts on the tty,
/// until it reaches CONNECTED or exits. `iter` is a signal stream subscribed BEFORE
/// the connection started; we filter it to this connection's object path.
fn follow_connection(
    bus: &blocking::Connection,
    cpath: &str,
    iter: blocking::MessageIterator,
) -> ExitCode {
    let state_of = |bus: &blocking::Connection| -> String {
        blocking::Proxy::new(bus, DBUS_SYSTEM_NAME, cpath, DBUS_CONNECTION_IFACE)
            .ok()
            .and_then(|p| p.get_property::<String>("State").ok())
            .unwrap_or_default()
    };

    let mut last = state_of(bus);
    if !last.is_empty() {
        println!("  {last}");
    }
    // The connection may already be terminal by the time we subscribe (race).
    if last == "CONNECTED" {
        println!("Connected.");
        return ExitCode::SUCCESS;
    }
    if last == "EXITING" {
        println!("Disconnected.");
        return ExitCode::FAILURE;
    }

    for msg in iter.flatten() {
        let header = msg.header();
        // Only this connection's signals (the stream covers all connections).
        if header.path().map(|p| p.as_str().to_owned()).as_deref() != Some(cpath) {
            continue;
        }
        let member = header.member().map(|m| m.as_str().to_owned());
        match member.as_deref() {
            Some("AuthRequest") => {
                if let Ok((kind, realm, _prompt, challenge, echo)) =
                    msg.body().deserialize::<(String, String, String, String, bool)>()
                {
                    answer_auth(bus, cpath, &kind, &realm, &challenge, echo);
                }
            }
            Some("WebAuth") => {
                if let Ok((url,)) = msg.body().deserialize::<(String,)>() {
                    println!("  Open this URL in your browser to sign in:");
                    println!("    {url}");
                }
            }
            Some("PropertiesChanged") => {
                let now = state_of(bus);
                if now != last && !now.is_empty() {
                    println!("  {now}");
                    last = now.clone();
                }
                if now == "CONNECTED" {
                    println!("Connected.");
                    return ExitCode::SUCCESS;
                }
                if now.is_empty() || now == "EXITING" {
                    println!("Disconnected.");
                    return ExitCode::FAILURE;
                }
            }
            _ => {}
        }
    }
    ExitCode::SUCCESS
}

fn answer_auth(
    bus: &blocking::Connection,
    cpath: &str,
    kind: &str,
    realm: &str,
    challenge: &str,
    echo: bool,
) {
    println!("Authentication required for '{realm}':");
    let mut fields: HashMap<&str, Value> = HashMap::new();
    let username = if kind == "auth-user-pass" {
        Some(read_line("  Username: "))
    } else {
        None
    };
    if let Some(u) = &username {
        fields.insert("username", Value::from(u.as_str()));
    }
    let password = rpassword::prompt_password("  Password: ").unwrap_or_default();
    fields.insert("password", Value::from(password.as_str()));

    let challenge_resp = if challenge.is_empty() {
        None
    } else if echo {
        Some(read_line(&format!("  {challenge}: ")))
    } else {
        Some(rpassword::prompt_password(format!("  {challenge}: ")).unwrap_or_default())
    };
    if let Some(c) = &challenge_resp {
        fields.insert("challenge", Value::from(c.as_str()));
    }

    if let Ok(p) = blocking::Proxy::new(bus, DBUS_SYSTEM_NAME, cpath, DBUS_CONNECTION_IFACE) {
        if let Err(e) = p.call::<_, _, ()>("ProvideCredentials", &(kind, fields)) {
            eprintln!("warrenvpnctl: ProvideCredentials failed: {e}");
        }
    }
}

fn cmd_disconnect(bus: &blocking::Connection, args: &[String]) -> ExitCode {
    let Some(needle) = args.first() else {
        return fail("usage: warrenvpnctl disconnect <name|id>");
    };
    let id = resolve(bus, needle).map(|(id, _)| id).unwrap_or_else(|| needle.clone());
    let Some((_, _, path)) = connection_states(bus).into_iter().find(|(cid, _, _)| cid == &id)
    else {
        return fail(&format!("'{needle}' is not connected"));
    };
    match blocking::Proxy::new(bus, DBUS_SYSTEM_NAME, path.as_str(), DBUS_CONNECTION_IFACE)
        .and_then(|p| p.call::<_, _, ()>("Disconnect", &()))
    {
        Ok(()) => {
            println!("Disconnecting.");
            ExitCode::SUCCESS
        }
        Err(e) => fail(&format!("disconnect failed: {e}")),
    }
}

fn cmd_remove(bus: &blocking::Connection, args: &[String]) -> ExitCode {
    let Some(needle) = args.first() else {
        return fail("usage: warrenvpnctl remove <name|id>");
    };
    let id = resolve(bus, needle).map(|(id, _)| id).unwrap_or_else(|| needle.clone());
    match manager(bus).and_then(|m| m.call::<_, _, ()>("RemoveConfig", &(id.as_str(),))) {
        Ok(()) => {
            println!("Removed '{needle}'.");
            ExitCode::SUCCESS
        }
        Err(e) => fail(&format!("remove failed: {e}")),
    }
}

fn cmd_recover(bus: &blocking::Connection) -> ExitCode {
    match manager(bus).and_then(|m| m.call::<_, _, ()>("RecoverNetwork", &())) {
        Ok(()) => {
            println!("Network restored (kill-switch cleared).");
            ExitCode::SUCCESS
        }
        Err(e) => fail(&format!("recover failed: {e}")),
    }
}

fn usage_text() -> String {
    "warrenvpnctl — control the WarrenVPN VPN daemon\n\n\
     Usage:\n  \
     warrenvpnctl list\n  \
     warrenvpnctl status\n  \
     warrenvpnctl import <file.ovpn> [name]\n  \
     warrenvpnctl connect <name|id> [--killswitch]\n  \
     warrenvpnctl disconnect <name|id>\n  \
     warrenvpnctl remove <name|id>\n  \
     warrenvpnctl recover\n"
        .to_string()
}

fn usage() -> ExitCode {
    eprint!("{}", usage_text());
    ExitCode::FAILURE
}

fn fail(msg: &str) -> ExitCode {
    eprintln!("warrenvpnctl: {msg}");
    ExitCode::FAILURE
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let bus = match connect_bus() {
        Ok(b) => b,
        Err(e) => return fail(&format!("could not connect to D-Bus: {e}")),
    };
    match args.first().map(String::as_str) {
        Some("list") => cmd_list(&bus),
        Some("status") => cmd_status(&bus),
        Some("import") => cmd_import(&bus, &args[1..]),
        Some("connect") => cmd_connect(&bus, &args[1..]),
        Some("disconnect") => cmd_disconnect(&bus, &args[1..]),
        Some("remove") => cmd_remove(&bus, &args[1..]),
        Some("recover") => cmd_recover(&bus),
        Some("help") | Some("-h") | Some("--help") => {
            print!("{}", usage_text());
            ExitCode::SUCCESS
        }
        _ => usage(),
    }
}
