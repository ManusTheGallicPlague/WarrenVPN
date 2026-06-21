//! WarrenVPN GUI — a GTK4 + libadwaita front-end for the warrenvpnd daemon.
//!
//! Lists installed configurations, imports a `.ovpn`, connects/disconnects, shows
//! live state, and lives in the system tray (StatusNotifierItem). Connection state
//! refreshes are event-driven: a background thread listens for the daemon's D-Bus
//! signals and nudges the UI, with a short polling fallback for intermediate state
//! transitions. Daemon calls use zbus's blocking API for simplicity.
//!
//! Development: set `WARRENVPN_BUS=session` (or `WARRENVPND_BUS=session`) to reach a
//! daemon running on the session bus.

use std::collections::HashMap;

use adw::prelude::*;
use gtk::{gio, glib};

use zbus::blocking;
use zbus::zvariant::{OwnedObjectPath, OwnedValue};

use warrenvpn_common::{
    APP_ID, DBUS_CONNECTION_IFACE, DBUS_MANAGER_IFACE, DBUS_SYSTEM_NAME, DBUS_SYSTEM_PATH,
};

mod secret;
mod settings;

/// Events delivered to the GTK main loop from the tray and the signal listener.
#[derive(Debug, Clone)]
enum UiEvent {
    Refresh,
    Show,
    Quit,
    /// OpenVPN asked for credentials on a connection object.
    Auth {
        path: String,
        kind: String,
        realm: String,
        /// Static-challenge prompt text (empty if none).
        challenge: String,
        /// Whether the challenge response may be shown on screen.
        echo: bool,
    },
    /// Single-sign-on: open this URL in a browser.
    WebAuth { url: String },
}

// --------------------------------------------------------------- D-Bus client ---

fn on_session_bus() -> bool {
    std::env::var("WARRENVPN_BUS").as_deref() == Ok("session")
        || std::env::var("WARRENVPND_BUS").as_deref() == Ok("session")
}

fn connect_bus() -> zbus::Result<blocking::Connection> {
    if on_session_bus() {
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

fn list_connection_states(bus: &blocking::Connection) -> Vec<(String, String, String)> {
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

fn install_config(bus: &blocking::Connection, name: &str, contents: &str) -> zbus::Result<String> {
    let opts: HashMap<String, OwnedValue> = HashMap::new();
    manager(bus)?.call("InstallConfig", &(name, contents, "private", opts))
}

fn start_connection(
    bus: &blocking::Connection,
    id: &str,
    killswitch: bool,
) -> zbus::Result<OwnedObjectPath> {
    use zbus::zvariant::Value;
    let mut opts: HashMap<&str, Value> = HashMap::new();
    if killswitch {
        opts.insert("killswitch", Value::from(true));
    }
    manager(bus)?.call("StartConnection", &(id, opts))
}

/// Start every configuration marked auto-connect that is not already up.
fn auto_connect_all(bus: &blocking::Connection) {
    let Ok(configs) = list_configs(bus) else { return };
    let active = list_connection_states(bus);
    for (id, _name, _safe) in configs {
        if settings::get_bool(&id, settings::AUTOCONNECT)
            && !active.iter().any(|(cid, _, _)| cid == &id)
        {
            let ks = settings::get_bool(&id, settings::KILLSWITCH);
            if let Err(e) = start_connection(bus, &id, ks) {
                eprintln!("warrenvpn: auto-connect of {id} failed: {e}");
            }
        }
    }
}

/// Per-config settings dialog: kill-switch + auto-connect (persisted immediately) +
/// a destructive "remove configuration" action.
fn show_config_settings(
    parent: Option<&gtk::Window>,
    bus: &blocking::Connection,
    list_box: &gtk::ListBox,
    config_id: &str,
    name: &str,
) {
    let group = adw::PreferencesGroup::new();
    let killswitch = adw::SwitchRow::builder()
        .title("Kill-switch")
        .subtitle("Blocca tutto il traffico fuori dalla VPN")
        .active(settings::get_bool(config_id, settings::KILLSWITCH))
        .build();
    let autoconnect = adw::SwitchRow::builder()
        .title("Connetti all'avvio")
        .active(settings::get_bool(config_id, settings::AUTOCONNECT))
        .build();
    group.add(&killswitch);
    group.add(&autoconnect);

    {
        let id = config_id.to_owned();
        killswitch.connect_active_notify(move |r| {
            settings::set_bool(&id, settings::KILLSWITCH, r.is_active());
        });
    }
    {
        let id = config_id.to_owned();
        autoconnect.connect_active_notify(move |r| {
            settings::set_bool(&id, settings::AUTOCONNECT, r.is_active());
        });
    }

    let dialog = adw::MessageDialog::builder()
        .heading(format!("Impostazioni — {name}"))
        .build();
    if let Some(p) = parent {
        dialog.set_transient_for(Some(p));
        dialog.set_modal(true);
    }
    dialog.set_extra_child(Some(&group));
    dialog.add_response("close", "Chiudi");
    dialog.add_response("remove", "Rimuovi");
    dialog.set_response_appearance("remove", adw::ResponseAppearance::Destructive);
    dialog.set_default_response(Some("close"));
    dialog.set_close_response("close");

    {
        let bus = bus.clone();
        let list_box = list_box.clone();
        let id = config_id.to_owned();
        dialog.connect_response(None, move |_dlg, resp| {
            if resp != "remove" {
                return;
            }
            if let Err(e) = remove_config(&bus, &id) {
                eprintln!("warrenvpn: RemoveConfig failed: {e}");
            }
            // Forget any saved credentials for the removed config.
            secret::clear(&id, "username");
            secret::clear(&id, "password");
            populate(&list_box, &bus);
        });
    }
    dialog.present();
}

fn disconnect(bus: &blocking::Connection, path: &str) -> zbus::Result<()> {
    blocking::Proxy::new(bus, DBUS_SYSTEM_NAME, path, DBUS_CONNECTION_IFACE)?.call("Disconnect", &())
}

fn remove_config(bus: &blocking::Connection, id: &str) -> zbus::Result<()> {
    let _: () = manager(bus)?.call("RemoveConfig", &(id,))?;
    Ok(())
}

/// The configuration id behind a live connection object (for keying saved secrets).
fn conn_config_id(bus: &blocking::Connection, path: &str) -> Option<String> {
    blocking::Proxy::new(bus, DBUS_SYSTEM_NAME, path, DBUS_CONNECTION_IFACE)
        .ok()?
        .get_property::<String>("ConfigId")
        .ok()
}

fn provide_credentials(
    bus: &blocking::Connection,
    path: &str,
    kind: &str,
    username: Option<&str>,
    password: &str,
    challenge: Option<&str>,
) -> zbus::Result<()> {
    use zbus::zvariant::Value;
    let mut fields: HashMap<&str, Value> = HashMap::new();
    if let Some(u) = username {
        fields.insert("username", Value::from(u));
    }
    fields.insert("password", Value::from(password));
    if let Some(c) = challenge {
        fields.insert("challenge", Value::from(c));
    }
    let proxy = blocking::Proxy::new(bus, DBUS_SYSTEM_NAME, path, DBUS_CONNECTION_IFACE)?;
    let _: () = proxy.call("ProvideCredentials", &(kind, fields))?;
    Ok(())
}

/// Listen for the daemon's signals on a dedicated connection and forward UI events:
/// `AuthRequest` becomes an [`UiEvent::Auth`]; anything else triggers a refresh.
fn spawn_signal_listener(tx: async_channel::Sender<UiEvent>) {
    std::thread::spawn(move || {
        let conn = match connect_bus() {
            Ok(c) => c,
            Err(_) => return,
        };
        let rule = match zbus::MatchRule::builder()
            .msg_type(zbus::message::Type::Signal)
            .sender(DBUS_SYSTEM_NAME)
        {
            Ok(b) => b.build(),
            Err(_) => return,
        };
        let iter = match blocking::MessageIterator::for_match_rule(rule, &conn, None) {
            Ok(i) => i,
            Err(_) => return,
        };
        for msg in iter.flatten() {
            let header = msg.header();
            let member = header.member().map(|m| m.as_str().to_owned());
            match member.as_deref() {
                Some("AuthRequest") => {
                    let path = header
                        .path()
                        .map(|p| p.as_str().to_owned())
                        .unwrap_or_default();
                    if let Ok((kind, realm, _prompt, challenge, echo)) =
                        msg.body().deserialize::<(String, String, String, String, bool)>()
                    {
                        let _ = tx.send_blocking(UiEvent::Auth {
                            path,
                            kind,
                            realm,
                            challenge,
                            echo,
                        });
                    }
                }
                Some("WebAuth") => {
                    if let Ok((url,)) = msg.body().deserialize::<(String,)>() {
                        let _ = tx.send_blocking(UiEvent::WebAuth { url });
                    }
                }
                // Refresh on state/property changes and config/connection set changes;
                // ignore the high-frequency LogLine stream (handshake) to avoid jank.
                Some("PropertiesChanged")
                | Some("ConnectionAdded")
                | Some("ConnectionRemoved")
                | Some("ConfigurationsChanged") => {
                    let _ = tx.send_blocking(UiEvent::Refresh);
                }
                _ => {}
            }
        }
    });
}

// --------------------------------------------------------------------- tray ---

struct WarrenVPNTray {
    tx: async_channel::Sender<UiEvent>,
}

impl ksni::Tray for WarrenVPNTray {
    fn icon_name(&self) -> String {
        "network-vpn".into()
    }
    fn title(&self) -> String {
        "WarrenVPN".into()
    }
    fn id(&self) -> String {
        APP_ID.into()
    }
    fn activate(&mut self, _x: i32, _y: i32) {
        let _ = self.tx.send_blocking(UiEvent::Show);
    }
    fn menu(&self) -> Vec<ksni::MenuItem<Self>> {
        use ksni::menu::{MenuItem, StandardItem};
        vec![
            StandardItem {
                label: "Apri WarrenVPN".into(),
                icon_name: "view-list-symbolic".into(),
                activate: Box::new(|t: &mut Self| {
                    let _ = t.tx.send_blocking(UiEvent::Show);
                }),
                ..Default::default()
            }
            .into(),
            MenuItem::Separator,
            StandardItem {
                label: "Esci".into(),
                icon_name: "application-exit-symbolic".into(),
                activate: Box::new(|t: &mut Self| {
                    let _ = t.tx.send_blocking(UiEvent::Quit);
                }),
                ..Default::default()
            }
            .into(),
        ]
    }
}

// --------------------------------------------------------------------- UI ---

fn populate(list_box: &gtk::ListBox, bus: &blocking::Connection) {
    while let Some(child) = list_box.first_child() {
        list_box.remove(&child);
    }

    let configs = match list_configs(bus) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("warrenvpn: ListConfigs failed: {e}");
            let row = adw::ActionRow::builder()
                .title("Servizio non raggiungibile")
                .subtitle("Impossibile contattare warrenvpnd")
                .build();
            list_box.append(&row);
            return;
        }
    };

    if configs.is_empty() {
        let row = adw::ActionRow::builder()
            .title("Nessuna configurazione")
            .subtitle("Usa il pulsante + per importare un file .ovpn")
            .build();
        list_box.append(&row);
        return;
    }

    let active = list_connection_states(bus);

    for (id, name, safe) in configs {
        let row = adw::ActionRow::builder().title(&name).build();
        let button = gtk::Button::builder().valign(gtk::Align::Center).build();

        match active.iter().find(|(cid, _, _)| cid == &id) {
            Some((_, state, path)) => {
                row.set_subtitle(&format!("● {state}"));
                button.set_label("Disconnetti");
                button.add_css_class("destructive-action");
                let bus = bus.clone();
                let list_box = list_box.clone();
                let path = path.clone();
                button.connect_clicked(move |b| {
                    b.set_sensitive(false);
                    b.set_label("Disconnessione…");
                    if let Err(e) = disconnect(&bus, &path) {
                        eprintln!("warrenvpn: Disconnect failed: {e}");
                    }
                    populate(&list_box, &bus);
                });
            }
            None => {
                row.set_subtitle(if safe {
                    "Pronta"
                } else {
                    "⚠ Non sicura — richiederà privilegi di amministratore"
                });
                button.set_label("Connetti");
                button.add_css_class("suggested-action");
                let bus = bus.clone();
                let list_box = list_box.clone();
                let id = id.clone();
                button.connect_clicked(move |b| {
                    b.set_sensitive(false);
                    b.set_label("Connessione…");
                    let ks = settings::get_bool(&id, settings::KILLSWITCH);
                    if let Err(e) = start_connection(&bus, &id, ks) {
                        eprintln!("warrenvpn: StartConnection failed: {e}");
                    }
                    populate(&list_box, &bus);
                });
            }
        }

        // Per-config settings (kill-switch / auto-connect).
        let gear = gtk::Button::from_icon_name("emblem-system-symbolic");
        gear.set_valign(gtk::Align::Center);
        gear.add_css_class("flat");
        gear.set_tooltip_text(Some("Impostazioni"));
        {
            let id = id.clone();
            let name = name.clone();
            let bus = bus.clone();
            let list_box = list_box.clone();
            gear.connect_clicked(move |b| {
                let parent = b.root().and_downcast::<gtk::Window>();
                show_config_settings(parent.as_ref(), &bus, &list_box, &id, &name);
            });
        }
        row.add_suffix(&gear);
        row.add_suffix(&button);
        list_box.append(&row);
    }
}

fn import_dialog(
    parent: &adw::ApplicationWindow,
    list_box: &gtk::ListBox,
    bus: &blocking::Connection,
) {
    let filter = gtk::FileFilter::new();
    filter.set_name(Some("Configurazioni OpenVPN"));
    filter.add_pattern("*.ovpn");
    filter.add_pattern("*.conf");
    let filters = gio::ListStore::new::<gtk::FileFilter>();
    filters.append(&filter);

    let dialog = gtk::FileDialog::builder()
        .title("Importa una configurazione")
        .filters(&filters)
        .build();

    let bus = bus.clone();
    let list_box = list_box.clone();
    dialog.open(Some(parent), gio::Cancellable::NONE, move |result| {
        if let Ok(file) = result {
            if let Some(path) = file.path() {
                // Read the file as the (unprivileged) user; the daemon never opens a
                // user-controlled path as root.
                match std::fs::read_to_string(&path) {
                    Ok(contents) => {
                        let name = path
                            .file_stem()
                            .map(|s| s.to_string_lossy().into_owned())
                            .unwrap_or_else(|| "configuration".to_string());
                        match install_config(&bus, &name, &contents) {
                            Ok(id) => eprintln!("warrenvpn: installed config {id}"),
                            Err(e) => eprintln!("warrenvpn: InstallConfig failed: {e}"),
                        }
                        populate(&list_box, &bus);
                    }
                    Err(e) => eprintln!("warrenvpn: could not read {}: {e}", path.display()),
                }
            }
        }
    });
}

/// Prompt for credentials in response to an `AuthRequest`, send them back, and
/// optionally persist them in the keyring (keyed by `config_id`).
#[allow(clippy::too_many_arguments)]
fn show_auth_dialog(
    parent: &adw::ApplicationWindow,
    bus: &blocking::Connection,
    path: &str,
    kind: &str,
    realm: &str,
    config_id: Option<String>,
    challenge: &str,
    echo: bool,
) {
    let needs_user = kind == "auth-user-pass";

    let group = adw::PreferencesGroup::new();
    let user_row = adw::EntryRow::builder().title("Nome utente").build();
    let pass_row = adw::PasswordEntryRow::builder().title("Password").build();
    let save_row = adw::SwitchRow::builder()
        .title("Salva nel portachiavi")
        .active(true)
        .build();
    if needs_user {
        group.add(&user_row);
    }
    group.add(&pass_row);

    // Optional static-challenge response (e.g. a token PIN) — never saved.
    let challenge_entry: Option<gtk::Editable> = if challenge.is_empty() {
        None
    } else if echo {
        let r = adw::EntryRow::builder().title(challenge).build();
        group.add(&r);
        Some(r.upcast())
    } else {
        let r = adw::PasswordEntryRow::builder().title(challenge).build();
        group.add(&r);
        Some(r.upcast())
    };

    if config_id.is_some() {
        group.add(&save_row);
    }

    // Pre-fill any saved values so a re-prompt (after a failure) keeps them.
    if let Some(id) = &config_id {
        if needs_user {
            if let Some(u) = secret::lookup(id, "username") {
                user_row.set_text(&u);
            }
        }
        if let Some(p) = secret::lookup(id, "password") {
            pass_row.set_text(&p);
        }
    }

    let dialog = adw::MessageDialog::builder()
        .transient_for(parent)
        .modal(true)
        .heading("Autenticazione VPN")
        .body(format!("Inserisci le credenziali per «{realm}»"))
        .build();
    dialog.set_extra_child(Some(&group));
    dialog.add_response("cancel", "Annulla");
    dialog.add_response("connect", "Connetti");
    dialog.set_response_appearance("connect", adw::ResponseAppearance::Suggested);
    dialog.set_default_response(Some("connect"));
    dialog.set_close_response("cancel");

    let bus = bus.clone();
    let path = path.to_owned();
    let kind = kind.to_owned();
    dialog.connect_response(None, move |_dlg, resp| {
        if resp != "connect" {
            return;
        }
        let pass = pass_row.text().to_string();
        let user = needs_user.then(|| user_row.text().to_string());
        let chal = challenge_entry.as_ref().map(|e| e.text().to_string());
        if let Err(e) =
            provide_credentials(&bus, &path, &kind, user.as_deref(), &pass, chal.as_deref())
        {
            eprintln!("warrenvpn: ProvideCredentials failed: {e}");
        }
        // Persist or forget, per the switch.
        if let Some(id) = &config_id {
            if save_row.is_active() {
                secret::store(id, "password", &pass);
                if let Some(u) = &user {
                    secret::store(id, "username", u);
                }
            } else {
                secret::clear(id, "password");
                secret::clear(id, "username");
            }
        }
    });
    dialog.present();
}

fn build_ui(app: &adw::Application, bus: Option<blocking::Connection>) {
    let window = adw::ApplicationWindow::builder()
        .application(app)
        .title("WarrenVPN")
        .default_width(540)
        .default_height(600)
        .build();

    let header = adw::HeaderBar::new();
    let import_button = gtk::Button::from_icon_name("list-add-symbolic");
    import_button.set_tooltip_text(Some("Importa configurazione"));
    header.pack_start(&import_button);

    let list_box = gtk::ListBox::new();
    list_box.set_selection_mode(gtk::SelectionMode::None);
    list_box.add_css_class("boxed-list");
    list_box.set_margin_top(18);
    list_box.set_margin_bottom(18);

    let clamp = adw::Clamp::builder()
        .maximum_size(560)
        .margin_start(12)
        .margin_end(12)
        .child(&list_box)
        .build();
    let scrolled = gtk::ScrolledWindow::builder().vexpand(true).child(&clamp).build();

    let toolbar = adw::ToolbarView::new();
    toolbar.add_top_bar(&header);
    toolbar.set_content(Some(&scrolled));
    window.set_content(Some(&toolbar));

    // Closing the window hides it to the tray rather than quitting.
    window.connect_close_request(|w| {
        w.set_visible(false);
        glib::Propagation::Stop
    });

    let Some(bus) = bus else {
        import_button.set_sensitive(false);
        let row = adw::ActionRow::builder()
            .title("Servizio non raggiungibile")
            .subtitle("Impossibile connettersi al bus D-Bus")
            .build();
        list_box.append(&row);
        window.present();
        return;
    };

    populate(&list_box, &bus);
    auto_connect_all(&bus);
    populate(&list_box, &bus);

    {
        let bus = bus.clone();
        let list_box = list_box.clone();
        let window = window.clone();
        import_button.connect_clicked(move |_| {
            import_dialog(&window, &list_box, &bus);
        });
    }

    // Tray + signal listener feed UI events; keep the app alive without a window.
    std::mem::forget(app.hold());
    let (tx, rx) = async_channel::unbounded::<UiEvent>();
    spawn_signal_listener(tx.clone());
    ksni::TrayService::new(WarrenVPNTray { tx }).spawn();

    {
        let app = app.clone();
        let window = window.clone();
        let bus = bus.clone();
        let list_box = list_box.clone();
        glib::spawn_future_local(async move {
            while let Ok(ev) = rx.recv().await {
                match ev {
                    UiEvent::Refresh => populate(&list_box, &bus),
                    UiEvent::Show => {
                        window.set_visible(true);
                        window.present();
                    }
                    UiEvent::Quit => app.quit(),
                    UiEvent::WebAuth { url } => {
                        // Defence in depth (the daemon already filters): only ever
                        // hand http(s) URLs to the desktop opener.
                        let lower = url.to_ascii_lowercase();
                        if lower.starts_with("https://") || lower.starts_with("http://") {
                            eprintln!("warrenvpn: opening SSO URL in browser: {url}");
                            let _ = gio::AppInfo::launch_default_for_uri(
                                &url,
                                None::<&gio::AppLaunchContext>,
                            );
                        } else {
                            eprintln!("warrenvpn: refusing non-http(s) SSO URL: {url}");
                        }
                    }
                    UiEvent::Auth {
                        path,
                        kind,
                        realm,
                        challenge,
                        echo,
                    } => {
                        let needs_user = kind == "auth-user-pass";
                        let config_id = conn_config_id(&bus, &path);
                        // A static challenge always needs fresh input, so only
                        // auto-provide saved credentials when there is no challenge.
                        let mut handled = false;
                        if challenge.is_empty() {
                            if let Some(id) = &config_id {
                                let saved_pass = secret::lookup(id, "password");
                                let saved_user = secret::lookup(id, "username");
                                if saved_pass.is_some() && (!needs_user || saved_user.is_some()) {
                                    let pass = saved_pass.unwrap_or_default();
                                    let user = saved_user.unwrap_or_default();
                                    let user_opt = needs_user.then_some(user.as_str());
                                    match provide_credentials(
                                        &bus, &path, &kind, user_opt, &pass, None,
                                    ) {
                                        Ok(()) => handled = true,
                                        Err(e) => eprintln!("warrenvpn: auto-auth failed: {e}"),
                                    }
                                }
                            }
                        }
                        if !handled {
                            show_auth_dialog(
                                &window, &bus, &path, &kind, &realm, config_id, &challenge, echo,
                            );
                        }
                    }
                }
            }
        });
    }

    // Slow safety-net poll in case a signal is ever missed; refreshes are primarily
    // event-driven via the signal listener above.
    {
        let bus = bus.clone();
        let list_box = list_box.clone();
        glib::timeout_add_seconds_local(5, move || {
            populate(&list_box, &bus);
            glib::ControlFlow::Continue
        });
    }

    window.present();
}

fn main() -> glib::ExitCode {
    let app = adw::Application::builder().application_id(APP_ID).build();
    app.connect_activate(|app| {
        // Single-instance: a second launch just raises the existing window.
        if let Some(win) = app.active_window() {
            win.present();
            return;
        }
        let bus = match connect_bus() {
            Ok(b) => Some(b),
            Err(e) => {
                eprintln!("warrenvpn: D-Bus connection failed: {e}");
                None
            }
        };
        build_ui(app, bus);
    });
    app.run()
}
