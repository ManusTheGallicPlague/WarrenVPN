# WarrenVPN

**A full-featured OpenVPN client, with a native GUI, for the Linux desktop.**

WarrenVPN lets you import `.ovpn` profiles and bring VPN connections up and down
from a GTK4 desktop app (or the command line) without handing your whole session
root privileges. The actual connection work happens in a small, polkit-gated
**system daemon** that drives OpenVPN directly through its management interface —
one transient OpenVPN process per connection. The GUI and CLI are entirely
unprivileged clients of that daemon. WarrenVPN handles the parts that make
OpenVPN annoying in practice: interactive auth (passwords, key passphrases,
static/dynamic challenges, web/SSO logins), DNS pushed by the server, a
fail-closed kill-switch, credential storage, and a tray icon.

> **Status: working MVP (v0.0.1).** The core flow — import, connect, authenticate,
> route DNS, kill-switch, disconnect — is implemented and exercised by tests and
> end-to-end smoke runs. A few items are deferred; see
> [Project status](#project-status) for the honest list.

---

## What it is

WarrenVPN is a Rust workspace that produces three binaries:

| Binary         | Role                                                                 |
|----------------|----------------------------------------------------------------------|
| `warrenvpnd`   | The privileged D-Bus **system** daemon — the only security boundary. |
| `warrenvpn`    | The GTK4 + libadwaita desktop GUI (an unprivileged client).          |
| `warrenvpnctl` | The command-line client (also unprivileged).                         |

The daemon owns the system bus name `net.warrenvpn.WarrenVPN1` and is D-Bus
activated on demand — you do not start it by hand.

## Features

Everything below is implemented:

- **Import `.ovpn` configs.** Each profile is parsed and classified **safe** or
  **unsafe** by the daemon itself (unsafe = the config could run code as root,
  e.g. via `up`/`down`/plugin directives).
- **Connect / disconnect**, with one transient OpenVPN process per connection.
- **Live connection state and byte counters** streamed from the management
  interface.
- **Interactive authentication:**
  - username / password,
  - private-key passphrase,
  - static challenge (`SCRV1`),
  - dynamic challenge (`CRV1`),
  - **web auth / SSO** — `OPEN_URL` logins are opened in your browser.
- **nftables kill-switch:** egress is allowed only through the tunnel and the
  ruleset is **fail-closed**. A mandatory boot-recovery unit clears any stale
  table after an unclean shutdown, and a "restore connectivity" action is always
  available.
- **DNS via systemd-resolved**, using the DNS settings the server pushes.
- **Credential persistence** through the Secret Service (libsecret).
- **Tray icon** via StatusNotifierItem.
- **Per-config settings:** kill-switch and auto-connect toggles.
- **Clean teardown** of the tunnel on logout/shutdown via logind.

## Architecture

WarrenVPN's security rests on a single idea: **the daemon is the only trust
boundary, and it never trusts its clients.**

```
  warrenvpn (GUI)  ──┐
                     ├──  D-Bus (system bus)  ──►  warrenvpnd  ──►  openvpn
  warrenvpnctl (CLI) ┘     net.warrenvpn.WarrenVPN1            (management iface)
        unprivileged              polkit-gated                 one process / connection
```

Every privileged operation is a D-Bus method on `warrenvpnd`. The client can ask
for anything; the daemon decides. It authorizes each method via polkit, scopes
every operation to the authenticated caller's uid, re-parses and re-classifies
each config **server-side** rather than believing the client's verdict, and
writes root-owned shadow copies of configs atomically.

The Rust workspace (crates):

- **`ovpn-config`** — the OpenVPN config tokenizer/parser and the safe/unsafe
  classifier. This is the trusted computing base: its verdict decides whether a
  config may run OpenVPN as root without an admin prompt. Pure and heavily tested
  (hardened against quoted/escaped option-name evasion).
- **`warrenvpn-common`** — the single source of truth for identity: app-id, D-Bus
  names, polkit action ids, filesystem paths.
- **`warrenvpn-core`** — transport-agnostic daemon logic: management-protocol
  parsing (including auth prompts), the OpenVPN argv builder, the root-owned
  shadow config store, pushed-DNS parsing, and the nftables kill-switch ruleset
  builder.
- **`warrenvpnd`** — the privileged system daemon itself.
- **`warrenvpn-gui`** — the GTK4 + libadwaita front-end (`warrenvpn`).
- **`warrenvpn-cli`** — `warrenvpnctl`.

## Security model

- **polkit per action.** Each privileged method maps to a polkit action under
  `net.warrenvpn.*` — for example `net.warrenvpn.connect`,
  `net.warrenvpn.install-config`, `net.warrenvpn.manage-daemon`,
  `net.warrenvpn.killswitch`. The system administrator controls policy in one
  place.
- **Server-side re-classification.** The daemon re-parses every config and
  decides for itself whether it is safe (cannot run code as root) or unsafe.
  Running an unsafe config requires its own elevated authorization; the client's
  opinion is never trusted.
- **Per-caller scoping.** Installed configs and connections are scoped to the
  uid that authenticated, and root-owned shadow copies are written atomically.
- **Fail-closed kill-switch.** The nftables ruleset permits egress only through
  the tunnel; if anything goes wrong, traffic is blocked rather than leaked, and
  the boot-recovery unit guarantees you are never locked out after a crash.

## Requirements

- A **Rust toolchain, 1.80 or newer**, to build.
- At runtime: **GTK4**, **libadwaita**, **polkit**, **libsecret**,
  **libnftables**, **systemd** (with **systemd-resolved**), **openvpn**, and a
  `/dev/net/tun` device.

## Building

From the repository root:

```sh
cargo build --release          # build the whole workspace
cargo test --workspace         # run the unit + smoke tests
cargo clippy --workspace --all-targets   # lint (kept warning-free)
```

## Installing (Arch Linux)

A native Arch package is provided via `makepkg`:

```sh
cd packaging/arch
makepkg -si
```

This builds the workspace and installs everything the product needs as a unit:
the daemon, the GUI and CLI, the D-Bus system service and bus policy, the polkit
policy, the systemd units (the daemon plus the boot-recovery unit), the
`warrenvpn` sysusers group, tmpfiles, the `.desktop` entry and icon, and the man
pages.

You do **not** need to `systemctl start` anything: the daemon is D-Bus
activated. After installation, launch the GUI with `warrenvpn` or use the
`warrenvpnctl` CLI.

## Usage

### GUI

```sh
warrenvpn
```

Import a `.ovpn` file, then connect from the list. Connection state, byte
counters, auth prompts, the per-config kill-switch / auto-connect toggles, and
the tray icon are all handled in the app.

### CLI

```sh
warrenvpnctl list                          # list installed configs
warrenvpnctl status                        # show connection states
warrenvpnctl import office.ovpn            # import a profile
warrenvpnctl connect office                # connect
warrenvpnctl connect office --killswitch   # connect with the kill-switch on
warrenvpnctl disconnect office             # disconnect
warrenvpnctl remove office                 # remove an installed config
warrenvpnctl recover                       # restore connectivity (clear kill-switch)
```

Interactive authentication (passwords, passphrases, challenges) is prompted in
the terminal.

## Project status

This is a real, working MVP. Evidence:

- **75 unit tests pass.**
- **clippy is warning-free.**
- **5 end-to-end smoke tests pass** — config install/classify/sanitize, the
  connect lifecycle, username/password auth, static-challenge (`SCRV1`) auth, and
  the full CLI. These run **without root and without a real VPN**, by driving the
  daemon on a private session bus against a Python fake OpenVPN.

### Not yet implemented (deferred)

Honest about the gaps (see [`docs/DECISIONS.md`](docs/DECISIONS.md)):

- surviving a daemon restart (adopting already-running connections via a
  transient systemd scope),
- connect-at-boot, before any user logs in,
- PKCS#11 PIN and `CR_TEXT` authentication,
- moving a config between scopes,
- forced / managed enterprise preferences,
- self-update,
- internationalization,
- a clean-room AUR PKGBUILD,
- `.deb` / `.rpm` packaging.

## Documentation

- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) — architecture, the privilege
  model, the feature reference, and the risk register.
- [`docs/IPC-CONTRACT.md`](docs/IPC-CONTRACT.md) — the D-Bus privilege /
  automation contract and the daemon's trust rules.
- [`docs/DECISIONS.md`](docs/DECISIONS.md) — decisions and open questions.
- [`docs/MANUALE-IT.md`](docs/MANUALE-IT.md) — Italian user manual.

## License

WarrenVPN is licensed under **GPL-2.0-only**. See [`COPYING`](COPYING).
