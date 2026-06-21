# IPC & privilege contract

WarrenVPN is two processes joined by D-Bus, plus one transient worker per connection.
This document is the authoritative description of that boundary; the introspection
XML under `packaging/dbus/` and the polkit actions under `packaging/polkit/` are
the machine-readable form, and `warrenvpn_common` holds the names both sides import.

```
 ┌─────────────────────────┐         session bus           ┌──────────────────────┐
 │  warrenvpn (GUI agent)      │  net.warrenvpn.WarrenVPN         │  warrenvpn CLI / scripts │
 │  GTK4 + libadwaita       │  .Control  (automation API) ──┤  (thin D-Bus client)  │
 │  - tray (SNI+DBusMenu)   │                               └──────────────────────┘
 │  - windows, dialogs      │
 │  - libsecret credentials │         system bus
 │  unprivileged, per-user  │  net.warrenvpn.WarrenVPN1
 └───────────┬─────────────┘  .Manager  +  .Connection/<id>
             │                        │
             │  D-Bus (polkit-gated)  │  signals: state, bytecount, auth, log
             ▼                        ▼
 ┌──────────────────────────────────────────────────────────┐
 │  warrenvpnd (privileged daemon, root, D-Bus-activated)        │
 │  THE ONLY SECURITY BOUNDARY                                │
 │  - polkit CheckAuthorization per method                    │
 │  - re-parses + re-classifies configs SERVER-SIDE           │
 │  - root-owned shadow copies, atomic writes                 │
 │  - DNS via systemd-resolved, kill-switch via nftables      │
 │  - proxies each OpenVPN management channel                 │
 └───────────┬────────────────────────────────────────────────┘
             │ launches as transient systemd scope
             ▼
   warrenvpn-<uuid>.scope ──► openvpn --management <unix-sock in /run/warrenvpn>
```

## Two interfaces, one boundary

* **System bus — `net.warrenvpn.WarrenVPN1`** (`packaging/dbus/net.warrenvpn.WarrenVPN1.xml`).
  Owned only by the root daemon. `.Manager` is the entry point; each live tunnel is
  a `.Connection/<id>` object. This is where *all* privilege lives.
* **Session bus — `net.warrenvpn.WarrenVPN` `.Control`**
  (`packaging/dbus/net.warrenvpn.WarrenVPN.Control.xml`). Served by the GUI agent; the
  `warrenvpn` CLI is a thin client. This is the single, typed automation surface
  for the GUI and the CLI.

## Non-negotiable daemon rules (the TCB)

1. **Never trust the caller's verdict.** The daemon re-tokenizes, re-parses and
   re-classifies every configuration with the shared `ovpn-config` crate and
   computes safe/unsafe itself. The GUI's opinion is advisory only.
2. **Authorize every privileged method** via polkit `CheckAuthorization` with the
   D-Bus caller as subject (`GetConnectionUnixUser` / `GetConnectionUnixProcessID`,
   never raw `SO_PEERCRED` parsing), re-checked per call.
3. **Allowlist before exec.** OpenVPN options are validated against an allowlist
   (anti option-injection); the environment is cleared and rebuilt; user-supplied
   hook scripts run privilege-dropped (`systemd-run --uid=<caller>`) with ownership
   and permission checks.
4. **Proxy the management channel.** The raw OpenVPN management socket
   (`/run/warrenvpn/<id>.sock`, root 0600) is never handed to unprivileged clients;
   they drive it through the `.Connection` object. (Risk register #9.)
5. **Shadow copies are the only thing OpenVPN runs against.** Written atomically
   (temp + `rename`, `O_NOFOLLOW`, `fchown`/`fchmod` on the fd) under
   `/var/lib/warrenvpn/users/<uid>/`, root-owned, group `warrenvpn`, not world-readable.

## polkit action mapping

| Method(s) | Action | Default for active session |
|---|---|---|
| `StartConnection`, `AdoptRunningConnections`, `Connection.Disconnect` | `connect` | **yes** (no prompt) |
| `InstallConfig`, `MoveConfig`, `RemoveConfig` | `install-config` | `auth_admin_keep` |
| `SetForcedPreferences`, daemon install/reload | `manage-daemon` | `auth_admin` |
| `InstallUpdate` | `update-install` | `auth_admin` |
| `SetConnectAtBoot` | `connect-at-boot` | `auth_admin` |
| `ArmKillSwitch`, `RecoverNetwork` | `killswitch` | **yes** (lenient, so a user can always restore their own network) |

A forced (admin) preference may relax `install-config` to `yes` for configurations
the daemon classifies as *safe* — expressed as a polkit `.rules` file, never by
weakening the `.policy` defaults.

## Known constraints carried from the open questions

* **Connect-at-boot** (`SetConnectAtBoot`) only applies to configurations with no
  saved password (cert-only / root-readable creds), because no user keyring exists
  before login. Until the boot-credential policy is finalized this stays
  conditional.
* **No polkit agent** (headless/SSH/container): `connect`/`killswitch`
  (`allow_active=yes`) still work; admin-gated methods fail with a clear error
  rather than hanging. Final fallback behavior is an open question.
