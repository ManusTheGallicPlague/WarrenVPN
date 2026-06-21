# Decisions & open questions

## Decided (2026-06-17)

1. **Connection backend = own privileged daemon driving OpenVPN directly** via its
   management interface. Rationale: the NetworkManager-openvpn plugin hides the
   management channel and kills interactive auth, SSO/WEB_AUTH, PKCS#11, live
   stats, custom up/down hooks and per-config OpenVPN version selection — all
   required for full parity. Firm commitment, not revisitable without dropping
   parity.
2. **GUI toolkit = GTK4 + libadwaita.** (Caveat: GNOME has no native tray — needs
   the AppIndicator extension; tray-vs-main-window policy on GNOME is still open.)
3. **Primary packaging = native packages** (.deb / .rpm / Arch AUR). Full privilege
   story (systemd unit + polkit policy + `/etc` forced-prefs). AppImage/Flatpak are
   secondary and reduced-capability.
4. **OpenVPN/OpenSSL = full bundled matrix** (multi-version × multi-OpenSSL, with
   the scramble patch and old-server support, per-config version selection). Chosen
   for maximum parity; **accepts a permanent CVE-tracking obligation** across 3
   OpenSSL branches × 2 architectures (tracked risk).

## Still open (must be resolved before claiming parity — see ARCHITECTURE doc §8)

- **Product name / brand** → drives the app-id and all identity namespaces.
- Per-connect re-authorization policy (polkit `connect` allow_active vs prompt).
- Connect-at-boot before login (needs root-readable creds or cert-only configs).
- Two-key update forgery model for AppImage.
- GNOME tray policy (require AppIndicator extension / bundle one / main-window
  fallback).
- systemd as a hard requirement vs. resolvconf/raw fallback parity.
- Scope cuts: SMB/WINS/NetBIOS, TAP/bridged + DHCP-lease machinery, the 5 numbered
  DNS script variants, SSD "secure erase" in the uninstaller.
- Enterprise forced-preferences depth (a `/etc` policy file vs. full MDM tooling).
- Privacy: public-IP check default-on/off and self-hosted vs. a public IP-echo endpoint.
- openvpn as full root vs. an unprivileged worker with only `CAP_NET_ADMIN`.
- Behavior with no polkit agent (headless/SSH/container).

## Security notes discovered while porting (TCB)

The OpenVPN config parser is the highest-risk component: its safe/unsafe verdict
decides whether a configuration may launch OpenVPN **as root** without an admin
prompt. While porting `ConfigurationParser.m` we found and addressed:

1. **Quoting/escape evasion of the unsafe-option check.** Upstream keeps quote and
   backslash characters in the token and compares the *raw* token against the
   unsafe list. OpenVPN strips them, so `"up" /evil`, `'plugin' …`, `u\p …` parse
   as the unsafe options `up`/`plugin` (running code as root) yet would not match
   the raw list. Our classifier compares the **normalized** option name
   (`unquote()`), closing the gap. Covered by tests.
   - `unquote()` is an approximation of OpenVPN's `parse_line()` and still needs a
     byte-level cross-check against OpenVPN's real lexer — tracked as a TCB audit
     gate (`TODO(tcb-audit)`).
2. **`dns-updown` over-conservative bug.** Upstream's `containsDnsUpdownCommand`
   compares an array against a string, so it flags every `dns-updown` (even the
   safe `force`/`disable` forms) as a command. We implement the documented intent
   (check the first parameter); still safe for genuine commands.
3. **Missing comma in the SAFE list** (`defines.h`) concatenated
   `ifconfig-pool` + `ifconfig-push-constraint` into one bogus token. Split back
   into two correct entries.

### Pending TCB hardening (before the verdict gates a real privilege decision)

- `cargo fuzz` target over `Config::parse` + `is_safe` (no panics; differential
  check vs. OpenVPN's parser where feasible).
- Independent review of `unquote()` vs. OpenVPN `options.c::parse_line()`.
- The daemon MUST re-run this classifier server-side and never trust the GUI.

## Adversarial privilege/packaging review (2026-06-17)

A multi-agent review (5 lenses + refute-by-default verification) of the privilege
+ packaging surface produced 30 findings. **Fixed:**

- **Per-caller store scoping.** The daemon now derives the store root from the
  *authenticated* caller uid (`GetConnectionUnixUser`), not its own (root) uid, and
  `ListConfigs`/`GetSanitizedConfig`/`StartConnection` are scoped per caller — closing
  unauthenticated cross-user config disclosure and passwordless cross-user connect.
- **Content-based `InstallConfig`.** The client sends config *bytes* (read as the
  user); the daemon never opens a caller-controlled path as root (kills an
  arbitrary-file-read-as-root vector and lets `ProtectHome=yes` stay).
- **Connect-time defense in depth.** `StartConnection` re-derives safe/unsafe from
  the on-disk bytes and gates safe configs with `connect` (passwordless) but unsafe
  ones with a new `connect-unsafe` action (admin) — so an unsafe config can never
  reach a passwordless root path even if install is later relaxed.
- **`config_id` validation** (`is_valid_id`: exactly 32 lowercase hex) at the store
  boundary — kills path traversal via `Path::join`.
- **`--script-security 1`** forced for safe configs (independent of the classifier).
- **systemd:** removed unjustified `CAP_SYS_ADMIN`; corrected the idle-exit comment.
- **Packaging:** ship + install the GPLv2 `COPYING`; `/etc/warrenvpn` declared in
  tmpfiles; absolute paths in the install scriptlet.
- **Polkit bypass** (`WARRENVPND_INSECURE_ALLOW_ALL`) compiled out of release builds
  (`cfg(debug_assertions)`).

**Deferred (tracked):** audit `UNSAFE`/`WINDOWS_ONLY` lists + `unquote()` against
OpenVPN 2.6-on-Linux (the big TCB audit above); clean-room AUR PKGBUILD with a
versioned source; `DeviceAllow=/dev/net/tun` + man page + branded icon; idle-exit
implementation. **Verified sound (no change):** D-Bus bus policy, sysusers/tmpfiles
invocation, `--locked`, the `-debug` subpackage. CAP_SETUID/CAP_SETGID were **kept**
(the OpenVPN child needs them to honour its own `user`/`group` privilege-drop).

## Phase 1 completion (2026-06-18): DNS, tray, signal-driven GUI

- **DNS via systemd-resolved.** `warrenvpn_core::dns` parses OpenVPN's pushed
  `dhcp-option` values (unit-tested) and resolves the tun link index from
  `/sys/class/net`. A shipped, root-owned trusted up/down helper
  (`packaging/scripts/warrenvpn-updown`) captures `dev` + `foreign_option_*` to a file;
  the daemon reads it on `CONNECTED` and applies DNS via `org.freedesktop.resolve1`
  (`warrenvpnd/src/dns.rs`: SetLinkDNS/SetLinkDomains/SetLinkDefaultRoute), reverting on
  teardown. End-to-end DNS needs a real tun + running resolved, so it is not covered
  by the in-repo smoke tests (the parser + ifindex lookup are).
  - **Security trade-off (documented):** the up/down helper needs
    `--script-security 2`, which is enabled **only for safe configs** (whose
    classification guarantees no user scripts, so the only script that runs is ours)
    and **only when the helper is installed**; otherwise safe configs keep
    `--script-security 1`. This re-couples DNS to the UNSAFE-list completeness audit
    (already tracked). Unsafe (admin-approved) configs are launched without our
    injection and manage their own DNS.
- **Tray.** `warrenvpn-gui` registers a StatusNotifierItem via `ksni` (menu: open /
  quit; activate → show window). Closing the window hides to tray; the app holds
  itself alive; Quit exits. (GNOME still needs the AppIndicator extension to show
  it.)
- **Signal-driven refresh.** A background thread listens for the daemon's
  `net.warrenvpn.WarrenVPN1.Manager` signals and nudges the GTK loop via an
  `async-channel`; a 2 s poll remains as a fallback for intermediate state
  transitions. (Full PropertiesChanged-driven updates can replace the poll later.)

**Deferred (tracked):** launching OpenVPN in a transient systemd scope — kept as a
direct spawn (`TODO(scope)` in `connection.rs`) because the scope path needs
root + `systemd-run` and cannot be exercised in the dev/test environment, while the
direct spawn is functionally complete and is what the smoke tests verify.

## Phase 2 (2026-06-18): interactive authentication — username/password + passphrase

- `warrenvpn_core::management` now parses the `>PASSWORD:` prompt (realm, needs-username,
  failed) and builds quoted/escaped `username`/`password` reply commands.
  `escape_mgmt_value` is a security invariant (prevents argument injection via a
  quote/backslash in a password) and is unit-tested.
- The daemon records the pending realm per connection, emits a richer `AuthRequest`
  (kind, realm, prompt), and `Connection.ProvideCredentials` writes the escaped
  replies to the management socket.
- The GUI's signal listener turns `AuthRequest` into a modal credential dialog
  (AdwMessageDialog + entry rows) that calls `ProvideCredentials`.
- **Verified end-to-end** by `scripts/smoke-auth.sh` + `scripts/fake-openvpn-auth.py`:
  a fake openvpn queries credentials, and the test asserts the daemon sends back
  exactly `username "Auth" "alice"` / `password "Auth" "s3cret"` and the connection
  reaches CONNECTED.

## Phase 3 (2026-06-18): nftables kill-switch

- `warrenvpn_core::killswitch::build_ruleset` generates a dedicated `inet warrenvpn` table
  with an `output` chain, `policy drop`, allowing only loopback, the tun device, the
  VPN server endpoint (family-correct, from `trusted_ip`/`trusted_port`/`proto`), and
  DHCP/DHCPv6 renewals. Because the table is `inet` + default-drop, non-tunnel IPv6
  is dropped (closes the IPv6 leak). Atomic create/delete/create install; interface
  name validated against injection. Unit-tested as a string (kernel apply needs root,
  so not exercised in-repo; `nft -c` also needs CAP_NET_ADMIN).
- The trusted up helper now also captures `trusted_ip(6)`/`trusted_port`/`proto`. The
  daemon arms the kill-switch on first CONNECTED (when `StartConnection` is passed
  `killswitch=true`) and, on teardown, **disarms only on an expected disconnect** —
  an unexpected drop keeps egress blocked until the user reconnects or calls
  `RecoverNetwork` (the `-ku` behavior). `Manager.RecoverNetwork` (polkit `killswitch`,
  lenient) tears it down and works with no active connection.
- A boot-time `warrenvpn-recover.service` (enabled by the package) idempotently clears a
  stale table left by a crash, so the kill-switch can never strand the machine; the
  uninstaller does the same.

### Kill-switch adversarial review fixes (2026-06-18)

A multi-lens review found the ruleset sound but the *lifecycle* fail-open in several
ways. Applied:
- **Daemon-level reference-counted manager** (`warrenvpnd::killswitch::KillSwitch`): the
  singleton `inet warrenvpn` table now installs the UNION of every armed tunnel's
  device+endpoint. Disarming one connection rebuilds the union and tears the table
  down only when the last armed tunnel exits — it can never open another live
  tunnel's protection.
- **FORWARD chain** added (drop policy, allow only tun + established/related), so
  Docker/VM/routed egress is also blocked while armed.
- **Re-arm on every CONNECTED** (not just the first), so a reconnect to a different
  server IP / tun device self-heals instead of being stranded.
- **Fail-closed**: a requested kill-switch that cannot be armed (no endpoint, nft
  failure) tears the connection down instead of running unprotected; `StartConnection`
  rejects `killswitch=true` up front when `nft` is absent; `Probe` reports
  `killswitch_available`.
- **Boot ordering**: `warrenvpn-recover.service` is `Before=warrenvpnd.service` so recovery
  never clears a freshly-armed kill-switch.

**Queued (tracked):** pre-connect protection (arm a connect-phase ruleset before
spawning OpenVPN, resolving `remote` hostnames — closes the connect-window + endpoint
DNS leak); daemon-restart adoption of an orphaned table (needs the transient systemd
scope); treat a DNS-apply failure as fatal when kill-switch is on; pin the
server-allow + DHCP rules to the physical interface; expose kill-switch state on the
connection object + a GUI per-config toggle.

## Final review resolved — v1 release-ready (2026-06-18)

The comprehensive final review (38 findings, 10 serious) is fully addressed. All
**6 mustFix** are fixed and verified:
1. Per-connection authorization (owner-uid check on Disconnect/ProvideCredentials;
   ListConnections scoped per caller) — closed cross-user hijack.
2. Kill-switch protects the connect window (connect-phase lockdown armed before
   OpenVPN spawns; fail-closed if unarmable; tunnel-locked on CONNECTED).
3. Package upgrade no longer restarts the daemon (would kill live tunnels).
4. SSO/web-auth URLs restricted to http(s).
5. GUI no longer repopulates on the LogLine storm (no main-thread jank).
6. CLI subscribes before StartConnection (no hang) + path-filters the stream.

Key **shouldFix** also done: DNS-apply failure is fatal under kill-switch;
warrenvpn-updown strips CR/LF + first-write-wins env keys; openvpn `kill_on_drop`;
absolute `nft` path; sandbox tidy (/etc/warrenvpn RW, dropped resolv.conf + @mount).

74 tests, clippy clean, all smoke tests pass.

### Deliberately deferred backlog (post-v1 polish / future phases)

Not release blockers (the review classified these as `consider` or lower):
transient systemd scope + AdoptRunningConnections (tunnels survive a daemon
restart) and idle-exit; daemon-driven reconnect + sleep/wake (logind PrepareForSleep)
— OpenVPN ping-restart covers the common case today; PKCS#11 PIN + CR_TEXT auth;
polkit `unix-process` pinned subject; finish the `unquote()` vs OpenVPN `parse_line()`
audit + the real Linux WINDOWS_ONLY set; trim the D-Bus XML to the implemented method
set (or implement MoveConfig/RemoveConfig/SetForcedPreferences/InstallUpdate/
SetConnectAtBoot/ArmKillSwitch); bounded management line read; GUI connect spinner;
pin kill-switch server-allow to the physical iface; clean-room AUR PKGBUILD; full
i18n; man page for warrenvpnd already shipped.

## Remaining Phase 2 (historical, now largely done — see above)

**(historical):** credential persistence via the Secret Service
("save password", auto-fill on reconnect, credential groups); static (SCRV1) and
dynamic (CRV1) challenge/response; CR_TEXT; WEB_AUTH browser SSO; PKCS#11/smart-card
PIN; auth-token handling; sleep/wake + shutdown disconnect/reconnect (logind).
