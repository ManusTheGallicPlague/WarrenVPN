# WarrenVPN — repository guide

WarrenVPN is a full-featured OpenVPN GUI for the Linux desktop. Rust workspace;
GTK4 GUI; a polkit-gated D-Bus system daemon that drives OpenVPN directly via its
management interface.

## Build / test / lint

```sh
cargo build                 # debug
cargo build --release       # release (what the package ships)
cargo test --workspace      # all unit tests
cargo clippy --workspace --all-targets   # keep clean — CI gate
```

The package: `cd packaging/arch && makepkg -fd` (builds the workspace + assembles
`warrenvpn-*.pkg.tar.zst`).

## Crates

- `ovpn-config` — OpenVPN config tokenizer/parser + safe/unsafe classifier. **TCB**:
  its verdict decides whether a config may run OpenVPN as root without an admin
  prompt. Hardened against quoted/escaped option-name evasion. Pure, heavily tested.
- `warrenvpn-common` — single source of truth for identity (app-id, D-Bus names, polkit
  action ids, filesystem paths). Rebrand = edit this + the `packaging/` templates.
- `warrenvpn-core` — transport-agnostic daemon logic: management-protocol parsing
  (incl. auth prompts, SCRV1), OpenVPN argv builder, root-owned shadow config store,
  pushed-DNS parsing, and the nftables kill-switch ruleset builder. Unit-tested.
- `warrenvpnd` — the privileged D-Bus system daemon (`net.warrenvpn.WarrenVPN1`). The only
  security boundary: polkit per method, server-side re-classification, per-caller
  store scoping, live `Connection` objects, DNS via systemd-resolved, kill-switch,
  logind shutdown handling.
- `warrenvpn-gui` — GTK4 + libadwaita front-end (`warrenvpn`): list/import/connect, live
  state, tray (StatusNotifierItem), credential dialog + libsecret persistence,
  per-config settings.
- `warrenvpn-cli` — `warrenvpnctl`: headless control (list/status/import/connect/
  disconnect/recover), with interactive terminal auth.

## Architecture & decisions

- `docs/ARCHITECTURE.md` — the WarrenVPN architecture, the privilege model, the
  feature checklist, roadmap, and risk register.
- `docs/IPC-CONTRACT.md` — the D-Bus privilege/automation contract + daemon TCB rules.
- `docs/DECISIONS.md` — decisions, open questions, and the adversarial-review fixes.

## Local dev harness (no root, no real VPN)

The daemon and clients run on a private session bus with a Python fake OpenVPN, so
the full flow is exercised without root or a server:

```sh
dbus-run-session -- bash scripts/smoke-warrenvpnd.sh   # config install/classify/sanitize
dbus-run-session -- bash scripts/smoke-connect.sh    # connect lifecycle + live state
dbus-run-session -- bash scripts/smoke-auth.sh       # username/password auth
dbus-run-session -- bash scripts/smoke-sc.sh         # static challenge (SCRV1)
dbus-run-session -- bash scripts/smoke-cli.sh        # warrenvpnctl end-to-end
bash scripts/demo-gui.sh                              # launch GUI + grim screenshot
```

Dev env vars: `WARRENVPND_BUS=session` / `WARRENVPN_BUS=session` (use the session bus),
`WARRENVPND_STATE_DIR` / `WARRENVPND_RUNTIME_DIR` (relocate state),
`WARRENVPND_OPENVPN_PATH` (point at a fake/specific openvpn),
`WARRENVPND_INSECURE_ALLOW_ALL=1` (bypass polkit — **debug builds only**, compiled out
of release).

## Conventions

- Keep `cargo clippy` warning-free.
- The daemon must never trust the client: re-parse/re-classify configs server-side,
  authorize every privileged method via polkit, scope per authenticated caller uid.
- Security-relevant invariants (the parser, `unquote`, `escape_mgmt_value`, the
  shadow-store atomic writes, the kill-switch ruleset) are unit-tested; add a test
  when you touch them.
