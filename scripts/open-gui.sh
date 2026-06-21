#!/usr/bin/env bash
# Open WarrenVPN live on the desktop (dev mode: session bus, no root) with the daemon,
# two sample configs pre-imported, and a fake openvpn so connect/disconnect work
# without a real server. Keeps running (GUI in foreground) until killed.
set -uo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN="$ROOT/target/debug"
WORK=/tmp/warrenvpn-live
mkdir -p "$WORK"

export WARRENVPND_BUS=session WARRENVPN_BUS=session WARRENVPND_INSECURE_ALLOW_ALL=1
export WARRENVPND_STATE_DIR="$WORK/state" WARRENVPND_RUNTIME_DIR="$WORK/run"
export WARRENVPND_OPENVPN_PATH="$ROOT/scripts/fake-openvpn.py"

SVC=net.warrenvpn.WarrenVPN1
OBJ=/net/warrenvpn/WarrenVPN1
MGR=net.warrenvpn.WarrenVPN1.Manager

# Start the daemon.
"$BIN/warrenvpnd" >"$WORK/warrenvpnd.log" 2>&1 &
for _ in $(seq 1 50); do busctl --user status "$SVC" >/dev/null 2>&1 && break; sleep 0.1; done

# Pre-import two sample configurations (idempotent-ish: only if none exist yet).
if [ "$(busctl --user call "$SVC" "$OBJ" "$MGR" ListConfigs 2>/dev/null)" = "a(ssb) 0" ]; then
  printf 'client\ndev tun\nremote vpn.example.com 1194\nauth-user-pass\n' > "$WORK/Ufficio.ovpn"
  printf 'client\ndev tun\nremote casa.example.net 1194\n' > "$WORK/Casa.ovpn"
  busctl --user call "$SVC" "$OBJ" "$MGR" InstallConfig sssa{sv} Ufficio "$(cat "$WORK/Ufficio.ovpn")" private 0 >/dev/null 2>&1
  busctl --user call "$SVC" "$OBJ" "$MGR" InstallConfig sssa{sv} Casa "$(cat "$WORK/Casa.ovpn")" private 0 >/dev/null 2>&1
fi

# Launch the GUI in the foreground so this script stays alive with it.
exec "$BIN/warrenvpn" >"$WORK/gui.log" 2>&1
