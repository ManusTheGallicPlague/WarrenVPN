#!/usr/bin/env bash
# Launch warrenvpnd + the GUI on the real session bus/display and screenshot the GUI.
set -uo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN="$ROOT/target/debug"
WORK="$(mktemp -d /tmp/warrenvpn-demo.XXXXXX)"
SHOT="${1:-$ROOT/warrenvpn-gui-screenshot.png}"

export WARRENVPND_BUS=session
export WARRENVPND_INSECURE_ALLOW_ALL=1
export WARRENVPND_STATE_DIR="$WORK/state"
export WARRENVPND_RUNTIME_DIR="$WORK/run"
export WARRENVPND_OPENVPN_PATH="$ROOT/scripts/fake-openvpn.py"

SVC=net.warrenvpn.WarrenVPN1
OBJ=/net/warrenvpn/WarrenVPN1
MGR=net.warrenvpn.WarrenVPN1.Manager

cleanup() { kill "${GPID:-0}" "${DPID:-0}" 2>/dev/null || true; rm -rf "$WORK"; }
trap cleanup EXIT

echo "== start daemon =="
"$BIN/warrenvpnd" >"$WORK/warrenvpnd.log" 2>&1 &
DPID=$!
for _ in $(seq 1 50); do busctl --user status "$SVC" >/dev/null 2>&1 && break; sleep 0.1; done

cat > "$WORK/Work VPN.ovpn" <<'EOF'
client
dev tun
remote vpn.example.com 1194
auth-user-pass
EOF
cat > "$WORK/Home.ovpn" <<'EOF'
client
dev tun
remote home.example.net 1194
EOF

echo "== install two configs =="
ID1=$(busctl --user call "$SVC" "$OBJ" "$MGR" InstallConfig sssa{sv} "Work VPN" "$(cat "$WORK/Work VPN.ovpn")" private 0 | sed -E 's/^s "([^"]+)".*/\1/')
busctl --user call "$SVC" "$OBJ" "$MGR" InstallConfig sssa{sv} Home "$(cat "$WORK/Home.ovpn")" private 0 >/dev/null

echo "== connect the first one =="
busctl --user call "$SVC" "$OBJ" "$MGR" StartConnection sa{sv} "$ID1" 0 >/dev/null || echo "start failed"

echo "== launch GUI =="
export WARRENVPN_BUS=session
"$BIN/warrenvpn" >"$WORK/gui.log" 2>&1 &
GPID=$!
sleep 3

echo "== screenshot -> $SHOT =="
if grim "$SHOT" 2>"$WORK/grim.log"; then
  echo "grim OK"; ls -l "$SHOT"
else
  echo "grim FAILED:"; cat "$WORK/grim.log"
fi

echo "== gui.log =="; cat "$WORK/gui.log"
echo "== warrenvpnd.log (tail) =="; tail -5 "$WORK/warrenvpnd.log"
