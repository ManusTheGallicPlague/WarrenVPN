#!/usr/bin/env bash
# End-to-end test of the username/password auth flow using a fake openvpn that
# queries credentials over the management interface. No root, no real VPN.
# Run via:  dbus-run-session -- bash scripts/smoke-auth.sh
set -uo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN="$ROOT/target/debug/warrenvpnd"
WORK="$(mktemp -d /tmp/warrenvpn-auth.XXXXXX)"
trap 'kill "${DPID:-0}" 2>/dev/null || true; rm -rf "$WORK"' EXIT

export WARRENVPND_BUS=session
export WARRENVPND_INSECURE_ALLOW_ALL=1
export WARRENVPND_STATE_DIR="$WORK/state"
export WARRENVPND_RUNTIME_DIR="$WORK/run"
export WARRENVPND_OPENVPN_PATH="$ROOT/scripts/fake-openvpn-auth.py"
export WARRENVPN_AUTH_OUT="$WORK/auth.out"

SVC=net.warrenvpn.WarrenVPN1
OBJ=/net/warrenvpn/WarrenVPN1
MGR=net.warrenvpn.WarrenVPN1.Manager
CONN_IF=net.warrenvpn.WarrenVPN1.Connection

cat > "$WORK/work.ovpn" <<'EOF'
client
dev tun
remote vpn.example.com 1194
auth-user-pass
EOF

echo "== start daemon =="
"$BIN" >"$WORK/warrenvpnd.log" 2>&1 &
DPID=$!
for _ in $(seq 1 50); do busctl --user status "$SVC" >/dev/null 2>&1 && break; sleep 0.1; done

ID=$(busctl --user call "$SVC" "$OBJ" "$MGR" InstallConfig sssa{sv} work "$(cat "$WORK/work.ovpn")" private 0 | sed -E 's/^s "([^"]+)".*/\1/')
CPATH=$(busctl --user call "$SVC" "$OBJ" "$MGR" StartConnection sa{sv} "$ID" 0 | sed -E 's/^o "([^"]+)".*/\1/')
echo "  connection=$CPATH"

# Wait for the daemon to receive the PASSWORD request and record pending auth.
sleep 1

echo "== ProvideCredentials =="
busctl --user call "$SVC" "$CPATH" "$CONN_IF" ProvideCredentials sa{sv} auth-user-pass 2 username s alice password s s3cret

# Wait for the fake to verify the creds and report CONNECTED.
sleep 1

STATE=$(busctl --user get-property "$SVC" "$CPATH" "$CONN_IF" State | sed -E 's/^s "([^"]*)".*/\1/')
echo "== State=$STATE =="
echo "== credentials the daemon sent (recorded by fake openvpn) =="
cat "$WORK/auth.out" 2>/dev/null || echo "(none recorded)"

echo ""
FAIL=0
grep -qx 'username "Auth" "alice"' "$WORK/auth.out" 2>/dev/null || { echo "FAIL: username not sent correctly"; FAIL=1; }
grep -qx 'password "Auth" "s3cret"' "$WORK/auth.out" 2>/dev/null || { echo "FAIL: password not sent correctly"; FAIL=1; }
[ "$STATE" = "CONNECTED" ] || { echo "FAIL: expected CONNECTED after auth, got '$STATE'"; FAIL=1; }
if [ "$FAIL" = 0 ]; then echo "ALL AUTH CHECKS PASSED"; else exit 1; fi
