#!/usr/bin/env bash
# End-to-end test of the connect path using a fake openvpn (no root, no VPN server).
# Run via:  dbus-run-session -- bash scripts/smoke-connect.sh
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN="$ROOT/target/debug/warrenvpnd"
FAKE="$ROOT/scripts/fake-openvpn.py"
WORK="$(mktemp -d /tmp/warrenvpn-connect.XXXXXX)"
trap 'kill "${DPID:-0}" 2>/dev/null || true; rm -rf "$WORK"' EXIT

export WARRENVPND_BUS=session
export WARRENVPND_INSECURE_ALLOW_ALL=1
export WARRENVPND_STATE_DIR="$WORK/state"
export WARRENVPND_RUNTIME_DIR="$WORK/run"
export WARRENVPND_OPENVPN_PATH="$FAKE"

SVC=net.warrenvpn.WarrenVPN1
OBJ=/net/warrenvpn/WarrenVPN1
MGR=net.warrenvpn.WarrenVPN1.Manager
CONN_IF=net.warrenvpn.WarrenVPN1.Connection

cat > "$WORK/work.ovpn" <<'EOF'
client
dev tun
proto udp
remote vpn.example.com 1194
auth-user-pass
EOF

echo "== starting warrenvpnd =="
"$BIN" &
DPID=$!
for _ in $(seq 1 50); do
  busctl --user status "$SVC" >/dev/null 2>&1 && break
  sleep 0.1
done

echo "== InstallConfig =="
ID=$(busctl --user call "$SVC" "$OBJ" "$MGR" InstallConfig sssa{sv} work "$(cat "$WORK/work.ovpn")" private 0 \
     | sed -E 's/^s "([^"]+)".*/\1/')
echo "  id=$ID"

echo "== StartConnection =="
CPATH=$(busctl --user call "$SVC" "$OBJ" "$MGR" StartConnection sa{sv} "$ID" 0 \
        | sed -E 's/^o "([^"]+)".*/\1/')
echo "  connection object=$CPATH"

# Give the relay a moment to read the management notifications.
sleep 1

echo "== ListConnections =="
busctl --user call "$SVC" "$OBJ" "$MGR" ListConnections

echo "== Connection State =="
STATE=$(busctl --user get-property "$SVC" "$CPATH" "$CONN_IF" State | sed -E 's/^s "([^"]*)".*/\1/')
echo "  State=$STATE"

echo "== Connection BytesIn / BytesOut =="
BIN_=$(busctl --user get-property "$SVC" "$CPATH" "$CONN_IF" BytesIn | awk '{print $2}')
BOUT_=$(busctl --user get-property "$SVC" "$CPATH" "$CONN_IF" BytesOut | awk '{print $2}')
echo "  BytesIn=$BIN_ BytesOut=$BOUT_"

echo "== Disconnect (sends SIGTERM over management) =="
busctl --user call "$SVC" "$CPATH" "$CONN_IF" Disconnect

echo ""
FAIL=0
[ "$STATE" = "CONNECTED" ] || { echo "FAIL: expected State=CONNECTED, got '$STATE'"; FAIL=1; }
[ "$BIN_" = "1024" ] || { echo "FAIL: expected BytesIn=1024, got '$BIN_'"; FAIL=1; }
[ "$BOUT_" = "2048" ] || { echo "FAIL: expected BytesOut=2048, got '$BOUT_'"; FAIL=1; }
if [ "$FAIL" = 0 ]; then echo "ALL CONNECT CHECKS PASSED"; else exit 1; fi
