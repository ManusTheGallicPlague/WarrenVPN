#!/usr/bin/env bash
# Smoke test for warrenvpnd on a private session bus (no root, no openvpn needed).
# Run via:  dbus-run-session -- bash scripts/smoke-warrenvpnd.sh
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN="$ROOT/target/debug/warrenvpnd"
WORK="$(mktemp -d /tmp/warrenvpn-smoke.XXXXXX)"
trap 'kill "${DPID:-0}" 2>/dev/null || true; rm -rf "$WORK"' EXIT

export WARRENVPND_BUS=session
export WARRENVPND_INSECURE_ALLOW_ALL=1
export WARRENVPND_STATE_DIR="$WORK/state"
export WARRENVPND_RUNTIME_DIR="$WORK/run"

SVC=net.warrenvpn.WarrenVPN1
OBJ=/net/warrenvpn/WarrenVPN1
IF=net.warrenvpn.WarrenVPN1.Manager

# --- sample configs ---
cat > "$WORK/work.ovpn" <<'EOF'
client
dev tun
proto udp
remote vpn.example.com 1194
ca ca.crt
<key>
SUPER SECRET PRIVATE KEY MATERIAL
</key>
auth-user-pass
EOF

cat > "$WORK/sketchy.ovpn" <<'EOF'
client
dev tun
up /tmp/evil.sh
EOF

echo "== starting warrenvpnd =="
"$BIN" &
DPID=$!
# wait for the name to appear on the bus
for _ in $(seq 1 50); do
  if busctl --user status "$SVC" >/dev/null 2>&1; then break; fi
  sleep 0.1
done

echo "== GetVersion =="
busctl --user call "$SVC" "$OBJ" "$IF" GetVersion

echo "== Probe =="
busctl --user call "$SVC" "$OBJ" "$IF" Probe

echo "== InstallConfig (safe) =="
ID_SAFE=$(busctl --user call "$SVC" "$OBJ" "$IF" InstallConfig sssa{sv} work "$(cat "$WORK/work.ovpn")" private 0 \
          | sed -E 's/^s "([^"]+)".*/\1/')
echo "  -> id=$ID_SAFE"

echo "== InstallConfig (unsafe) =="
ID_UNSAFE=$(busctl --user call "$SVC" "$OBJ" "$IF" InstallConfig sssa{sv} sketchy "$(cat "$WORK/sketchy.ovpn")" private 0 \
            | sed -E 's/^s "([^"]+)".*/\1/')
echo "  -> id=$ID_UNSAFE"

echo "== ListConfigs (expect one safe=true, one safe=false) =="
busctl --user call "$SVC" "$OBJ" "$IF" ListConfigs

echo "== GetSanitizedConfig (safe one; key block must be stripped) =="
busctl --user call "$SVC" "$OBJ" "$IF" GetSanitizedConfig s "$ID_SAFE"

echo "== verifying secret is NOT present in sanitized output =="
OUT=$(busctl --user call "$SVC" "$OBJ" "$IF" GetSanitizedConfig s "$ID_SAFE")
if echo "$OUT" | grep -q "SUPER SECRET"; then
  echo "FAIL: secret leaked in sanitized config"; exit 1
else
  echo "OK: secret stripped"
fi

echo ""
echo "ALL SMOKE CHECKS PASSED"
