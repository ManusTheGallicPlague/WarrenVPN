#!/usr/bin/env bash
# Smoke test for warrenvpnctl against a session-bus daemon + fake openvpn.
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WORK="$(mktemp -d /tmp/warrenvpn-cli.XXXXXX)"
trap 'kill "${DPID:-0}" 2>/dev/null || true; rm -rf "$WORK"' EXIT

export WARRENVPND_BUS=session WARRENVPN_BUS=session WARRENVPND_INSECURE_ALLOW_ALL=1
export WARRENVPND_STATE_DIR="$WORK/state" WARRENVPND_RUNTIME_DIR="$WORK/run"
export WARRENVPND_OPENVPN_PATH="$ROOT/scripts/fake-openvpn.py"
CTL="$ROOT/target/debug/warrenvpnctl"

cat > "$WORK/Office.ovpn" <<'EOF'
client
dev tun
remote vpn.example.com 1194
EOF

"$ROOT/target/debug/warrenvpnd" >"$WORK/d.log" 2>&1 & DPID=$!
for _ in $(seq 1 50); do busctl --user status net.warrenvpn.WarrenVPN1 >/dev/null 2>&1 && break; sleep 0.1; done

echo "== import =="; "$CTL" import "$WORK/Office.ovpn" Office
echo "== list =="; "$CTL" list
echo "== connect =="; "$CTL" connect Office
echo "== status =="; "$CTL" status
echo "== disconnect =="; "$CTL" disconnect Office
echo "DONE"
