#!/usr/bin/env bash
# Install LaunchAgent so Proton local SOCKS starts at login.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
START_SCRIPT="$ROOT/scripts/proton_socks/start_socks.sh"
PLIST_ID="com.olbin.logoscyber.proton-socks"
PLIST_DST="$HOME/Library/LaunchAgents/${PLIST_ID}.plist"
LOG_DIR="$HOME/Library/Logs/LogosCyber"
CONF_DIR="$HOME/Library/Application Support/LogosCyber"

mkdir -p "$HOME/Library/LaunchAgents" "$LOG_DIR" "$CONF_DIR"
chmod +x "$START_SCRIPT" "$ROOT/scripts/proton_socks/stop_socks.sh" \
  "$ROOT/scripts/proton_socks/install_launch_agent.sh" \
  "$ROOT/scripts/proton_socks/uninstall_launch_agent.sh" 2>/dev/null || true

# Resolve tunmux into absolute path for LaunchAgent PATH stability
TUNMUX_BIN="$(command -v tunmux || true)"
if [[ -z "$TUNMUX_BIN" ]]; then
  echo "tunmux not found. Install first:" >&2
  echo "  cargo install --git https://github.com/CaddyGlow/tunmux tunmux" >&2
  exit 1
fi
TUNMUX_DIR="$(dirname "$TUNMUX_BIN")"
CARGO_BIN="${CARGO_HOME:-$HOME/.cargo}/bin"

cat > "$PLIST_DST" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>${PLIST_ID}</string>
  <key>ProgramArguments</key>
  <array>
    <string>/bin/bash</string>
    <string>${START_SCRIPT}</string>
  </array>
  <key>RunAtLoad</key>
  <true/>
  <key>KeepAlive</key>
  <true/>
  <key>WorkingDirectory</key>
  <string>${ROOT}</string>
  <key>EnvironmentVariables</key>
  <dict>
    <key>PATH</key>
    <string>${TUNMUX_DIR}:${CARGO_BIN}:/usr/local/bin:/opt/homebrew/bin:/usr/bin:/bin</string>
    <key>HOME</key>
    <string>${HOME}</string>
  </dict>
  <key>StandardOutPath</key>
  <string>${LOG_DIR}/proton-socks.out.log</string>
  <key>StandardErrorPath</key>
  <string>${LOG_DIR}/proton-socks.err.log</string>
</dict>
</plist>
EOF

launchctl bootout "gui/$(id -u)/${PLIST_ID}" >/dev/null 2>&1 || true
launchctl bootstrap "gui/$(id -u)" "$PLIST_DST"
launchctl enable "gui/$(id -u)/${PLIST_ID}" >/dev/null 2>&1 || true
launchctl kickstart -k "gui/$(id -u)/${PLIST_ID}" >/dev/null 2>&1 || true

echo "Installed LaunchAgent: $PLIST_DST"
echo "Place WireGuard conf at: $CONF_DIR/proton.conf"
echo "Logs: $LOG_DIR/proton-socks.*.log"
echo "SOCKS: socks5://127.0.0.1:1080"
