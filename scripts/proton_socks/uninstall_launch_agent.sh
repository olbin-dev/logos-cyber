#!/usr/bin/env bash
# Remove LaunchAgent for Proton local SOCKS.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
PLIST_ID="com.olbin.logoscyber.proton-socks"
PLIST_DST="$HOME/Library/LaunchAgents/${PLIST_ID}.plist"

launchctl bootout "gui/$(id -u)/${PLIST_ID}" >/dev/null 2>&1 || true
rm -f "$PLIST_DST"

"$ROOT/scripts/proton_socks/stop_socks.sh" || true

echo "Uninstalled LaunchAgent: ${PLIST_ID}"
