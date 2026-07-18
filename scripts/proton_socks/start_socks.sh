#!/usr/bin/env bash
# Start Proton WireGuard as userspace local SOCKS (no Proton VPN app, no system-wide tunnel).
# Requires: tunmux with `connect wgconf --local-proxy` (defaults: socks5://127.0.0.1:1080).
set -euo pipefail

export PATH="${HOME}/.cargo/bin:${PATH:-/usr/bin:/bin}"

CONF="${LOGOSCYBER_PROTON_CONF:-$HOME/Library/Application Support/LogosCyber/proton.conf}"
LOG_DIR="${LOGOSCYBER_SOCKS_LOG_DIR:-$HOME/Library/Logs/LogosCyber}"
mkdir -p "$(dirname "$CONF")" "$LOG_DIR"

if [[ ! -f "$CONF" ]]; then
  echo "Missing WireGuard conf: $CONF" >&2
  echo "See docs/PROTON_SOCKS.md (account.protonvpn.com → Downloads → WireGuard configuration)." >&2
  exit 1
fi

if ! command -v tunmux >/dev/null 2>&1; then
  echo "tunmux not found in PATH." >&2
  echo "Install (HTTPS submodule workaround):" >&2
  echo "  git clone https://github.com/CaddyGlow/tunmux.git /tmp/tunmux-src && cd /tmp/tunmux-src" >&2
  echo "  git config -f .gitmodules submodule.third_party/smoltcp.url https://github.com/CaddyGlow/smoltcp.git" >&2
  echo "  git submodule sync && git submodule update --init --recursive" >&2
  echo "  cargo install --path . --locked" >&2
  exit 1
fi

# Prefer disconnecting prior wgconf instances so port 1080 stays stable.
tunmux disconnect --provider wgconf --all >/dev/null 2>&1 || true

echo "Starting LogosCyber-only Proton SOCKS (typical: socks5://127.0.0.1:1080)…"
echo "Keep this terminal open. Browser / other apps are NOT routed through this."

# Newer tunmux: --local-proxy only (ports default to 1080 / 8118).
exec tunmux connect wgconf \
  --file "$CONF" \
  --local-proxy
