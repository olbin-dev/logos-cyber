#!/usr/bin/env bash
# Stop LogosCyber Proton local SOCKS (tunmux wgconf).
set -euo pipefail

if command -v tunmux >/dev/null 2>&1; then
  tunmux disconnect --provider wgconf --all || true
fi

# Best-effort: free default SOCKS port if something is still listening
SOCKS_PORT="${LOGOSCYBER_SOCKS_PORT:-1080}"
if command -v lsof >/dev/null 2>&1; then
  PIDS="$(lsof -nP -iTCP:"$SOCKS_PORT" -sTCP:LISTEN -t 2>/dev/null || true)"
  if [[ -n "${PIDS}" ]]; then
    # shellcheck disable=SC2086
    kill $PIDS 2>/dev/null || true
  fi
fi

echo "Proton local SOCKS stopped (best effort)."
