#!/usr/bin/env sh
set -eu

ROOT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)"

if [ "${PROXMCP_SERVER_CMD:-}" != "" ]; then
  exec sh -c "$PROXMCP_SERVER_CMD"
fi

if command -v proxmcp-server >/dev/null 2>&1; then
  exec proxmcp-server
fi

if [ -x "$ROOT_DIR/.venv/bin/proxmcp-server" ]; then
  exec "$ROOT_DIR/.venv/bin/proxmcp-server"
fi

if command -v python3 >/dev/null 2>&1; then
  if [ -d "$ROOT_DIR/src" ]; then
    export PYTHONPATH="$ROOT_DIR/src${PYTHONPATH:+:$PYTHONPATH}"
  fi
  exec python3 -m proxmcp.mcp_server
fi

echo "proxmcp: unable to start server (missing proxmcp-server/.venv/python3)" >&2
exit 1
