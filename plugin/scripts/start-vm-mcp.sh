#!/usr/bin/env sh
set -eu

ROOT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)"

if [ "${VM_MCP_SERVER_CMD:-}" != "" ]; then
  exec sh -c "$VM_MCP_SERVER_CMD"
fi

if command -v vm-mcp-server >/dev/null 2>&1; then
  exec vm-mcp-server
fi

if [ -x "$ROOT_DIR/.venv/bin/vm-mcp-server" ]; then
  exec "$ROOT_DIR/.venv/bin/vm-mcp-server"
fi

if command -v python3 >/dev/null 2>&1; then
  if [ -d "$ROOT_DIR/src" ]; then
    export PYTHONPATH="$ROOT_DIR/src${PYTHONPATH:+:$PYTHONPATH}"
  fi
  exec python3 -m vm_mcp.mcp_server
fi

echo "vm-mcp: unable to start server (missing vm-mcp-server/.venv/python3)" >&2
exit 1
