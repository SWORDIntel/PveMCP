#!/usr/bin/env bash

set -euo pipefail

usage() {
cat <<'EOF'
Usage:
  install-vm-mcp.sh [--repo PATH] [--client codex|gemini|both] [--no-pip] [--config-dir DIR]
  install-vm-mcp.sh [--install-service]
  install-vm-mcp.sh --uninstall [--client codex|gemini|both] [--config-dir DIR]
  install-vm-mcp.sh --uninstall [--client codex|gemini|both] [--config-dir DIR] --remove-service

Defaults:
  --repo "$(pwd)"
  --client both
  --install-service no
  --uninstall no
  --config-dir
    macOS: /Users/<you>/.codex
    Linux: /home/<you>/.codex
  --remove-service no (uninstall only)
EOF
}

resolve_service_execution() {
  SERVICE_EXEC_ENV=""
  SERVICE_EXEC_COMMAND=""
  SERVICE_EXEC_WORKDIR=""

  if [[ -n "${MCP_COMMAND}" ]]; then
    SERVICE_EXEC_COMMAND="${MCP_COMMAND}"
    return 0
  fi

  if command -v vm-mcp-server >/dev/null 2>&1; then
    SERVICE_EXEC_COMMAND="$(command -v vm-mcp-server)"
    return 0
  fi

  if [[ -x "${REPO_DIR}/.venv/bin/vm-mcp-server" ]]; then
    SERVICE_EXEC_COMMAND="${REPO_DIR}/.venv/bin/vm-mcp-server"
    return 0
  fi

  return 1
}

resolve_mcp_command() {
  if command -v vm-mcp-server >/dev/null 2>&1; then
    MCP_COMMAND="$(command -v vm-mcp-server)"
  elif [[ -x "${REPO_DIR}/.venv/bin/vm-mcp-server" ]]; then
    MCP_COMMAND="${REPO_DIR}/.venv/bin/vm-mcp-server"
  else
    MCP_COMMAND="vm-mcp-server"
  fi
}

write_client_config() {
  local target_path="$1"
  local transport="$2"

  "${PYTHON_BIN}" - "$target_path" "$MCP_COMMAND" "$transport" "$AUDIT_LOG" <<'PY'
import json
import sys
from pathlib import Path

target = Path(sys.argv[1])
command = sys.argv[2]
transport = sys.argv[3]
audit_log = sys.argv[4]

server = {
    "command": command,
    "args": [],
    "env": {
        "VM_MCP_AUDIT_LOG": audit_log,
        "VM_MCP_ALLOW_BREAK_GLASS": "1",
    },
}
if transport:
    server["transport"] = transport

target.parent.mkdir(parents=True, exist_ok=True)
target.write_text(
    json.dumps({"mcpServers": {"vm-mcp": server}}, indent=2) + "\n",
    encoding="utf-8",
)
PY
}

write_service_unit() {
  local target_path="$1"
  local exec_command="$2"
  local working_dir="$3"
  local extra_env="$4"

  cat > "${target_path}" <<EOF
[Unit]
Description=vm-mcp MCP server
After=network.target

[Service]
Type=simple
User=root
Environment=VM_MCP_AUDIT_LOG=${AUDIT_LOG}
Environment=VM_MCP_ALLOW_BREAK_GLASS=1
${extra_env}
ExecStart=${exec_command}
${working_dir:+WorkingDirectory=${working_dir}}
Restart=on-failure
RestartSec=5
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF
}

sync_codex_settings() {
  local settings_path="$1"
  local source_path="$2"

  "${PYTHON_BIN}" - "$settings_path" "$source_path" <<'PY'
import json
import sys
from pathlib import Path


settings_path = Path(sys.argv[1])
source_path = Path(sys.argv[2])

if not source_path.exists():
    raise FileNotFoundError(f"Cannot find source config: {source_path}")

source_cfg = json.loads(source_path.read_text(encoding="utf-8"))
source_servers = source_cfg.get("mcpServers", {})
source_server = source_servers.get("vm-mcp")
if not isinstance(source_server, dict):
    raise ValueError("Invalid source config: expected mcpServers.vm-mcp object")

if settings_path.exists():
    current_raw = settings_path.read_text(encoding="utf-8").strip()
    if current_raw:
        current = json.loads(current_raw)
        if not isinstance(current, dict):
            current = {}
    else:
        current = {}
else:
    current = {}

mcp_servers = current.setdefault("mcpServers", {})
if not isinstance(mcp_servers, dict):
    mcp_servers = {}
    current["mcpServers"] = mcp_servers

existing_server = mcp_servers.get("vm-mcp", {})
if not isinstance(existing_server, dict):
    existing_server = {}

merged_env = {}
merged_env.update(existing_server.get("env", {}))
merged_env.update(source_server.get("env", {}))

merged_server = dict(existing_server)
for key, value in source_server.items():
    if key == "env":
        continue
    merged_server[key] = value
merged_server["env"] = merged_env

mcp_servers["vm-mcp"] = merged_server

settings_path.parent.mkdir(parents=True, exist_ok=True)
settings_path.write_text(
    json.dumps(current, indent=2, sort_keys=True) + "\n",
    encoding="utf-8",
)
PY
}

cleanup_codex_settings() {
  local settings_path="$1"

  "${PYTHON_BIN}" - "$settings_path" <<'PY'
import json
import sys
from pathlib import Path

settings_path = Path(sys.argv[1])

if not settings_path.exists():
    print(f"No settings file at: {settings_path}")
    raise SystemExit(1)

raw = settings_path.read_text(encoding="utf-8").strip()
if not raw:
    print(f"Settings file is empty: {settings_path}")
    raise SystemExit(1)

data = json.loads(raw)
if not isinstance(data, dict):
    print(f"Invalid settings format: {settings_path}")
    raise SystemExit(1)

mcp_servers = data.get("mcpServers")
if not isinstance(mcp_servers, dict):
    print(f"No mcpServers block in settings: {settings_path}")
    raise SystemExit(1)

mcp_servers.pop("vm-mcp", None)
data["mcpServers"] = mcp_servers

settings_path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY
}

remove_systemd_service() {
  if [[ "$(uname -s)" != "Linux" ]]; then
    echo "systemd uninstall is only supported on Linux hosts."
    return 1
  fi

  if ! command -v systemctl >/dev/null 2>&1; then
    echo "systemctl not found; skipping systemd cleanup."
    return 0
  fi

  SUDO=""
  if [[ $(id -u) -ne 0 ]]; then
    SUDO="sudo "
  fi

  if ${SUDO}systemctl list-unit-files vm-mcp.service >/dev/null 2>&1; then
    ${SUDO}systemctl stop vm-mcp.service || true
    ${SUDO}systemctl disable vm-mcp.service || true
    ${SUDO}rm -f /etc/systemd/system/vm-mcp.service
    ${SUDO}systemctl daemon-reload
    echo "Removed vm-mcp systemd unit."
  else
    echo "No vm-mcp systemd unit found."
  fi
}

REPO_DIR=""
CLIENT="both"
INSTALL_PIP=true
INSTALL_SERVICE=false
UNINSTALL=false
REMOVE_SERVICE=false
CONFIG_DIR=""
PYTHON_BIN=""
MCP_COMMAND=""
AUDIT_LOG=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --repo)
      REPO_DIR="$2"
      shift 2
      ;;
    --client)
      CLIENT="$2"
      shift 2
      ;;
    --no-pip)
      INSTALL_PIP=false
      shift
      ;;
    --install-service)
      INSTALL_SERVICE=true
      shift
      ;;
    --uninstall)
      UNINSTALL=true
      shift
      ;;
    --remove-service)
      REMOVE_SERVICE=true
      shift
      ;;
    --config-dir)
      CONFIG_DIR="$2"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown argument: $1"
      usage
      exit 1
      ;;
  esac
done

if [[ -z "${REPO_DIR}" ]]; then
  REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
fi

if [[ -z "${CONFIG_DIR}" ]]; then
  CONFIG_DIR="${HOME}/.codex"
fi
AUDIT_LOG="${CONFIG_DIR}/logs/vm-mcp-audit.log"

if [[ "${CLIENT}" != "codex" && "${CLIENT}" != "gemini" && "${CLIENT}" != "both" ]]; then
  echo "Unknown --client value: ${CLIENT}"
  usage
  exit 1
fi

if [[ -n "${PYTHON_BIN}" ]]; then
  :
elif command -v python >/dev/null 2>&1; then
  PYTHON_BIN="python"
elif command -v python3 >/dev/null 2>&1; then
  PYTHON_BIN="python3"
else
  echo "Neither python nor python3 is available in PATH."
  exit 1
fi

if "${UNINSTALL}"; then
  if [[ "${CLIENT}" == "codex" || "${CLIENT}" == "both" ]]; then
    if [[ -f "${CONFIG_DIR}/mcp/vm-mcp-codex.json" ]]; then
      rm -f "${CONFIG_DIR}/mcp/vm-mcp-codex.json"
      echo "Removed ${CONFIG_DIR}/mcp/vm-mcp-codex.json"
    else
      echo "No Codex file at ${CONFIG_DIR}/mcp/vm-mcp-codex.json"
    fi

    if cleanup_codex_settings "${CONFIG_DIR}/settings.json"; then
      echo "Removed vm-mcp from ${CONFIG_DIR}/settings.json"
    else
      echo "No Codex settings update needed at ${CONFIG_DIR}/settings.json"
    fi
  fi

  if [[ "${CLIENT}" == "gemini" || "${CLIENT}" == "both" ]]; then
    if [[ -f "${CONFIG_DIR}/mcp/vm-mcp-gemini.json" ]]; then
      rm -f "${CONFIG_DIR}/mcp/vm-mcp-gemini.json"
      echo "Removed ${CONFIG_DIR}/mcp/vm-mcp-gemini.json"
    else
      echo "No Gemini file at ${CONFIG_DIR}/mcp/vm-mcp-gemini.json"
    fi
  fi

  if [[ "${REMOVE_SERVICE}" == "true" ]]; then
    remove_systemd_service
  fi

  echo "vm-mcp uninstall complete."
  exit 0
fi

if [[ -z "${REPO_DIR}" ]]; then
  REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
fi

if [[ ! -f "${REPO_DIR}/pyproject.toml" ]]; then
  echo "Cannot find pyproject.toml in ${REPO_DIR}"
  exit 1
fi

if "${INSTALL_PIP}"; then
  echo "Installing vm-mcp..."
  if ! "${PYTHON_BIN}" -m pip install -e "${REPO_DIR}"; then
    echo "System pip install failed; installing into ${REPO_DIR}/.venv instead."
    "${PYTHON_BIN}" -m venv "${REPO_DIR}/.venv"
    "${REPO_DIR}/.venv/bin/python" -m pip install -e "${REPO_DIR}"
  fi
fi

resolve_mcp_command

mkdir -p "${CONFIG_DIR}"
mkdir -p "${CONFIG_DIR}/mcp"
mkdir -p "$(dirname "${AUDIT_LOG}")"

if [[ "${CLIENT}" == "codex" || "${CLIENT}" == "both" ]]; then
  write_client_config "${CONFIG_DIR}/mcp/vm-mcp-codex.json" ""
  echo "Wrote Codex config to ${CONFIG_DIR}/mcp/vm-mcp-codex.json"
  if sync_codex_settings "${CONFIG_DIR}/settings.json" "${CONFIG_DIR}/mcp/vm-mcp-codex.json"; then
    echo "Updated native Codex settings at ${CONFIG_DIR}/settings.json"
  else
    echo "Warning: failed to merge native Codex settings at ${CONFIG_DIR}/settings.json"
    echo "Install complete, but manual merge is required for native Codex discovery."
  fi
fi

if [[ "${CLIENT}" == "gemini" || "${CLIENT}" == "both" ]]; then
  write_client_config "${CONFIG_DIR}/mcp/vm-mcp-gemini.json" "stdio"
  echo "Wrote Gemini config to ${CONFIG_DIR}/mcp/vm-mcp-gemini.json"
fi

if [[ "${INSTALL_SERVICE}" == "true" ]]; then
  if [[ "$(uname -s)" != "Linux" ]]; then
    echo "systemd install is only supported on Linux hosts."
    exit 1
  fi

  if ! resolve_service_execution; then
    echo "Cannot resolve a vm-mcp execution target for systemd."
    echo "Install with pip (default) or run from an environment with vm-mcp-server on PATH."
    exit 1
  fi

  SUDO=""
  if [[ $(id -u) -ne 0 ]]; then
    SUDO="sudo "
  fi

  SERVICE_UNIT="$(mktemp)"
  trap 'rm -f "${SERVICE_UNIT}"' EXIT
  write_service_unit "${SERVICE_UNIT}" "${SERVICE_EXEC_COMMAND}" "${SERVICE_EXEC_WORKDIR}" "${SERVICE_EXEC_ENV}"

  echo "Installing systemd service..."
  ${SUDO}cp "${SERVICE_UNIT}" /etc/systemd/system/vm-mcp.service
  ${SUDO}systemctl daemon-reload
  ${SUDO}systemctl enable --now vm-mcp.service
  ${SUDO}systemctl status vm-mcp.service --no-pager
  echo "Systemd service installed and started."
fi

cat <<EOF
vm-mcp install complete.
Config directory: ${CONFIG_DIR}/mcp
Native Codex settings: ${CONFIG_DIR}/settings.json
Executable: vm-mcp-server
EOF
