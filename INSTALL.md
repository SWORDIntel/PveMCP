# vm-mcp installation and MCP wiring

## Native plugin layout (Codex)

`vm-mcp` now includes native plugin metadata and skill packaging:

- `.codex-plugin/plugin.json`
- `.mcp.json`
- `plugin/scripts/start-vm-mcp.sh`
- `plugin/skills/vm-mcp/SKILL.md`

This means Codex can consume vm-mcp as a first-class MCP+skill plugin without custom per-tool scaffolding.

## Install from git (host-side)

```bash
python -m pip install git+https://github.com/SWORDIntel/vm-mcp.git
```

## Editable install for local development

```bash
git clone https://github.com/SWORDIntel/vm-mcp.git
cd vm-mcp
python -m pip install -e .
```

## MCP entrypoint

```bash
vm-mcp-server
```

This launches the MCP server using stdio transport via `FastMCP("vm-mcp")`.

## Client wiring (Codex / Gemini style)

- Copied samples:
  - `examples/codex-mcp.json`
  - `examples/gemini-mcp.json`
- Replace only paths/values and merge into your client config.

```json
{
  "mcpServers": {
    "vm-mcp": {
      "command": "vm-mcp-server",
      "env": {
        "VM_MCP_AUDIT_LOG": "/var/log/vm-mcp-audit.log",
        "VM_MCP_ALLOW_BREAK_GLASS": "1"
      }
    }
  }
}
```

## Host trust behavior

- Host commands are allowed to run without strict checks automatically when:
  - `VM_MCP_ALLOW_BREAK_GLASS=1`
  - or `/etc/pve` exists (i.e., when running on a Proxmox host).

For everything else, guest actions continue to be policy-constrained.

## One-shot install helper

```bash
chmod +x scripts/install-vm-mcp.sh
scripts/install-vm-mcp.sh --client both
```

Install client configs, register Codex natively, and optionally start the service in one pass:

```bash
scripts/install-vm-mcp.sh --client both --install-service
```

The installer now also updates:

```text
~/.codex/settings.json
```

by merging `mcpServers.vm-mcp` under the `mcpServers` section when `--client codex` or `--client both` is used.

### Uninstall

Remove local file artifacts and native Codex registration from the unified installer:

```bash
scripts/install-vm-mcp.sh --uninstall
```

To also remove the systemd unit:

```bash
scripts/install-vm-mcp.sh --uninstall --remove-service
```

Default client configs are written under:

```text
~/.codex/mcp/vm-mcp-*.json
```

## Optional: run as a systemd service

Use this unit file when you want `vm-mcp-server` to start automatically on the host.

```bash
sudo cp examples/vm-mcp.service /etc/systemd/system/vm-mcp.service
sudo systemctl daemon-reload
sudo systemctl enable --now vm-mcp.service
sudo systemctl status vm-mcp.service
```

If you need to tune env values, edit `/etc/systemd/system/vm-mcp.service` before reloading.
