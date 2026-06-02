# proxmcp installation and MCP wiring

## Native plugin layout (Codex)

`proxmcp` now includes native plugin metadata and skill packaging:

- `.codex-plugin/plugin.json`
- `.mcp.json`
- `plugin/scripts/start-proxmcp.sh`
- `plugin/skills/proxmcp/SKILL.md`

This means Codex can consume proxmcp as a first-class MCP+skill plugin without custom per-tool scaffolding.

## Install from git (host-side)

```bash
python -m pip install git+https://github.com/SWORDIntel/proxmcp.git
```

## Editable install for local development

```bash
git clone https://github.com/SWORDIntel/proxmcp.git
cd proxmcp
python -m pip install -e .
```

## MCP entrypoint

```bash
proxmcp-server
```

This launches the MCP server using stdio transport via `FastMCP("ProxMCP")`.

## Client wiring (Codex / Gemini style)

- Copied samples:
  - `examples/codex-mcp.json`
  - `examples/gemini-mcp.json`
- Replace only paths/values and merge into your client config.

```json
{
  "mcpServers": {
    "proxmcp": {
      "command": "proxmcp-server",
      "env": {
        "PROXMCP_AUDIT_LOG": "/var/log/proxmcp-audit.log",
        "PROXMCP_ALLOW_BREAK_GLASS": "1"
      }
    }
  }
}
```

## Host trust behavior

- Host commands are allowed to run without strict checks automatically when:
  - `PROXMCP_ALLOW_BREAK_GLASS=1`
  - or `/etc/pve` exists (i.e., when running on a Proxmox host).

For everything else, guest actions continue to be policy-constrained.

## One-shot install helper

```bash
chmod +x scripts/install-proxmcp.sh
scripts/install-proxmcp.sh --client both
```

Install client configs, register Codex natively, and optionally start the service in one pass:

```bash
scripts/install-proxmcp.sh --client both --install-service
```

The installer now also updates:

```text
~/.codex/settings.json
```

by merging `mcpServers.proxmcp` under the `mcpServers` section when `--client codex` or `--client both` is used.

### Uninstall

Remove local file artifacts and native Codex registration from the unified installer:

```bash
scripts/install-proxmcp.sh --uninstall
```

To also remove the systemd unit:

```bash
scripts/install-proxmcp.sh --uninstall --remove-service
```

Default client configs are written under:

```text
~/.codex/mcp/proxmcp-*.json
```

## Optional: run as a systemd service

Use this unit file when you want `proxmcp-server` to start automatically on the host.

```bash
sudo cp examples/proxmcp.service /etc/systemd/system/proxmcp.service
sudo systemctl daemon-reload
sudo systemctl enable --now proxmcp.service
sudo systemctl status proxmcp.service
```

If you need to tune env values, edit `/etc/systemd/system/proxmcp.service` before reloading.
