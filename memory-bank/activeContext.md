# Active Context — vm-mcp

## Current Focus
Expanding vm-mcp with broader VM control, per-VM memory/context, ripgrep/find search tools, and cleaner output formatting.

## Active Assumptions
- Proxmox is the primary target platform (qm, pct, vzdump commands)
- Guest agent (QEMU guest agent) must be running in VMs for guest-exec operations
- Policy enforcer validates all commands before execution
- `rg` (ripgrep) is preferred for guest search; falls back to `grep` automatically

## Immediate Next Steps
- Run test suite to validate new modules: `pytest`
- Verify mcp_server.py changes from subagent are complete and correct
- Update README.md with new command reference table
