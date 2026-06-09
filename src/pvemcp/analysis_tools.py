from __future__ import annotations

import asyncio
import json
import logging
from typing import Any, Literal

from .mcp_server import (
    mcp,
    _run_with_policy,
    gexec,
    service,
    _guest_exec_command,
    _guest_stdout,
    _fmt,
)

# ---------------------------------------------------------------------------
# ANALYSIS & FORENSICS TOOLS
# ---------------------------------------------------------------------------

@mcp.tool()
async def vm_fork_sandbox(
    vmid: str,
    new_vmid: str,
    name: str = "sandbox-clone",
    isolated_bridge: str = "vmbr1",
    actor: str = "mcp-agent",
    danger_mode: bool | Literal["safe", "maintenance", "break_glass"] = False,
    audit_tag: str | None = None,
) -> dict[str, Any]:
    """Instantly create a Linked Clone of a VM for safe analysis, placing it on an isolated network bridge."""
    # 1. Create linked clone
    cmd_clone = f"qm clone {vmid} {new_vmid} --name {name} --full 0"
    res_clone = await _run_with_policy(vmid=vmid, actor=actor, action="sandbox:clone", command=cmd_clone, execute=lambda: service.runner.run(vmid="0", cmd=cmd_clone), danger_mode=danger_mode, audit_tag=audit_tag, command_context="host")
    if not res_clone.get("ok"):
        return {"ok": False, "summary": f"Failed to create linked clone: {res_clone.get('error')}"}

    # 2. Modify network interface to isolated bridge
    cmd_net = f"qm set {new_vmid} --net0 model=virtio,bridge={isolated_bridge},firewall=1"
    await _run_with_policy(vmid=new_vmid, actor=actor, action="sandbox:isolate", command=cmd_net, execute=lambda: service.runner.run(vmid="0", cmd=cmd_net), danger_mode=danger_mode, audit_tag=audit_tag, command_context="host")

    # 3. Start the sandbox
    cmd_start = f"qm start {new_vmid}"
    await _run_with_policy(vmid=new_vmid, actor=actor, action="sandbox:start", command=cmd_start, execute=lambda: service.runner.run(vmid="0", cmd=cmd_start), danger_mode=danger_mode, audit_tag=audit_tag, command_context="host")

    return {"ok": True, "summary": f"Sandbox VM {new_vmid} created from {vmid} and started on isolated bridge {isolated_bridge}."}


@mcp.tool()
async def vm_ram_dump(
    vmid: str,
    output_file: str,
    actor: str = "mcp-agent",
    danger_mode: bool | Literal["safe", "maintenance", "break_glass"] = False,
    audit_tag: str | None = None,
) -> dict[str, Any]:
    """Agentless Forensics: Dump the live RAM of a VM to a file on the Proxmox host using QEMU monitor."""
    # QEMU monitor command: dump-guest-memory
    cmd = f"qm monitor {vmid} -c 'dump-guest-memory {output_file}'"
    res = await _run_with_policy(vmid=vmid, actor=actor, action="ram_dump", command=cmd, execute=lambda: service.runner.run(vmid="0", cmd=cmd, timeout_s=300), danger_mode=danger_mode, audit_tag=audit_tag, command_context="host")
    return _fmt(res, label="ram_dump")


@mcp.tool()
async def vm_network_quarantine(
    vmid: str,
    enable: bool = True,
    actor: str = "mcp-agent",
    danger_mode: bool | Literal["safe", "maintenance", "break_glass"] = False,
    audit_tag: str | None = None,
) -> dict[str, Any]:
    """Instantly quarantine a VM using Proxmox firewall rules, dropping all network traffic (airgap) while maintaining QEMU Guest Agent access."""
    # We can quarantine by setting a default DROP rule for the VM in pve-firewall
    if enable:
        # Enable firewall for the VM and set default policy to drop
        cmd1 = f"pvesh set /nodes/localhost/qemu/{vmid}/firewall/options -enable 1 -policy_in DROP -policy_out DROP"
        res = await _run_with_policy(vmid=vmid, actor=actor, action="quarantine:enable", command=cmd1, execute=lambda: service.runner.run(vmid="0", cmd=cmd1), danger_mode=danger_mode, audit_tag=audit_tag, command_context="host")
        summary = f"VM {vmid} quarantined (Airgapped via PVE Firewall)."
    else:
        # Disable firewall or restore policies (Assuming ACCEPT/ACCEPT or just disabling the strict drop)
        cmd1 = f"pvesh set /nodes/localhost/qemu/{vmid}/firewall/options -policy_in ACCEPT -policy_out ACCEPT"
        res = await _run_with_policy(vmid=vmid, actor=actor, action="quarantine:disable", command=cmd1, execute=lambda: service.runner.run(vmid="0", cmd=cmd1), danger_mode=danger_mode, audit_tag=audit_tag, command_context="host")
        summary = f"VM {vmid} quarantine lifted."

    return {"ok": res.get("ok"), "summary": summary, "details": res}


@mcp.tool()
async def vm_etc_diff(
    vmid: str,
    actor: str = "mcp-agent",
    danger_mode: bool | Literal["safe", "maintenance", "break_glass"] = False,
    audit_tag: str | None = None,
) -> dict[str, Any]:
    """Find configuration files inside the VM that have been modified from their package baseline (Configuration Bisection)."""
    # Try dpkg -V for debian/ubuntu, rpm -Va for rhel/centos
    script = """
    if command -v dpkg >/dev/null 2>&1; then
        dpkg -V | grep '^..5' | awk '{print $2}' | grep -E '^/etc/'
    elif command -v rpm >/dev/null 2>&1; then
        rpm -Va | grep '^..5' | awk '{print $NF}' | grep -E '^/etc/'
    else
        echo "No supported package manager found for verification."
    fi
    """
    res = await _run_with_policy(vmid=vmid, actor=actor, action="etc_diff", command=_guest_exec_command(vmid, script), execute=lambda: gexec.exec(vmid=vmid, cmd=script, timeout=120), danger_mode=danger_mode, audit_tag=audit_tag, command_context="guest")
    
    stdout = _guest_stdout(str(res.get("stdout", ""))).strip()
    modified_files = stdout.splitlines() if stdout else []
    
    return {
        "ok": res.get("ok"),
        "summary": f"Found {len(modified_files)} modified configuration files in /etc/.",
        "modified_files": modified_files
    }


# ---------------------------------------------------------------------------
# WATCHDOG HTTP LISTENER
# ---------------------------------------------------------------------------
# A lightweight asyncio HTTP server to receive triggers from pipelines.

async def handle_watchdog_request(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    request_line = await reader.readline()
    if not request_line:
        writer.close()
        return

    method, path, _ = request_line.decode().strip().split(' ', 2)
    
    # Read headers
    content_length = 0
    while True:
        line = await reader.readline()
        if line == b'\r\n':
            break
        if line.lower().startswith(b'content-length:'):
            content_length = int(line.split(b':')[1].strip())

    body = ""
    if content_length > 0:
        body = (await reader.readexactly(content_length)).decode()

    if path == '/trigger' and method == 'POST':
        # Log it so MCP sees it, or we could emit a custom MCP notification if the FastMCP API allows.
        # FastMCP uses `mcp.server.notification_manager`. For now, we log it, and the client
        # can poll `pvemcp://metrics` or we can just print it to stderr.
        logging.warning(f"[WATCHDOG TRIGGER] Pipeline event received: {body}")
        
        # Respond OK
        response = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK"
        writer.write(response.encode())
    else:
        response = "HTTP/1.1 404 Not Found\r\nContent-Length: 9\r\n\r\nNot Found"
        writer.write(response.encode())
        
    await writer.drain()
    writer.close()

async def start_watchdog_server(port: int = 8000):
    server = await asyncio.start_server(handle_watchdog_request, '0.0.0.0', port)
    logging.info(f"Watchdog trigger listening on 0.0.0.0:{port} (POST /trigger)")
    async with server:
        await server.serve_forever()

# Start the watchdog task when this module is loaded (if running inside asyncio loop)
try:
    loop = asyncio.get_running_loop()
    loop.create_task(start_watchdog_server())
except RuntimeError:
    pass # No running loop yet, that's fine.
