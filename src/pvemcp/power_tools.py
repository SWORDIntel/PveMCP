from __future__ import annotations
from .vm_memory import load_vm_memory, save_vm_memory, annotate_vm, get_vm_secret, annotate_vm_secret

from typing import Any, Literal
from .mcp_server import (
    mcp, 
    _run_with_policy, 
    snapshot, 
    _guest_exec_command, 
    gexec, 
    service, 
    _guest_stdout, 
    _fmt
)

# ---------------------------------------------------------------------------
# POWER-USER TOOLS
# ---------------------------------------------------------------------------

@mcp.tool()
async def vm_transactional_exec(
    vmid: str,
    cmd: str,
    validate_cmd: str,
    actor: str = "mcp-agent",
    danger_mode: bool | Literal["safe", "maintenance", "break_glass"] = False,
    audit_tag: str | None = None,
) -> dict[str, Any]:
    """Execute a destructive command safely by taking a snapshot first, running the command, and validating. Rolls back if validation fails."""
    import time
    snap_name = f"tx_{int(time.time())}"
    
    # 1. Snapshot
    snap_res = await _run_with_policy(vmid=vmid, actor=actor, action="tx:snapshot", command=f"qm snapshot {vmid} {snap_name}", execute=lambda: snapshot.create(vmid, snap_name), danger_mode=danger_mode, audit_tag=audit_tag, command_context="host")
    if not snap_res.get("ok"): return {"ok": False, "summary": f"Failed to take snapshot {snap_name}", "error": snap_res}

    # 2. Exec
    exec_res = await _run_with_policy(vmid=vmid, actor=actor, action="tx:exec", command=_guest_exec_command(vmid, cmd), execute=lambda: gexec.exec(vmid=vmid, cmd=cmd), danger_mode=danger_mode, audit_tag=audit_tag, command_context="guest")
    
    # 3. Validate
    val_res = await _run_with_policy(vmid=vmid, actor=actor, action="tx:validate", command=_guest_exec_command(vmid, validate_cmd), execute=lambda: gexec.exec(vmid=vmid, cmd=validate_cmd), danger_mode=danger_mode, audit_tag=audit_tag, command_context="guest")
    
    if val_res.get("ok"):
        # Success, delete snapshot
        del_res = await _run_with_policy(vmid=vmid, actor=actor, action="tx:delete_snap", command=f"qm delsnapshot {vmid} {snap_name}", execute=lambda: snapshot.delete(vmid, snap_name), danger_mode=danger_mode, audit_tag=audit_tag, command_context="host")
        return {"ok": True, "summary": "Transaction committed successfully.", "exec": exec_res, "validate": val_res, "cleanup": del_res.get("ok")}
    else:
        # Failure, rollback
        roll_res = await _run_with_policy(vmid=vmid, actor=actor, action="tx:rollback", command=f"qm rollback {vmid} {snap_name}", execute=lambda: snapshot.rollback(vmid, snap_name), danger_mode=danger_mode, audit_tag=audit_tag, command_context="host")
        # And delete
        await _run_with_policy(vmid=vmid, actor=actor, action="tx:delete_snap", command=f"qm delsnapshot {vmid} {snap_name}", execute=lambda: snapshot.delete(vmid, snap_name), danger_mode=danger_mode, audit_tag=audit_tag, command_context="host")
        return {"ok": False, "summary": "Validation failed. Transaction rolled back.", "exec": exec_res, "validate": val_res, "rollback": roll_res.get("ok")}


@mcp.tool()
async def vm_expose_port(
    vmid: str,
    guest_port: int,
    actor: str = "mcp-agent",
    danger_mode: bool | Literal["safe", "maintenance", "break_glass"] = False,
    audit_tag: str | None = None,
) -> dict[str, Any]:
    """Expose a port from the VM to the Proxmox host's LAN IP on a random high port using socat."""
    import random
    host_port = random.randint(45000, 65000)
    
    # 1. Get Guest IP
    ip_cmd = "ip -4 -j addr show | grep -oP '(?<=\"local\": \")[^\"]*' | grep -v '^127' | head -1"
    ip_res = await _run_with_policy(vmid=vmid, actor=actor, action="port_fwd:get_ip", command=_guest_exec_command(vmid, ip_cmd), execute=lambda: gexec.exec(vmid=vmid, cmd=ip_cmd), danger_mode=danger_mode, audit_tag=audit_tag, command_context="guest")
    guest_ip = _guest_stdout(str(ip_res.get("stdout", ""))).strip()
    if not guest_ip: return {"ok": False, "summary": "Could not determine guest IP."}

    # 2. Get Host LAN IP
    host_ip_cmd = r"ip route get 1.1.1.1 | grep -oP 'src \K\S+'"
    host_ip_res = await _run_with_policy(vmid="0", actor=actor, action="port_fwd:get_host_ip", command=host_ip_cmd, execute=lambda: service.runner.run(vmid="0", cmd=host_ip_cmd), danger_mode=danger_mode, audit_tag=audit_tag, command_context="host")
    host_ip = str(host_ip_res.get("stdout", "")).strip()
    if not host_ip: return {"ok": False, "summary": "Could not determine host LAN IP."}

    # 3. Setup socat forwarding in background on host
    socat_cmd = f"socat TCP-LISTEN:{host_port},bind={host_ip},fork,reuseaddr TCP:{guest_ip}:{guest_port} >/dev/null 2>&1 &"
    await _run_with_policy(vmid="0", actor=actor, action="port_fwd:socat", command=socat_cmd, execute=lambda: service.runner.run(vmid="0", cmd=socat_cmd), danger_mode=danger_mode, audit_tag=audit_tag, command_context="host")

    return {"ok": True, "summary": f"Port forwarded successfully! Access via http://{host_ip}:{host_port}", "host_ip": host_ip, "host_port": host_port, "guest_ip": guest_ip, "guest_port": guest_port}


@mcp.tool()
async def host_storage_list(actor: str = "mcp-agent", danger_mode: bool | Literal["safe", "maintenance", "break_glass"] = False, audit_tag: str | None = None) -> dict[str, Any]:
    """List Proxmox datastores and their current usage."""
    cmd = "pvesm status"
    res = await _run_with_policy(vmid="0", actor=actor, action="storage_list", command=cmd, execute=lambda: service.runner.run(vmid="0", cmd=cmd), danger_mode=danger_mode, audit_tag=audit_tag, command_context="host")
    return _fmt(res, label="pvesm")

@mcp.tool()
async def host_iso_download(storage: str, url: str, filename: str, actor: str = "mcp-agent", danger_mode: bool | Literal["safe", "maintenance", "break_glass"] = False, audit_tag: str | None = None) -> dict[str, Any]:
    """Download an ISO directly to a Proxmox storage pool."""
    cmd = f"pveam download {storage} {url} --filename {filename}"
    res = await _run_with_policy(vmid="0", actor=actor, action="iso_download", command=cmd, execute=lambda: service.runner.run(vmid="0", cmd=cmd, timeout_s=300), danger_mode=danger_mode, audit_tag=audit_tag, command_context="host")
    return _fmt(res, label="pveam")

@mcp.tool()
async def vm_deploy_compose(vmid: str, project_name: str, compose_yaml: str, actor: str = "mcp-agent", danger_mode: bool | Literal["safe", "maintenance", "break_glass"] = False, audit_tag: str | None = None) -> dict[str, Any]:
    """Deploy a complete docker-compose stack inside a VM in one shot."""
    import base64
    encoded = base64.b64encode(compose_yaml.encode("utf-8")).decode("ascii")
    
    script = f"mkdir -p /opt/{project_name} && echo '{encoded}' | base64 -d > /opt/{project_name}/docker-compose.yml && cd /opt/{project_name} && docker compose up -d"
    res = await _run_with_policy(vmid=vmid, actor=actor, action="deploy_compose", command=_guest_exec_command(vmid, script), execute=lambda: gexec.exec(vmid=vmid, cmd=script, timeout=120), danger_mode=danger_mode, audit_tag=audit_tag, command_context="guest")
    return _fmt(res, label=f"compose:{project_name}")

@mcp.tool()
async def vm_pcap_analyze(vmid: str, interface: str = "any", port: int | None = None, duration: int = 10, actor: str = "mcp-agent", danger_mode: bool | Literal["safe", "maintenance", "break_glass"] = False, audit_tag: str | None = None) -> dict[str, Any]:
    """Run a 10-second packet capture inside the VM and analyze top talkers."""
    port_filter = f"port {port}" if port else ""
    script = f"timeout {duration} tcpdump -i {interface} -n -nn -q {port_filter} > /tmp/pcap.txt 2>/dev/null; awk '{{print $3\" -> \"$5}}' /tmp/pcap.txt | sort | uniq -c | sort -nr | head -n 10"
    res = await _run_with_policy(vmid=vmid, actor=actor, action="pcap_analyze", command=_guest_exec_command(vmid, script), execute=lambda: gexec.exec(vmid=vmid, cmd=script, timeout=duration+5), danger_mode=danger_mode, audit_tag=audit_tag, command_context="guest")
    
    stdout = _guest_stdout(str(res.get("stdout", "")))
    return {"ok": res.get("ok"), "summary": f"PCAP analysis for {duration}s", "top_talkers": stdout.splitlines()}

# ---------------------------------------------------------------------------
# REMOTE SSH / LOG STREAMING TOOLS
# ---------------------------------------------------------------------------

@mcp.tool()
async def remote_tail(
    host: str,
    path: str,
    lines: int = 50,
    user: str = "root",
    identity_file: str = "~/.ssh/id_ed25519",
    actor: str = "mcp-agent"
) -> dict[str, Any]:
    """Fetch the last N lines of a log file on a remote host via SSH."""
    import shlex
    from .remote import SSHRunner
    runner = SSHRunner(host=host, user=user, identity_file=identity_file)
    res = await runner.run(f"tail -n {lines} {shlex.quote(path)}")
    return _fmt(res, label=f"remote_tail:{host}")

@mcp.tool()
async def remote_log_capture(
    host: str,
    path: str,
    duration: int = 10,
    user: str = "root",
    identity_file: str = "~/.ssh/id_ed25519",
    actor: str = "mcp-agent"
) -> dict[str, Any]:
    """Watch a live remote log (tail -f) for a specific duration (seconds) and return the output. Perfect for capturing pipeline stages."""
    import shlex
    from .remote import SSHRunner
    runner = SSHRunner(host=host, user=user, identity_file=identity_file)
    # We use timeout on the SSH side to kill the tail
    cmd = f"timeout {duration} tail -f {shlex.quote(path)} || true"
    # We also need a timeout on the runner side slightly longer than duration
    res = await runner.run(cmd, timeout_s=duration + 5)
    
    stdout = str(res.stdout or "")
    return {
        "ok": True, 
        "summary": f"Captured {duration}s of {path} on {host}", 
        "lines": stdout.splitlines()
    }

@mcp.tool()
async def remote_file_get(
    host: str,
    remote_path: str,
    user: str = "root",
    identity_file: str = "~/.ssh/id_ed25519",
) -> dict[str, Any]:
    """Read a file from a remote host via SSH (useful for extracting certs, configs, etc)."""
    import shlex
    from .remote import SSHRunner
    runner = SSHRunner(host=host, user=user, identity_file=identity_file)
    res = await runner.run(f"cat {shlex.quote(remote_path)}")
    return _fmt(res, label=f"remote_file_get:{host}")


@mcp.tool()
async def vm_ssh_config_set(
    vmid: str,
    key_path: str | None = None,
    key_content: str | None = None,
    user: str | None = "root",
) -> dict[str, Any]:
    """Save SSH configuration for a VM. If key_content is provided, it is stored encrypted with AES-256."""
    updates = {}
    if user:
        annotate_vm(vmid, env={"ssh_user": user})
    if key_path:
        annotate_vm(vmid, env={"ssh_key_path": key_path})
    if key_content:
        annotate_vm_secret(vmid, "ssh_key_content", key_content)
        
    return {"ok": True, "summary": f"SSH configuration saved for VM {vmid}"}

@mcp.tool()
async def vm_remote_tail(
    vmid: str,
    path: str,
    lines: int = 50,
    identity_file: str | None = None,
) -> dict[str, Any]:
    """Tail a log on a VM using its saved SSH configuration."""
    import shlex
    import tempfile
    from .remote import SSHRunner
    
    mem = load_vm_memory(vmid)
    user = mem.get("env", {}).get("ssh_user", "root")
    key_path = identity_file or mem.get("env", {}).get("ssh_key_path", "~/.ssh/id_ed25519")
    key_content = get_vm_secret(vmid, "ssh_key_content")
    
    # Resolve host IP from VM status or environment
    host = mem.get("env", {}).get("hostname")
    if not host:
        # Fallback to checking qm status/config logic if needed, 
        # but for now we expect the AI to have autodiscovered it.
        return {"ok": False, "summary": "Host IP/Hostname not found in VM memory. Run vm_autodiscover first."}

    tmp_key = None
    if key_content:
        # Write encrypted content to a temporary file for the SSH command
        fd, tmp_key = tempfile.mkstemp()
        os.write(fd, key_content.encode())
        os.close(fd)
        os.chmod(tmp_key, 0o600)
        key_path = tmp_key

    try:
        runner = SSHRunner(host=host, user=user, identity_file=key_path)
        res = await runner.run(f"tail -n {lines} {shlex.quote(path)}")
        return _fmt(res, label=f"vm_remote_tail:{vmid}")
    finally:
        if tmp_key and os.path.exists(tmp_key):
            os.remove(tmp_key)

@mcp.tool()
async def vm_disk_reclaim(
    vmid: str,
    actor: str = "mcp-agent",
    danger_mode: bool | Literal["safe", "maintenance", "break_glass"] = False,
    audit_tag: str | None = None,
) -> dict[str, Any]:
    """Run fstrim inside the VM to reclaim unused blocks on the host (requires discard=on in VM config)."""
    cmd = "fstrim -a"
    res = await _run_with_policy(
        vmid=vmid, 
        actor=actor, 
        action="disk_reclaim", 
        command=_guest_exec_command(vmid, cmd), 
        execute=lambda: gexec.exec(vmid=vmid, cmd=cmd), 
        danger_mode=danger_mode, 
        audit_tag=audit_tag, 
        command_context="guest"
    )
    return _fmt(res, label=f"fstrim:{vmid}")

@mcp.tool()
async def gitlab_cleanup(
    actor: str = "mcp-agent",
    danger_mode: bool | Literal["safe", "maintenance", "break_glass"] = False,
    audit_tag: str | None = None,
) -> dict[str, Any]:
    """Weekly GitLab maintenance: reclaim host disk space for VM 9320."""
    return await vm_disk_reclaim(
        vmid="9320", 
        actor=actor, 
        danger_mode=danger_mode, 
        audit_tag=audit_tag
    )
