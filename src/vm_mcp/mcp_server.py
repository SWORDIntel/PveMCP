from __future__ import annotations

import asyncio
import json
import os
import shlex
from typing import Any, Callable, Literal

from fastmcp import FastMCP

from .service import VMService
from .proxmox import (
    ProxmoxBackup,
    ProxmoxConfig,
    ProxmoxFileOps,
    ProxmoxGuestExec,
    ProxmoxLifecycle,
    ProxmoxSnapshot,
)
from .workflows import WorkflowManager, ArtifactIndex
from .models import CommandResult
from .metrics import Timer

# Initialize FastMCP
mcp = FastMCP("vm-mcp")

# Build the internal service
service = VMService.build(
    audit_path=os.getenv("VM_MCP_AUDIT_LOG", "logs/audit.log"),
    use_host_sudo=True,
)
proxmox = ProxmoxLifecycle(runner=service.runner)
snapshot = ProxmoxSnapshot(runner=service.runner)
file_ops = ProxmoxFileOps(runner=service.runner)
proxmox_config = ProxmoxConfig(runner=service.runner)
artifact_idx = ArtifactIndex()
proxmox_backup = ProxmoxBackup(runner=service.runner)
gexec = ProxmoxGuestExec(runner=service.runner)
workflow_mgr = WorkflowManager(service=service, file_ops=file_ops, gexec=gexec, artifact_idx=artifact_idx)


def _guest_exec_command(vmid: str, cmd: str, cwd: str | None = None, env: dict[str, str] | None = None, timeout: int | None = None) -> str:
    parts: list[str] = ["qm", "guest", "exec", str(vmid)]
    if cwd:
        parts.extend(["--cwd", cwd])
    if env:
        for k, v in env.items():
            parts.extend(["--env", f"{k}={v}"])
    if timeout:
        parts.extend(["--timeout", str(timeout)])
    parts.append("--")
    try:
        parts.extend(shlex.split(cmd))
    except ValueError:
        parts.append(cmd)
    return " ".join(shlex.quote(part) for part in parts)


def _q_cmd(*parts: object) -> str:
    return " ".join(shlex.quote(str(part)) for part in parts)


def _guest_stdout(stdout: str) -> str:
    try:
        payload = json.loads(stdout)
    except json.JSONDecodeError:
        return stdout
    if isinstance(payload, dict) and isinstance(payload.get("out-data"), str):
        return payload["out-data"]
    return stdout


async def _run_with_policy(
    *,
    vmid: str,
    actor: str,
    action: str,
    command: str,
    execute: Callable[[], Any],
    danger_mode: bool | Literal["safe", "maintenance", "break_glass"] = False,
    audit_tag: str | None = None,
    command_context: Literal["host", "guest"] = "host",
) -> dict[str, Any]:
    timer = Timer()
    try:
        service.policy.validate(command, danger_mode=danger_mode, command_context=command_context)
    except Exception as exc:
        result = CommandResult(
            ok=False,
            code=1,
            stdout="",
            stderr=str(exc),
            duration_ms=timer.elapsed_ms(),
            vmid=vmid,
            cmd=command,
        )
        result.stdout = service.redactor.redact(result.stdout)
        result.stderr = service.redactor.redact(result.stderr)
        service.audit.log(actor=actor, action=action, vmid=vmid, cmd=command, result=result.to_dict(), audit_tag=audit_tag)
        service.metrics.record_policy_block()
        service.metrics.record(action=action, duration_ms=result.duration_ms, ok=False, timeout=False)
        return result.to_dict()

    try:
        result = await execute()
    except Exception as exc:  # noqa: BLE001
        result = CommandResult(
            ok=False,
            code=1,
            stdout="",
            stderr=str(exc),
            duration_ms=timer.elapsed_ms(),
            vmid=vmid,
            cmd=command,
        )

    result.stdout = service.redactor.redact(result.stdout)
    result.stderr = service.redactor.redact(result.stderr)
    service.audit.log(actor=actor, action=action, vmid=vmid, cmd=command, result=result.to_dict(), audit_tag=audit_tag)
    service.metrics.record(action=action, duration_ms=timer.elapsed_ms(), ok=result.ok, timeout=(result.code == 124))
    return result.to_dict()


async def _guest_health_check(
    *,
    vmid: str,
    services: list[str],
    containers: list[str],
    actor: str,
    danger_mode: bool | Literal["safe", "maintenance", "break_glass"],
    audit_tag: str | None = None,
) -> dict[str, Any]:
    details: dict[str, dict[str, bool]] = {"services": {}, "containers": {}}
    all_ok = True

    for service_name in services:
        cmd = f"systemctl is-active {service_name}"
        guest_cmd = _guest_exec_command(vmid=vmid, cmd=cmd)
        res = await _run_with_policy(
            vmid=vmid,
            actor=actor,
            action=f"vm_slo_check:service:{service_name}",
            command=guest_cmd,
            execute=lambda vmid=vmid, cmd=cmd: gexec.exec(vmid=vmid, cmd=cmd),
            danger_mode=danger_mode,
            audit_tag=audit_tag,
            command_context="guest",
        )
        service_stdout = _guest_stdout(str(res.get("stdout", "")))
        is_active = res.get("ok", False) and service_stdout.strip() == "active"
        details["services"][service_name] = is_active
        if not is_active:
            all_ok = False

    if containers:
        ps_cmd = "docker ps --format '{{.ID}}\\t{{.Names}}\\t{{.Status}}'"
        ps_command = _guest_exec_command(vmid=vmid, cmd=ps_cmd)
        ps_res = await _run_with_policy(
            vmid=vmid,
            actor=actor,
            action="vm_slo_check:containers:ps",
            command=ps_command,
            execute=lambda vmid=vmid, ps_cmd=ps_cmd: gexec.exec(vmid=vmid, cmd=ps_cmd),
            danger_mode=danger_mode,
            audit_tag=audit_tag,
            command_context="guest",
        )
        ps_output = _guest_stdout(str(ps_res.get("stdout", "")))
        for container_name in containers:
            is_running = container_name in ps_output
            details["containers"][container_name] = is_running
            if not is_running:
                all_ok = False

    return {"ok": all_ok, "details": details}

@mcp.tool()
async def vm_fan_out(
    vmids: list[str], 
    cmd: str,
    actor: str = "mcp-agent",
    danger_mode: bool | Literal["safe", "maintenance", "break_glass"] = False,
    audit_tag: str | None = None,
) -> dict[str, Any]:
    """Execute a command on multiple VMs in parallel."""
    tasks = [
        _run_with_policy(
            vmid=vmid,
            actor=actor,
            action=f"vm_fan_out:{vmid}",
            command=cmd,
            execute=lambda vmid=vmid, cmd=cmd: service.exec(
                vmid=vmid,
                cmd=cmd,
                actor=actor,
                danger_mode=danger_mode,
                audit_tag=audit_tag,
                action="vm_fan_out",
                skip_audit=True,
                skip_metrics=True,
                skip_policy=True,
                command_context="host",
            ),
            danger_mode=danger_mode,
            audit_tag=audit_tag,
            command_context="host",
        )
        for vmid in vmids
    ]
    results = await asyncio.gather(*tasks, return_exceptions=True)

    output: dict[str, Any] = {}
    for vmid, result in zip(vmids, results):
        if isinstance(result, Exception):
            output[vmid] = {
                "ok": False,
                "code": 500,
                "stdout": "",
                "stderr": str(result),
                "duration_ms": 0,
                "vmid": vmid,
                "cmd": cmd,
            }
        else:
            output[vmid] = result
    return output

@mcp.tool()
async def vm_orchestrate(
    plan: list[dict[str, Any]],
    actor: str = "mcp-agent",
    danger_mode: bool | Literal["safe", "maintenance", "break_glass"] = False,
    audit_tag: str | None = None,
) -> list[dict[str, Any]]:
    """Execute a sequence of commands across different VMs (dependency graph)."""
    results: list[dict[str, Any]] = []
    for step in plan:
        vmid = step["vmid"]
        cmd = step["cmd"]
        result = await _run_with_policy(
            vmid=vmid,
            actor=actor,
            action=f"vm_orchestrate:{vmid}",
            command=cmd,
            execute=lambda vmid=vmid, cmd=cmd: service.exec(
                vmid=vmid,
                cmd=cmd,
                actor=actor,
                danger_mode=danger_mode,
                audit_tag=audit_tag,
                action="vm_orchestrate_step",
                skip_audit=True,
                skip_metrics=True,
                skip_policy=True,
                command_context="host",
            ),
            danger_mode=danger_mode,
            audit_tag=audit_tag,
            command_context="host",
        )
        results.append({"step": step, "result": result})
        if not result.get("ok"):
            break
    return results

@mcp.tool()
async def run_workflow_generate(
    vmid: str,
    script_path: str,
    actor: str = "mcp-agent",
    danger_mode: bool | Literal["safe", "maintenance", "break_glass"] = False,
    audit_tag: str | None = None,
) -> dict[str, Any]:
    """Run a generation workflow: upload script, execute, and return results."""
    result = await workflow_mgr.run_generate_outputs(
        vmid=vmid,
        script_path=script_path,
        output_path="/tmp/workflow_output.txt",
        actor=actor,
        danger_mode=danger_mode,
        audit_tag=audit_tag,
    )
    return result.to_dict()

@mcp.tool()
async def run_eval_scorecard(
    vmid: str,
    data_path: str,
    actor: str = "mcp-agent",
    danger_mode: bool | Literal["safe", "maintenance", "break_glass"] = False,
    audit_tag: str | None = None,
) -> dict[str, Any]:
    """Run an evaluation scorecard workflow on data within the VM."""
    return await workflow_mgr.run_eval_scorecard(
        vmid=vmid,
        data_path=data_path,
        actor=actor,
        danger_mode=danger_mode,
        audit_tag=audit_tag,
    )

@mcp.tool()
def list_artifacts() -> dict[str, Any]:
    """List all tracked artifacts in the index."""
    return artifact_idx.list()

@mcp.tool()
async def vm_exec(
    vmid: str,
    cmd: str,
    actor: str = "mcp-agent",
    danger_mode: bool | Literal["safe", "maintenance", "break_glass"] = False,
    audit_tag: str | None = None,
) -> dict[str, Any]:
    """Execute a command on a VM with policy enforcement."""
    return await _run_with_policy(
        vmid=vmid,
        actor=actor,
        action="vm_exec",
        command=cmd,
        execute=lambda: service.exec(
            vmid=vmid,
            cmd=cmd,
            actor=actor,
            danger_mode=danger_mode,
            audit_tag=audit_tag,
            action="vm_exec",
            skip_policy=True,
            skip_audit=True,
            skip_metrics=True,
        ),
        danger_mode=danger_mode,
        audit_tag=audit_tag,
        command_context="host",
    )

@mcp.tool()
async def vm_guest_exec(
    vmid: str,
    cmd: str,
    actor: str = "mcp-agent",
    danger_mode: bool | Literal["safe", "maintenance", "break_glass"] = False,
    cwd: str | None = None,
    env: dict[str, str] | None = None,
    timeout: int | None = None,
    audit_tag: str | None = None,
) -> dict[str, Any]:
    """Execute a command inside a Proxmox guest using the guest agent."""
    command = _guest_exec_command(vmid=vmid, cmd=cmd, cwd=cwd, env=env, timeout=timeout)
    return await _run_with_policy(
        vmid=vmid,
        actor=actor,
        action="vm_guest_exec",
        command=command,
        execute=lambda: gexec.exec(vmid=vmid, cmd=cmd, cwd=cwd, env=env, timeout=timeout),
        danger_mode=danger_mode,
        audit_tag=audit_tag,
        command_context="guest",
    )

@mcp.tool()
async def vm_file_put(
    vmid: str,
    local_path: str,
    remote_path: str,
    actor: str = "mcp-agent",
    danger_mode: bool | Literal["safe", "maintenance", "break_glass"] = False,
    audit_tag: str | None = None,
) -> dict[str, Any]:
    """Upload a file to a VM."""
    command = _q_cmd("qm", "guest", "file", "write", vmid, remote_path, local_path)
    return await _run_with_policy(
        vmid=vmid,
        actor=actor,
        action="vm_file_put",
        command=command,
        execute=lambda: file_ops.put(vmid=vmid, local_path=local_path, remote_path=remote_path),
        danger_mode=danger_mode,
        audit_tag=audit_tag,
        command_context="guest",
    )

@mcp.tool()
async def vm_file_get(
    vmid: str,
    remote_path: str,
    actor: str = "mcp-agent",
    danger_mode: bool | Literal["safe", "maintenance", "break_glass"] = False,
    audit_tag: str | None = None,
) -> dict[str, Any]:
    """Read a file from a VM."""
    command = _q_cmd("qm", "guest", "exec", vmid, "--", "cat", remote_path)
    return await _run_with_policy(
        vmid=vmid,
        actor=actor,
        action="vm_file_get",
        command=command,
        execute=lambda: file_ops.get(vmid=vmid, remote_path=remote_path),
        danger_mode=danger_mode,
        audit_tag=audit_tag,
        command_context="guest",
    )

@mcp.tool()
async def vm_state(
    vmid: str,
    action: str,
    actor: str = "mcp-agent",
    danger_mode: bool | Literal["safe", "maintenance", "break_glass"] = False,
    audit_tag: str | None = None,
) -> dict[str, Any]:
    """Manage VM power state: status, start, stop, reboot, shutdown."""
    if action not in ["status", "start", "stop", "reboot", "shutdown"]:
        return {"ok": False, "error": f"Invalid action: {action}"}
    if action == "shutdown":
        return await _run_with_policy(
            vmid=vmid,
            actor=actor,
            action=f"vm_state:{action}",
            command=_q_cmd("qm", "shutdown", vmid),
            execute=lambda: proxmox.shutdown(vmid),
            danger_mode=danger_mode,
            audit_tag=audit_tag,
            command_context="host",
        )

    command = _q_cmd("qm", action, vmid)
    return await _run_with_policy(
        vmid=vmid,
        actor=actor,
        action=f"vm_state:{action}",
        command=command,
        execute=lambda: getattr(proxmox, action)(vmid),
        danger_mode=danger_mode,
        audit_tag=audit_tag,
        command_context="host",
    )


@mcp.tool()
async def vm_create(
    vmid: str,
    params: dict[str, str],
    actor: str = "mcp-agent",
    danger_mode: bool | Literal["safe", "maintenance", "break_glass"] = False,
    audit_tag: str | None = None,
) -> dict[str, Any]:
    """Create a new VM."""
    if not params:
        return {"ok": False, "error": "params must not be empty"}
    command_parts: list[str] = ["qm", "create", vmid]
    for key, value in params.items():
        command_parts.extend([f"-{key}", str(value)])
    return await _run_with_policy(
        vmid=vmid,
        actor=actor,
        action="vm_create",
        command=_q_cmd(*command_parts),
        execute=lambda: proxmox.create(vmid, params),
        danger_mode=danger_mode,
        audit_tag=audit_tag,
        command_context="host",
    )


@mcp.tool()
async def vm_clone(
    source_vmid: str,
    target_vmid: str,
    name: str | None = None,
    target_node: str | None = None,
    full_clone: bool = False,
    actor: str = "mcp-agent",
    danger_mode: bool | Literal["safe", "maintenance", "break_glass"] = False,
    audit_tag: str | None = None,
) -> dict[str, Any]:
    """Clone a VM."""
    command_parts: list[str] = ["qm", "clone", source_vmid, target_vmid]
    if name:
        command_parts.extend(["--name", name])
    if target_node:
        command_parts.extend(["--target", target_node])
    if full_clone:
        command_parts.append("--full")

    return await _run_with_policy(
        vmid=target_vmid,
        actor=actor,
        action="vm_clone",
        command=_q_cmd(*command_parts),
        execute=lambda: proxmox.clone(
            source_vmid=source_vmid,
            target_vmid=target_vmid,
            name=name,
            target_node=target_node,
            full_clone=full_clone,
        ),
        danger_mode=danger_mode,
        audit_tag=audit_tag,
        command_context="host",
    )


@mcp.tool()
async def vm_migrate(
    vmid: str,
    target_node: str,
    online: bool = True,
    actor: str = "mcp-agent",
    danger_mode: bool | Literal["safe", "maintenance", "break_glass"] = False,
    audit_tag: str | None = None,
) -> dict[str, Any]:
    """Migrate a VM."""
    return await _run_with_policy(
        vmid=vmid,
        actor=actor,
        action="vm_migrate",
        command=_q_cmd("qm", "migrate", vmid, target_node, "--online", "1" if online else "0"),
        execute=lambda: proxmox.migrate(vmid=vmid, target_node=target_node, online=online),
        danger_mode=danger_mode,
        audit_tag=audit_tag,
        command_context="host",
    )


@mcp.tool()
async def vm_backup(
    vmid: str,
    storage: str | None = None,
    mode: str = "snapshot",
    compress: str | None = None,
    remove: int | None = None,
    actor: str = "mcp-agent",
    danger_mode: bool | Literal["safe", "maintenance", "break_glass"] = False,
    audit_tag: str | None = None,
) -> dict[str, Any]:
    """Create a VM backup."""
    command_parts = ["vzdump", vmid, "--mode", mode]
    if storage:
        command_parts.extend(["--storage", storage])
    if compress:
        command_parts.extend(["--compress", compress])
    if remove is not None:
        command_parts.extend(["--remove", str(remove)])
    return await _run_with_policy(
        vmid=vmid,
        actor=actor,
        action="vm_backup",
        command=_q_cmd(*command_parts),
        execute=lambda: proxmox_backup.create(vmid=vmid, storage=storage, mode=mode, compress=compress, remove=remove),
        danger_mode=danger_mode,
        audit_tag=audit_tag,
        command_context="host",
    )

@mcp.tool()
async def vm_snapshot(
    vmid: str,
    action: str,
    name: str | None = None,
    actor: str = "mcp-agent",
    danger_mode: bool | Literal["safe", "maintenance", "break_glass"] = False,
    audit_tag: str | None = None,
) -> dict[str, Any]:
    """Manage VM snapshots: list, create, rollback, delete."""
    if action == "list":
        command = _q_cmd("qm", "listsnapshot", vmid)
        result = await _run_with_policy(
            vmid=vmid,
            actor=actor,
            action="vm_snapshot:list",
            command=command,
            execute=lambda: snapshot.list(vmid),
            danger_mode=danger_mode,
            audit_tag=audit_tag,
            command_context="host",
        )
        return result
    elif action == "create" and name:
        command = _q_cmd("qm", "snapshot", vmid, name)
        return await _run_with_policy(
            vmid=vmid,
            actor=actor,
            action="vm_snapshot:create",
            command=command,
            execute=lambda: snapshot.create(vmid, name),
            danger_mode=danger_mode,
            audit_tag=audit_tag,
            command_context="host",
        )
    elif action == "rollback" and name:
        command = _q_cmd("qm", "rollback", vmid, name)
        return await _run_with_policy(
            vmid=vmid,
            actor=actor,
            action="vm_snapshot:rollback",
            command=command,
            execute=lambda: snapshot.rollback(vmid, name),
            danger_mode=danger_mode,
            audit_tag=audit_tag,
            command_context="host",
        )
    elif action == "delete" and name:
        command = _q_cmd("qm", "delsnapshot", vmid, name)
        return await _run_with_policy(
            vmid=vmid,
            actor=actor,
            action="vm_snapshot:delete",
            command=command,
            execute=lambda: snapshot.delete(vmid, name),
            danger_mode=danger_mode,
            audit_tag=audit_tag,
            command_context="host",
        )
    else:
        return {"ok": False, "error": f"Invalid action or missing name: {action}"}

@mcp.tool()
async def vm_config(
    vmid: str,
    action: str,
    params: dict[str, str] | None = None,
    actor: str = "mcp-agent",
    danger_mode: bool | Literal["safe", "maintenance", "break_glass"] = False,
    audit_tag: str | None = None,
) -> dict[str, Any]:
    """Get or set VM configuration."""
    if action == "get":
        command = _q_cmd("qm", "config", vmid)
        return await _run_with_policy(
            vmid=vmid,
            actor=actor,
            action="vm_config:get",
            command=command,
            execute=lambda: proxmox_config.get(vmid),
            danger_mode=danger_mode,
            audit_tag=audit_tag,
            command_context="host",
        )
    elif action == "set" and params:
        command_parts: list[str] = ["qm", "set", vmid]
        for key, value in params.items():
            command_parts.extend([f"-{key}", str(value)])
        command = _q_cmd(*command_parts)
        return await _run_with_policy(
            vmid=vmid,
            actor=actor,
            action="vm_config:set",
            command=command,
            execute=lambda: proxmox_config.set(vmid, params),
            danger_mode=danger_mode,
            audit_tag=audit_tag,
            command_context="host",
        )
    else:
        return {"ok": False, "error": f"Invalid action or missing params: {action}"}

@mcp.tool()
async def vm_service(
    vmid: str,
    action: str,
    service_name: str,
    actor: str = "mcp-agent",
    danger_mode: bool | Literal["safe", "maintenance", "break_glass"] = False,
    audit_tag: str | None = None,
) -> dict[str, Any]:
    """Manage services in the guest: status, enable, disable, journal_tail."""
    if action == "status":
        guest_cmd = f"systemctl is-active {service_name}"
        return await _run_with_policy(
            vmid=vmid,
            actor=actor,
            action="vm_service:status",
            command=_guest_exec_command(vmid, guest_cmd),
            execute=lambda: gexec.exec(vmid=vmid, cmd=guest_cmd),
            danger_mode=danger_mode,
            audit_tag=audit_tag,
            command_context="guest",
        )
    if action == "enable":
        guest_cmd = f"systemctl enable {service_name}"
        return await _run_with_policy(
            vmid=vmid,
            actor=actor,
            action="vm_service:enable",
            command=_guest_exec_command(vmid, guest_cmd),
            execute=lambda: gexec.exec(vmid=vmid, cmd=guest_cmd),
            danger_mode=danger_mode,
            audit_tag=audit_tag,
            command_context="guest",
        )
    if action == "disable":
        guest_cmd = f"systemctl disable {service_name}"
        return await _run_with_policy(
            vmid=vmid,
            actor=actor,
            action="vm_service:disable",
            command=_guest_exec_command(vmid, guest_cmd),
            execute=lambda: gexec.exec(vmid=vmid, cmd=guest_cmd),
            danger_mode=danger_mode,
            audit_tag=audit_tag,
            command_context="guest",
        )
    if action == "journal_tail":
        guest_cmd = f"journalctl -u {service_name} -n 50 --no-pager"
        return await _run_with_policy(
            vmid=vmid,
            actor=actor,
            action="vm_service:journal_tail",
            command=_guest_exec_command(vmid, guest_cmd),
            execute=lambda: gexec.exec(vmid=vmid, cmd=guest_cmd),
            danger_mode=danger_mode,
            audit_tag=audit_tag,
            command_context="guest",
        )
    else:
        return {"ok": False, "error": f"Invalid action: {action}"}

@mcp.tool()
async def vm_docker(
    vmid: str,
    action: str,
    container: str | None = None,
    path: str | None = None,
    actor: str = "mcp-agent",
    danger_mode: bool | Literal["safe", "maintenance", "break_glass"] = False,
    audit_tag: str | None = None,
) -> dict[str, Any]:
    """Manage Docker containers in the guest: ps, logs, restart, compose_up."""
    if action == "ps":
        guest_cmd = "docker ps --format '{{.ID}}\\t{{.Names}}\\t{{.Status}}'"
        return await _run_with_policy(
            vmid=vmid,
            actor=actor,
            action="vm_docker:ps",
            command=_guest_exec_command(vmid, guest_cmd),
            execute=lambda: gexec.exec(vmid=vmid, cmd=guest_cmd),
            danger_mode=danger_mode,
            audit_tag=audit_tag,
            command_context="guest",
        )
    if action == "logs" and container:
        guest_cmd = f"docker logs --tail 50 {container}"
        return await _run_with_policy(
            vmid=vmid,
            actor=actor,
            action="vm_docker:logs",
            command=_guest_exec_command(vmid, guest_cmd),
            execute=lambda: gexec.exec(vmid=vmid, cmd=guest_cmd),
            danger_mode=danger_mode,
            audit_tag=audit_tag,
            command_context="guest",
        )
    if action == "restart" and container:
        guest_cmd = f"docker restart {container}"
        return await _run_with_policy(
            vmid=vmid,
            actor=actor,
            action="vm_docker:restart",
            command=_guest_exec_command(vmid, guest_cmd),
            execute=lambda: gexec.exec(vmid=vmid, cmd=guest_cmd),
            danger_mode=danger_mode,
            audit_tag=audit_tag,
            command_context="guest",
        )
    if action == "compose_up" and path:
        guest_cmd = f"docker-compose -f {path} up -d"
        return await _run_with_policy(
            vmid=vmid,
            actor=actor,
            action="vm_docker:compose_up",
            command=_guest_exec_command(vmid, guest_cmd),
            execute=lambda: gexec.exec(vmid=vmid, cmd=guest_cmd),
            danger_mode=danger_mode,
            audit_tag=audit_tag,
            command_context="guest",
        )
    else:
        return {"ok": False, "error": f"Invalid action or missing args: {action}"}

@mcp.tool()
async def vm_slo_check(
    vmid: str | None = None,
    services: list[str] | None = None,
    containers: list[str] | None = None,
    actor: str = "mcp-agent",
    danger_mode: bool | Literal["safe", "maintenance", "break_glass"] = False,
    audit_tag: str | None = None,
) -> dict[str, Any]:
    """Check SLO compliance for the system and optionally for a specific VM."""
    metrics_res = service.slo.check_metrics()
    guest_res = None
    if vmid:
        guest_res = await _guest_health_check(
            vmid=vmid,
            services=services or [],
            containers=containers or [],
            actor=actor,
            danger_mode=danger_mode,
            audit_tag=audit_tag,
        )

    final_ok = metrics_res.ok and (guest_res["ok"] if guest_res else True)
    output = {
        "ok": final_ok,
        "metrics": {"ok": metrics_res.ok, "details": metrics_res.details}
    }
    if guest_res:
        if audit_tag is not None:
            service.audit.log(
                actor=actor,
                action="vm_slo_check",
                vmid=vmid or "system",
                cmd="vm_slo_check",
                result=guest_res,
                audit_tag=audit_tag,
            )
        output["guest"] = guest_res
    return output

@mcp.tool()
def vm_metrics() -> dict[str, Any]:
    """Get system performance metrics."""
    return service.metrics_snapshot()

def main():
    mcp.run()

if __name__ == "__main__":
    main()
