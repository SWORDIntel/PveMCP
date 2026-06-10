from __future__ import annotations

import asyncio
import json
import os
import re
import shlex
import textwrap
from typing import Any, Callable, Literal

from fastmcp import FastMCP

from .service import VMService
from .proxmox import (
    ProxmoxBackup,
    ProxmoxConfig,
    ProxmoxFileOps,
    ProxmoxHostOps,
    ProxmoxGuestExec,
    ProxmoxLifecycle,
    ProxmoxSnapshot,
)
from .workflows import WorkflowManager, ArtifactIndex
from .models import CommandResult
from .metrics import Timer
from .vm_memory import (
    clear_vm_memory,
    _now,
    annotate_vm,
    list_all_vm_memories,
    load_vm_memory,
    memory_context_summary,
    record_history,
)
from .cloudinit import generate_user_data
from .replay import get_vm_history
from .federation import FederationManager

# Initialize FastMCP
mcp = FastMCP("PveMCP")

# Build the internal service
service = VMService.build(
    audit_path=os.getenv("PVEMCP_AUDIT_LOG", os.getenv("VM_MCP_AUDIT_LOG", "logs/audit.log")),
    use_host_sudo=True,
)
proxmox = ProxmoxLifecycle(runner=service.runner)
snapshot = ProxmoxSnapshot(runner=service.runner)
file_ops = ProxmoxFileOps(runner=service.runner)
host_ops = ProxmoxHostOps(runner=service.runner)
proxmox_config = ProxmoxConfig(runner=service.runner)
artifact_idx = ArtifactIndex()
proxmox_backup = ProxmoxBackup(runner=service.runner)
gexec = ProxmoxGuestExec(runner=service.runner)
workflow_mgr = WorkflowManager(service=service, file_ops=file_ops, gexec=gexec, artifact_idx=artifact_idx)
federation_mgr = FederationManager(service=service)


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


def _fmt(result: dict[str, Any], *, label: str = "") -> dict[str, Any]:
    """Produce a clean, human-readable summary envelope around a raw CommandResult dict.

    Strips empty fields, trims long stdout to 4 KB, and adds a 'summary' key
    with a one-line status so callers don't need to parse raw exit codes.
    It also handles qm guest exec JSON output to reflect the guest-side status.
    """
    ok: bool = bool(result.get("ok"))
    stdout: str = str(result.get("stdout") or "").strip()
    stderr: str = str(result.get("stderr") or "").strip()
    code: int = int(result.get("code", 0))
    duration: int = int(result.get("duration_ms", 0))
    vmid: str = str(result.get("vmid", ""))

    # If it looks like qm guest exec JSON, parse it
    guest_exit_code = None
    if ok and stdout.startswith("{") and stdout.endswith("}"):
        try:
            payload = json.loads(stdout)
            if isinstance(payload, dict) and "exitcode" in payload:
                guest_exit_code = payload["exitcode"]
                ok = (guest_exit_code == 0)
                stdout = str(payload.get("out-data") or "").strip()
                if not ok:
                    guest_stderr = str(payload.get("err-data") or "").strip()
                    if guest_stderr:
                        stderr = f"{stderr}\n{guest_stderr}".strip()
                    if not stderr:
                        stderr = f"Guest command failed with exit code {guest_exit_code}"
        except json.JSONDecodeError:
            pass

    # Truncate very long output
    if len(stdout) > 4096:
        stdout = stdout[:4096] + "\n... [truncated]"
    if len(stderr) > 1024:
        stderr = stderr[:1024] + "\n... [truncated]"

    status_icon = "\u2713" if ok else "\u2717"
    if guest_exit_code is not None:
        status = f"{status_icon} GUEST OK" if ok else f"{status_icon} GUEST FAILED (exit {guest_exit_code})"
    else:
        status = f"{status_icon} OK" if ok else f"{status_icon} FAILED (exit {code})"
    
    parts = [status]
    if label:
        parts = [f"[{label}] {status}"]
    if duration:
        parts.append(f"{duration}ms")

    out: dict[str, Any] = {"ok": ok, "summary": " | ".join(parts)}
    if stdout:
        out["output"] = stdout
    if stderr:
        out["error"] = stderr
    if guest_exit_code is not None:
        out["guest_exit_code"] = guest_exit_code
    if not ok:
        out["exit_code"] = code
    if vmid:
        out["vmid"] = vmid
    return out


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
    result = await _run_with_policy(
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
    return _fmt(result, label="exec")

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
    result = await _run_with_policy(
        vmid=vmid,
        actor=actor,
        action="vm_guest_exec",
        command=command,
        execute=lambda: gexec.exec(vmid=vmid, cmd=cmd, cwd=cwd, env=env, timeout=timeout),
        danger_mode=danger_mode,
        audit_tag=audit_tag,
        command_context="guest",
    )
    return _fmt(result, label="guest_exec")

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
    command = _q_cmd("qm", "guest", "file", "read", vmid, remote_path)
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

# ---------------------------------------------------------------------------
# VM MEMORY / CONTEXT TOOLS
# ---------------------------------------------------------------------------

@mcp.tool()
def vm_memory_get(vmid: str) -> dict[str, Any]:
    """Recall all stored knowledge about a VM: known paths, services, containers, notes, and recent command history.

    This is automatically useful when starting a session with a VM — it tells you what is already known
    so you don't need to rediscover the same things repeatedly.
    """
    rec = load_vm_memory(vmid)
    ctx = memory_context_summary(vmid)
    # Also include the last 5 history entries for quick context
    history = rec.get("history", [])[-5:]
    ctx["recent_history"] = history
    return ctx


@mcp.tool()
def vm_memory_set(
    vmid: str,
    notes: str | None = None,
    paths: dict[str, str] | None = None,
    services: list[str] | None = None,
    containers: list[str] | None = None,
    env: dict[str, str] | None = None,
    tags: list[str] | None = None,
) -> dict[str, Any]:
    """Save or update persistent knowledge about a VM.

    Use this to remember:
    - notes: free-form text about the VM's purpose or quirks
    - paths: labelled filesystem paths, e.g. {"app": "/opt/myapp", "config": "/etc/app.conf"}
    - services: systemd service names known to run on this VM
    - containers: Docker container names known on this VM
    - env: important environment variables or context strings
    - tags: descriptive tags like ["production", "nginx", "db"]

    Knowledge is merged (not replaced) with existing entries.
    """
    updated = annotate_vm(
        vmid,
        notes=notes,
        paths=paths,
        services=services,
        containers=containers,
        env=env,
        tags=tags,
    )
    return {
        "ok": True,
        "summary": f"Memory updated for VM {vmid}",
        "record": updated,
    }


@mcp.tool()
def vm_memory_list() -> dict[str, Any]:
    """List all VMs that have stored memory/context records, with a preview of what is known about each."""
    summaries = list_all_vm_memories()
    return {
        "ok": True,
        "count": len(summaries),
        "vms": summaries,
    }


@mcp.tool()
def vm_memory_clear(vmid: str) -> dict[str, Any]:
    """Clear all stored memory for a VM (resets notes, paths, services, containers, etc)."""
    if clear_vm_memory(vmid):
        return {"ok": True, "summary": f"Memory cleared for VM {vmid}"}
    return {"ok": True, "summary": f"No memory record found for VM {vmid} (nothing to clear)"}


# ---------------------------------------------------------------------------
# ENHANCED SEARCH / INSPECTION TOOLS
# ---------------------------------------------------------------------------

@mcp.tool()
async def vm_ripgrep(
    vmid: str,
    pattern: str,
    path: str = "/",
    file_glob: str | None = None,
    case_insensitive: bool = False,
    max_results: int = 50,
    actor: str = "mcp-agent",
    danger_mode: bool | Literal["safe", "maintenance", "break_glass"] = False,
    audit_tag: str | None = None,
) -> dict[str, Any]:
    """Run ripgrep (rg) inside a VM guest to search file contents by pattern.

    Returns matched file paths, line numbers, and snippets — much faster and more useful than grep.
    Requires ripgrep to be installed in the guest. Falls back to grep if rg is not found.

    Examples:
    - Find all occurrences of 'SECRET_KEY' under /etc: pattern='SECRET_KEY', path='/etc'
    - Find Python files importing 'requests': pattern='import requests', file_glob='*.py'
    """
    rg_parts = ["rg", "--line-number", "--no-heading", f"--max-count={max_results}"]
    if case_insensitive:
        rg_parts.append("-i")
    if file_glob:
        rg_parts.extend(["--glob", file_glob])
    rg_parts.extend([pattern, path])
    rg_cmd = " ".join(shlex.quote(p) for p in rg_parts)

    command = _guest_exec_command(vmid=vmid, cmd=rg_cmd)
    result = await _run_with_policy(
        vmid=vmid,
        actor=actor,
        action="vm_ripgrep",
        command=command,
        execute=lambda: gexec.exec(vmid=vmid, cmd=rg_cmd),
        danger_mode=danger_mode,
        audit_tag=audit_tag,
        command_context="guest",
    )
    stdout = _guest_stdout(str(result.get("stdout", "")))

    # If rg not found, fall back to grep
    if not result.get("ok") and "command not found" in str(result.get("stderr", "")).lower():
        grep_parts = ["grep", "-rn"]
        if case_insensitive:
            grep_parts.append("-i")
        grep_parts.extend([pattern, path])
        if file_glob:
            grep_parts.extend(["--include", file_glob])
        grep_cmd = " ".join(shlex.quote(p) for p in grep_parts)
        command = _guest_exec_command(vmid=vmid, cmd=grep_cmd)
        result = await _run_with_policy(
            vmid=vmid,
            actor=actor,
            action="vm_ripgrep:fallback_grep",
            command=command,
            execute=lambda: gexec.exec(vmid=vmid, cmd=grep_cmd),
            danger_mode=danger_mode,
            audit_tag=audit_tag,
            command_context="guest",
        )
        stdout = _guest_stdout(str(result.get("stdout", "")))

    lines = [l for l in stdout.splitlines() if l.strip()]
    fmt = _fmt(result, label=f"rg:{pattern}")
    fmt["matches"] = lines[:max_results]
    fmt["match_count"] = len(lines)
    fmt["search_path"] = path
    fmt["pattern"] = pattern
    return fmt


@mcp.tool()
async def vm_find(
    vmid: str,
    path: str = "/",
    name: str | None = None,
    file_type: str | None = None,
    mtime_days: int | None = None,
    size_gt: str | None = None,
    max_depth: int | None = None,
    actor: str = "mcp-agent",
    danger_mode: bool | Literal["safe", "maintenance", "break_glass"] = False,
    audit_tag: str | None = None,
) -> dict[str, Any]:
    """Run find inside a VM guest to locate files by name, type, age, or size.

    - name: filename pattern e.g. '*.conf' or 'app.py'
    - file_type: 'f' (file), 'd' (directory), 'l' (symlink)
    - mtime_days: files modified within N days
    - size_gt: files larger than e.g. '10M' or '1G'
    - max_depth: limit directory traversal depth
    """
    parts = ["find", path]
    if max_depth is not None:
        parts.extend(["-maxdepth", str(max_depth)])
    if file_type:
        parts.extend(["-type", file_type])
    if name:
        parts.extend(["-name", name])
    if mtime_days is not None:
        parts.extend(["-mtime", f"-{mtime_days}"])
    if size_gt:
        parts.extend(["-size", f"+{size_gt}"])
    cmd = " ".join(shlex.quote(p) for p in parts)

    command = _guest_exec_command(vmid=vmid, cmd=cmd)
    result = await _run_with_policy(
        vmid=vmid,
        actor=actor,
        action="vm_find",
        command=command,
        execute=lambda: gexec.exec(vmid=vmid, cmd=cmd),
        danger_mode=danger_mode,
        audit_tag=audit_tag,
        command_context="guest",
    )
    stdout = _guest_stdout(str(result.get("stdout", "")))
    files = [l for l in stdout.splitlines() if l.strip()]
    fmt = _fmt(result, label="find")
    fmt["files"] = files
    fmt["count"] = len(files)
    return fmt


# ---------------------------------------------------------------------------
# PROCESS / RESOURCE INSPECTION
# ---------------------------------------------------------------------------

@mcp.tool()
async def vm_ps(
    vmid: str,
    filter_name: str | None = None,
    actor: str = "mcp-agent",
    danger_mode: bool | Literal["safe", "maintenance", "break_glass"] = False,
    audit_tag: str | None = None,
) -> dict[str, Any]:
    """List running processes inside a VM guest. Optionally filter by process name substring.

    Returns a structured list of processes with PID, user, CPU%, MEM%, and command.
    """
    ps_cmd = "ps aux --no-header"
    command = _guest_exec_command(vmid=vmid, cmd=ps_cmd)
    result = await _run_with_policy(
        vmid=vmid,
        actor=actor,
        action="vm_ps",
        command=command,
        execute=lambda: gexec.exec(vmid=vmid, cmd=ps_cmd),
        danger_mode=danger_mode,
        audit_tag=audit_tag,
        command_context="guest",
    )
    stdout = _guest_stdout(str(result.get("stdout", "")))
    processes = []
    for line in stdout.splitlines():
        parts = line.split(None, 10)
        if len(parts) >= 11:
            entry = {
                "user": parts[0],
                "pid": parts[1],
                "cpu": parts[2],
                "mem": parts[3],
                "cmd": parts[10],
            }
            if filter_name is None or filter_name.lower() in entry["cmd"].lower():
                processes.append(entry)
    fmt = _fmt(result, label="ps")
    fmt["processes"] = processes
    fmt["count"] = len(processes)
    return fmt


@mcp.tool()
async def vm_top(
    vmid: str,
    lines: int = 20,
    actor: str = "mcp-agent",
    danger_mode: bool | Literal["safe", "maintenance", "break_glass"] = False,
    audit_tag: str | None = None,
) -> dict[str, Any]:
    """Show top resource consumers inside a VM guest (CPU and memory).

    Returns the top N processes sorted by CPU usage, plus system load and memory overview.
    """
    # Use ps to get sorted process list (more reliable in non-interactive context)
    top_cmd = f"ps aux --no-header --sort=-%cpu | head -{lines}"
    mem_cmd = "free -h"
    load_cmd = "cat /proc/loadavg"

    top_command = _guest_exec_command(vmid=vmid, cmd=top_cmd)
    top_result = await _run_with_policy(
        vmid=vmid, actor=actor, action="vm_top:ps",
        command=top_command,
        execute=lambda: gexec.exec(vmid=vmid, cmd=top_cmd),
        danger_mode=danger_mode, audit_tag=audit_tag, command_context="guest",
    )
    mem_command = _guest_exec_command(vmid=vmid, cmd=mem_cmd)
    mem_result = await _run_with_policy(
        vmid=vmid, actor=actor, action="vm_top:mem",
        command=mem_command,
        execute=lambda: gexec.exec(vmid=vmid, cmd=mem_cmd),
        danger_mode=danger_mode, audit_tag=audit_tag, command_context="guest",
    )
    load_command = _guest_exec_command(vmid=vmid, cmd=load_cmd)
    load_result = await _run_with_policy(
        vmid=vmid, actor=actor, action="vm_top:load",
        command=load_command,
        execute=lambda: gexec.exec(vmid=vmid, cmd=load_cmd),
        danger_mode=danger_mode, audit_tag=audit_tag, command_context="guest",
    )

    top_stdout = _guest_stdout(str(top_result.get("stdout", "")))
    processes = []
    for line in top_stdout.splitlines():
        parts = line.split(None, 10)
        if len(parts) >= 11:
            processes.append({"user": parts[0], "pid": parts[1], "cpu": parts[2], "mem": parts[3], "cmd": parts[10]})

    return {
        "ok": top_result.get("ok", False),
        "summary": f"Top {lines} processes by CPU",
        "vmid": vmid,
        "load_avg": _guest_stdout(str(load_result.get("stdout", ""))).strip(),
        "memory": _guest_stdout(str(mem_result.get("stdout", ""))).strip(),
        "top_processes": processes,
    }


@mcp.tool()
async def vm_disk(
    vmid: str,
    actor: str = "mcp-agent",
    danger_mode: bool | Literal["safe", "maintenance", "break_glass"] = False,
    audit_tag: str | None = None,
) -> dict[str, Any]:
    """Show disk usage inside a VM guest: df -h summary and top 10 largest directories."""
    df_cmd = "df -h --output=source,fstype,size,used,avail,pcent,target"
    du_cmd = "du -sh /* 2>/dev/null | sort -rh | head -10"

    df_command = _guest_exec_command(vmid=vmid, cmd=df_cmd)
    df_result = await _run_with_policy(
        vmid=vmid, actor=actor, action="vm_disk:df",
        command=df_command,
        execute=lambda: gexec.exec(vmid=vmid, cmd=df_cmd),
        danger_mode=danger_mode, audit_tag=audit_tag, command_context="guest",
    )
    du_command = _guest_exec_command(vmid=vmid, cmd=du_cmd)
    du_result = await _run_with_policy(
        vmid=vmid, actor=actor, action="vm_disk:du",
        command=du_command,
        execute=lambda: gexec.exec(vmid=vmid, cmd=du_cmd),
        danger_mode=danger_mode, audit_tag=audit_tag, command_context="guest",
    )

    return {
        "ok": df_result.get("ok", False),
        "summary": "Disk usage overview",
        "vmid": vmid,
        "filesystems": _guest_stdout(str(df_result.get("stdout", ""))).strip(),
        "largest_directories": _guest_stdout(str(du_result.get("stdout", ""))).strip(),
    }


@mcp.tool()
async def vm_network(
    vmid: str,
    actor: str = "mcp-agent",
    danger_mode: bool | Literal["safe", "maintenance", "break_glass"] = False,
    audit_tag: str | None = None,
) -> dict[str, Any]:
    """Show network configuration and active connections inside a VM guest.

    Returns: IP addresses, routing table summary, listening ports, and active connections.
    """
    ip_cmd = "ip -brief addr"
    route_cmd = "ip route"
    ss_cmd = "ss -tlnp"

    async def _g(cmd: str, action: str) -> str:
        c = _guest_exec_command(vmid=vmid, cmd=cmd)
        r = await _run_with_policy(
            vmid=vmid, actor=actor, action=action,
            command=c, execute=lambda cmd=cmd: gexec.exec(vmid=vmid, cmd=cmd),
            danger_mode=danger_mode, audit_tag=audit_tag, command_context="guest",
        )
        return _guest_stdout(str(r.get("stdout", ""))).strip()

    ip_out, route_out, ss_out = await asyncio.gather(
        _g(ip_cmd, "vm_network:ip"),
        _g(route_cmd, "vm_network:route"),
        _g(ss_cmd, "vm_network:ss"),
    )

    return {
        "ok": True,
        "summary": "Network configuration",
        "vmid": vmid,
        "interfaces": ip_out,
        "routes": route_out,
        "listening_ports": ss_out,
    }


@mcp.tool()
async def vm_tail(
    vmid: str,
    path: str,
    lines: int = 50,
    actor: str = "mcp-agent",
    danger_mode: bool | Literal["safe", "maintenance", "break_glass"] = False,
    audit_tag: str | None = None,
) -> dict[str, Any]:
    """Tail the last N lines of a log file inside a VM guest.

    More explicit and clear than vm_guest_exec with cat/tail.
    Also records the path in VM memory for future sessions.
    """
    tail_cmd = f"tail -n {int(lines)} {shlex.quote(path)}"
    command = _guest_exec_command(vmid=vmid, cmd=tail_cmd)
    result = await _run_with_policy(
        vmid=vmid, actor=actor, action="vm_tail",
        command=command,
        execute=lambda: gexec.exec(vmid=vmid, cmd=tail_cmd),
        danger_mode=danger_mode, audit_tag=audit_tag, command_context="guest",
    )
    stdout = _guest_stdout(str(result.get("stdout", "")))
    fmt = _fmt(result, label=f"tail:{path}")
    fmt["path"] = path
    fmt["lines_returned"] = len(stdout.splitlines())
    return fmt


@mcp.tool()
async def vm_write(
    vmid: str,
    path: str,
    content: str,
    mode: str = "write",
    actor: str = "mcp-agent",
    danger_mode: bool | Literal["safe", "maintenance", "break_glass"] = False,
    audit_tag: str | None = None,
) -> dict[str, Any]:
    """Write or append text content to a file inside a VM guest.

    - mode='write': overwrite the file with content
    - mode='append': append content to the file

    More convenient than vm_file_put for small text files or config snippets.
    """
    if mode not in ("write", "append"):
        return {"ok": False, "summary": f"Invalid mode: {mode}. Use 'write' or 'append'."}

    # Escape content for safe shell embedding
    import base64 as _b64
    encoded = _b64.b64encode(content.encode("utf-8")).decode("ascii")
    redirect = ">" if mode == "write" else ">>"
    write_cmd = f"python3 -c \"import base64,sys; sys.stdout.buffer.write(base64.b64decode('{encoded}'))\" {redirect} {shlex.quote(path)}"
    command = _guest_exec_command(vmid=vmid, cmd=write_cmd)
    result = await _run_with_policy(
        vmid=vmid, actor=actor, action="vm_write",
        command=command,
        execute=lambda: gexec.exec(vmid=vmid, cmd=write_cmd),
        danger_mode=danger_mode, audit_tag=audit_tag, command_context="guest",
    )
    return _fmt(result, label=f"write:{path}")


@mcp.tool()
async def vm_env(
    vmid: str,
    actor: str = "mcp-agent",
    danger_mode: bool | Literal["safe", "maintenance", "break_glass"] = False,
    audit_tag: str | None = None,
) -> dict[str, Any]:
    """Dump the environment variables of the default shell inside a VM guest.

    Useful for quickly understanding what env vars, PATH entries, and proxies are set.
    Secrets are automatically redacted from the output.
    """
    env_cmd = "env"
    command = _guest_exec_command(vmid=vmid, cmd=env_cmd)
    result = await _run_with_policy(
        vmid=vmid, actor=actor, action="vm_env",
        command=command,
        execute=lambda: gexec.exec(vmid=vmid, cmd=env_cmd),
        danger_mode=danger_mode, audit_tag=audit_tag, command_context="guest",
    )
    stdout = _guest_stdout(str(result.get("stdout", "")))
    env_vars: dict[str, str] = {}
    for line in stdout.splitlines():
        if "=" in line:
            k, _, v = line.partition("=")
            env_vars[k.strip()] = v
    fmt = _fmt(result, label="env")
    fmt["env"] = env_vars
    fmt["var_count"] = len(env_vars)
    return fmt


@mcp.tool()
async def vm_bootstrap(
    vmid: str,
    user_data_yaml: str,
    filename: str | None = None,
    auto_start: bool = True,
    actor: str = "mcp-agent",
    danger_mode: bool | Literal["safe", "maintenance", "break_glass"] = False,
    audit_tag: str | None = None,
) -> dict[str, Any]:
    """Bootstrap a VM using a custom cloud-init user-data snippet.
    
    This acts as a 'Cloud-init Factory'. It securely stages the YAML on the host, 
    attaches it to the VM via cicustom, and optionally boots the VM.
    
    Use this to dynamically provision packages, users, and services on first boot.
    """
    if not filename:
        filename = f"mcp-bootstrap-{vmid}.yaml"
        
    # 1. Write the snippet to the host
    write_cmd = _q_cmd("host", "write_snippet", filename)
    write_res = await _run_with_policy(
        vmid="0", actor=actor, action="host_write_snippet", command=write_cmd,
        execute=lambda: host_ops.write_snippet(filename, user_data_yaml),
        danger_mode=danger_mode, audit_tag=audit_tag, command_context="host"
    )
    if not write_res.get("ok"):
        return _fmt(write_res, label="bootstrap:stage")

    # 2. Attach it to the VM
    attach_cmd = _q_cmd("qm", "set", vmid, "--cicustom", f"user=local:snippets/{filename}")
    attach_res = await _run_with_policy(
        vmid=vmid, actor=actor, action="vm_config_set", command=attach_cmd,
        execute=lambda: proxmox_config.set(vmid, {"cicustom": f"user=local:snippets/{filename}"}),
        danger_mode=danger_mode, audit_tag=audit_tag, command_context="host"
    )
    if not attach_res.get("ok"):
         return _fmt(attach_res, label="bootstrap:attach")

    # 3. Start the VM if requested
    if auto_start:
        start_cmd = _q_cmd("qm", "start", vmid)
        start_res = await _run_with_policy(
            vmid=vmid, actor=actor, action="vm_start", command=start_cmd,
            execute=lambda: proxmox.start(vmid),
            danger_mode=danger_mode, audit_tag=audit_tag, command_context="host"
        )
        return _fmt(start_res, label="bootstrap:complete")
        
    return _fmt(attach_res, label="bootstrap:staged")


@mcp.tool()
async def vm_console_read(
    vmid: str,
    timeout: float = 2.0,
    actor: str = "mcp-agent",
    danger_mode: bool | Literal["safe", "maintenance", "break_glass"] = False,
    audit_tag: str | None = None,
) -> dict[str, Any]:
    """Read the recent output from the VM's serial console socket.
    
    This is extremely useful for diagnosing 'black box' failures (e.g., stuck at GRUB, 
    kernel panic, or network dead) where SSH or QEMU Guest Agent are unreachable.
    Requires 'serial0: socket' to be configured on the VM.
    """
    command = _q_cmd("qm", "terminal", vmid, "--dump") # Symbolic command for audit log
    result = await _run_with_policy(
        vmid=vmid,
        actor=actor,
        action="vm_console_read",
        command=command,
        execute=lambda: host_ops.read_serial_console(vmid=vmid, timeout=timeout),
        danger_mode=danger_mode,
        audit_tag=audit_tag,
        command_context="host",
    )
    return _fmt(result, label="console")

@mcp.tool()
async def vm_network_audit(
    vmid: str,
    actor: str = "mcp-agent",
    danger_mode: bool | Literal["safe", "maintenance", "break_glass"] = False,
    audit_tag: str | None = None,
) -> dict[str, Any]:
    """Perform an end-to-end network path audit for a VM.
    
    This tool cross-references host-side bridge and firewall configurations with 
    guest-side network state to diagnose 'black box' connectivity failures.
    
    Returns a combined report of:
    1. Host: PVE Firewall rules for the VM
    2. Host: Bridge forwarding database (FDB) entries
    3. Guest: Internal firewall (nftables/iptables) and routing state
    """
    import asyncio
    
    async def _host_exec(cmd_name: str, args: list[str]) -> str:
        cmd_str = _q_cmd(*args)
        res = await _run_with_policy(
            vmid=vmid, actor=actor, action=f"audit_host_{cmd_name}", command=cmd_str,
            execute=lambda c=cmd_str: service.runner.run(vmid="0", cmd=c),
            danger_mode=danger_mode, audit_tag=audit_tag, command_context="host"
        )
        return str(res.get("stdout") or res.get("stderr") or "").strip()

    async def _guest_exec(cmd: str) -> str:
        cmd_str = _guest_exec_command(vmid=vmid, cmd=cmd)
        res = await _run_with_policy(
            vmid=vmid, actor=actor, action="audit_guest_net", command=cmd_str,
            execute=lambda c=cmd_str: gexec.exec(vmid=vmid, cmd=c),
            danger_mode=danger_mode, audit_tag=audit_tag, command_context="guest"
        )
        return _guest_stdout(str(res.get("stdout") or res.get("stderr") or "")).strip()

    # Gather data in parallel where possible
    # We use 'cat /etc/pve/firewall/{vmid}.fw' as reading the file is safer than raw iptables dumps
    host_fw, host_fdb, guest_fw, guest_routes = await asyncio.gather(
        _host_exec("cat", ["cat", f"/etc/pve/firewall/{vmid}.fw"]),
        _host_exec("bridge", ["bridge", "fdb", "show"]),
        _guest_exec("nft list ruleset 2>/dev/null || iptables-save 2>/dev/null"),
        _guest_exec("ip route"),
        return_exceptions=True
    )
    
    def _clean(val: Any) -> str:
        if isinstance(val, Exception):
            return f"Error: {val}"
        return val if val else "(empty/none)"

    return {
        "ok": True,
        "vmid": vmid,
        "host_pve_firewall": _clean(host_fw),
        "host_bridge_fdb": _clean(host_fdb),
        "guest_firewall": _clean(guest_fw),
        "guest_routes": _clean(guest_routes),
        "summary": "Network audit completed. Review fields for discrepancies."
    }

@mcp.tool()
async def vm_list(
    actor: str = "mcp-agent",
    danger_mode: bool | Literal["safe", "maintenance", "break_glass"] = False,
    audit_tag: str | None = None,
) -> dict[str, Any]:
    """List all VMs on the Proxmox host with their status, name, and resource usage.

    Runs 'qm list' on the host. Cross-references with stored VM memory records to show
    which VMs have saved context.
    """
    cmd = "qm list"
    result = await _run_with_policy(
        vmid="host",
        actor=actor,
        action="vm_list",
        command=cmd,
        execute=lambda: service.exec(vmid="host", cmd=cmd, actor=actor, danger_mode=danger_mode,
                                       audit_tag=audit_tag, action="vm_list",
                                       skip_policy=True, skip_audit=True, skip_metrics=True),
        danger_mode=danger_mode,
        audit_tag=audit_tag,
        command_context="host",
    )
    stdout = str(result.get("stdout") or "").strip()
    vms = []
    memories = {m["vmid"]: m for m in list_all_vm_memories()}
    for line in stdout.splitlines()[1:]:  # skip header
        parts = line.split()
        if parts:
            vmid = parts[0]
            entry: dict[str, Any] = {
                "vmid": vmid,
                "name": parts[1] if len(parts) > 1 else "",
                "status": parts[2] if len(parts) > 2 else "",
                "mem": parts[3] if len(parts) > 3 else "",
                "bootdisk": parts[4] if len(parts) > 4 else "",
                "pid": parts[5] if len(parts) > 5 else "",
            }
            if vmid in memories:
                entry["memory"] = {
                    "tags": memories[vmid].get("tags", []),
                    "notes_preview": memories[vmid].get("notes_preview", ""),
                    "known_services": memories[vmid].get("known_services", []),
                }
            vms.append(entry)
    fmt = _fmt(result, label="qm list")
    fmt["vms"] = vms
    fmt["count"] = len(vms)
    return fmt


@mcp.tool()
async def vm_port_check(
    vmid: str,
    port: int,
    host: str = "127.0.0.1",
    actor: str = "mcp-agent",
    danger_mode: bool | Literal["safe", "maintenance", "break_glass"] = False,
    audit_tag: str | None = None,
) -> dict[str, Any]:
    """Check whether a TCP port is open/listening inside a VM guest.

    Uses ss to check if the port is bound. Returns whether it is listening
    and which process owns it.
    """
    ss_cmd = f"ss -tlnp 'sport = :{port}'"
    command = _guest_exec_command(vmid=vmid, cmd=ss_cmd)
    result = await _run_with_policy(
        vmid=vmid, actor=actor, action="vm_port_check",
        command=command,
        execute=lambda: gexec.exec(vmid=vmid, cmd=ss_cmd),
        danger_mode=danger_mode, audit_tag=audit_tag, command_context="guest",
    )
    stdout = _guest_stdout(str(result.get("stdout", ""))).strip()
    lines = [l for l in stdout.splitlines() if l.strip() and "State" not in l]
    listening = len(lines) > 0
    return {
        "ok": result.get("ok", False),
        "summary": f"Port {port}: {'LISTENING' if listening else 'NOT listening'}",
        "vmid": vmid,
        "port": port,
        "listening": listening,
        "details": lines,
    }


@mcp.tool()
async def vm_service_restart(
    vmid: str,
    service_name: str,
    actor: str = "mcp-agent",
    danger_mode: bool | Literal["safe", "maintenance", "break_glass"] = False,
    audit_tag: str | None = None,
) -> dict[str, Any]:
    """Restart a systemd service inside a VM guest and return status after restart."""
    restart_cmd = f"systemctl restart {service_name}"
    status_cmd = f"systemctl status {service_name} --no-pager -l"

    command = _guest_exec_command(vmid=vmid, cmd=restart_cmd)
    restart_result = await _run_with_policy(
        vmid=vmid, actor=actor, action="vm_service_restart:restart",
        command=command,
        execute=lambda: gexec.exec(vmid=vmid, cmd=restart_cmd),
        danger_mode=danger_mode, audit_tag=audit_tag, command_context="guest",
    )

    status_command = _guest_exec_command(vmid=vmid, cmd=status_cmd)
    status_result = await _run_with_policy(
        vmid=vmid, actor=actor, action="vm_service_restart:status",
        command=status_command,
        execute=lambda: gexec.exec(vmid=vmid, cmd=status_cmd),
        danger_mode=danger_mode, audit_tag=audit_tag, command_context="guest",
    )

    ok = restart_result.get("ok", False)
    return {
        "ok": ok,
        "summary": f"Service '{service_name}' {'restarted OK' if ok else 'FAILED to restart'}",
        "vmid": vmid,
        "service": service_name,
        "status_after": _guest_stdout(str(status_result.get("stdout", ""))).strip(),
        "restart_error": _guest_stdout(str(restart_result.get("stderr", ""))).strip() if not ok else None,
    }


@mcp.tool()
async def vm_install_package(
    vmid: str,
    package: str,
    manager: str = "apt",
    actor: str = "mcp-agent",
    danger_mode: bool | Literal["safe", "maintenance", "break_glass"] = False,
    audit_tag: str | None = None,
) -> dict[str, Any]:
    """Install a package inside a VM guest using the specified package manager.

    - manager: 'apt' (Debian/Ubuntu), 'yum' or 'dnf' (RHEL/CentOS/Fedora), 'apk' (Alpine)

    Runs non-interactively with -y. Requires root/sudo in the guest.
    """
    if manager == "apt":
        cmd = f"DEBIAN_FRONTEND=noninteractive apt-get install -y {shlex.quote(package)}"
    elif manager == "yum":
        cmd = f"yum install -y {shlex.quote(package)}"
    elif manager == "dnf":
        cmd = f"dnf install -y {shlex.quote(package)}"
    elif manager == "apk":
        cmd = f"apk add --no-cache {shlex.quote(package)}"
    else:
        return {"ok": False, "summary": f"Unknown package manager: {manager}. Use apt, yum, dnf, or apk."}

    command = _guest_exec_command(vmid=vmid, cmd=cmd)
    result = await _run_with_policy(
        vmid=vmid, actor=actor, action="vm_install_package",
        command=command,
        execute=lambda: gexec.exec(vmid=vmid, cmd=cmd),
        danger_mode=danger_mode, audit_tag=audit_tag, command_context="guest",
    )
    return _fmt(result, label=f"install:{package}")


@mcp.tool()
async def vm_sysinfo(
    vmid: str,
    actor: str = "mcp-agent",
    danger_mode: bool | Literal["safe", "maintenance", "break_glass"] = False,
    audit_tag: str | None = None,
) -> dict[str, Any]:
    """Get a comprehensive system information snapshot from a VM guest.

    Returns: OS info, kernel, uptime, CPU count, memory, disk, hostname, and IP addresses.
    Auto-saves basic context to VM memory.
    """
    cmds = {
        "os": "cat /etc/os-release 2>/dev/null || cat /etc/issue",
        "kernel": "uname -r",
        "uptime": "uptime -p 2>/dev/null || uptime",
        "cpu": "nproc",
        "hostname": "hostname -f 2>/dev/null || hostname",
        "ip": "ip -brief addr",
        "mem": "free -h | head -2",
        "df": "df -h --output=target,size,avail,pcent | head -10",
    }

    results: dict[str, str] = {}
    for key, cmd in cmds.items():
        guest_cmd = _guest_exec_command(vmid=vmid, cmd=cmd)
        r = await _run_with_policy(
            vmid=vmid, actor=actor, action=f"vm_sysinfo:{key}",
            command=guest_cmd,
            execute=lambda cmd=cmd: gexec.exec(vmid=vmid, cmd=cmd),
            danger_mode=danger_mode, audit_tag=audit_tag, command_context="guest",
        )
        results[key] = _guest_stdout(str(r.get("stdout", ""))).strip()

    # Auto-annotate VM memory with hostname
    if results.get("hostname"):
        annotate_vm(vmid, env={"hostname": results["hostname"]})

    return {
        "ok": True,
        "summary": f"System info for VM {vmid}",
        "vmid": vmid,
        "hostname": results.get("hostname", ""),
        "os": results.get("os", ""),
        "kernel": results.get("kernel", ""),
        "uptime": results.get("uptime", ""),
        "cpu_cores": results.get("cpu", ""),
        "memory": results.get("mem", ""),
        "disk": results.get("df", ""),
        "network": results.get("ip", ""),
    }


# ---------------------------------------------------------------------------
# KERNEL / SYSTEM LOGS
# ---------------------------------------------------------------------------

@mcp.tool()
async def vm_dmesg(
    vmid: str,
    level: str | None = None,
    lines: int = 50,
    actor: str = "mcp-agent",
    danger_mode: bool | Literal["safe", "maintenance", "break_glass"] = False,
    audit_tag: str | None = None,
) -> dict[str, Any]:
    """Read the kernel ring buffer (dmesg) from inside a VM guest.

    Reveals OOM kills, hardware errors, driver issues, and disk failures that
    don't appear in application logs.

    - level: filter by severity — 'err', 'warn', 'info', 'debug' (uses dmesg -l)
    - lines: how many recent lines to return (default 50)
    """
    parts = ["dmesg", "--time-format=reltime", f"--level={'err,warn' if level is None else level}",
             "-T"]
    # Tail via shell pipe since dmesg has no --tail
    cmd = " ".join(shlex.quote(p) for p in parts) + f" | tail -n {int(lines)}"
    command = _guest_exec_command(vmid=vmid, cmd=cmd)
    result = await _run_with_policy(
        vmid=vmid, actor=actor, action="vm_dmesg",
        command=command,
        execute=lambda: gexec.exec(vmid=vmid, cmd=cmd),
        danger_mode=danger_mode, audit_tag=audit_tag, command_context="guest",
    )
    stdout = _guest_stdout(str(result.get("stdout", "")))
    fmt = _fmt(result, label="dmesg")
    fmt["lines"] = stdout.splitlines()
    fmt["line_count"] = len(fmt["lines"])
    return fmt


@mcp.tool()
async def vm_journal(
    vmid: str,
    unit: str | None = None,
    lines: int = 100,
    priority: str | None = None,
    since: str | None = None,
    grep: str | None = None,
    actor: str = "mcp-agent",
    danger_mode: bool | Literal["safe", "maintenance", "break_glass"] = False,
    audit_tag: str | None = None,
) -> dict[str, Any]:
    """Query the systemd journal inside a VM guest with rich filtering.

    More powerful than vm_service's journal_tail — supports cross-unit queries,
    priority filtering, time windows, and text grep.

    - unit: service name e.g. 'nginx' or 'docker' (omit for all units)
    - lines: number of recent lines (default 100)
    - priority: 'emerg','alert','crit','err','warning','notice','info','debug'
    - since: time string e.g. '1 hour ago', '2026-01-01 00:00:00', '-30m'
    - grep: filter output lines by regex pattern
    """
    parts = ["journalctl", "--no-pager", "-n", str(int(lines)), "--output=short-precise"]
    if unit:
        parts.extend(["-u", unit])
    if priority:
        parts.extend(["-p", priority])
    if since:
        parts.extend(["--since", since])
    if grep:
        parts.extend(["--grep", grep])
    cmd = " ".join(shlex.quote(p) for p in parts)
    command = _guest_exec_command(vmid=vmid, cmd=cmd)
    result = await _run_with_policy(
        vmid=vmid, actor=actor, action="vm_journal",
        command=command,
        execute=lambda: gexec.exec(vmid=vmid, cmd=cmd),
        danger_mode=danger_mode, audit_tag=audit_tag, command_context="guest",
    )
    stdout = _guest_stdout(str(result.get("stdout", "")))
    fmt = _fmt(result, label=f"journal{':'+unit if unit else ''}")
    fmt["entries"] = stdout.splitlines()
    fmt["entry_count"] = len(fmt["entries"])
    return fmt


# ---------------------------------------------------------------------------
# PROCESS / FILE HANDLE INSPECTION
# ---------------------------------------------------------------------------

@mcp.tool()
async def vm_lsof(
    vmid: str,
    pid: int | None = None,
    port: int | None = None,
    path: str | None = None,
    actor: str = "mcp-agent",
    danger_mode: bool | Literal["safe", "maintenance", "break_glass"] = False,
    audit_tag: str | None = None,
) -> dict[str, Any]:
    """List open files and sockets inside a VM guest.

    Use cases:
    - Find which process holds a file open: path='/var/log/app.log'
    - Find which process owns a port: port=8080
    - See all file handles for a process: pid=1234
    - No args: list everything (can be large)
    """
    parts = ["lsof", "-n", "-P"]
    if pid is not None:
        parts.extend(["-p", str(pid)])
    if port is not None:
        parts.extend([f"-i:{port}"])
    if path:
        parts.append(shlex.quote(path))
    cmd = " ".join(shlex.quote(p) if not p.startswith("-i") else p for p in parts)
    command = _guest_exec_command(vmid=vmid, cmd=cmd)
    result = await _run_with_policy(
        vmid=vmid, actor=actor, action="vm_lsof",
        command=command,
        execute=lambda: gexec.exec(vmid=vmid, cmd=cmd),
        danger_mode=danger_mode, audit_tag=audit_tag, command_context="guest",
    )
    stdout = _guest_stdout(str(result.get("stdout", "")))
    lines = stdout.splitlines()
    fmt = _fmt(result, label="lsof")
    fmt["handles"] = lines
    fmt["count"] = max(0, len(lines) - 1)  # subtract header
    return fmt


# ---------------------------------------------------------------------------
# NETWORK DIAGNOSTICS
# ---------------------------------------------------------------------------

@mcp.tool()
async def vm_traceroute(
    vmid: str,
    host: str,
    max_hops: int = 20,
    use_tcp: bool = False,
    actor: str = "mcp-agent",
    danger_mode: bool | Literal["safe", "maintenance", "break_glass"] = False,
    audit_tag: str | None = None,
) -> dict[str, Any]:
    """Trace the network path from inside a VM guest to a destination host.

    Useful for diagnosing routing issues, firewall drops, and latency spikes.

    - host: destination IP or hostname
    - max_hops: maximum TTL / hops (default 20)
    - use_tcp: use TCP SYN instead of UDP (helps bypass ICMP-blocking firewalls)

    Falls back to tracepath if traceroute is not installed.
    """
    parts = ["traceroute", "-m", str(int(max_hops))]
    if use_tcp:
        parts.append("-T")
    parts.append(shlex.quote(host))
    cmd = " ".join(shlex.quote(p) if not p.startswith("-") else p for p in parts)

    command = _guest_exec_command(vmid=vmid, cmd=cmd)
    result = await _run_with_policy(
        vmid=vmid, actor=actor, action="vm_traceroute",
        command=command,
        execute=lambda: gexec.exec(vmid=vmid, cmd=cmd),
        danger_mode=danger_mode, audit_tag=audit_tag, command_context="guest",
    )

    # Fallback to tracepath if traceroute missing
    if not result.get("ok") and "not found" in str(result.get("stderr", "")).lower():
        fb_cmd = f"tracepath -m {int(max_hops)} {shlex.quote(host)}"
        fb_command = _guest_exec_command(vmid=vmid, cmd=fb_cmd)
        result = await _run_with_policy(
            vmid=vmid, actor=actor, action="vm_traceroute:fallback",
            command=fb_command,
            execute=lambda: gexec.exec(vmid=vmid, cmd=fb_cmd),
            danger_mode=danger_mode, audit_tag=audit_tag, command_context="guest",
        )

    stdout = _guest_stdout(str(result.get("stdout", "")))
    fmt = _fmt(result, label=f"traceroute:{host}")
    fmt["hops"] = [l for l in stdout.splitlines() if l.strip()]
    fmt["destination"] = host
    return fmt


@mcp.tool()
async def vm_dns_check(
    vmid: str,
    hostname: str,
    record_type: str = "A",
    server: str | None = None,
    actor: str = "mcp-agent",
    danger_mode: bool | Literal["safe", "maintenance", "break_glass"] = False,
    audit_tag: str | None = None,
) -> dict[str, Any]:
    """Resolve a DNS name from inside a VM guest to catch split-DNS / resolver issues.

    - hostname: name to resolve
    - record_type: 'A', 'AAAA', 'MX', 'TXT', 'CNAME', etc.
    - server: optional specific DNS server to query e.g. '8.8.8.8'

    Uses 'dig' if available, falls back to 'nslookup'.
    """
    if server:
        dig_cmd = f"dig @{shlex.quote(server)} {shlex.quote(hostname)} {record_type} +short"
    else:
        dig_cmd = f"dig {shlex.quote(hostname)} {record_type} +short"

    command = _guest_exec_command(vmid=vmid, cmd=dig_cmd)
    result = await _run_with_policy(
        vmid=vmid, actor=actor, action="vm_dns_check",
        command=command,
        execute=lambda: gexec.exec(vmid=vmid, cmd=dig_cmd),
        danger_mode=danger_mode, audit_tag=audit_tag, command_context="guest",
    )

    if not result.get("ok") and "not found" in str(result.get("stderr", "")).lower():
        ns_cmd = f"nslookup {shlex.quote(hostname)}" + (f" {shlex.quote(server)}" if server else "")
        command = _guest_exec_command(vmid=vmid, cmd=ns_cmd)
        result = await _run_with_policy(
            vmid=vmid, actor=actor, action="vm_dns_check:fallback",
            command=command,
            execute=lambda: gexec.exec(vmid=vmid, cmd=ns_cmd),
            danger_mode=danger_mode, audit_tag=audit_tag, command_context="guest",
        )

    stdout = _guest_stdout(str(result.get("stdout", ""))).strip()
    answers = [l.strip() for l in stdout.splitlines() if l.strip()]
    fmt = _fmt(result, label=f"dns:{hostname}")
    fmt["hostname"] = hostname
    fmt["record_type"] = record_type
    fmt["answers"] = answers
    fmt["resolved"] = len(answers) > 0
    return fmt


@mcp.tool()
async def vm_curl(
    vmid: str,
    url: str,
    method: str = "GET",
    headers: dict[str, str] | None = None,
    body: str | None = None,
    follow_redirects: bool = True,
    timeout: int = 15,
    actor: str = "mcp-agent",
    danger_mode: bool | Literal["safe", "maintenance", "break_glass"] = False,
    audit_tag: str | None = None,
) -> dict[str, Any]:
    """Make an HTTP request from inside a VM guest and return status code + response body.

    Essential for verifying that a service is reachable from inside the VM's
    network namespace (not just from the Proxmox host).

    - method: HTTP verb — GET, POST, PUT, DELETE, HEAD
    - headers: dict of header name -> value
    - body: request body (for POST/PUT)
    - follow_redirects: follow 3xx responses (default True)
    - timeout: seconds before giving up (default 15)
    """
    parts = [
        "curl", "-s", "-S",
        "-w", r"\n---HTTP_STATUS:%{http_code}---",
        "-X", method.upper(),
        "--max-time", str(int(timeout)),
    ]
    if follow_redirects:
        parts.append("-L")
    if headers:
        for k, v in headers.items():
            parts.extend(["-H", f"{k}: {v}"])
    if body:
        parts.extend(["--data-raw", body])
    parts.append(url)
    cmd = " ".join(shlex.quote(p) if not p.startswith("-") else p for p in parts)

    command = _guest_exec_command(vmid=vmid, cmd=cmd)
    result = await _run_with_policy(
        vmid=vmid, actor=actor, action="vm_curl",
        command=command,
        execute=lambda: gexec.exec(vmid=vmid, cmd=cmd),
        danger_mode=danger_mode, audit_tag=audit_tag, command_context="guest",
    )
    stdout = _guest_stdout(str(result.get("stdout", "")))

    # Parse injected status sentinel
    http_status: int | None = None
    body_text = stdout
    if "---HTTP_STATUS:" in stdout:
        parts_split = stdout.rsplit("---HTTP_STATUS:", 1)
        body_text = parts_split[0].strip()
        try:
            http_status = int(parts_split[1].rstrip("-").strip())
        except (ValueError, IndexError):
            pass

    fmt = _fmt(result, label=f"curl:{method}:{url[:60]}")
    fmt["url"] = url
    fmt["http_status"] = http_status
    fmt["http_ok"] = http_status is not None and 200 <= http_status < 400
    fmt["body"] = body_text[:4096] if body_text else None
    if http_status:
        fmt["summary"] = f"[curl] HTTP {http_status} {'✓' if fmt['http_ok'] else '✗'} — {url[:60]}"
    return fmt


@mcp.tool()
async def vm_iptables(
    vmid: str,
    table: str = "filter",
    ipv6: bool = False,
    actor: str = "mcp-agent",
    danger_mode: bool | Literal["safe", "maintenance", "break_glass"] = False,
    audit_tag: str | None = None,
) -> dict[str, Any]:
    """Dump firewall rules inside a VM guest.

    - table: 'filter' (default), 'nat', 'mangle', 'raw'
    - ipv6: if True, query ip6tables instead

    Also tries 'nft list ruleset' if iptables returns nothing (nftables systems).
    """
    bin_name = "ip6tables" if ipv6 else "iptables"
    cmd = f"{bin_name} -t {shlex.quote(table)} -L -n -v --line-numbers"
    command = _guest_exec_command(vmid=vmid, cmd=cmd)
    result = await _run_with_policy(
        vmid=vmid, actor=actor, action="vm_iptables",
        command=command,
        execute=lambda: gexec.exec(vmid=vmid, cmd=cmd),
        danger_mode=danger_mode, audit_tag=audit_tag, command_context="guest",
    )
    stdout = _guest_stdout(str(result.get("stdout", ""))).strip()

    # Also pull nftables ruleset if iptables shows nothing useful
    nft_output: str | None = None
    if not stdout or "nftables" in str(result.get("stderr", "")).lower():
        nft_cmd = "nft list ruleset"
        nft_command = _guest_exec_command(vmid=vmid, cmd=nft_cmd)
        nft_result = await _run_with_policy(
            vmid=vmid, actor=actor, action="vm_iptables:nft",
            command=nft_command,
            execute=lambda: gexec.exec(vmid=vmid, cmd=nft_cmd),
            danger_mode=danger_mode, audit_tag=audit_tag, command_context="guest",
        )
        nft_out = _guest_stdout(str(nft_result.get("stdout", ""))).strip()
        if nft_out:
            nft_output = nft_out

    fmt = _fmt(result, label=f"iptables:{table}")
    fmt["rules"] = stdout
    fmt["table"] = table
    if nft_output:
        fmt["nft_ruleset"] = nft_output
    return fmt


# ---------------------------------------------------------------------------
# FILE OPERATIONS (EXPANDED)
# ---------------------------------------------------------------------------

@mcp.tool()
async def vm_tar_extract(
    vmid: str,
    archive_path: str,
    dest_path: str = "/tmp",
    strip_components: int = 0,
    actor: str = "mcp-agent",
    danger_mode: bool | Literal["safe", "maintenance", "break_glass"] = False,
    audit_tag: str | None = None,
) -> dict[str, Any]:
    """Extract a tar archive that already exists inside a VM guest.

    Supports .tar, .tar.gz, .tar.bz2, .tar.xz — auto-detected from filename.

    - archive_path: path to the archive inside the guest
    - dest_path: directory to extract into (created if needed)
    - strip_components: strip N leading path components from extracted names
    """
    # Auto-detect compression flag
    lower = archive_path.lower()
    if lower.endswith((".tar.gz", ".tgz")):
        compress_flag = "z"
    elif lower.endswith((".tar.bz2", ".tbz2")):
        compress_flag = "j"
    elif lower.endswith((".tar.xz", ".txz")):
        compress_flag = "J"
    else:
        compress_flag = ""

    parts = ["tar", f"-x{compress_flag}f", archive_path, "-C", dest_path]
    if strip_components > 0:
        parts.extend([f"--strip-components={strip_components}"])
    # Ensure dest exists first
    prep_cmd = f"mkdir -p {shlex.quote(dest_path)}"
    tar_cmd = " ".join(shlex.quote(p) if not p.startswith("--") else p for p in parts)
    combined_cmd = f"{prep_cmd} && {tar_cmd}"

    command = _guest_exec_command(vmid=vmid, cmd=combined_cmd)
    result = await _run_with_policy(
        vmid=vmid, actor=actor, action="vm_tar_extract",
        command=command,
        execute=lambda: gexec.exec(vmid=vmid, cmd=combined_cmd),
        danger_mode=danger_mode, audit_tag=audit_tag, command_context="guest",
    )
    fmt = _fmt(result, label=f"tar:{archive_path.split('/')[-1]}")
    fmt["archive"] = archive_path
    fmt["extracted_to"] = dest_path
    return fmt


# ---------------------------------------------------------------------------
# DOCKER (EXPANDED)
# ---------------------------------------------------------------------------

@mcp.tool()
async def vm_docker_exec(
    vmid: str,
    container: str,
    cmd: str,
    workdir: str | None = None,
    user: str | None = None,
    env: dict[str, str] | None = None,
    actor: str = "mcp-agent",
    danger_mode: bool | Literal["safe", "maintenance", "break_glass"] = False,
    audit_tag: str | None = None,
) -> dict[str, Any]:
    """Run a command inside a Docker container running in a VM guest.

    This goes two levels deep: Proxmox host → VM guest (via guest agent) → Docker container.

    - container: container name or ID
    - cmd: command to run inside the container
    - workdir: working directory inside the container
    - user: run as this user inside the container
    - env: environment variables to pass into the container exec
    """
    docker_parts = ["docker", "exec"]
    if workdir:
        docker_parts.extend(["-w", workdir])
    if user:
        docker_parts.extend(["-u", user])
    if env:
        for k, v in env.items():
            docker_parts.extend(["-e", f"{k}={v}"])
    docker_parts.append(container)
    # Append the command as shell to handle pipes/redirects
    docker_parts.extend(["sh", "-c", cmd])
    docker_cmd = " ".join(shlex.quote(p) for p in docker_parts)

    command = _guest_exec_command(vmid=vmid, cmd=docker_cmd)
    result = await _run_with_policy(
        vmid=vmid, actor=actor, action="vm_docker_exec",
        command=command,
        execute=lambda: gexec.exec(vmid=vmid, cmd=docker_cmd),
        danger_mode=danger_mode, audit_tag=audit_tag, command_context="guest",
    )
    fmt = _fmt(result, label=f"docker-exec:{container}")
    fmt["container"] = container
    fmt["cmd"] = cmd
    return fmt


@mcp.tool()
async def vm_docker_pull(
    vmid: str,
    image: str,
    actor: str = "mcp-agent",
    danger_mode: bool | Literal["safe", "maintenance", "break_glass"] = False,
    audit_tag: str | None = None,
) -> dict[str, Any]:
    """Pull a Docker image inside a VM guest.

    - image: image name with optional tag e.g. 'nginx:latest', 'myrepo/myapp:2.0'
    """
    pull_cmd = f"docker pull {shlex.quote(image)}"
    command = _guest_exec_command(vmid=vmid, cmd=pull_cmd)
    result = await _run_with_policy(
        vmid=vmid, actor=actor, action="vm_docker_pull",
        command=command,
        execute=lambda: gexec.exec(vmid=vmid, cmd=pull_cmd),
        danger_mode=danger_mode, audit_tag=audit_tag, command_context="guest",
    )
    return _fmt(result, label=f"docker-pull:{image}")


@mcp.tool()
async def vm_docker_inspect(
    vmid: str,
    container: str,
    actor: str = "mcp-agent",
    danger_mode: bool | Literal["safe", "maintenance", "break_glass"] = False,
    audit_tag: str | None = None,
) -> dict[str, Any]:
    """Return full Docker inspect JSON for a container inside a VM guest.

    Shows network settings, mounts, environment variables, resource limits,
    restart policy, and the full container config.
    """
    inspect_cmd = f"docker inspect {shlex.quote(container)}"
    command = _guest_exec_command(vmid=vmid, cmd=inspect_cmd)
    result = await _run_with_policy(
        vmid=vmid, actor=actor, action="vm_docker_inspect",
        command=command,
        execute=lambda: gexec.exec(vmid=vmid, cmd=inspect_cmd),
        danger_mode=danger_mode, audit_tag=audit_tag, command_context="guest",
    )
    stdout = _guest_stdout(str(result.get("stdout", "")))
    try:
        parsed = json.loads(stdout)
    except json.JSONDecodeError:
        parsed = None

    fmt = _fmt(result, label=f"docker-inspect:{container}")
    fmt["container"] = container
    if parsed is not None:
        # Extract the most useful fields
        info = parsed[0] if isinstance(parsed, list) and parsed else {}
        fmt["state"] = info.get("State", {})
        fmt["config"] = info.get("Config", {})
        fmt["network"] = info.get("NetworkSettings", {}).get("Networks", {})
        fmt["mounts"] = info.get("Mounts", [])
        fmt["host_config"] = {
            k: v for k, v in info.get("HostConfig", {}).items()
            if k in ("RestartPolicy", "Memory", "CpuShares", "Binds", "PortBindings")
        }
    else:
        fmt["raw"] = stdout
    return fmt


# ---------------------------------------------------------------------------
# SERVICE CONTROL (EXPANDED)
# ---------------------------------------------------------------------------

@mcp.tool()
async def vm_service_enable_now(
    vmid: str,
    service_name: str,
    actor: str = "mcp-agent",
    danger_mode: bool | Literal["safe", "maintenance", "break_glass"] = False,
    audit_tag: str | None = None,
) -> dict[str, Any]:
    """Enable AND immediately start a systemd service inside a VM guest in one call.

    Equivalent to 'systemctl enable --now <service>'.
    Also returns the service status after the operation.
    """
    cmd = f"systemctl enable --now {shlex.quote(service_name)}"
    status_cmd = f"systemctl status {shlex.quote(service_name)} --no-pager -l"

    command = _guest_exec_command(vmid=vmid, cmd=cmd)
    result = await _run_with_policy(
        vmid=vmid, actor=actor, action="vm_service_enable_now",
        command=command,
        execute=lambda: gexec.exec(vmid=vmid, cmd=cmd),
        danger_mode=danger_mode, audit_tag=audit_tag, command_context="guest",
    )
    status_command = _guest_exec_command(vmid=vmid, cmd=status_cmd)
    status_result = await _run_with_policy(
        vmid=vmid, actor=actor, action="vm_service_enable_now:status",
        command=status_command,
        execute=lambda: gexec.exec(vmid=vmid, cmd=status_cmd),
        danger_mode=danger_mode, audit_tag=audit_tag, command_context="guest",
    )
    ok = result.get("ok", False)
    fmt = _fmt(result, label=f"enable-now:{service_name}")
    fmt["service"] = service_name
    fmt["status_after"] = _guest_stdout(str(status_result.get("stdout", ""))).strip()

    # Auto-save service to VM memory if successful
    if ok:
        annotate_vm(vmid, services=[service_name])
        fmt["memory_updated"] = True
    return fmt


# ---------------------------------------------------------------------------
# HOST-SIDE PROXMOX TOOLS
# ---------------------------------------------------------------------------

@mcp.tool()
async def vm_agent_probe(
    vmid: str,
    actor: str = "mcp-agent",
    danger_mode: bool | Literal["safe", "maintenance", "break_glass"] = False,
    audit_tag: str | None = None,
) -> dict[str, Any]:
    """Ping the QEMU guest agent to confirm it is running before attempting guest-exec.

    Returns ok=True if the agent responds. If this fails, all vm_guest_exec and
    guest-context commands will also fail — run this first to diagnose connectivity.
    """
    cmd = f"qm guest agent {vmid} ping"
    result = await _run_with_policy(
        vmid=vmid, actor=actor, action="vm_agent_probe",
        command=cmd,
        execute=lambda: service.exec(
            vmid=vmid, cmd=cmd, actor=actor, danger_mode=danger_mode,
            audit_tag=audit_tag, action="vm_agent_probe",
            skip_policy=True, skip_audit=True, skip_metrics=True,
        ),
        danger_mode=danger_mode, audit_tag=audit_tag, command_context="host",
    )
    res = _fmt(result, label="agent_probe")
    res["agent_online"] = res.get("ok", False)
    return res


@mcp.tool()
async def vm_cgroup_mem(
    vmid: str,
    unit: str | None = None,
    actor: str = "mcp-agent",
    danger_mode: bool | Literal["safe", "maintenance", "break_glass"] = False,
    audit_tag: str | None = None,
) -> dict[str, Any]:
    """Read cgroup memory limits and current usage from inside a VM guest.

    - unit: systemd service or slice name e.g. 'docker' or 'nginx.service'
            If omitted, reads the system-level memory cgroup.

    Useful for diagnosing OOM kills and container memory throttling.
    """
    if unit:
        # Try cgroup v2 path first
        safe_unit = unit.replace("/", "_")
        cg2_cmd = (
            f"cat /sys/fs/cgroup/system.slice/{shlex.quote(unit)}/memory.current "
            f"/sys/fs/cgroup/system.slice/{shlex.quote(unit)}/memory.max 2>/dev/null || "
            f"cat /sys/fs/cgroup/memory/system.slice/{shlex.quote(unit)}/memory.usage_in_bytes "
            f"/sys/fs/cgroup/memory/system.slice/{shlex.quote(unit)}/memory.limit_in_bytes 2>/dev/null"
        )
        cmd = cg2_cmd
    else:
        cmd = (
            "cat /sys/fs/cgroup/memory.current /sys/fs/cgroup/memory.max 2>/dev/null || "
            "cat /sys/fs/cgroup/memory/memory.usage_in_bytes /sys/fs/cgroup/memory/memory.limit_in_bytes 2>/dev/null"
        )

    command = _guest_exec_command(vmid=vmid, cmd=cmd)
    result = await _run_with_policy(
        vmid=vmid, actor=actor, action="vm_cgroup_mem",
        command=command,
        execute=lambda: gexec.exec(vmid=vmid, cmd=cmd),
        danger_mode=danger_mode, audit_tag=audit_tag, command_context="guest",
    )
    stdout = _guest_stdout(str(result.get("stdout", ""))).strip()
    values = [l.strip() for l in stdout.splitlines() if l.strip()]

    def _bytes_to_human(b: str) -> str:
        try:
            n = int(b)
            if n >= 1 << 30:
                return f"{n / (1<<30):.1f} GiB"
            if n >= 1 << 20:
                return f"{n / (1<<20):.1f} MiB"
            if n >= 1 << 10:
                return f"{n / (1<<10):.1f} KiB"
            return f"{n} B"
        except ValueError:
            return b

    fmt = _fmt(result, label="cgroup-mem")
    fmt["unit"] = unit or "system"
    if len(values) >= 2:
        fmt["current"] = _bytes_to_human(values[0])
        fmt["limit"] = _bytes_to_human(values[1]) if values[1] != "max" else "unlimited"
        fmt["current_bytes"] = values[0]
        fmt["limit_bytes"] = values[1]
    else:
        fmt["raw"] = stdout
    return fmt


# ---------------------------------------------------------------------------
# AUTOMATION: AUTODISCOVER + DRIFT CHECK
# ---------------------------------------------------------------------------

@mcp.tool()
async def vm_autodiscover(
    vmid: str,
    actor: str = "mcp-agent",
    danger_mode: bool | Literal["safe", "maintenance", "break_glass"] = False,
    audit_tag: str | None = None,
) -> dict[str, Any]:
    """One-shot VM discovery: probe agent, collect system info, map services and containers,
    scan network, and save everything to VM memory automatically.

    Run this as the first command on any new or unfamiliar VM.
    After this, vm_memory_get will show everything discovered.

    Returns a structured summary plus confirms what was saved.
    """
    # 1. Probe agent first
    agent_ok_result = await vm_agent_probe(vmid=vmid, actor=actor,
                                           danger_mode=danger_mode, audit_tag=audit_tag)
    if not agent_ok_result.get("agent_online"):
        return {
            "ok": False,
            "summary": f"VM {vmid}: guest agent offline — cannot autodiscover",
            "vmid": vmid,
            "agent_online": False,
        }

    # 2. Gather all data in parallel
    sysinfo_task = asyncio.create_task(
        vm_sysinfo(vmid=vmid, actor=actor, danger_mode=danger_mode, audit_tag=audit_tag)
    )
    network_task = asyncio.create_task(
        vm_network(vmid=vmid, actor=actor, danger_mode=danger_mode, audit_tag=audit_tag)
    )
    disk_task = asyncio.create_task(
        vm_disk(vmid=vmid, actor=actor, danger_mode=danger_mode, audit_tag=audit_tag)
    )
    ps_task = asyncio.create_task(
        vm_ps(vmid=vmid, actor=actor, danger_mode=danger_mode, audit_tag=audit_tag)
    )

    sysinfo, network, disk, ps = await asyncio.gather(
        sysinfo_task, network_task, disk_task, ps_task, return_exceptions=True
    )

    # 3. Extract docker containers if docker is running
    containers_found: list[str] = []
    docker_ps_cmd = "docker ps --format '{{.Names}}' 2>/dev/null"
    docker_command = _guest_exec_command(vmid=vmid, cmd=docker_ps_cmd)
    docker_result = await _run_with_policy(
        vmid=vmid, actor=actor, action="vm_autodiscover:docker_ps",
        command=docker_command,
        execute=lambda: gexec.exec(vmid=vmid, cmd=docker_ps_cmd),
        danger_mode=danger_mode, audit_tag=audit_tag, command_context="guest",
    )
    docker_stdout = _guest_stdout(str(docker_result.get("stdout", ""))).strip()
    if docker_stdout:
        containers_found = [c for c in docker_stdout.splitlines() if c.strip()]

    # 4. Extract active systemd services
    svc_cmd = "systemctl list-units --type=service --state=running --no-pager --no-legend --plain"
    svc_command = _guest_exec_command(vmid=vmid, cmd=svc_cmd)
    svc_result = await _run_with_policy(
        vmid=vmid, actor=actor, action="vm_autodiscover:services",
        command=svc_command,
        execute=lambda: gexec.exec(vmid=vmid, cmd=svc_cmd),
        danger_mode=danger_mode, audit_tag=audit_tag, command_context="guest",
    )
    svc_stdout = _guest_stdout(str(svc_result.get("stdout", ""))).strip()
    services_found: list[str] = []
    for line in svc_stdout.splitlines():
        parts = line.split()
        if parts and parts[0].endswith(".service"):
            services_found.append(parts[0].removesuffix(".service"))

    # 5. Save everything to VM memory
    si = sysinfo if isinstance(sysinfo, dict) else {}
    env_data: dict[str, str] = {}
    if si.get("hostname"):
        env_data["hostname"] = si["hostname"]
    if si.get("os"):
        env_data["os"] = si["os"].splitlines()[0] if si["os"] else ""
    if si.get("kernel"):
        env_data["kernel"] = si["kernel"]

    notes = f"Auto-discovered {_now()[:10]}. OS: {env_data.get('os', 'unknown')}. Hostname: {env_data.get('hostname', 'unknown')}."

    annotate_vm(
        vmid,
        notes=notes,
        services=services_found,
        containers=containers_found,
        env=env_data,
    )

    return {
        "ok": True,
        "summary": f"VM {vmid} autodiscovered and saved to memory",
        "vmid": vmid,
        "agent_online": True,
        "sysinfo": si,
        "network": network if isinstance(network, dict) else {},
        "disk": disk if isinstance(disk, dict) else {},
        "active_services": services_found,
        "running_containers": containers_found,
        "memory_saved": {
            "services": services_found,
            "containers": containers_found,
            "env": env_data,
            "notes": notes,
        },
    }


@mcp.tool()
async def vm_drift_check(
    vmid: str,
    actor: str = "mcp-agent",
    danger_mode: bool | Literal["safe", "maintenance", "break_glass"] = False,
    audit_tag: str | None = None,
) -> dict[str, Any]:
    """Compare a VM's current state against what is saved in memory.

    Detects:
    - Services that are expected (in memory) but not running
    - Services that are running but were not expected (new/rogue processes)
    - Containers that are expected but not running
    - Containers that are running but not expected

    Run after vm_autodiscover establishes the baseline.
    """
    mem = load_vm_memory(vmid)
    expected_services = set(mem.get("services", []))
    expected_containers = set(mem.get("containers", []))

    if not expected_services and not expected_containers:
        return {
            "ok": True,
            "summary": f"No baseline in memory for VM {vmid} — run vm_autodiscover first",
            "vmid": vmid,
            "has_baseline": False,
        }

    # Get current running services
    svc_cmd = "systemctl list-units --type=service --state=running --no-pager --no-legend --plain"
    svc_command = _guest_exec_command(vmid=vmid, cmd=svc_cmd)
    svc_result = await _run_with_policy(
        vmid=vmid, actor=actor, action="vm_drift_check:services",
        command=svc_command,
        execute=lambda: gexec.exec(vmid=vmid, cmd=svc_cmd),
        danger_mode=danger_mode, audit_tag=audit_tag, command_context="guest",
    )
    svc_stdout = _guest_stdout(str(svc_result.get("stdout", ""))).strip()
    current_services: set[str] = set()
    for line in svc_stdout.splitlines():
        parts = line.split()
        if parts and parts[0].endswith(".service"):
            current_services.add(parts[0].removesuffix(".service"))

    # Get current running containers
    current_containers: set[str] = set()
    if expected_containers:
        docker_cmd = "docker ps --format '{{.Names}}' 2>/dev/null"
        docker_command = _guest_exec_command(vmid=vmid, cmd=docker_cmd)
        docker_result = await _run_with_policy(
            vmid=vmid, actor=actor, action="vm_drift_check:containers",
            command=docker_command,
            execute=lambda: gexec.exec(vmid=vmid, cmd=docker_cmd),
            danger_mode=danger_mode, audit_tag=audit_tag, command_context="guest",
        )
        docker_stdout = _guest_stdout(str(docker_result.get("stdout", ""))).strip()
        if docker_stdout:
            current_containers = {c for c in docker_stdout.splitlines() if c.strip()}

    # Compute drift
    missing_services = sorted(expected_services - current_services)
    new_services = sorted(current_services - expected_services)
    missing_containers = sorted(expected_containers - current_containers)
    new_containers = sorted(current_containers - expected_containers)

    has_drift = bool(missing_services or missing_containers)
    has_new = bool(new_services or new_containers)
    ok = not has_drift

    parts = []
    if missing_services:
        parts.append(f"{len(missing_services)} service(s) DOWN")
    if missing_containers:
        parts.append(f"{len(missing_containers)} container(s) MISSING")
    if new_services:
        parts.append(f"{len(new_services)} unexpected service(s)")
    if new_containers:
        parts.append(f"{len(new_containers)} unexpected container(s)")
    summary = f"VM {vmid}: {'⚠ ' + ', '.join(parts) if parts else '✓ No drift detected'}"

    return {
        "ok": ok,
        "summary": summary,
        "vmid": vmid,
        "has_baseline": True,
        "drift_detected": has_drift,
        "unexpected_found": has_new,
        "missing_services": missing_services,
        "new_services": new_services,
        "missing_containers": missing_containers,
        "new_containers": new_containers,
        "baseline_services": sorted(expected_services),
        "baseline_containers": sorted(expected_containers),
    }


@mcp.tool()
def vm_metrics() -> dict[str, Any]:
    """Get system performance metrics."""
    return service.metrics_snapshot()


# ---------------------------------------------------------------------------
@mcp.tool()
async def vm_generate_cloudinit(
    packages: list[str] | None = None,
    users: list[dict] | None = None,
    runcmd: list[str] | None = None,
) -> str:
    """Generate a cloud-init user-data YAML string."""
    return generate_user_data(packages=packages, users=users, runcmd=runcmd)

@mcp.tool()
def vm_history_replay(vmid: str, limit: int = 20) -> list[dict[str, Any]]:
    """Replay the last N audit events for a specific VM."""
    path = os.getenv("PVEMCP_AUDIT_LOG", "logs/audit.log")
    return get_vm_history(path, vmid, limit)

@mcp.tool()
async def vm_remote_exec(host: str, cmd: str, user: str | None = None) -> dict[str, Any]:
    """Execute a command on a remote host via SSH (Federation Gateway)."""
    from .remote import SSHRunner
    runner = SSHRunner(host=host, user=user)
    res = await runner.run(cmd)
    return res.to_dict()

# MCP RESOURCES
@mcp.resource("pvemcp://dashboard")
async def get_dashboard_resource() -> str:
    """Get a live dashboard of all VMs and their status."""
    cmd = "qm list"
    res = await service.runner.run(vmid="0", cmd=cmd)
    if not res.ok:
        return f"Error fetching VM list: {res.stderr}"
    
    vms = []
    lines = res.stdout.strip().splitlines()
    header = lines[0].split()
    for line in lines[1:]:
        parts = line.split()
        if len(parts) >= 3:
            vms.append({"vmid": parts[0], "name": parts[1], "status": parts[2]})
    
    md = "# PveMCP Live Dashboard\n\n"
    md += "| VMID | Name | Status | Health |\n"
    md += "|---|---|---|---|\n"
    for vm in vms:
        health = "✓" if vm["status"] == "running" else "○"
        md += f"| {vm['vmid']} | {vm['name']} | {vm['status']} | {health} |\n"
    return md

@mcp.resource("pvemcp://vms/{vmid}/console/stream")
async def get_vm_console_stream(vmid: str) -> str:
    """Get the recent console output for a VM."""
    res = await host_ops.read_serial_console(vmid=vmid)
    return res.stdout if res.ok else f"Error: {res.stderr}"

# ---------------------------------------------------------------------------

@mcp.resource("pvemcp://metrics")
def get_metrics_resource() -> str:
    """Get current system metrics as a resource."""
    return json.dumps(service.metrics_snapshot(), indent=2)

@mcp.resource("pvemcp://vms/{vmid}/memory")
def get_vm_memory_resource(vmid: str) -> str:
    """Get the persistent memory/context for a specific VM."""
    return json.dumps(load_vm_memory(vmid), indent=2)


# ---------------------------------------------------------------------------
# MCP PROMPTS
@mcp.prompt("vm-auto-heal")
def auto_heal_prompt(vmid: str) -> str:
    """Generate an auto-healing plan for a VM based on drift."""
    return f"""
    VM {vmid} has detected drift from its baseline.
    Please:
    1. Run vm_drift_check for {vmid}.
    2. Identify missing services or containers.
    3. Attempt to restart missing services using vm_service_restart.
    4. Verify health with vm_slo_check.
    """

# ---------------------------------------------------------------------------

@mcp.prompt("vm-troubleshoot")
def troubleshoot_prompt(vmid: str) -> str:
    """Generate a troubleshooting plan for a specific VM."""
    return f"""
    I need to troubleshoot VM {vmid}. Please follow these steps:
    1. Check VM status using vm_state.
    2. Check guest agent connectivity with vm_agent_probe.
    3. If reachable, check system load and memory with vm_top.
    4. Check for critical errors in the kernel log with vm_dmesg.
    5. Check active network connections with vm_network.
    """


import pvemcp.power_tools  # Register power-user tools
import pvemcp.analysis_tools  # Register analysis & forensic tools


@mcp.tool()
def vm_run_workflow(script_name: str) -> dict[str, Any]:
    """Execute a Lua workflow script."""
    from .lua_engine import LuaWorkflowEngine
    from .mcp_server import vm_state, vm_guest_exec, vm_service_restart, vm_drift_check, vm_remote_exec, vm_metrics
    from .analysis_tools import admin_notify, host_zfs_status, host_io_metrics, host_zfs_scrub_control, vm_run_kp14_pipeline, sync_vm_run_kp14_pipeline
    from .power_tools import vm_disk_reclaim
    
    engine = LuaWorkflowEngine()
    engine.bind_tool("vm_state", vm_state)
    engine.bind_tool("vm_guest_exec", vm_guest_exec)
    engine.bind_tool("vm_service_restart", vm_service_restart)
    engine.bind_tool("vm_drift_check", vm_drift_check)
    engine.bind_tool("vm_disk_reclaim", vm_disk_reclaim)
    engine.bind_tool("vm_remote_exec", vm_remote_exec)
    engine.bind_tool("admin_notify", admin_notify)
    engine.bind_tool("vm_metrics", vm_metrics)
    engine.bind_tool("host_zfs_status", host_zfs_status)
    engine.bind_tool("host_io_metrics", host_io_metrics)
    engine.bind_tool("host_zfs_scrub_control", host_zfs_scrub_control)
    engine.bind_tool("vm_run_kp14_pipeline", sync_vm_run_kp14_pipeline)
    
    try:
        result = engine.run_script(script_name)
        return {"ok": True, "result": str(result)}
    except Exception as e:
        return {"ok": False, "error": str(e)}
def main():
    mcp.run()

if __name__ == "__main__":
    main()
