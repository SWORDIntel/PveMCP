from __future__ import annotations

import argparse
import asyncio
import json
import shlex
from typing import Awaitable, Callable, Literal

from .service import VMService
from .proxmox import (
    ProxmoxBackup,
    ProxmoxConfig,
    ProxmoxFileOps,
    ProxmoxGuestExec,
    ProxmoxLifecycle,
    ProxmoxSnapshot,
)
from .xen import XenLifecycle
from .models import CommandResult
from .metrics import Timer
from .vm_memory import (
    annotate_vm,
    list_all_vm_memories,
    load_vm_memory,
    memory_context_summary,
)



def _guest_exec_command(
    vmid: str,
    cmd: str,
    cwd: str | None = None,
    env: dict[str, str] | None = None,
    timeout: int | None = None,
) -> str:
    parts: list[str] = ["qm", "guest", "exec", vmid]
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


async def _run_with_policy(
    *,
    vmid: str,
    actor: str,
    action: str,
    command: str,
    execute: Callable[[], Awaitable[CommandResult]],
    danger_mode: bool | Literal["safe", "maintenance", "break_glass"] = False,
    audit_tag: str | None = None,
    command_context: str = "host",
) -> dict:
    timer = Timer()
    try:
        service.policy.validate(command, danger_mode=danger_mode, command_context=command_context)
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
        service.metrics.record_policy_block()
        service.audit.log(actor=actor, action=action, vmid=vmid, cmd=command, result=result.to_dict(), audit_tag=audit_tag)
        service.metrics.record(action=action, duration_ms=result.duration_ms, ok=False)
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
    result.vmid = vmid
    result.cmd = command
    service.audit.log(actor=actor, action=action, vmid=vmid, cmd=command, result=result.to_dict(), audit_tag=audit_tag)
    service.metrics.record(action=action, duration_ms=timer.elapsed_ms(), ok=result.ok, timeout=(result.code == 124))
    return result.to_dict()


def _q_cmd(*parts: object) -> str:
    return " ".join(shlex.quote(str(part)) for part in parts)


def _parse_kv_params(items: list[str] | None) -> dict[str, str]:
    params: dict[str, str] = {}
    if not items:
        return params
    for item in items:
        if "=" not in item:
            continue
        key, value = item.split("=", 1)
        if key:
            params[key] = value
    return params


async def _guest_health_check(vmid: str, services: list[str], containers: list[str], actor: str, danger_mode: bool | Literal["safe", "maintenance", "break_glass"], audit_tag: str | None) -> dict:
    details: dict[str, dict[str, bool]] = {"services": {}, "containers": {}}
    all_ok = True

    for service_name in services:
        command = _guest_exec_command(vmid, f"systemctl is-active {service_name}")
        res = await _run_with_policy(
            vmid=vmid,
            actor=actor,
            action=f"vm_slo_check:service:{service_name}",
            command=command,
            execute=lambda vmid=vmid, service_name=service_name: gexec.exec(vmid=vmid, cmd=f"systemctl is-active {service_name}"),
            danger_mode=danger_mode,
            audit_tag=audit_tag,
            command_context="guest",
        )
        is_active = res.get("ok", False) and str(res.get("stdout", "")).strip() == "active"
        details["services"][service_name] = is_active
        if not is_active:
            all_ok = False

    if containers:
        ps_cmd = "docker ps --format '{{.ID}}\\t{{.Names}}\\t{{.Status}}'"
        ps_command = _guest_exec_command(vmid, ps_cmd)
        ps_result = await _run_with_policy(
            vmid=vmid,
            actor=actor,
            action="vm_slo_check:containers:ps",
            command=ps_command,
            execute=lambda vmid=vmid: gexec.exec(vmid=vmid, cmd=ps_cmd),
            danger_mode=danger_mode,
            audit_tag=audit_tag,
            command_context="guest",
        )
        stdout = str(ps_result.get("stdout", ""))
        for container_name in containers:
            is_running = container_name in stdout
            details["containers"][container_name] = is_running
            if not is_running:
                all_ok = False

    return {"ok": all_ok, "details": details}


def main() -> int:
    parser = argparse.ArgumentParser(prog="vmctl")
    parser.add_argument("--actor", default="operator")
    parser.add_argument("--audit-tag")
    sub = parser.add_subparsers(dest="command", required=True)

    run_parser = sub.add_parser("exec")
    state_parser = sub.add_parser("state")
    metrics_parser = sub.add_parser("metrics")

    file_parser = sub.add_parser("file")
    file_sub = file_parser.add_subparsers(dest="action", required=True)
    
    put_parser = file_sub.add_parser("put")
    put_parser.add_argument("--vmid", required=True)
    put_parser.add_argument("--local", required=True)
    put_parser.add_argument("--remote", required=True)
    
    get_parser = file_sub.add_parser("get")
    get_parser.add_argument("--vmid", required=True)
    get_parser.add_argument("--remote", required=True)

    service_parser = sub.add_parser("service")
    service_sub = service_parser.add_subparsers(dest="action", required=True)

    svc_status_parser = service_sub.add_parser("status")
    svc_status_parser.add_argument("--vmid", required=True)
    svc_status_parser.add_argument("--name", required=True)

    svc_enable_parser = service_sub.add_parser("enable")
    svc_enable_parser.add_argument("--vmid", required=True)
    svc_enable_parser.add_argument("--name", required=True)

    svc_disable_parser = service_sub.add_parser("disable")
    svc_disable_parser.add_argument("--vmid", required=True)
    svc_disable_parser.add_argument("--name", required=True)

    svc_restart_parser = service_sub.add_parser("restart")
    svc_restart_parser.add_argument("--vmid", required=True)
    svc_restart_parser.add_argument("--name", required=True)
    svc_journal_parser = service_sub.add_parser("journal")
    svc_journal_parser.add_argument("--vmid", required=True)
    svc_journal_parser.add_argument("--name", required=True)
    svc_journal_parser.add_argument("--lines", type=int, default=50)

    docker_parser = sub.add_parser("docker")
    docker_sub = docker_parser.add_subparsers(dest="action", required=True)
    
    docker_ps_parser = docker_sub.add_parser("ps")
    docker_ps_parser.add_argument("--vmid", required=True)

    docker_logs_parser = docker_sub.add_parser("logs")
    docker_logs_parser.add_argument("--vmid", required=True)
    docker_logs_parser.add_argument("--container", required=True)
    docker_logs_parser.add_argument("--lines", type=int, default=50)

    docker_restart_parser = docker_sub.add_parser("restart")
    docker_restart_parser.add_argument("--vmid", required=True)
    docker_restart_parser.add_argument("--container", required=True)

    docker_compose_parser = docker_sub.add_parser("compose-up")
    docker_compose_parser.add_argument("--vmid", required=True)
    docker_compose_parser.add_argument("--path", required=True)

    slo_parser = sub.add_parser("slo")
    slo_sub = slo_parser.add_subparsers(dest="action", required=True)
    slo_check_parser = slo_sub.add_parser("check")
    slo_check_parser.add_argument("--vmid")
    slo_check_parser.add_argument("--services", nargs="+", default=[])
    slo_check_parser.add_argument("--containers", nargs="+", default=[])

    snap_parser = sub.add_parser("snapshot")
    snap_parser.add_argument("--vmid", required=True)
    snap_parser.add_argument("--action", choices=["list", "create", "rollback", "delete"], required=True)
    snap_parser.add_argument("--name")

    config_parser = sub.add_parser("config")
    config_parser.add_argument("--vmid", required=True)
    config_parser.add_argument("--action", choices=["get", "set"], required=True)
    config_parser.add_argument("--params", nargs="+", help="key=value pairs for set")

    state_parser.add_argument("--vmid", required=True)
    state_parser.add_argument("--action", choices=["status", "start", "stop", "reboot", "shutdown"], required=True)
    state_parser.add_argument("--provider", choices=["proxmox", "xen"], default="proxmox")
    run_parser.add_argument("--vmid", required=True)
    run_parser.add_argument("--cmd", required=True)

    create_parser = sub.add_parser("create")
    create_parser.add_argument("--vmid", required=True)
    create_parser.add_argument("--params", nargs="+", help="key=value pairs for create")

    clone_parser = sub.add_parser("clone")
    clone_parser.add_argument("--source-vmid", required=True)
    clone_parser.add_argument("--target-vmid", required=True)
    clone_parser.add_argument("--name")
    clone_parser.add_argument("--target-node")
    clone_parser.add_argument("--full-clone", action="store_true")

    migrate_parser = sub.add_parser("migrate")
    migrate_parser.add_argument("--vmid", required=True)
    migrate_parser.add_argument("--target-node", required=True)
    migrate_parser.add_argument("--no-online", action="store_true")

    backup_parser = sub.add_parser("backup")
    backup_parser.add_argument("--vmid", required=True)
    backup_parser.add_argument("--storage")
    backup_parser.add_argument("--mode", default="snapshot", choices=["snapshot", "suspend", "stop"])
    backup_parser.add_argument("--compress", default=None)
    backup_parser.add_argument("--remove", type=int, default=None)

    gexec_parser = sub.add_parser("guest-exec")
    gexec_parser.add_argument("--vmid", required=True)
    gexec_parser.add_argument("--cmd", required=True)
    gexec_parser.add_argument("--cwd")
    gexec_parser.add_argument("--env", nargs="+", help="K=V pairs")
    gexec_parser.add_argument("--timeout", type=int)

    # --- New commands ---
    list_parser = sub.add_parser("list", help="List all VMs on the Proxmox host")

    ps_parser = sub.add_parser("ps", help="List processes in a VM guest")
    ps_parser.add_argument("--vmid", required=True)
    ps_parser.add_argument("--filter", dest="filter_name", help="Filter by process name substring")

    top_parser = sub.add_parser("top", help="Show top resource consumers in a VM guest")
    top_parser.add_argument("--vmid", required=True)
    top_parser.add_argument("--lines", type=int, default=20)

    disk_parser = sub.add_parser("disk", help="Show disk usage in a VM guest")
    disk_parser.add_argument("--vmid", required=True)

    network_parser = sub.add_parser("network", help="Show network config in a VM guest")
    network_parser.add_argument("--vmid", required=True)

    tail_parser = sub.add_parser("tail", help="Tail a log file in a VM guest")
    tail_parser.add_argument("--vmid", required=True)
    tail_parser.add_argument("--path", required=True)
    tail_parser.add_argument("--lines", type=int, default=50)

    sysinfo_parser = sub.add_parser("sysinfo", help="Get system info from a VM guest")
    sysinfo_parser.add_argument("--vmid", required=True)

    env_parser = sub.add_parser("env", help="Dump environment variables in a VM guest")
    env_parser.add_argument("--vmid", required=True)

    ripgrep_parser = sub.add_parser("ripgrep", help="Search file contents with ripgrep in a VM guest")
    ripgrep_parser.add_argument("--vmid", required=True)
    ripgrep_parser.add_argument("--pattern", required=True)
    ripgrep_parser.add_argument("--path", default="/")
    ripgrep_parser.add_argument("--glob", dest="file_glob")
    ripgrep_parser.add_argument("-i", "--ignore-case", action="store_true")
    ripgrep_parser.add_argument("--max", type=int, default=50, dest="max_results")

    find_parser = sub.add_parser("find", help="Find files in a VM guest")
    find_parser.add_argument("--vmid", required=True)
    find_parser.add_argument("--path", default="/")
    find_parser.add_argument("--name")
    find_parser.add_argument("--type", dest="file_type", choices=["f", "d", "l"])
    find_parser.add_argument("--mtime", type=int, dest="mtime_days")
    find_parser.add_argument("--size-gt", dest="size_gt")
    find_parser.add_argument("--maxdepth", type=int, dest="max_depth")

    port_parser = sub.add_parser("port", help="Check if a port is listening in a VM guest")
    port_parser.add_argument("--vmid", required=True)
    port_parser.add_argument("--port", type=int, required=True)

    install_parser = sub.add_parser("install", help="Install a package in a VM guest")
    install_parser.add_argument("--vmid", required=True)
    install_parser.add_argument("--package", required=True)
    install_parser.add_argument("--manager", default="apt", choices=["apt", "yum", "dnf", "apk"])

    mem_parser = sub.add_parser("memory", help="Manage VM memory/context store")
    mem_sub = mem_parser.add_subparsers(dest="action", required=True)
    mem_get_parser = mem_sub.add_parser("get")
    mem_get_parser.add_argument("--vmid", required=True)
    mem_set_parser = mem_sub.add_parser("set")
    mem_set_parser.add_argument("--vmid", required=True)
    mem_set_parser.add_argument("--notes")
    mem_set_parser.add_argument("--tags", nargs="+")
    mem_set_parser.add_argument("--services", nargs="+")
    mem_set_parser.add_argument("--containers", nargs="+")
    mem_set_parser.add_argument("--paths", nargs="+", help="label=path pairs")
    mem_sub.add_parser("list")
    mem_clear_parser = mem_sub.add_parser("clear")
    mem_clear_parser.add_argument("--vmid", required=True)

    args = parser.parse_args()
    danger_mode = "maintenance"
    global service
    service = VMService.build(use_host_sudo=False)
    global gexec
    xen = XenLifecycle(runner=service.runner)
    proxmox = ProxmoxLifecycle(runner=service.runner)
    snapshot = ProxmoxSnapshot(runner=service.runner)
    file_ops = ProxmoxFileOps(runner=service.runner)
    proxmox_config = ProxmoxConfig(runner=service.runner)
    proxmox_backup = ProxmoxBackup(runner=service.runner)
    gexec = ProxmoxGuestExec(runner=service.runner)
    actor = args.actor

    if args.command == "exec":
        result = asyncio.run(
            service.exec(
                vmid=args.vmid,
                cmd=args.cmd,
                actor=actor,
                danger_mode=danger_mode,
                audit_tag=args.audit_tag,
            )
        )
        print(json.dumps(result.to_dict(), sort_keys=True))
        return 0 if result.ok else 1

    if args.command == "guest-exec":
        env_dict = {}
        if args.env:
            for item in args.env:
                if "=" in item:
                    k, v = item.split("=", 1)
                    env_dict[k] = v
        command = _guest_exec_command(args.vmid, args.cmd, cwd=args.cwd, env=env_dict, timeout=args.timeout)
        result_dict = asyncio.run(_run_with_policy(
            vmid=args.vmid,
            actor=actor,
            action="vm_guest_exec",
            command=command,
            execute=lambda: gexec.exec(vmid=args.vmid, cmd=args.cmd, cwd=args.cwd, env=env_dict, timeout=args.timeout),
            danger_mode=danger_mode,
            audit_tag=args.audit_tag,
            command_context="guest",
        ))
        print(json.dumps(result_dict, sort_keys=True))
        return 0 if result_dict.get("ok") else 1

    if args.command == "create":
        params = _parse_kv_params(args.params)
        if not params:
            raise SystemExit("--params is required for create")
        command_parts = ["qm", "create", args.vmid]
        for key, value in params.items():
            command_parts.extend([f"-{key}", value])
        result_dict = asyncio.run(_run_with_policy(
            vmid=args.vmid,
            actor=actor,
            action="vm_create",
            command=_q_cmd(*command_parts),
            execute=lambda: proxmox.create(args.vmid, params),
            danger_mode=danger_mode,
            audit_tag=args.audit_tag,
            command_context="host",
        ))
        print(json.dumps(result_dict, sort_keys=True))
        return 0 if result_dict.get("ok") else 1

    if args.command == "clone":
        command_parts = ["qm", "clone", args.source_vmid, args.target_vmid]
        if args.name:
            command_parts.extend(["--name", args.name])
        if args.target_node:
            command_parts.extend(["--target", args.target_node])
        if args.full_clone:
            command_parts.append("--full")
        result_dict = asyncio.run(_run_with_policy(
            vmid=args.target_vmid,
            actor=actor,
            action="vm_clone",
            command=_q_cmd(*command_parts),
            execute=lambda: proxmox.clone(
                source_vmid=args.source_vmid,
                target_vmid=args.target_vmid,
                name=args.name,
                target_node=args.target_node,
                full_clone=args.full_clone,
            ),
            danger_mode=danger_mode,
            audit_tag=args.audit_tag,
            command_context="host",
        ))
        print(json.dumps(result_dict, sort_keys=True))
        return 0 if result_dict.get("ok") else 1

    if args.command == "migrate":
        command = _q_cmd("qm", "migrate", args.vmid, args.target_node, "--online", "0" if args.no_online else "1")
        result_dict = asyncio.run(_run_with_policy(
            vmid=args.vmid,
            actor=actor,
            action="vm_migrate",
            command=command,
            execute=lambda: proxmox.migrate(vmid=args.vmid, target_node=args.target_node, online=not args.no_online),
            danger_mode=danger_mode,
            audit_tag=args.audit_tag,
            command_context="host",
        ))
        print(json.dumps(result_dict, sort_keys=True))
        return 0 if result_dict.get("ok") else 1

    if args.command == "backup":
        command_parts = ["vzdump", args.vmid, "--mode", args.mode]
        if args.storage:
            command_parts.extend(["--storage", args.storage])
        if args.compress:
            command_parts.extend(["--compress", args.compress])
        if args.remove is not None:
            command_parts.extend(["--remove", str(args.remove)])
        result_dict = asyncio.run(_run_with_policy(
            vmid=args.vmid,
            actor=actor,
            action="vm_backup",
            command=_q_cmd(*command_parts),
            execute=lambda: proxmox_backup.create(
                vmid=args.vmid,
                storage=args.storage,
                mode=args.mode,
                compress=args.compress,
                remove=args.remove,
            ),
            danger_mode=danger_mode,
            audit_tag=args.audit_tag,
            command_context="host",
        ))
        print(json.dumps(result_dict, sort_keys=True))
        return 0 if result_dict.get("ok") else 1
    
    if args.command == "config":
        if args.action == "get":
            command = _q_cmd("qm", "config", args.vmid)
            result_dict = asyncio.run(_run_with_policy(
                vmid=args.vmid,
                actor=actor,
                action="vm_config:get",
                command=command,
                execute=lambda: proxmox_config.get(args.vmid),
                danger_mode=danger_mode,
                audit_tag=args.audit_tag,
                command_context="host",
            ))
        else:  # set
            params = _parse_kv_params(args.params)
            command_parts: list[str] = ["qm", "set", args.vmid]
            for key, value in params.items():
                command_parts.extend([f"-{key}", str(value)])
            command = _q_cmd(*command_parts)
            result_dict = asyncio.run(_run_with_policy(
                vmid=args.vmid,
                actor=actor,
                action="vm_config:set",
                command=command,
                execute=lambda: proxmox_config.set(args.vmid, params),
                danger_mode=danger_mode,
                audit_tag=args.audit_tag,
                command_context="host",
            ))
        print(json.dumps(result_dict, sort_keys=True))
        return 0 if result_dict.get("ok") else 1

    if args.command == "file":
        if args.action == "put":
            command = _q_cmd("qm", "guest", "file", "write", args.vmid, args.remote, args.local)
            result_dict = asyncio.run(_run_with_policy(
                vmid=args.vmid,
                actor=actor,
                action="vm_file_put",
                command=command,
                execute=lambda: file_ops.put(vmid=args.vmid, local_path=args.local, remote_path=args.remote),
                danger_mode=danger_mode,
                audit_tag=args.audit_tag,
                command_context="guest",
            ))
        else:  # get
            command = _q_cmd("qm", "guest", "file", "read", args.vmid, args.remote)
            result_dict = asyncio.run(_run_with_policy(
                vmid=args.vmid,
                actor=actor,
                action="vm_file_get",
                command=command,
                execute=lambda: file_ops.get(vmid=args.vmid, remote_path=args.remote),
                danger_mode=danger_mode,
                audit_tag=args.audit_tag,
                command_context="guest",
            ))
        print(json.dumps(result_dict, sort_keys=True))
        return 0 if result_dict.get("ok") else 1

    if args.command == "service":
        if args.action == "status":
            guest_cmd = f"systemctl is-active {args.name}"
            action_name = "vm_service:status"
        elif args.action == "enable":
            guest_cmd = f"systemctl enable {args.name}"
            action_name = "vm_service:enable"
        elif args.action == "disable":
            guest_cmd = f"systemctl disable {args.name}"
            action_name = "vm_service:disable"
        elif args.action == "restart":
            guest_cmd = f"systemctl restart {args.name}"
            action_name = "vm_service:restart"
        elif args.action == "journal":
            guest_cmd = f"journalctl -u {args.name} -n {args.lines} --no-pager"
            action_name = "vm_service:journal"
        else:
            return 1

        result_dict = asyncio.run(_run_with_policy(
            vmid=args.vmid,
            actor=actor,
            action=action_name,
            command=_guest_exec_command(args.vmid, guest_cmd),
            execute=lambda: gexec.exec(vmid=args.vmid, cmd=guest_cmd),
            danger_mode=danger_mode,
            audit_tag=args.audit_tag,
            command_context="guest",
        ))
        print(json.dumps(result_dict, sort_keys=True))
        return 0 if result_dict.get("ok") else 1

    if args.command == "docker":
        if args.action == "ps":
            guest_cmd = "docker ps --format '{{.ID}}\\t{{.Names}}\\t{{.Status}}'"
            action_name = "vm_docker:ps"
        elif args.action == "logs":
            guest_cmd = f"docker logs --tail {args.lines} {args.container}"
            action_name = "vm_docker:logs"
        elif args.action == "restart":
            guest_cmd = f"docker restart {args.container}"
            action_name = "vm_docker:restart"
        elif args.action == "compose-up":
            guest_cmd = f"docker-compose -f {args.path} up -d"
            action_name = "vm_docker:compose_up"
        else:
            return 1

        result_dict = asyncio.run(_run_with_policy(
            vmid=args.vmid,
            actor=actor,
            action=action_name,
            command=_guest_exec_command(args.vmid, guest_cmd),
            execute=lambda: gexec.exec(vmid=args.vmid, cmd=guest_cmd),
            danger_mode=danger_mode,
            audit_tag=args.audit_tag,
            command_context="guest",
        ))
        print(json.dumps(result_dict, sort_keys=True))
        return 0 if result_dict.get("ok") else 1

    if args.command == "slo":
        metrics_res = service.slo.check_metrics()
        guest_res = None
        if args.vmid:
            guest_res = asyncio.run(
                _guest_health_check(
                    vmid=args.vmid,
                    services=args.services,
                    containers=args.containers,
                    actor=actor,
                    danger_mode=danger_mode,
                    audit_tag=args.audit_tag,
                )
            )

        final_ok = metrics_res.ok and (guest_res["ok"] if guest_res else True)
        output = {
            "ok": final_ok,
            "metrics": {
                "ok": metrics_res.ok,
                "details": metrics_res.details,
            },
        }
        if guest_res:
            output["guest"] = guest_res

        print(json.dumps(output, sort_keys=True))
        return 0 if final_ok else 1

    if args.command == "state":
        adapter = proxmox if args.provider == "proxmox" else xen
        action = getattr(adapter, args.action)
        if args.provider == "proxmox":
            command = _q_cmd("qm", args.action, args.vmid)
            result_dict = asyncio.run(_run_with_policy(
                vmid=args.vmid,
                actor=actor,
                action=f"vm_state:{args.action}",
                command=command,
                execute=lambda: action(args.vmid),
                danger_mode=danger_mode,
                audit_tag=args.audit_tag,
                command_context="host",
            ))
            print(json.dumps(result_dict, sort_keys=True))
            return 0 if result_dict.get("ok") else 1

        result = asyncio.run(action(args.vmid))
        print(json.dumps(result.to_dict(), sort_keys=True))
        return 0 if result.ok else 1

    if args.command == "metrics":
        print(json.dumps(service.metrics_snapshot(), sort_keys=True))
        return 0

    if args.command == "snapshot":
        if args.action == "create" and not args.name:
            raise SystemExit("--name is required for snapshot create")
        if args.action == "list":
            command = _q_cmd("qm", "listsnapshot", args.vmid)
            result_dict = asyncio.run(_run_with_policy(
                vmid=args.vmid,
                actor=actor,
                action="vm_snapshot:list",
                command=command,
                execute=lambda: snapshot.list(args.vmid),
                danger_mode=danger_mode,
                audit_tag=args.audit_tag,
                command_context="host",
            ))
        elif args.action == "create":
            command = _q_cmd("qm", "snapshot", args.vmid, args.name)
            result_dict = asyncio.run(_run_with_policy(
                vmid=args.vmid,
                actor=actor,
                action="vm_snapshot:create",
                command=command,
                execute=lambda: snapshot.create(args.vmid, args.name),
                danger_mode=danger_mode,
                audit_tag=args.audit_tag,
                command_context="host",
            ))
        elif args.action == "rollback":
            command = _q_cmd("qm", "rollback", args.vmid, args.name)
            result_dict = asyncio.run(_run_with_policy(
                vmid=args.vmid,
                actor=actor,
                action="vm_snapshot:rollback",
                command=command,
                execute=lambda: snapshot.rollback(args.vmid, args.name),
                danger_mode=danger_mode,
                audit_tag=args.audit_tag,
                command_context="host",
            ))
        elif args.action == "delete":
            command = _q_cmd("qm", "delsnapshot", args.vmid, args.name)
            result_dict = asyncio.run(_run_with_policy(
                vmid=args.vmid,
                actor=actor,
                action="vm_snapshot:delete",
                command=command,
                execute=lambda: snapshot.delete(args.vmid, args.name),
                danger_mode=danger_mode,
                audit_tag=args.audit_tag,
                command_context="host",
            ))
        else:
            return 1

        print(json.dumps(result_dict, sort_keys=True))
        return 0 if result_dict.get("ok") else 1

    if args.command == "list":
        cmd = "qm list"
        result = asyncio.run(
            service.exec(vmid="host", cmd=cmd, actor=actor, danger_mode=danger_mode,
                         audit_tag=args.audit_tag, action="vm_list",
                         skip_policy=True, skip_audit=True, skip_metrics=True)
        )
        stdout = (result.stdout or "").strip()
        memories = {m["vmid"]: m for m in list_all_vm_memories()}
        print(stdout)
        for m in list_all_vm_memories():
            vmid = m["vmid"]
            if m.get("tags") or m.get("notes_preview"):
                print(f"  [{vmid}] tags={m['tags']} | {m['notes_preview']}")
        return 0 if result.ok else 1

    if args.command == "ps":
        ps_cmd = "ps aux --no-header"
        result_dict = asyncio.run(_run_with_policy(
            vmid=args.vmid, actor=actor, action="vm_ps",
            command=_guest_exec_command(args.vmid, ps_cmd),
            execute=lambda: gexec.exec(vmid=args.vmid, cmd=ps_cmd),
            danger_mode=danger_mode, audit_tag=args.audit_tag, command_context="guest",
        ))
        from .mcp_server import _guest_stdout as _gs
        stdout = _gs(str(result_dict.get("stdout", "")))
        if args.filter_name:
            lines = [l for l in stdout.splitlines() if args.filter_name.lower() in l.lower()]
        else:
            lines = stdout.splitlines()
        print("\n".join(lines))
        return 0 if result_dict.get("ok") else 1

    if args.command == "top":
        top_cmd = f"ps aux --no-header --sort=-%cpu | head -{args.lines}"
        result_dict = asyncio.run(_run_with_policy(
            vmid=args.vmid, actor=actor, action="vm_top",
            command=_guest_exec_command(args.vmid, top_cmd),
            execute=lambda: gexec.exec(vmid=args.vmid, cmd=top_cmd),
            danger_mode=danger_mode, audit_tag=args.audit_tag, command_context="guest",
        ))
        from .mcp_server import _guest_stdout as _gs
        print(_gs(str(result_dict.get("stdout", ""))))
        return 0 if result_dict.get("ok") else 1

    if args.command == "disk":
        df_cmd = "df -h --output=source,fstype,size,used,avail,pcent,target"
        result_dict = asyncio.run(_run_with_policy(
            vmid=args.vmid, actor=actor, action="vm_disk",
            command=_guest_exec_command(args.vmid, df_cmd),
            execute=lambda: gexec.exec(vmid=args.vmid, cmd=df_cmd),
            danger_mode=danger_mode, audit_tag=args.audit_tag, command_context="guest",
        ))
        from .mcp_server import _guest_stdout as _gs
        print(_gs(str(result_dict.get("stdout", ""))))
        return 0 if result_dict.get("ok") else 1

    if args.command == "network":
        cmds = {"IPs": "ip -brief addr", "Routes": "ip route", "Listening": "ss -tlnp"}
        for label, ncmd in cmds.items():
            r = asyncio.run(_run_with_policy(
                vmid=args.vmid, actor=actor, action=f"vm_network:{label}",
                command=_guest_exec_command(args.vmid, ncmd),
                execute=lambda cmd=ncmd: gexec.exec(vmid=args.vmid, cmd=cmd),
                danger_mode=danger_mode, audit_tag=args.audit_tag, command_context="guest",
            ))
            from .mcp_server import _guest_stdout as _gs
            print(f"--- {label} ---")
            print(_gs(str(r.get("stdout", ""))))
        return 0

    if args.command == "tail":
        tail_cmd = f"tail -n {args.lines} {shlex.quote(args.path)}"
        result_dict = asyncio.run(_run_with_policy(
            vmid=args.vmid, actor=actor, action="vm_tail",
            command=_guest_exec_command(args.vmid, tail_cmd),
            execute=lambda: gexec.exec(vmid=args.vmid, cmd=tail_cmd),
            danger_mode=danger_mode, audit_tag=args.audit_tag, command_context="guest",
        ))
        from .mcp_server import _guest_stdout as _gs
        print(_gs(str(result_dict.get("stdout", ""))))
        return 0 if result_dict.get("ok") else 1

    if args.command == "sysinfo":
        cmds = {
            "OS": "cat /etc/os-release 2>/dev/null || cat /etc/issue",
            "Kernel": "uname -r",
            "Uptime": "uptime -p 2>/dev/null || uptime",
            "CPU cores": "nproc",
            "Hostname": "hostname -f 2>/dev/null || hostname",
            "Network": "ip -brief addr",
            "Memory": "free -h | head -2",
            "Disk": "df -h --output=target,size,avail,pcent | head -10",
        }
        from .mcp_server import _guest_stdout as _gs
        for label, scmd in cmds.items():
            r = asyncio.run(_run_with_policy(
                vmid=args.vmid, actor=actor, action=f"vm_sysinfo:{label}",
                command=_guest_exec_command(args.vmid, scmd),
                execute=lambda cmd=scmd: gexec.exec(vmid=args.vmid, cmd=cmd),
                danger_mode=danger_mode, audit_tag=args.audit_tag, command_context="guest",
            ))
            out = _gs(str(r.get("stdout", ""))).strip()
            print(f"=== {label} ===")
            print(out or "(no output)")
        return 0

    if args.command == "env":
        env_cmd = "env"
        result_dict = asyncio.run(_run_with_policy(
            vmid=args.vmid, actor=actor, action="vm_env",
            command=_guest_exec_command(args.vmid, env_cmd),
            execute=lambda: gexec.exec(vmid=args.vmid, cmd=env_cmd),
            danger_mode=danger_mode, audit_tag=args.audit_tag, command_context="guest",
        ))
        from .mcp_server import _guest_stdout as _gs
        print(_gs(str(result_dict.get("stdout", ""))))
        return 0 if result_dict.get("ok") else 1

    if args.command == "ripgrep":
        rg_parts = ["rg", "--line-number", "--no-heading", f"--max-count={args.max_results}"]
        if args.ignore_case:
            rg_parts.append("-i")
        if args.file_glob:
            rg_parts.extend(["--glob", args.file_glob])
        rg_parts.extend([args.pattern, args.path])
        rg_cmd = " ".join(shlex.quote(p) for p in rg_parts)
        result_dict = asyncio.run(_run_with_policy(
            vmid=args.vmid, actor=actor, action="vm_ripgrep",
            command=_guest_exec_command(args.vmid, rg_cmd),
            execute=lambda: gexec.exec(vmid=args.vmid, cmd=rg_cmd),
            danger_mode=danger_mode, audit_tag=args.audit_tag, command_context="guest",
        ))
        from .mcp_server import _guest_stdout as _gs
        print(_gs(str(result_dict.get("stdout", ""))))
        return 0 if result_dict.get("ok") else 1

    if args.command == "find":
        f_parts = ["find", args.path]
        if args.max_depth is not None:
            f_parts.extend(["-maxdepth", str(args.max_depth)])
        if args.file_type:
            f_parts.extend(["-type", args.file_type])
        if args.name:
            f_parts.extend(["-name", args.name])
        if args.mtime_days is not None:
            f_parts.extend(["-mtime", f"-{args.mtime_days}"])
        if args.size_gt:
            f_parts.extend(["-size", f"+{args.size_gt}"])
        find_cmd = " ".join(shlex.quote(p) for p in f_parts)
        result_dict = asyncio.run(_run_with_policy(
            vmid=args.vmid, actor=actor, action="vm_find",
            command=_guest_exec_command(args.vmid, find_cmd),
            execute=lambda: gexec.exec(vmid=args.vmid, cmd=find_cmd),
            danger_mode=danger_mode, audit_tag=args.audit_tag, command_context="guest",
        ))
        from .mcp_server import _guest_stdout as _gs
        print(_gs(str(result_dict.get("stdout", ""))))
        return 0 if result_dict.get("ok") else 1

    if args.command == "port":
        ss_cmd = f"ss -tlnp 'sport = :{args.port}'"
        result_dict = asyncio.run(_run_with_policy(
            vmid=args.vmid, actor=actor, action="vm_port_check",
            command=_guest_exec_command(args.vmid, ss_cmd),
            execute=lambda: gexec.exec(vmid=args.vmid, cmd=ss_cmd),
            danger_mode=danger_mode, audit_tag=args.audit_tag, command_context="guest",
        ))
        from .mcp_server import _guest_stdout as _gs
        stdout = _gs(str(result_dict.get("stdout", ""))).strip()
        lines = [l for l in stdout.splitlines() if l.strip() and "State" not in l]
        print(f"Port {args.port}: {'LISTENING' if lines else 'NOT listening'}")
        if lines:
            print("\n".join(lines))
        return 0 if result_dict.get("ok") else 1

    if args.command == "install":
        if args.manager == "apt":
            pkg_cmd = f"DEBIAN_FRONTEND=noninteractive apt-get install -y {shlex.quote(args.package)}"
        elif args.manager == "yum":
            pkg_cmd = f"yum install -y {shlex.quote(args.package)}"
        elif args.manager == "dnf":
            pkg_cmd = f"dnf install -y {shlex.quote(args.package)}"
        else:  # apk
            pkg_cmd = f"apk add --no-cache {shlex.quote(args.package)}"
        result_dict = asyncio.run(_run_with_policy(
            vmid=args.vmid, actor=actor, action="vm_install_package",
            command=_guest_exec_command(args.vmid, pkg_cmd),
            execute=lambda: gexec.exec(vmid=args.vmid, cmd=pkg_cmd),
            danger_mode=danger_mode, audit_tag=args.audit_tag, command_context="guest",
        ))
        print(json.dumps(result_dict, sort_keys=True))
        return 0 if result_dict.get("ok") else 1

    if args.command == "memory":
        if args.action == "get":
            print(json.dumps(memory_context_summary(args.vmid), indent=2))
        elif args.action == "list":
            records = list_all_vm_memories()
            print(json.dumps(records, indent=2))
        elif args.action == "set":
            paths_dict = None
            if args.paths:
                paths_dict = {}
                for item in args.paths:
                    if "=" in item:
                        k, v = item.split("=", 1)
                        paths_dict[k] = v
            annotate_vm(
                args.vmid,
                notes=args.notes,
                paths=paths_dict,
                services=args.services,
                containers=args.containers,
                tags=args.tags,
            )
            print(json.dumps(memory_context_summary(args.vmid), indent=2))
        elif args.action == "clear":
            import os as _os
            from .vm_memory import _MEMORY_DIR
            path = _MEMORY_DIR / f"{args.vmid}.json"
            if path.exists():
                _os.remove(path)
                print(f"Memory cleared for VM {args.vmid}")
            else:
                print(f"No memory found for VM {args.vmid}")
        return 0

    return 1


if __name__ == "__main__":
    raise SystemExit(main())
