from __future__ import annotations

import shlex
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Awaitable, Callable, Literal

from .metrics import Timer
from .models import CommandResult
from .proxmox import ProxmoxFileOps, ProxmoxGuestExec
from .service import VMService


CommandExecutor = Callable[[], Awaitable[CommandResult]]


def _q_cmd(*parts: object) -> str:
    return " ".join(shlex.quote(str(part)) for part in parts)


@dataclass(slots=True)
class WorkflowManager:
    service: VMService
    file_ops: ProxmoxFileOps
    gexec: ProxmoxGuestExec
    artifact_idx: ArtifactIndex | None = None

    async def _run_with_policy(
        self,
        *,
        vmid: str,
        actor: str,
        action: str,
        command: str,
        execute: CommandExecutor,
        danger_mode: bool | Literal["safe", "maintenance", "break_glass"],
        audit_tag: str | None = None,
        command_context: str = "host",
    ) -> CommandResult:
        timer = Timer()
        try:
            self.service.policy.validate(command, danger_mode=danger_mode, command_context=command_context)
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
            result.stdout = self.service.redactor.redact(result.stdout)
            result.stderr = self.service.redactor.redact(result.stderr)
            self.service.audit.log(
                actor=actor,
                action=action,
                vmid=vmid,
                cmd=command,
                result=result.to_dict(),
                audit_tag=audit_tag,
            )
            self.service.metrics.record_policy_block()
            self.service.metrics.record(action=action, duration_ms=timer.elapsed_ms(), ok=False, timeout=False)
            return result

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

        result.stdout = self.service.redactor.redact(result.stdout)
        result.stderr = self.service.redactor.redact(result.stderr)
        self.service.audit.log(
            actor=actor,
            action=action,
            vmid=vmid,
            cmd=command,
            result=result.to_dict(),
            audit_tag=audit_tag,
        )
        self.service.metrics.record(action=action, duration_ms=timer.elapsed_ms(), ok=result.ok, timeout=(result.code == 124))
        return result

    async def run_generate_outputs(
        self,
        vmid: str,
        script_path: str,
        output_path: str,
        actor: str = "mcp-agent",
        danger_mode: bool | Literal["safe", "maintenance", "break_glass"] = False,
        audit_tag: str | None = None,
    ) -> CommandResult:
        """Example workflow: upload script, run it, collect output."""
        # 1. Put script
        remote_script = "/tmp/workflow_script.sh"
        put_res = await self._run_with_policy(
            vmid=vmid,
            actor=actor,
            action="workflow_generate:put_script",
            command=_q_cmd("qm", "guest", "file", "write", vmid, remote_script, script_path),
            execute=lambda: self.file_ops.put(vmid, script_path, remote_script),
            danger_mode=danger_mode,
            audit_tag=audit_tag,
            command_context="guest",
        )
        if not put_res.ok:
            return put_res

        # 2. Run script
        exec_res = await self._run_with_policy(
            vmid=vmid,
            actor=actor,
            action="workflow_generate:run_script",
            command=_q_cmd("bash", remote_script),
            execute=lambda: self.gexec.exec(vmid=vmid, cmd=_q_cmd("bash", remote_script)),
            danger_mode=danger_mode,
            audit_tag=audit_tag,
            command_context="guest",
        )
        if not exec_res.ok:
            return exec_res

        # 3. Get output
        get_res = await self._run_with_policy(
            vmid=vmid,
            actor=actor,
            action="workflow_generate:get_output",
            command=_q_cmd("qm", "guest", "file", "read", vmid, output_path),
            execute=lambda: self.file_ops.get(vmid, output_path),
            danger_mode=danger_mode,
            audit_tag=audit_tag,
            command_context="guest",
        )

        if get_res.ok and self.artifact_idx is not None:
            self.artifact_idx.add(
                name=f"workflow_output:{vmid}:{script_path}",
                vmid=vmid,
                path=output_path,
                size=len(get_res.stdout),
            )

        return get_res

    async def run_eval_scorecard(
        self,
        vmid: str,
        data_path: str,
        actor: str = "mcp-agent",
        danger_mode: bool | Literal["safe", "maintenance", "break_glass"] = False,
        audit_tag: str | None = None,
    ) -> dict[str, Any]:
        """Example workflow: evaluate a scorecard based on data in VM."""
        # This is a mock implementation of a high-level workflow
        res = await self._run_with_policy(
            vmid=vmid,
            actor=actor,
            action="workflow_scorecard:read_data",
            command=_q_cmd("cat", data_path),
            execute=lambda: self.gexec.exec(vmid=vmid, cmd=_q_cmd("cat", data_path)),
            danger_mode=danger_mode,
            audit_tag=audit_tag,
            command_context="guest",
        )

        if not res.ok:
            return {
                "ok": False,
                "error": res.stderr,
                "score": 0,
                "vmid": vmid,
                "ts": datetime.now(tz=timezone.utc).isoformat(),
            }

        score = len(res.stdout) % 100
        return {
            "ok": True,
            "score": score,
            "vmid": vmid,
            "bytes": len(res.stdout),
            "ts": datetime.now(tz=timezone.utc).isoformat(),
        }


@dataclass(slots=True)
class ArtifactIndex:
    artifacts: dict[str, dict[str, Any]] = field(default_factory=dict)

    def add(self, name: str, vmid: str, path: str, size: int):
        self.artifacts[name] = {
            "vmid": vmid,
            "path": path,
            "size": size,
            "mtime": datetime.now(tz=timezone.utc).isoformat(),
        }

    def list(self) -> dict[str, dict[str, Any]]:
        return self.artifacts
