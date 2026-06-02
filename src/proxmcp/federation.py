from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import Any, Literal

from .service import VMService
from .models import CommandResult

@dataclass(slots=True)
class FederationManager:
    service: VMService
    
    async def fan_out_exec(
        self,
        vmids: list[str],
        cmd: str,
        actor: str = "mcp-agent",
        danger_mode: bool | Literal["safe", "maintenance", "break_glass"] = False,
        audit_tag: str | None = None,
        command_context: str = "host",
    ) -> dict[str, CommandResult]:
        """Execute a command on multiple VMs in parallel."""
        output = {}
        try:
            self.service.policy.validate(
                cmd=cmd,
                danger_mode=danger_mode,
                command_context=command_context,
            )
        except Exception as exc:
            for vmid in vmids:
                output[vmid] = CommandResult(
                    ok=False,
                    code=403,
                    stdout="",
                    stderr=str(exc),
                    duration_ms=0,
                    vmid=vmid,
                    cmd=cmd,
                )
            return output

        tasks = [
            self.service.exec(
                vmid=vmid,
                cmd=cmd,
                actor=actor,
                danger_mode=danger_mode,
                audit_tag=audit_tag,
                action="vm_fan_out",
                command_context=command_context,
            )
            for vmid in vmids
        ]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        for vmid, res in zip(vmids, results):
            if isinstance(res, Exception):
                output[vmid] = CommandResult(
                    ok=False,
                    code=500,
                    stdout="",
                    stderr=str(res),
                    duration_ms=0,
                    vmid=vmid,
                    cmd=cmd,
                )
            else:
                output[vmid] = res
        return output

    async def cross_vm_dependency_exec(
        self,
        plan: list[dict[str, Any]],
        actor: str = "mcp-agent",
        danger_mode: bool | Literal["safe", "maintenance", "break_glass"] = False,
        audit_tag: str | None = None,
        command_context: str = "host",
    ) -> list[dict[str, Any]]:
        """
        Execute a sequence of commands across different VMs.
        Example plan: [{"vmid": "100", "cmd": "ls"}, {"vmid": "101", "cmd": "ps"}]
        """
        results = []
        for step in plan:
            vmid = step["vmid"]
            cmd = step["cmd"]
            try:
                self.service.policy.validate(
                    cmd=cmd,
                    danger_mode=danger_mode,
                    command_context=command_context,
                )
            except Exception as exc:
                results.append({"step": step, "result": CommandResult(
                    ok=False,
                    code=403,
                    stdout="",
                    stderr=str(exc),
                    duration_ms=0,
                    vmid=vmid,
                    cmd=cmd,
                ).to_dict()})
                break

            res = await self.service.exec(
                vmid=vmid,
                cmd=cmd,
                actor=actor,
                danger_mode=danger_mode,
                audit_tag=audit_tag,
                action="vm_orchestrate_step",
                command_context=command_context,
            )
            results.append({"step": step, "result": res.to_dict()})
            if not res.ok:
                break # Stop on failure
        return results
