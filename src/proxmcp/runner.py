from __future__ import annotations

import asyncio
import shlex
import time
from dataclasses import dataclass

from .models import CommandResult

HOST_SUDO_COMMANDS = {
    "qm",
    "pct",
    "pvesh",
    "pveam",
    "pvecm",
    "vzdump",
    "qmgmt",
    "xe",
    "xl",
    "qemu-img",
}


@dataclass(slots=True)
class RunnerConfig:
    timeout_s: float = 30.0
    retries: int = 1
    auto_host_sudo: bool = False


class CommandRunner:
    def __init__(self, config: RunnerConfig | None = None) -> None:
        self.config = config or RunnerConfig()

    async def run(
        self,
        vmid: str,
        cmd: str,
        timeout_s: float | None = None,
        retries: int | None = None,
        cwd: str | None = None,
        env: dict[str, str] | None = None,
    ) -> CommandResult:
        timeout = timeout_s if timeout_s is not None else self.config.timeout_s
        max_retries = retries if retries is not None else self.config.retries

        try:
            argv = shlex.split(cmd)
        except ValueError as exc:
            return CommandResult(
                ok=False,
                code=2,
                stdout="",
                stderr=f"command tokenization failed: {exc}",
                duration_ms=0,
                vmid=vmid,
                cmd=cmd,
            )

        if not argv:
            return CommandResult(
                ok=False,
                code=2,
                stdout="",
                stderr="empty command is not allowed",
                duration_ms=0,
                vmid=vmid,
                cmd=cmd,
            )
        if self.config.auto_host_sudo and argv[0] in HOST_SUDO_COMMANDS and argv[0] != "sudo":
            argv = ["sudo", "-n", *argv]

        last_err = ""
        start = time.monotonic()
        for attempt in range(max_retries + 1):
            try:
                proc = await asyncio.create_subprocess_exec(
                    *argv,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                    cwd=cwd,
                    env=env,
                )
                stdout_b, stderr_b = await asyncio.wait_for(proc.communicate(), timeout=timeout)
                duration_ms = int((time.monotonic() - start) * 1000)
                code = proc.returncode or 0
                return CommandResult(
                    ok=(code == 0),
                    code=code,
                    stdout=stdout_b.decode(),
                    stderr=stderr_b.decode(),
                    duration_ms=duration_ms,
                    vmid=vmid,
                    cmd=cmd,
                )
            except TimeoutError:
                last_err = f"timeout after {timeout}s"
            except Exception as exc:  # noqa: BLE001
                last_err = str(exc)

            if attempt < max_retries:
                await asyncio.sleep(0.2 * (attempt + 1))

        duration_ms = int((time.monotonic() - start) * 1000)
        return CommandResult(
            ok=False,
            code=124,
            stdout="",
            stderr=last_err,
            duration_ms=duration_ms,
            vmid=vmid,
            cmd=cmd,
        )
