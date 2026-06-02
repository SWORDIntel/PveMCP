from __future__ import annotations

from dataclasses import dataclass

from .runner import CommandRunner


@dataclass(slots=True)
class XenLifecycle:
    runner: CommandRunner

    async def status(self, vmid: str):
        return await self.runner.run(vmid=vmid, cmd=f"xl list {vmid}")

    async def start(self, vmid: str):
        return await self.runner.run(vmid=vmid, cmd=f"xl create /etc/xen/{vmid}.cfg")

    async def stop(self, vmid: str):
        return await self.runner.run(vmid=vmid, cmd=f"xl shutdown {vmid}")

    async def reboot(self, vmid: str):
        return await self.runner.run(vmid=vmid, cmd=f"xl reboot {vmid}")
