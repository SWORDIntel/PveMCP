import asyncio

from proxmcp.proxmox import ProxmoxLifecycle, ProxmoxSnapshot
from proxmcp.runner import CommandRunner


def test_proxmox_state_cmds() -> None:
    async def _run() -> None:
        pve = ProxmoxLifecycle(runner=CommandRunner())
        status = await pve.status("100")
        reboot = await pve.reboot("100")
        assert status.cmd == "qm status 100"
        assert reboot.cmd == "qm reboot 100"

    asyncio.run(_run())


def test_proxmox_snapshot_cmds() -> None:
    async def _run() -> None:
        snap = ProxmoxSnapshot(runner=CommandRunner())
        result = await snap.create("100", "daily")
        assert result.cmd == "qm snapshot 100 daily"

    asyncio.run(_run())
