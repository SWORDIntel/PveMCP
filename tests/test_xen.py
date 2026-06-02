import asyncio

from proxmcp.files import vm_file_put, vm_file_tail
from proxmcp.profiles import ProfileRegistry, VMProfile
from proxmcp.xen import XenLifecycle
from proxmcp.runner import CommandRunner


def test_profile_registry() -> None:
    registry = ProfileRegistry([VMProfile(name="ops", vmid="101")])
    assert registry.resolve("ops").vmid == "101"


def test_file_helpers() -> None:
    cmd = vm_file_tail("/var/log/syslog", lines=20)
    assert cmd == "tail -n 20 /var/log/syslog"


def test_xen_status_invocation() -> None:
    async def _run() -> None:
        xen = XenLifecycle(runner=CommandRunner())
        result = await xen.status("Domain-0")
        assert result.cmd == "xl list Domain-0"

    asyncio.run(_run())
