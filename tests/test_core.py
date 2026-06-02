import asyncio

from proxmcp.jobs import JobManager
from proxmcp.policy import PolicyEnforcer, PolicyError
from proxmcp.runner import CommandRunner


def test_policy_blocks_dangerous_command() -> None:
    enforcer = PolicyEnforcer()
    try:
        enforcer.validate("rm -rf /tmp/demo")
        raise AssertionError("expected policy error")
    except PolicyError:
        pass


def test_runner_returns_schema_fields() -> None:
    result = asyncio.run(CommandRunner().run(vmid="100", cmd="echo ok"))
    assert set(result.to_dict()) == {"ok", "code", "stdout", "stderr", "duration_ms", "vmid", "cmd"}
    assert result.ok is True


def test_job_lifecycle() -> None:
    async def _run() -> None:
        manager = JobManager()
        job_id = manager.job_start("100", "echo hi")
        await asyncio.sleep(0.05)
        status = manager.job_status(job_id)
        assert status["status"] in {"running", "completed"}
        await asyncio.sleep(0.2)
        status = manager.job_status(job_id)
        assert status["status"] == "completed"
        assert status["result"]["stdout"].strip() == "hi"

    asyncio.run(_run())
