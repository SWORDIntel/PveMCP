import asyncio
import json
from pathlib import Path

from proxmcp.service import VMService


def test_service_redacts_and_audits(tmp_path: Path) -> None:
    audit_file = tmp_path / "audit.log"
    service = VMService.build(audit_path=str(audit_file))

    result = asyncio.run(service.exec(vmid="100", cmd="echo token=abc123", actor="tester"))
    assert result.ok is True
    assert "abc123" not in result.stdout

    lines = audit_file.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 1
    event = json.loads(lines[0])
    assert event["actor"] == "tester"
    assert event["action"] == "vm_exec"
