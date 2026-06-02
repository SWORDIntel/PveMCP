import asyncio

from proxmcp.metrics import MetricsStore
from proxmcp.service import VMService


def test_metrics_store_snapshot() -> None:
    metrics = MetricsStore()
    metrics.record(action="vm_exec", duration_ms=15, ok=True)
    metrics.record(action="vm_exec", duration_ms=30, ok=False, timeout=True)
    snap = metrics.snapshot()
    assert snap["request_count"] == 2
    assert snap["error_count"] == 1
    assert snap["timeout_count"] == 1


def test_service_updates_metrics(tmp_path) -> None:
    svc = VMService.build(audit_path=str(tmp_path / "audit.log"))
    asyncio.run(svc.exec(vmid="100", cmd="echo ok"))
    snap = svc.metrics_snapshot()
    assert snap["request_count"] == 1
    assert snap["by_action"]["vm_exec"] == 1
