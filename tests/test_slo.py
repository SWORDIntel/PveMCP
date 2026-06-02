import pytest
from unittest.mock import MagicMock, AsyncMock
from proxmcp.slo import SLOChecker, SLOThresholds
from proxmcp.metrics import MetricsStore
from proxmcp.models import CommandResult

def test_slo_metrics_ok():
    metrics = MetricsStore()
    metrics.record(action="test", duration_ms=100, ok=True)
    
    checker = SLOChecker(metrics)
    res = checker.check_metrics()
    assert res.ok is True
    assert res.details["error_rate"] == 0
    assert res.details["request_count"] == 1

def test_slo_metrics_fail_error_rate():
    metrics = MetricsStore()
    metrics.record(action="test", duration_ms=100, ok=True)
    metrics.record(action="test", duration_ms=100, ok=False) # 50% error rate
    
    checker = SLOChecker(metrics, thresholds=SLOThresholds(max_error_rate=0.1))
    res = checker.check_metrics()
    assert res.ok is False
    assert res.details["error_rate"] == 0.5

@pytest.mark.asyncio
async def test_slo_guest_health_ok():
    metrics = MetricsStore()
    checker = SLOChecker(metrics)
    
    svc_mgr = MagicMock()
    svc_mgr.status = AsyncMock(return_value=CommandResult(
        ok=True, code=0, stdout="active", stderr="", duration_ms=10, vmid="100", cmd="status"
    ))
    
    container_mgr = MagicMock()
    container_mgr.ps = AsyncMock(return_value=CommandResult(
        ok=True, code=0, stdout="my-container", stderr="", duration_ms=10, vmid="100", cmd="ps"
    ))
    
    res = await checker.check_guest_health(
        vmid="100", 
        services=["nginx"], 
        containers=["my-container"],
        svc_mgr=svc_mgr,
        container_mgr=container_mgr
    )
    
    assert res.ok is True
    assert res.details["services"]["nginx"] is True
    assert res.details["containers"]["my-container"] is True

@pytest.mark.asyncio
async def test_slo_guest_health_fail():
    metrics = MetricsStore()
    checker = SLOChecker(metrics)
    
    svc_mgr = MagicMock()
    svc_mgr.status = AsyncMock(return_value=CommandResult(
        ok=True, code=0, stdout="inactive", stderr="", duration_ms=10, vmid="100", cmd="status"
    ))
    
    container_mgr = MagicMock()
    container_mgr.ps = AsyncMock(return_value=CommandResult(
        ok=True, code=0, stdout="", stderr="", duration_ms=10, vmid="100", cmd="ps"
    ))
    
    res = await checker.check_guest_health(
        vmid="100", 
        services=["nginx"], 
        containers=["my-container"],
        svc_mgr=svc_mgr,
        container_mgr=container_mgr
    )
    
    assert res.ok is False
    assert res.details["services"]["nginx"] is False
    assert res.details["containers"]["my-container"] is False
