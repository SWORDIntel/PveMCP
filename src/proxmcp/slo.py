from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any
from .metrics import MetricsStore
from .orchestration import VMServiceManager, VMContainerManager

@dataclass(slots=True)
class SLOResult:
    ok: bool
    details: dict[str, Any]

@dataclass(slots=True)
class SLOThresholds:
    max_error_rate: float = 0.05  # 5%
    max_timeout_rate: float = 0.02 # 2%
    min_request_count: int = 0
    max_p95_latency_ms: int = 5000

class SLOChecker:
    def __init__(self, metrics: MetricsStore, thresholds: SLOThresholds | None = None) -> None:
        self.metrics = metrics
        self.thresholds = thresholds or SLOThresholds()

    def check_metrics(self) -> SLOResult:
        snap = self.metrics.snapshot()
        reqs = snap["request_count"]
        errors = snap["error_count"]
        timeouts = snap["timeout_count"]
        p95 = snap["latency_p95_ms"]

        error_rate = errors / reqs if reqs > 0 else 0
        timeout_rate = timeouts / reqs if reqs > 0 else 0

        details = {
            "error_rate": error_rate,
            "timeout_rate": timeout_rate,
            "p95_latency_ms": p95,
            "request_count": reqs,
        }

        ok = (
            error_rate <= self.thresholds.max_error_rate and
            timeout_rate <= self.thresholds.max_timeout_rate and
            reqs >= self.thresholds.min_request_count and
            p95 <= self.thresholds.max_p95_latency_ms
        )

        return SLOResult(ok=ok, details=details)

    async def check_guest_health(self, vmid: str, services: list[str], containers: list[str], 
                                 svc_mgr: VMServiceManager, container_mgr: VMContainerManager) -> SLOResult:
        details = {"services": {}, "containers": {}}
        all_ok = True

        for svc in services:
            res = await svc_mgr.status(vmid, svc)
            is_active = res.stdout.strip() == "active"
            details["services"][svc] = is_active
            if not is_active:
                all_ok = False

        if containers:
            res = await container_mgr.ps(vmid)
            # Simple check: is the container name in the ps output?
            # A more robust check would parse the docker ps format
            for cont in containers:
                is_running = cont in res.stdout
                details["containers"][cont] = is_running
                if not is_running:
                    all_ok = False

        return SLOResult(ok=all_ok, details=details)
