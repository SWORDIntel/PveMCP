from __future__ import annotations

import statistics
import time
from collections import Counter
from dataclasses import dataclass, field


@dataclass(slots=True)
class MetricsStore:
    request_count: int = 0
    error_count: int = 0
    timeout_count: int = 0
    durations_ms: list[int] = field(default_factory=list)
    policy_blocks: int = 0
    by_action: Counter[str] = field(default_factory=Counter)

    def record(self, *, action: str, duration_ms: int, ok: bool, timeout: bool = False) -> None:
        self.request_count += 1
        self.by_action[action] += 1
        self.durations_ms.append(duration_ms)
        if not ok:
            self.error_count += 1
        if timeout:
            self.timeout_count += 1

    def record_policy_block(self) -> None:
        self.policy_blocks += 1

    def snapshot(self) -> dict[str, float | int | dict[str, int]]:
        p50 = int(statistics.median(self.durations_ms)) if self.durations_ms else 0
        p95 = int(sorted(self.durations_ms)[max(0, int(len(self.durations_ms) * 0.95) - 1)]) if self.durations_ms else 0
        return {
            "request_count": self.request_count,
            "error_count": self.error_count,
            "timeout_count": self.timeout_count,
            "policy_blocks": self.policy_blocks,
            "latency_p50_ms": p50,
            "latency_p95_ms": p95,
            "by_action": dict(self.by_action),
        }


@dataclass(slots=True)
class Timer:
    started_at: float = field(default_factory=time.monotonic)

    def elapsed_ms(self) -> int:
        return int((time.monotonic() - self.started_at) * 1000)
