from __future__ import annotations

from dataclasses import dataclass, asdict
from typing import Any


@dataclass(slots=True)
class CommandResult:
    ok: bool
    code: int
    stdout: str
    stderr: str
    duration_ms: int
    vmid: str
    cmd: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
