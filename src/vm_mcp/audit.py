from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .security import SecretRedactor


@dataclass(slots=True)
class AuditLogger:
    path: Path
    redactor: SecretRedactor = SecretRedactor()

    def _redact_result(self, value: Any) -> Any:
        if isinstance(value, str):
            return self.redactor.redact(value)
        if isinstance(value, list):
            return [self._redact_result(item) for item in value]
        if isinstance(value, dict):
            return {key: self._redact_result(item) for key, item in value.items()}
        return value

    def log(self, *, actor: str, action: str, vmid: str, cmd: str, result: dict[str, Any], audit_tag: str | None = None) -> None:
        event = {
            "ts": datetime.now(tz=timezone.utc).isoformat(),
            "actor": actor,
            "action": action,
            "vmid": vmid,
            "cmd": self.redactor.redact(cmd),
            "result": self._redact_result(result),
            "audit_tag": audit_tag,
        }
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("a", encoding="utf-8") as fp:
            fp.write(json.dumps(event, sort_keys=True) + "\n")
