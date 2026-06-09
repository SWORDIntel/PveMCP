import json
from pathlib import Path
from typing import Any

def get_vm_history(audit_log_path: str, vmid: str, limit: int = 20) -> list[dict[str, Any]]:
    """Replay the last N audit events for a specific VM."""
    history = []
    if not Path(audit_log_path).exists():
        return []
        
    with open(audit_log_path, "r") as f:
        # Read lines in reverse to get newest first
        lines = f.readlines()
        for line in reversed(lines):
            try:
                event = json.loads(line)
                if event.get("vmid") == vmid:
                    history.append(event)
                    if len(history) >= limit:
                        break
            except json.JSONDecodeError:
                continue
    return history
