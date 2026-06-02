"""
vm_memory.py — Per-VM persistent knowledge store.

Each VM gets a JSON file at VM_MCP_MEMORY_DIR/<vmid>.json containing:
  - notes: free-form text notes
  - paths: labelled known filesystem paths (e.g. {"app": "/opt/myapp", "config": "/etc/myapp.conf"})
  - services: known systemd service names
  - containers: known docker container names
  - env: important environment variables or context hints
  - tags: arbitrary string tags
  - history: last 20 resolved command results (truncated stdout)
  - created_at: ISO timestamp
  - updated_at: ISO timestamp

The store is loaded automatically by get_vm_memory() and saved by save_vm_memory().
All MCP tools that accept a vmid should call load_context() so the AI gets a
compact structured context block without re-discovery every session.
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def _resolve_memory_dir() -> Path:
    for env_var in ("PROXMCP_MEMORY_DIR", "VM_MCP_MEMORY_DIR"):
        val = os.getenv(env_var)
        if val:
            try:
                p = Path(val).expanduser()
                p.mkdir(parents=True, exist_ok=True)
                return p
            except Exception:
                pass

    for path_str in ("~/.proxmcp/memory", "/var/lib/proxmcp/memory"):
        try:
            p = Path(path_str).expanduser()
            p.mkdir(parents=True, exist_ok=True)
            return p
        except Exception:
            pass

    import tempfile
    p = Path(tempfile.gettempdir()) / "proxmcp" / "memory"
    p.mkdir(parents=True, exist_ok=True)
    return p


_MEMORY_DIR = _resolve_memory_dir()
_MAX_HISTORY = 20
_MAX_STDOUT_LEN = 400


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _memory_path(vmid: str) -> Path:
    _MEMORY_DIR.mkdir(parents=True, exist_ok=True)
    return _MEMORY_DIR / f"{vmid}.json"


def _empty_record(vmid: str) -> dict[str, Any]:
    return {
        "vmid": vmid,
        "notes": "",
        "paths": {},
        "services": [],
        "containers": [],
        "env": {},
        "tags": [],
        "history": [],
        "created_at": _now(),
        "updated_at": _now(),
    }


def load_vm_memory(vmid: str) -> dict[str, Any]:
    """Load the memory record for a VM, returning an empty record if none exists."""
    path = _memory_path(vmid)
    if not path.exists():
        return _empty_record(vmid)
    try:
        with path.open("r", encoding="utf-8") as f:
            data = json.load(f)
        # Back-fill missing keys from newer schema
        defaults = _empty_record(vmid)
        for key, default in defaults.items():
            data.setdefault(key, default)
        return data
    except (json.JSONDecodeError, OSError):
        return _empty_record(vmid)


def save_vm_memory(record: dict[str, Any]) -> None:
    """Persist a memory record to disk."""
    vmid = record.get("vmid", "unknown")
    record["updated_at"] = _now()
    path = _memory_path(vmid)
    path.write_text(json.dumps(record, indent=2, ensure_ascii=False), encoding="utf-8")


def memory_context_summary(vmid: str) -> dict[str, Any]:
    """Return a compact summary of known VM context for injection into tool responses."""
    rec = load_vm_memory(vmid)
    return {
        "vmid": vmid,
        "notes": rec["notes"] or None,
        "known_paths": rec["paths"] or None,
        "known_services": rec["services"] or None,
        "known_containers": rec["containers"] or None,
        "tags": rec["tags"] or None,
        "env_hints": rec["env"] or None,
        "last_updated": rec["updated_at"],
    }


def record_history(vmid: str, cmd: str, stdout: str, ok: bool) -> None:
    """Append a command result snippet to the VM's history ring buffer."""
    rec = load_vm_memory(vmid)
    entry = {
        "ts": _now(),
        "cmd": cmd[:200],
        "ok": ok,
        "stdout_snippet": stdout[:_MAX_STDOUT_LEN],
    }
    history: list[dict[str, Any]] = rec.get("history", [])
    history.append(entry)
    rec["history"] = history[-_MAX_HISTORY:]
    save_vm_memory(rec)


def annotate_vm(
    vmid: str,
    *,
    notes: str | None = None,
    paths: dict[str, str] | None = None,
    services: list[str] | None = None,
    containers: list[str] | None = None,
    env: dict[str, str] | None = None,
    tags: list[str] | None = None,
) -> dict[str, Any]:
    """Merge new knowledge into a VM's memory record. Returns the updated record."""
    rec = load_vm_memory(vmid)
    if notes is not None:
        rec["notes"] = notes
    if paths:
        rec["paths"].update(paths)
    if services:
        existing = set(rec["services"])
        existing.update(services)
        rec["services"] = sorted(existing)
    if containers:
        existing = set(rec["containers"])
        existing.update(containers)
        rec["containers"] = sorted(existing)
    if env:
        rec["env"].update(env)
    if tags:
        existing = set(rec["tags"])
        existing.update(tags)
        rec["tags"] = sorted(existing)
    save_vm_memory(rec)
    return rec


def list_all_vm_memories() -> list[dict[str, Any]]:
    """Return a summary listing of all stored VM memory records."""
    if not _MEMORY_DIR.exists():
        return []
    summaries = []
    for p in sorted(_MEMORY_DIR.glob("*.json")):
        vmid = p.stem
        rec = load_vm_memory(vmid)
        summaries.append({
            "vmid": vmid,
            "tags": rec.get("tags", []),
            "notes_preview": (rec.get("notes") or "")[:80],
            "known_paths": list(rec.get("paths", {}).keys()),
            "known_services": rec.get("services", []),
            "known_containers": rec.get("containers", []),
            "updated_at": rec.get("updated_at"),
        })
    return summaries
