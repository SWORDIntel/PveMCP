from __future__ import annotations

from pathlib import Path


def vm_file_put(local_path: str, remote_staging_dir: str = "/tmp/proxmcp") -> str:
    src = Path(local_path)
    if not src.exists():
        raise FileNotFoundError(local_path)
    return f"mkdir -p {remote_staging_dir} && cat > {remote_staging_dir}/{src.name}"


def vm_file_tail(path: str, lines: int = 100) -> str:
    return f"tail -n {max(1, lines)} {path}"
