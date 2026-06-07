from __future__ import annotations

import re
import shlex
import tempfile
import shutil
from dataclasses import dataclass
from pathlib import Path

from .models import CommandResult
from .runner import CommandRunner
from .ftp_server import TemporaryFTPServer


_VMID_RE = re.compile(r"^[0-9]+$")
_NODE_RE = re.compile(r"^[A-Za-z][A-Za-z0-9._-]{0,63}$")
_SNAPSHOT_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_CONFIG_KEY_RE = re.compile(r"^[A-Za-z][A-Za-z0-9._-]{0,63}$")
_ENV_KEY_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")


def build_qm_command(*parts: object) -> str:
    return " ".join(shlex.quote(str(part)) for part in parts)


def _invalid(vmid: str, action: str, detail: str) -> CommandResult:
    return CommandResult(
        ok=False,
        code=2,
        stdout="",
        stderr=f"{action}: {detail}",
        duration_ms=0,
        vmid=vmid,
        cmd=action,
    )


def _ensure_vmid(vmid: str) -> str | None:
    if not isinstance(vmid, str) or not _VMID_RE.fullmatch(vmid):
        return "vmid must be a numeric string"
    return None


def _ensure_safe_token(value: str, name: str, pattern: re.Pattern[str]) -> str | None:
    if not isinstance(value, str) or not pattern.fullmatch(value):
        return f"{name} has invalid characters"
    return None


def _ensure_no_control_chars(value: str, name: str) -> str | None:
    if _CONTROL_RE.search(value):
        return f"{name} contains control characters"
    return None


def _ensure_snapshot_name(name: str) -> str | None:
    if not isinstance(name, str):
        return "snapshot name must be text"
    if _ensure_safe_token(name, "snapshot name", _SNAPSHOT_NAME_RE):
        return "snapshot name has invalid characters"
    return None


@dataclass(slots=True)
class ProxmoxLifecycle:
    runner: CommandRunner

    async def status(self, vmid: str) -> CommandResult:
        error = _ensure_vmid(vmid)
        if error:
            return _invalid(vmid, "status", error)
        return await self.runner.run(vmid=vmid, cmd=build_qm_command("qm", "status", vmid))

    async def start(self, vmid: str) -> CommandResult:
        error = _ensure_vmid(vmid)
        if error:
            return _invalid(vmid, "start", error)
        return await self.runner.run(vmid=vmid, cmd=build_qm_command("qm", "start", vmid))

    async def stop(self, vmid: str) -> CommandResult:
        error = _ensure_vmid(vmid)
        if error:
            return _invalid(vmid, "stop", error)
        return await self.runner.run(vmid=vmid, cmd=build_qm_command("qm", "stop", vmid))

    async def reboot(self, vmid: str) -> CommandResult:
        error = _ensure_vmid(vmid)
        if error:
            return _invalid(vmid, "reboot", error)
        return await self.runner.run(vmid=vmid, cmd=build_qm_command("qm", "reboot", vmid))

    async def shutdown(self, vmid: str) -> CommandResult:
        error = _ensure_vmid(vmid)
        if error:
            return _invalid(vmid, "shutdown", error)
        return await self.runner.run(vmid=vmid, cmd=build_qm_command("qm", "shutdown", vmid))

    async def create(self, vmid: str, params: dict[str, str]) -> CommandResult:
        error = _ensure_vmid(vmid)
        if error:
            return _invalid(vmid, "create", error)
        if not params:
            return _invalid(vmid, "create", "params must not be empty")

        command_parts: list[str] = ["qm", "create", vmid]
        for key, value in params.items():
            if _ensure_safe_token(key, "config key", _CONFIG_KEY_RE):
                return _invalid(vmid, "create", f"invalid config key: {key}")
            value_text = str(value)
            if _ensure_no_control_chars(value_text, "config value"):
                return _invalid(vmid, "create", "config value contains control characters")
            command_parts.extend([f"-{key}", value_text])

        return await self.runner.run(vmid=vmid, cmd=build_qm_command(*command_parts))

    async def clone(
        self,
        source_vmid: str,
        target_vmid: str,
        name: str | None = None,
        target_node: str | None = None,
        full_clone: bool = False,
    ) -> CommandResult:
        source_error = _ensure_vmid(source_vmid)
        if source_error:
            return _invalid(source_vmid, "clone", source_error)
        target_error = _ensure_vmid(target_vmid)
        if target_error:
            return _invalid(target_vmid, "clone", target_error)

        command_parts: list[str] = ["qm", "clone", source_vmid, target_vmid]
        if name:
            if _ensure_no_control_chars(name, "vm name"):
                return _invalid(source_vmid, "clone", "vm name contains control characters")
            command_parts.extend(["--name", name])
        if target_node:
            if _ensure_safe_token(target_node, "target node", _NODE_RE):
                return _invalid(target_vmid, "clone", "target node has invalid characters")
            command_parts.extend(["--target", target_node])
        if full_clone:
            command_parts.append("--full")

        return await self.runner.run(vmid=target_vmid, cmd=build_qm_command(*command_parts))

    async def migrate(self, vmid: str, target_node: str, online: bool = True) -> CommandResult:
        error = _ensure_vmid(vmid)
        if error:
            return _invalid(vmid, "migrate", error)
        if _ensure_safe_token(target_node, "target node", _NODE_RE):
            return _invalid(vmid, "migrate", "target node has invalid characters")

        command_parts: list[str] = ["qm", "migrate", vmid, target_node]
        command_parts.extend(["--online", "1" if online else "0"])
        return await self.runner.run(vmid=vmid, cmd=build_qm_command(*command_parts))


@dataclass(slots=True)
class ProxmoxSnapshot:
    runner: CommandRunner

    async def list(self, vmid: str) -> CommandResult:
        error = _ensure_vmid(vmid)
        if error:
            return _invalid(vmid, "snapshot list", error)
        return await self.runner.run(vmid=vmid, cmd=build_qm_command("qm", "listsnapshot", vmid))

    async def create(self, vmid: str, name: str) -> CommandResult:
        error = _ensure_vmid(vmid)
        if error:
            return _invalid(vmid, "snapshot create", error)
        error = _ensure_snapshot_name(name)
        if error:
            return _invalid(vmid, "snapshot create", error)
        return await self.runner.run(vmid=vmid, cmd=build_qm_command("qm", "snapshot", vmid, name))

    async def rollback(self, vmid: str, name: str) -> CommandResult:
        error = _ensure_vmid(vmid)
        if error:
            return _invalid(vmid, "snapshot rollback", error)
        error = _ensure_snapshot_name(name)
        if error:
            return _invalid(vmid, "snapshot rollback", error)
        return await self.runner.run(vmid=vmid, cmd=build_qm_command("qm", "rollback", vmid, name))

    async def delete(self, vmid: str, name: str) -> CommandResult:
        error = _ensure_vmid(vmid)
        if error:
            return _invalid(vmid, "snapshot delete", error)
        error = _ensure_snapshot_name(name)
        if error:
            return _invalid(vmid, "snapshot delete", error)
        return await self.runner.run(vmid=vmid, cmd=build_qm_command("qm", "delsnapshot", vmid, name))


@dataclass(slots=True)
class ProxmoxHostOps:
    runner: CommandRunner

    async def write_snippet(self, filename: str, content: str) -> CommandResult:
        """Write a cloud-init snippet to the host's default snippet directory."""
        if not filename.endswith((".yaml", ".yml")):
            filename += ".yaml"
        if _ensure_safe_token(filename, "filename", _NODE_RE) and not filename.replace("-", "").replace(".", "").isalnum():
             return _invalid("0", "write_snippet", "filename has invalid characters")

        snippet_dir = "/var/lib/vz/snippets"
        filepath = f"{snippet_dir}/{filename}"
        
        import base64
        encoded = base64.b64encode(content.encode("utf-8")).decode("ascii")
        
        # We use runner.run to ensure it respects the sudo wrapper if enabled
        cmd = f"bash -c \"mkdir -p {snippet_dir} && echo '{encoded}' | base64 -d > {filepath}\""
        return await self.runner.run(vmid="0", cmd=cmd)

    async def read_serial_console(self, vmid: str, timeout: float = 2.0) -> CommandResult:
        """Read the recent output from the VM's serial console socket."""
        error = _ensure_vmid(vmid)
        if error:
            return _invalid(vmid, "read_serial", error)

        # Python script to run on the host (with sudo) to read the Unix socket
        script = f"""
import socket
import sys
import time

s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
try:
    s.connect('/var/run/qemu-server/{vmid}.serial0')
    s.settimeout(0.5)
    s.sendall(b'\\r\\n')
    data = b""
    start = time.time()
    while time.time() - start < {timeout}:
        try:
            chunk = s.recv(4096)
            if not chunk: break
            data += chunk
        except socket.timeout:
            break
    s.close()
    # Write only printable ascii and basic control chars
    safe_data = bytes([b for b in data if b >= 32 or b in (9, 10, 13)])
    sys.stdout.buffer.write(safe_data)
except FileNotFoundError:
    print("Serial socket not found. Ensure 'serial0: socket' is configured.")
    sys.exit(1)
except Exception as e:
    print(str(e))
    sys.exit(1)
"""
        cmd = f"python3 -c {shlex.quote(script)}"
        return await self.runner.run(vmid=vmid, cmd=cmd)

@dataclass(slots=True)
class ProxmoxFileOps:
    runner: CommandRunner

    async def put(self, vmid: str, local_path: str, remote_path: str) -> CommandResult:
        """Upload a file to the guest using a temporary FTP server."""
        error = _ensure_vmid(vmid)
        if error:
            return _invalid(vmid, "file put", error)
        if _CONTROL_RE.search(remote_path):
            return _invalid(vmid, "file put", "remote path contains control characters")

        path = Path(local_path)
        if not path.exists():
            return _invalid(vmid, "file put", f"Local file not found: {local_path}")

        # Use a temporary directory to host the file for FTP
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir) / path.name
            shutil.copy2(path, tmp_path)
            
            with TemporaryFTPServer(tmpdir) as ftp:
                host_ip = ftp.get_reachable_ip()
                # Guest command to download the file from the host's temporary FTP server
                # We use python3 on the guest as it's typically available and has built-in FTP support
                guest_cmd = (
                    f"python3 -c \"import urllib.request; "
                    f"urllib.request.urlretrieve('ftp://{host_ip}:{ftp.port}/{path.name}', '{remote_path}')\""
                )
                cmd = build_qm_command("qm", "guest", "exec", vmid, "--", "bash", "-c", guest_cmd)
                return await self.runner.run(vmid=vmid, cmd=cmd)

    async def get(self, vmid: str, remote_path: str) -> CommandResult:
        """Read a file from the guest using a temporary FTP server."""
        error = _ensure_vmid(vmid)
        if error:
            return _invalid(vmid, "file get", error)
        if _CONTROL_RE.search(remote_path):
            return _invalid(vmid, "file get", "remote path contains control characters")

        filename = Path(remote_path).name
        with tempfile.TemporaryDirectory() as tmpdir:
            with TemporaryFTPServer(tmpdir) as ftp:
                host_ip = ftp.get_reachable_ip()
                # Guest command to upload the file to the host's temporary FTP server
                guest_cmd = (
                    f"python3 -c \"from ftplib import FTP; ftp=FTP(); "
                    f"ftp.connect('{host_ip}', {ftp.port}); ftp.login(); "
                    f"with open('{remote_path}', 'rb') as f: ftp.storbinary('STOR {filename}', f); "
                    f"ftp.quit()\""
                )
                cmd = build_qm_command("qm", "guest", "exec", vmid, "--", "bash", "-c", guest_cmd)
                result = await self.runner.run(vmid=vmid, cmd=cmd)
                
                if result.ok:
                    local_file = Path(tmpdir) / filename
                    if local_file.exists():
                        # Read the file content to return it in the CommandResult
                        with open(local_file, "r", errors="replace") as f:
                            result.stdout = f.read()
                    else:
                        result.ok = False
                        result.stderr = f"FTP transfer failed: {filename} not found on host"
                return result


@dataclass(slots=True)
class ProxmoxGuestExec:
    runner: CommandRunner

    async def exec(self, vmid: str, cmd: str, cwd: str | None = None, env: dict[str, str] | None = None, timeout: int | None = None) -> CommandResult:
        error = _ensure_vmid(vmid)
        if error:
            return _invalid(vmid, "guest exec", error)
        if not isinstance(cmd, str) or not cmd.strip():
            return _invalid(vmid, "guest exec", "command cannot be empty")

        try:
            command = shlex.split(cmd)
        except ValueError as exc:
            return _invalid(vmid, "guest exec", str(exc))

        if not command:
            return _invalid(vmid, "guest exec", "command could not be parsed")

        args = []
        if cwd:
            if _CONTROL_RE.search(cwd):
                return _invalid(vmid, "guest exec", "cwd contains control characters")
            args.extend(["--cwd", cwd])

        if env:
            for key, value in env.items():
                if _ensure_safe_token(key, "environment key", _ENV_KEY_RE):
                    return _invalid(vmid, "guest exec", "invalid environment key")
                value_text = str(value)
                if _ensure_no_control_chars(value_text, "environment value"):
                    return _invalid(vmid, "guest exec", "environment value contains control characters")
                args.extend(["--env", f"{key}={value_text}"])

        if timeout is not None:
            if timeout <= 0:
                return _invalid(vmid, "guest exec", "timeout must be positive")
            args.extend(["--timeout", str(timeout)])

        full_cmd = build_qm_command("qm", "guest", "exec", vmid, *args, "--", *command)
        return await self.runner.run(vmid=vmid, cmd=full_cmd)

    async def probe(self, vmid: str) -> CommandResult:
        error = _ensure_vmid(vmid)
        if error:
            return _invalid(vmid, "guest probe", error)
        return await self.runner.run(vmid=vmid, cmd=build_qm_command("qm", "guest", "agent", vmid, "ping"))


@dataclass(slots=True)
class ProxmoxConfig:
    runner: CommandRunner

    async def get(self, vmid: str) -> CommandResult:
        error = _ensure_vmid(vmid)
        if error:
            return _invalid(vmid, "config get", error)
        return await self.runner.run(vmid=vmid, cmd=build_qm_command("qm", "config", vmid))

    async def set(self, vmid: str, params: dict[str, str]) -> CommandResult:
        error = _ensure_vmid(vmid)
        if error:
            return _invalid(vmid, "config set", error)
        if not params:
            return _invalid(vmid, "config set", "params must not be empty")

        command_parts: list[str] = ["qm", "set", vmid]
        for key, value in params.items():
            if _ensure_safe_token(key, "config key", _CONFIG_KEY_RE):
                return _invalid(vmid, "config set", f"invalid config key: {key}")
            value_text = str(value)
            if _ensure_no_control_chars(value_text, "config value"):
                return _invalid(vmid, "config set", "config value contains control characters")
            command_parts.extend([f"-{key}", value_text])

        cmd = build_qm_command(*command_parts)
        return await self.runner.run(vmid=vmid, cmd=cmd)


@dataclass(slots=True)
class ProxmoxBackup:
    runner: CommandRunner

    async def create(
        self,
        vmid: str,
        storage: str | None = None,
        mode: str = "snapshot",
        compress: str | None = None,
        remove: int | None = None,
    ) -> CommandResult:
        error = _ensure_vmid(vmid)
        if error:
            return _invalid(vmid, "backup", error)
        if mode not in ("snapshot", "suspend", "stop"):
            return _invalid(vmid, "backup", "mode must be snapshot, suspend, or stop")

        command_parts: list[str] = ["vzdump", vmid, "--mode", mode]
        if storage:
            if _ensure_no_control_chars(storage, "storage"):
                return _invalid(vmid, "backup", "storage contains control characters")
            command_parts.extend(["--storage", storage])
        if compress:
            if _ensure_no_control_chars(compress, "compress"):
                return _invalid(vmid, "backup", "compress value contains control characters")
            command_parts.extend(["--compress", compress])
        if remove is not None:
            if remove < 0:
                return _invalid(vmid, "backup", "remove must be 0 or greater")
            command_parts.extend(["--remove", str(remove)])

        return await self.runner.run(vmid=vmid, cmd=build_qm_command(*command_parts))
