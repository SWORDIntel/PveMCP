from __future__ import annotations
import shlex
from dataclasses import dataclass
from .runner import CommandRunner
from .models import CommandResult

@dataclass(slots=True)
class SSHRunner:
    host: str
    user: str | None = None
    port: int = 22
    identity_file: str | None = None

    async def run(self, cmd: str, timeout_s: float = 30.0) -> CommandResult:
        ssh_cmd = ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=10"]
        if self.user:
            ssh_cmd.extend(["-l", self.user])
        if self.port != 22:
            ssh_cmd.extend(["-p", str(self.port)])
        if self.identity_file:
            ssh_cmd.extend(["-i", self.identity_file])
        
        ssh_cmd.append(self.host)
        ssh_cmd.append(cmd)
        
        # Use local runner to execute the ssh command
        local_runner = CommandRunner()
        return await local_runner.run(vmid=f"remote:{self.host}", cmd=" ".join(shlex.quote(p) for p in ssh_cmd), timeout_s=timeout_s)
