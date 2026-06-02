from __future__ import annotations

from dataclasses import dataclass


@dataclass(slots=True)
class PolicyConfig:
    allowlist: tuple[str, ...] = (
        # Core utilities
        "awk", "base64", "bash", "cat", "chmod", "cp", "curl", "cut",
        # Disk / filesystem
        "df", "diff", "du",
        # Containers
        "docker", "docker-compose",
        # Search
        "find", "grep", "rg",
        # System info
        "dmesg", "free", "head", "hostname", "id", "ip",
        # Logging
        "journalctl", "last", "lastb",
        # Shell / scripting
        "logrotate", "ls", "lsof", "mkdir", "mv",
        # Network
        "mullvad", "netstat", "nft", "nload", "nslookup", "dig",
        # Package managers
        "apt", "apt-get", "apk", "dnf", "yum",
        # Misc
        "nproc", "pip",
        # Process inspection
        "ps", "python3",
        # Security / audit
        "sha256sum", "stat", "strace",
        # Shell
        "pwd", "sh", "sed", "sort",
        # Network diagnostics
        "ss",
        # Service management
        "systemctl", "sysctl",
        # File ops
        "tail", "tar",
        # Network tracing
        "traceroute", "tracepath",
        # Resource monitoring
        "top", "uptime", "uname",
        # Environment
        "env",
        # Firewall
        "iptables", "ip6tables",
        # VM management (host side)
        "qm", "pct", "pvesh", "vzdump",
        # Misc system
        "vmstat", "wc", "xargs",
        # VPN tools
        "wg", "wg-quick",
        # Full paths
        "/usr/local/sbin/wg-rotate-mullvad",
        "/opt/osint-node/sources/ARGUS/scripts/wireguard-rotate-endpoint.sh",
        # Echo
        "echo",
    )
    denylist: tuple[str, ...] = ("rm -rf", "mkfs", "dd if=", "shutdown", "reboot")


class PolicyError(RuntimeError):
    pass


class PolicyEnforcer:
    def __init__(self, config: PolicyConfig | None = None) -> None:
        self.config = config or PolicyConfig()

    def validate(self, cmd: str, danger_mode: bool = False, command_context: str = "host") -> None:
        lowered = cmd.strip().lower()
        if not lowered:
            raise PolicyError("empty command is not allowed")

        if any(blocked in lowered for blocked in self.config.denylist) and not danger_mode:
            raise PolicyError("command blocked by denylist")

        if not lowered.startswith(self.config.allowlist):
            raise PolicyError("command does not match allowlist")
