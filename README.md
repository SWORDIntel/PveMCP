# proxmcp

`Python 3.11+` · `MCP` · `Proxmox` · `Production-Ready` · `54 Tools` · `License: MIT`

A production-grade **Proxmox VM control plane** with a native [Model Context Protocol](https://modelcontextprotocol.io/) server and a first-class CLI (`vmctl`). Runs directly on the Proxmox host, driving VMs through `qm`/`pct` commands and the QEMU guest agent.

---

## Table of Contents

- [Overview](#overview)
- [Quick Start](#quick-start)
- [Installation](#installation)
- [Environment Variables](#environment-variables)
- [MCP Server](#mcp-server)
  - [Client Wiring](#client-wiring)
  - [Tool Reference](#tool-reference)
- [vmctl CLI Reference](#vmctl-cli-reference)
- [Workflow Examples](#workflow-examples)
- [Security](#security)
- [Architecture](#architecture)
- [Development](#development)

---

## Overview

proxmcp exposes every Proxmox VM operation — lifecycle, execution, file I/O, logs, networking, Docker, packages, memory, and fleet orchestration — as MCP tools consumable by any MCP-compatible AI client (Claude Desktop, Cursor, etc.) and as `vmctl` subcommands for scripting and direct use.

**Key binaries**

| Binary | Purpose |
|---|---|
| `proxmcp-server` | MCP server (stdio transport, 54 tools) |
| `vmctl` | Human/script-facing CLI |

---

## Quick Start

```bash
# 1. Install on the Proxmox host
pip install git+https://github.com/SWORDIntel/proxmcp.git

# 2. Run the MCP server (stdio, picked up by your MCP client)
proxmcp-server

# 3. Or use the CLI directly
vmctl list
vmctl state 100 status
vmctl guest-exec 100 "systemctl status nginx"
```

**One-shot installer** (installs + configures + optionally registers systemd service):

```bash
bash scripts/install-proxmcp.sh --client both          # install for both root and a user
bash scripts/install-proxmcp.sh --install-service      # register systemd service
bash scripts/install-proxmcp.sh --uninstall            # remove everything
```

**Recommended first-run sequence for any VM:**

```bash
vmctl agent-probe 100            # 1. confirm guest agent is alive
vmctl autodiscover 100           # 2. map VM, save context to memory
vmctl memory get 100             # 3. verify saved context
vmctl drift-check 100            # 4. check for drift after changes
```

---

## Installation

### Production (Proxmox host)

```bash
python -m pip install git+https://github.com/SWORDIntel/proxmcp.git
```

### Local development

```bash
git clone https://github.com/SWORDIntel/proxmcp.git
cd proxmcp
pip install -e .
```

> **Note:** proxmcp must run **on the Proxmox host** itself. It calls `qm`, `pct`, and `qemu-guest-agent` directly — these are not available over a remote API.

---

## Environment Variables

| Variable | Default | Description |
|---|---|---|
| `PROXMCP_AUDIT_LOG` | `logs/audit.log` | Path to the append-only JSON audit log |
| `PROXMCP_ALLOW_BREAK_GLASS` | *(unset)* | Set to `1` to allow `break_glass` danger-mode commands |
| `PROXMCP_MEMORY_DIR` | `~/.proxmcp/memory` | Directory for per-VM JSON knowledge store files |

---

## MCP Server

### Client Wiring

Add to your MCP client config (e.g. `~/.config/claude/claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "proxmcp": {
      "command": "proxmcp-server",
      "env": {
        "PROXMCP_AUDIT_LOG": "/var/log/proxmcp-audit.log",
        "PROXMCP_ALLOW_BREAK_GLASS": "1",
        "PROXMCP_MEMORY_DIR": "/var/lib/proxmcp/memory"
      }
    }
  }
}
```

### Tool Reference

**54 tools** across 14 categories.

---

#### VM Lifecycle

| Tool | Description |
|---|---|
| `vm_state` | Power state: `status` / `start` / `stop` / `reboot` / `shutdown` |
| `vm_create` | Create a new VM |
| `vm_clone` | Clone an existing VM |
| `vm_migrate` | Migrate a VM to another node |
| `vm_backup` | Run a `vzdump` backup |
| `vm_snapshot` | List / create / rollback / delete snapshots |
| `vm_config` | Get or set VM configuration parameters |

---

#### Execution

| Tool | Description |
|---|---|
| `vm_exec` | Run a host-side command on a VM (via Proxmox host) |
| `vm_guest_exec` | Run a command inside the guest via QEMU guest agent |

---

#### Guest Inspection

| Tool | Description |
|---|---|
| `vm_ps` | List guest processes (filterable by name) |
| `vm_top` | Top N processes by CPU + load average + memory usage |
| `vm_disk` | `df -h` + top 10 largest directories |
| `vm_network` | IPs, routes, listening ports |
| `vm_env` | Guest environment variables |
| `vm_lsof` | Open file handles/sockets — filter by pid, port, or path |
| `vm_sysinfo` | Full system snapshot: OS, kernel, uptime, CPU, RAM, disk, network |

---

#### Guest Logs

| Tool | Description |
|---|---|
| `vm_dmesg` | Kernel ring buffer (filtered to `err`/`warn` by default) |
| `vm_journal` | systemd journal — filter by unit, priority, since, or grep pattern |
| `vm_tail` | Tail last N lines of any log file |

---

#### Guest File Operations

| Tool | Description |
|---|---|
| `vm_file_put` | Upload a local file to the guest |
| `vm_file_get` | Read a file from the guest |
| `vm_write` | Write or append text content to a guest file |
| `vm_tar_extract` | Extract `.tar` / `.tar.gz` / `.tar.bz2` / `.tar.xz` on the guest |

> **Performance Note:** `vm_file_put` and `vm_file_get` utilize a high-performance **Temporary FTP Server** mechanism. Instead of inefficient base64 chunking or `cat` stdout capture, ProxMCP spins up a short-lived FTP server on the host to transfer files directly to/from the guest via `ftplib` / `urllib`.

---

#### Guest Search

| Tool | Description |
|---|---|
| `vm_ripgrep` | Search file contents with `rg` (falls back to `grep`) |
| `vm_find` | Find files by name, type, age, or size |

---

#### Guest Network Diagnostics

| Tool | Description |
|---|---|
| `vm_network_audit` | End-to-end network path audit (Host bridge/firewall + Guest rules/routes) |
| `vm_curl` | HTTP request from inside the guest — returns status code + body |
| `vm_traceroute` | Trace network path (falls back to `tracepath`) |
| `vm_dns_check` | DNS resolution from inside the guest (falls back to `nslookup`) |
| `vm_port_check` | Check if a TCP port is listening |
| `vm_iptables` | Dump firewall rules (also tries `nft list ruleset`) |

---

#### Guest Service Management

| Tool | Description |
|---|---|
| `vm_service` | `status` / `enable` / `disable` / `journal_tail` for a systemd service |
| `vm_service_restart` | Restart a service and show status afterwards |
| `vm_service_enable_now` | `enable --now` in one call; auto-saves service name to VM memory |

---

#### Guest Docker

| Tool | Description |
|---|---|
| `vm_docker` | `ps` / `logs` / `restart` / `compose_up` |
| `vm_docker_exec` | Run a command inside a Docker container (host → guest → container) |
| `vm_docker_pull` | Pull an image inside the guest |
| `vm_docker_inspect` | Structured inspect: state, mounts, ports, restart policy |
| `vm_cgroup_mem` | cgroup memory limits and usage for a service or container |

---

#### Guest Package Management

| Tool | Description |
|---|---|
| `vm_install_package` | Install a package via `apt` / `yum` / `dnf` / `apk` (auto-detected) |

---

#### Host / Proxmox

| Tool | Description |
|---|---|
| `vm_list` | List all VMs with status, cross-referenced against the memory store |
| `vm_agent_probe` | Ping the guest agent before guest-exec to diagnose connectivity |
| `vm_console_read` | Read the VM's serial console socket (diagnose boot failures) |
| `vm_bootstrap` | Cloud-init factory: stage `user-data` snippet via FTP and boot |

---

#### Fleet Orchestration

| Tool | Description |
|---|---|
| `vm_fan_out` | Run a command across multiple VMs in parallel |
| `vm_orchestrate` | Dependency-graph sequenced multi-VM workflow |

---

#### VM Memory / Context Store

| Tool | Description |
|---|---|
| `vm_memory_get` | Recall all known context for a VM |
| `vm_memory_set` | Save notes, paths, services, tags, containers, env vars |
| `vm_memory_list` | List all VMs with saved context |
| `vm_memory_clear` | Reset a VM's memory |

---

#### Automation

| Tool | Description |
|---|---|
| `vm_autodiscover` | One-shot: probe agent, map everything, save to memory in parallel |
| `vm_drift_check` | Compare current state vs saved baseline; flag missing/unexpected services and containers |

---

#### Workflows & Artifacts

| Tool | Description |
|---|---|
| `run_workflow_generate` | Upload a script, execute it, return results |
| `run_eval_scorecard` | Run an evaluation scorecard workflow |
| `list_artifacts` | List tracked artifacts |

---

#### Observability

| Tool | Description |
|---|---|
| `vm_slo_check` | SLO compliance check (metrics + optional guest health) |
| `vm_metrics` | System performance metrics snapshot |

---

## vmctl CLI Reference

`vmctl` mirrors the MCP tool surface for direct scripting and interactive use.

### Core VM Operations

```bash
vmctl list                                    # list all VMs
vmctl state <vmid> status|start|stop|reboot|shutdown
vmctl create --name myvm --memory 2048 --cores 2
vmctl clone <vmid> --name clone-name
vmctl migrate <vmid> --target node2
vmctl backup <vmid>
vmctl config <vmid> [--set key=value]
vmctl snapshot <vmid> list|create|rollback|delete [name]
```

### Execution

```bash
vmctl exec <vmid> "qm agent <vmid> ping"
vmctl guest-exec <vmid> "systemctl status nginx"
```

### Guest Inspection

```bash
vmctl ps <vmid> [--filter nginx]
vmctl top <vmid> [--n 10]
vmctl disk <vmid>
vmctl network <vmid>
vmctl env <vmid>
vmctl sysinfo <vmid>
```

### Guest Logs

```bash
vmctl tail <vmid> /var/log/syslog [--lines 50]
```

### Guest File Operations

```bash
vmctl file put <vmid> /local/path /guest/path
vmctl file get <vmid> /guest/path
```

### Services

```bash
vmctl service status <vmid> nginx
vmctl service enable <vmid> nginx
vmctl service disable <vmid> nginx
vmctl service restart <vmid> nginx
vmctl service journal <vmid> nginx [--lines 100]
```

### Docker

```bash
vmctl docker ps <vmid>
vmctl docker logs <vmid> mycontainer
vmctl docker restart <vmid> mycontainer
vmctl docker compose-up <vmid> /path/to/compose
```

### Packages

```bash
vmctl install <vmid> htop curl jq
```

### Network Diagnostics

```bash
vmctl port <vmid> 80
```

### Observability

```bash
vmctl slo check <vmid>
vmctl metrics <vmid>
```

### Memory Store

```bash
vmctl memory get <vmid>
vmctl memory set <vmid> --notes "web server" --tags web,prod
vmctl memory list
vmctl memory clear <vmid>
```

### Search

```bash
vmctl ripgrep <vmid> "ERROR" /var/log
vmctl find <vmid> /etc --name "*.conf"
```

---

## Workflow Examples

### Onboard a new VM

```bash
vmctl agent-probe 101              # verify guest agent responds
vmctl autodiscover 101             # discover OS, services, containers → save to memory
vmctl memory get 101               # confirm what was saved
```

### Deploy a service and verify

```bash
vmctl guest-exec 101 "apt-get install -y nginx"
vmctl service enable 101 nginx
vmctl service status 101 nginx
vmctl port 101 80
vmctl curl 101 http://localhost
```

### Check for drift after maintenance

```bash
vmctl drift-check 101              # compare running state vs saved baseline
```

### Run a command across a fleet

```bash
# Via MCP tool: vm_fan_out with vmids=[101,102,103], command="uptime"
# Via orchestration: vm_orchestrate with a dependency graph YAML/JSON
```

### Investigate a failing service

```bash
vmctl service journal 101 myapp --lines 200
vmctl tail 101 /var/log/myapp/error.log
vmctl lsof 101 --port 8080
vmctl dmesg 101
```

---

## Security

### Policy Enforcement

`PolicyEnforcer` (`src/proxmcp/policy.py`) wraps every command execution:

- **Allowlist / denylist** — explicit lists of permitted and denied command patterns
- **Fail-closed** — if a command isn't on the allowlist it is denied by default
- **Danger mode escalation ladder:**
  - `safe` — default; no destructive host commands
  - `maintenance` — relaxed for planned ops
  - `break_glass` — full access; requires `PROXMCP_ALLOW_BREAK_GLASS=1`

### Audit Log

Every command executed is written to the append-only JSON audit log at `PROXMCP_AUDIT_LOG`. Log entries include timestamp, VMID, command, caller identity, and outcome.

### Secret Redaction

`SecretRedactor` (`src/proxmcp/security.py`) automatically strips passwords, tokens, and keys from stdout/stderr before they are returned to the caller.

---

## Architecture

```
src/proxmcp/
├── mcp_server.py    # FastMCP tool definitions — 54 tools (~2500 lines)
├── cli.py           # argparse CLI (vmctl)
├── proxmox.py       # Proxmox lifecycle, snapshot, file I/O, config, backup, guest exec
├── ftp_server.py    # Temporary FTP server for high-performance file transfers
├── vm_memory.py     # Per-VM JSON knowledge store (~/.proxmcp/memory/)
├── policy.py        # Allowlist/denylist policy enforcement (PolicyEnforcer)
├── runner.py        # Async subprocess runner with timeout + retry
├── service.py       # VMService — wires runner + policy + audit + metrics + redactor
├── audit.py         # Append-only JSON audit log
├── security.py      # SecretRedactor
├── metrics.py       # In-memory MetricsStore
├── slo.py           # SLO checker
├── jobs.py          # Async job manager
├── workflows.py     # WorkflowManager + ArtifactIndex
├── federation.py    # Fan-out fleet orchestration
└── xen.py           # Xen lifecycle stub
```

**Call flow:**

```
MCP client / vmctl
    │
    ▼
mcp_server.py  (tool dispatch)
    │
    ▼
service.py  (VMService)
    ├── policy.py       (allow/deny check)
    ├── runner.py       (async subprocess)
    ├── audit.py        (log every call)
    ├── metrics.py      (record latency/errors)
    └── security.py     (redact secrets from output)
```

---

## Development

### Editable install

```bash
git clone https://github.com/SWORDIntel/proxmcp.git
cd proxmcp
pip install -e ".[dev]"
```

### Run tests

```bash
pytest
pytest -v tests/test_policy.py      # specific module
pytest --cov=proxmcp                 # with coverage
```

### Run the MCP server locally

```bash
proxmcp-server
# or
python -m proxmcp.mcp_server
```

### Lint / type-check

```bash
ruff check src/
mypy src/proxmcp/
```

### Project layout

```
proxmcp/
├── src/proxmcp/          # package source
├── tests/               # pytest test suite
├── scripts/
│   └── install-proxmcp.sh
├── pyproject.toml
└── README.md
```

---

## License

MIT — see [LICENSE](LICENSE).
