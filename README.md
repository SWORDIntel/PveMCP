<div align="center">

# 🌌 PveMCP
### The Proxmox VM Control Plane for AI Agents

[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![License: AGPL-3.0](https://img.shields.io/badge/License-AGPL--3.0-orange.svg)](https://www.gnu.org/licenses/agpl-3.0)
[![MCP](https://img.shields.io/badge/MCP-Model%20Context%20Protocol-green.svg)](https://modelcontextprotocol.io/)
[![Production Ready](https://img.shields.io/badge/status-production--ready-success.svg)]()
[![Tools](https://img.shields.io/badge/tools-63-blueviolet.svg)]()

**A production-grade Proxmox orchestrator that gives your AI agent "God-mode" over your cluster and remote SSH hosts.**

[Tool Reference](docs/tools.md) • [Workflow Framework](docs/workflows.md) • [Installation](INSTALL.md) • [Security](docs/tools.md#security)

</div>

---

## 🚀 Showcase

PveMCP empowers your AI assistant (Claude, Cursor, Gemini) to handle complex infrastructure tasks autonomously and safely.

- **🛡️ Fearless Debugging**: `vm_transactional_exec` takes a snapshot, runs your fix, validates it, and rolls back instantly if it fails.
- **🌐 LAN Bridging**: `vm_expose_port` dynamically maps internal VM services to random high ports on your host's LAN IP for instant access.
- **🔐 Encrypted Secrets**: Store private SSH keys and credentials in a unified memory store, encrypted at rest with **AES-256-GCM**.
- **📊 Live Observability**: Stream remote logs in real-time and view a live Markdown "HUD" dashboard of your entire fleet.
- **✨ Zero-Config Onboarding**: `vm_autodiscover` maps an entire VM's services, containers, and OS architecture in seconds.

---

## 🛠️ Tooling Overview

PveMCP's **67 tools** are organized into functional categories to empower autonomous operation:

*   **⚡ VM Lifecycle**: Power states, cloning, migration, vzdump backups, and hardware configuration.
*   **🔍 Guest Inspection**: Real-time process monitoring, CPU/RAM telemetry, and disk health analysis.
*   **📜 Guest Logs**: Stream systemd journals, kernel ring buffers (dmesg), and specific log files.
*   **📂 File Operations**: High-performance FTP-bridge transfers, archive management, and config writing.
*   **🛰️ Federation**: SSH gateway for non-PVE hosts with persistent encrypted credential management.
*   **🏗️ Docker & Compose**: Deploy complete stacks in one shot and manage container lifecycles.
*   **🧠 VM Memory**: A unified, persistent JSON knowledge base for all VM-specific quirks and secrets.
*   **🧪 Network Diagnostics**: In-guest HTTP requests (`curl`), traceroutes, DNS checks, and port auditing.
*   **🤖 Automation**: One-shot autodiscovery and baseline drift detection for self-healing infrastructure.

---

## 🏗️ Key Components

| Binary | Purpose |
| :--- | :--- |
| `pvemcp-server` | High-performance MCP server (stdio transport) |
| `vmctl` | Human-facing CLI for scripting and manual cluster control |

---

## 🛠️ Advanced Configuration

### Sudo & Permissions
The `vmctl` CLI and `pvemcp-server` default to using `sudo` for host-side Proxmox commands to ensure access to the cluster filesystem (`pmxcfs`).

- **Environment Variables**:
  * `PVEMCP_USE_SUDO`: Set to `false` to disable automatic sudo prefixing (default: `true`).
  * `PVEMCP_AUDIT_LOG`: Path to the audit log file.
  * `PUSHBULLET_API_KEY`: Your Pushbullet Access Token for notifications.


### Error Diagnostics
PveMCP includes built-in diagnostics for common Proxmox cluster issues. If a command fails with `ipcc_send_rec` or ACL errors, the tool output will include a `[DIAGNOSTIC]` block explaining potential causes like lost cluster quorum or missing sudo permissions.


---

## ⚡ Quick Start

### 1. Installation
```bash
# Recommended: Install using uv
uv sync
uv run pvemcp-server

# Or use the one-shot installer to wire into your clients
bash scripts/install-pvemcp.sh --client both
```

### 2. First Run Sequence
```bash
uv run vmctl autodiscover 100           # map everything -> save to memory
uv run vmctl memory get 100             # verify saved context
uv run vmctl drift-check 100            # detect unauthorized changes later
```

---

## 🔒 Security & Safety

PveMCP is built for secure, single-operator environments:
- **Fail-Closed**: Every command must be explicitly permitted by policy.
- **Redaction**: Secrets and keys are stripped from outputs before the AI sees them.
- **Audit**: Every action is logged to an append-only JSON file for full accountability.
- **Encryption**: Sensitive memory fields are AES-256 encrypted using a machine-local secret.
- **Notifications**: Pushbullet integration for pipeline stages and AI alerts (`PUSHBULLET_API_KEY`).

---

## ⚖️ License

This project is licensed under the **GNU Affero General Public License v3.0 (AGPL-3.0)**.

> ⚠️ **Commercial Use Warning**: The AGPL-3.0 is a highly restrictive copyleft license. If you modify this software or use it over a network as part of a commercial service, you **must** open-source your entire service under the same license. 
> 
> - **Home & Personal Use**: 100% Free and Open Source.
> - **Commercial / Enterprise Use**: If the AGPL-3.0 is too harsh for your environment, please **email me** to discuss a commercial license.

See the [LICENSE](LICENSE) file for full details.
 full details.
