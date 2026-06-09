# pvemcp

`Python 3.11+` · `MCP` · `Proxmox` · `Production-Ready` · `63 Tools` · `License: MIT`

A production-grade **Proxmox VM control plane** with a native [Model Context Protocol](https://modelcontextprotocol.io/) server and a first-class CLI (`vmctl`). 

---

## 🚀 Showcase

pvemcp gives your AI agent "God-mode" over your Proxmox cluster and remote SSH hosts.

- **Fearless Debugging**: `vm_transactional_exec` takes a snapshot, runs your fix, validates it, and rolls back if it breaks.
- **LAN Bridging**: `vm_expose_port` dynamically maps internal VM services to random high ports on your host's LAN IP.
- **Encrypted Secrets**: Store private SSH keys in a unified memory store, encrypted at rest with AES-256-GCM.
- **Live Observability**: Stream remote logs for specific durations and view a live Markdown dashboard of your entire fleet.
- **Zero-Config Onboarding**: `vm_autodiscover` maps an entire VM's services, containers, and OS in seconds.

---

## 🛠️ Key Components

| Binary | Purpose |
|---|---|
| `pvemcp-server` | High-performance MCP server (stdio transport, 63 tools) |
| `vmctl` | Human-facing CLI for scripting and manual control |

---

## 📖 Documentation

- **[Full Tool Reference](docs/tools.md)** — Detailed technical docs for all 63 tools.
- **[Installation Guide](INSTALL.md)** — How to wire PveMCP into your AI client.

---

## ⚡ Quick Start

```bash
# 1. Install using uv (recommended)
uv sync
uv run pvemcp-server

# 2. Or use the one-shot installer
bash scripts/install-pvemcp.sh --client both
```

**First-run sequence for a new VM:**

```bash
uv run vmctl autodiscover 100           # map everything -> save to memory
uv run vmctl memory get 100             # verify saved context
uv run vmctl drift-check 100            # detect unauthorized changes later
```

---

## 🔒 Security & Safety

- **Fail-Closed Policy**: Every command must be explicitly allowed.
- **Danger Mode Escalation**: Destructive commands require `break_glass` mode.
- **Automatic Redaction**: Secrets, keys, and passwords never leave the host.
- **Audit Logging**: Every single AI action is logged to an append-only JSON file.

---

## License

MIT — see [LICENSE](LICENSE).
