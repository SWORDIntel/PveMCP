# PveMCP Tool Reference

This document provides a detailed technical reference for all **63 tools** available in PveMCP.

---

## Table of Contents

- [VM Lifecycle](#vm-lifecycle)
- [Execution](#execution)
- [Guest Inspection](#guest-inspection)
- [Guest Logs](#guest-logs)
- [Guest File Operations](#guest-file-operations)
- [Guest Search](#guest-search)
- [Guest Network Diagnostics](#guest-network-diagnostics)
- [Guest Service Management](#guest-service-management)
- [Guest Docker](#guest-docker)
- [Guest Package Management](#guest-package-management)
- [Host / Proxmox](#host--proxmox)
- [Fleet Orchestration](#fleet-orchestration)
- [VM Memory / Context Store](#vm-memory--context-store)
- [Power-User Tools (Autonomous)](#power-user-tools-autonomous)
- [Federation & Remote Control](#federation--remote-control)
- [Automation](#automation)
- [Workflows & Artifacts](#workflows--artifacts)
- [Observability](#observability)

---

## VM Lifecycle

Operations that control the VM's existence and power state.

| Tool | Parameters | Description |
|---|---|---|
| `vm_state` | `vmid`, `action` | Power state: `status`, `start`, `stop`, `reboot`, `shutdown`. |
| `vm_create` | `vmid`, `params` | Create a new VM with specified parameters. |
| `vm_clone` | `source_vmid`, `target_vmid`, `name`, `target_node`, `full_clone` | Clone an existing VM. |
| `vm_migrate` | `vmid`, `target_node`, `online` | Migrate a VM to another Proxmox node. |
| `vm_backup` | `vmid`, `storage`, `mode`, `compress`, `remove` | Run a `vzdump` backup. |
| `vm_snapshot` | `vmid`, `action`, `name` | List, create, rollback, or delete snapshots. |
| `vm_config` | `vmid`, `action`, `params` | Get or set VM configuration parameters. |

---

## Execution

Running commands on the host or inside the guest.

| Tool | Parameters | Description |
|---|---|---|
| `vm_exec` | `vmid`, `cmd` | Run a host-side command related to a VM. |
| `vm_guest_exec` | `vmid`, `cmd`, `cwd`, `env`, `timeout` | Run a command inside the guest via QEMU guest agent. |

---

## Guest Inspection

Understand what is happening inside a running VM.

| Tool | Parameters | Description |
|---|---|---|
| `vm_ps` | `vmid`, `filter_name` | List processes, optionally filtered by substring. |
| `vm_top` | `vmid`, `lines` | Top processes by CPU/RAM + load average. |
| `vm_disk` | `vmid` | Disk usage summary (`df`) + top 10 largest directories (`du`). |
| `vm_network` | `vmid` | IP addresses, routing table, and listening ports. |
| `vm_env` | `vmid` | Dump guest environment variables (redacted). |
| `vm_lsof` | `vmid`, `pid`, `port`, `path` | List open files, sockets, or process handles. |
| `vm_sysinfo` | `vmid` | Comprehensive snapshot: OS, kernel, uptime, CPU, RAM, disk, IP. |

---

## Guest Logs

Access system and application logs.

| Tool | Parameters | Description |
|---|---|---|
| `vm_dmesg` | `vmid`, `level`, `lines` | Read kernel ring buffer (e.g. for OOM kills or hardware errors). |
| `vm_journal` | `vmid`, `unit`, `lines`, `priority`, `since`, `grep` | Query systemd journal with rich filtering. |
| `vm_tail` | `vmid`, `path`, `lines` | Tail the last N lines of **any** log file inside the guest. |

---

## Guest File Operations

High-performance file transfers and manipulation.

| Tool | Parameters | Description |
|---|---|---|
| `vm_file_put` | `vmid`, `local_path`, `remote_path` | Upload a file via temporary FTP bridge. |
| `vm_file_get` | `vmid`, `remote_path` | Read a file from the guest via temporary FTP bridge. |
| `vm_write` | `vmid`, `path`, `content`, `mode` | Write or append text content to a guest file. |
| `vm_tar_extract` | `vmid`, `path`, `destination` | Extract archives on the guest. |

---

## Guest Search

Search files and content inside the guest.

| Tool | Parameters | Description |
|---|---|---|
| `vm_ripgrep` | `vmid`, `pattern`, `path`, `file_glob`, `case_insensitive` | Search file contents with `rg` (fast). |
| `vm_find` | `vmid`, `path`, `name`, `file_type`, `mtime_days`, `size_gt` | Locate files by name, type, age, or size. |

---

## Guest Network Diagnostics

Debug connectivity from the VM's perspective.

| Tool | Parameters | Description |
|---|---|---|
| `vm_network_audit` | `vmid` | End-to-end audit of host bridge/firewall and guest rules. |
| `vm_curl` | `vmid`, `url`, `method`, `headers`, `body` | Make HTTP requests from inside the guest. |
| `vm_traceroute` | `vmid`, `host`, `max_hops`, `use_tcp` | Trace network path to a destination. |
| `vm_dns_check` | `vmid`, `hostname`, `record_type`, `server` | Resolve DNS names from inside the guest. |
| `vm_port_check` | `vmid`, `port`, `host` | Check if a TCP port is listening. |

---

## Guest Service Management

Control systemd services.

| Tool | Parameters | Description |
|---|---|---|
| `vm_service` | `vmid`, `action`, `service_name` | status, enable, disable, or journal_tail. |
| `vm_service_restart` | `vmid`, `service_name` | Restart a service and return the new status. |
| `vm_service_enable_now` | `vmid`, `service_name` | Enable and start a service, auto-saving it to VM memory. |

---

## Guest Docker

Manage containers and compose stacks.

| Tool | Parameters | Description |
|---|---|---|
| `vm_docker` | `vmid`, `action`, `container`, `path` | ps, logs, restart, or compose_up. |
| `vm_docker_exec` | `vmid`, `container`, `cmd` | Run a command inside a specific container. |
| `vm_docker_pull` | `vmid`, `image` | Pull a Docker image inside the guest. |
| `vm_docker_inspect` | `vmid`, `container` | Get detailed container metadata. |

---

## Power-User Tools (Autonomous)

Advanced tools for fearless agent operation.

| Tool | Parameters | Description |
|---|---|---|
| `vm_transactional_exec` | `vmid`, `cmd`, `validate_cmd` | **Snapshot → Execute → Validate**. Automatically rolls back if validation fails. |
| `vm_expose_port` | `vmid`, `guest_port` | **LAN Exposure**. Maps a guest port to the Proxmox host's LAN IP on a random high port (45000-65000). |
| `vm_deploy_compose` | `vmid`, `project_name`, `compose_yaml` | Deploy a full Docker Compose stack in a single transaction. |
| `vm_pcap_analyze` | `vmid`, `interface`, `port`, `duration` | Run `tcpdump` and return a "Top Talkers" analysis. |

---

## Federation & Remote Control

Manage hosts outside of the primary Proxmox cluster.

| Tool | Parameters | Description |
|---|---|---|
| `vm_remote_exec` | `host`, `cmd`, `user` | Execute a command on **any** remote host via SSH. |
| `remote_tail` | `host`, `path`, `lines`, `user`, `identity_file` | **Requires `path` to a log file.** Fetches the last N lines via SSH. |
| `remote_log_capture` | `host`, `path`, `duration`, `user` | **Live Stream.** Watches `tail -f` for N seconds and returns the chunk. |
| `remote_file_get` | `host`, `remote_path`, `user` | Extract files (certs, configs) from a remote host via SSH. |
| `vm_ssh_config_set` | `vmid`, `key_path`, `key_content`, `user` | Save SSH credentials for a VM. **`key_content` is AES-256 encrypted at rest.** |
| `vm_remote_tail` | `vmid`, `path`, `lines` | Tail a log on a VM using its **saved/encrypted** SSH config. |

---

## VM Memory / Context Store

The unified persistent knowledge base (`~/.pvemcp/memory.json`).

| Tool | Parameters | Description |
|---|---|---|
| `vm_memory_get` | `vmid` | Recall all known context, secrets, and history for a VM. |
| `vm_memory_set` | `vmid`, `notes`, `paths`, `tags`, etc. | Update the knowledge base for a VM. |
| `vm_memory_list` | (none) | List all VMs with stored context. |
| `vm_memory_clear` | `vmid` | Wipe a VM's record from the unified store. |

---

## Host / Proxmox

Host-level operations.

| Tool | Parameters | Description |
|---|---|---|
| `host_storage_list` | (none) | List all datastores and ZFS pools with usage stats. |
| `host_iso_download` | `storage`, `url`, `filename` | Download an ISO directly to Proxmox storage. |
| `vm_console_read` | `vmid`, `timeout` | Emergency access: read the serial console socket. |
| `vm_bootstrap` | `vmid`, `user_data_yaml` | One-shot cloud-init provisioning and boot. |
