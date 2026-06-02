---
name: proxmcp
description: Operate Proxmox/Xen VMs through proxmcp MCP tools with policy-aware, auditable workflows. Use when users ask for VM lifecycle changes, host/guest commands, backup/snapshot work, fleet operations, or VM health checks.
---

# proxmcp Operations Skill

Use this skill when the request targets infrastructure controlled by proxmcp tools.

## Start of new session

1. **Always** call `vm_agent_probe` first to confirm the guest agent is online.
2. Call `vm_autodiscover` on any VM you have not seen before — this builds persistent memory.
3. Call `vm_memory_get` to recall everything already known about a familiar VM before acting.

## Core rule set

- Prefer read-only checks first (`vm_state` with `status`, `vm_metrics`, `vm_slo_check`).
- Treat guest operations as higher risk than host status checks.
- Use `vm_agent_probe` before any guest-exec operation if connectivity is uncertain.
- Use `vm_autodiscover` on the first session with any VM to populate context memory.
- Before mutating actions, capture rollback points (`vm_snapshot` create, `vm_config get`).
- Run `vm_drift_check` after changes to verify no unexpected state was introduced.
- Include `audit_tag` for every operation that should be traceable.
- All tools return a `summary` field — read it first before inspecting raw output.
- `ok=false` means check the `error` field, not just the `exit_code`.

## Tool map

### VM Lifecycle
`vm_state`, `vm_create`, `vm_clone`, `vm_migrate`, `vm_backup`, `vm_snapshot`, `vm_config`

### Execution
- `vm_exec` — host-side command execution
- `vm_guest_exec` — execute inside the guest via guest agent

### Guest Inspection
`vm_ps`, `vm_top`, `vm_disk`, `vm_network`, `vm_env`, `vm_lsof`, `vm_sysinfo`

### Guest Logs
`vm_dmesg`, `vm_journal`, `vm_tail`

### Guest Files
`vm_file_put`, `vm_file_get`, `vm_write`, `vm_tar_extract`

### Guest Search
`vm_ripgrep`, `vm_find`

### Guest Network Diagnostics
`vm_curl`, `vm_traceroute`, `vm_dns_check`, `vm_port_check`, `vm_iptables`

### Guest Service Management
`vm_service`, `vm_service_restart`, `vm_service_enable_now`

### Guest Docker
`vm_docker`, `vm_docker_exec`, `vm_docker_pull`, `vm_docker_inspect`, `vm_cgroup_mem`

### Guest Packages
`vm_install_package`

### Host / Proxmox
`vm_list`, `vm_agent_probe`

### Fleet
`vm_fan_out`, `vm_orchestrate`

### VM Memory / Context
`vm_memory_get`, `vm_memory_set`, `vm_memory_list`, `vm_memory_clear`

### Automation
`vm_autodiscover`, `vm_drift_check`

### Workflows
`run_workflow_generate`, `run_eval_scorecard`, `list_artifacts`

### Observability
`vm_slo_check`, `vm_metrics`

## Recommended execution sequence

1. **Probe** — confirm the guest agent is reachable:
   `vm_agent_probe`
2. **Context** — recall known state or discover a new VM:
   `vm_memory_get` (familiar VM) **or** `vm_autodiscover` (new VM)
3. **Baseline** — gather current health:
   `vm_state` status · `vm_metrics` · `vm_slo_check`
4. **Safety** — create a rollback point before any mutation:
   `vm_snapshot` create
5. **Change** — apply the minimal scoped mutation.
6. **Verify** — confirm the system reached the desired state:
   `vm_drift_check` · repeat health checks
7. **Report** — summarise VM IDs, actions taken, and outcomes.

## Examples

### Autodiscover a new VM

```json
{
  "tool": "vm_autodiscover",
  "arguments": {
    "vmid": "101",
    "actor": "codex",
    "audit_tag": "onboard-101"
  }
}
```

### Recall stored context

```json
{
  "tool": "vm_memory_get",
  "arguments": {
    "vmid": "101",
    "actor": "codex"
  }
}
```

### Drift check after a change

```json
{
  "tool": "vm_drift_check",
  "arguments": {
    "vmid": "101",
    "actor": "codex",
    "audit_tag": "post-change-verify"
  }
}
```

### Search logs inside the guest

```json
{
  "tool": "vm_ripgrep",
  "arguments": {
    "vmid": "101",
    "pattern": "FATAL",
    "path": "/var/log/app",
    "actor": "codex"
  }
}
```

### Run a command inside a Docker container

```json
{
  "tool": "vm_docker_exec",
  "arguments": {
    "vmid": "101",
    "container": "web",
    "cmd": "nginx -t",
    "actor": "codex",
    "audit_tag": "nginx-config-check"
  }
}
```

### HTTP probe from inside the guest

```json
{
  "tool": "vm_curl",
  "arguments": {
    "vmid": "101",
    "url": "http://localhost:8080/healthz",
    "actor": "codex"
  }
}
```
