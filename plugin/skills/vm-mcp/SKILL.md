---
name: vm-mcp
description: Operate Proxmox/Xen VMs through vm-mcp MCP tools with policy-aware, auditable workflows. Use when users ask for VM lifecycle changes, host/guest commands, backup/snapshot work, or VM health checks.
---

# vm-mcp Operations Skill

Use this skill when the request targets infrastructure controlled by vm-mcp tools.

## Core rule set

- Prefer read-only checks first (`vm_state` with `status`, `vm_metrics`, `vm_slo_check`).
- Treat guest operations as higher risk than host status checks.
- Before mutating actions, capture rollback points when possible (`vm_snapshot` create, current config via `vm_config get`).
- Include `audit_tag` for operations that should be easy to trace.

## Tool map

- Execution:
  - `vm_exec` (host-side command path)
  - `vm_guest_exec` (inside guest via guest agent)
- Lifecycle:
  - `vm_state`, `vm_create`, `vm_clone`, `vm_migrate`, `vm_backup`, `vm_snapshot`, `vm_config`
- Fleet orchestration:
  - `vm_fan_out`, `vm_orchestrate`
- Guest operations:
  - `vm_file_put`, `vm_file_get`, `vm_service`, `vm_docker`
- Workflows and artifacts:
  - `run_workflow_generate`, `run_eval_scorecard`, `list_artifacts`
- Observability:
  - `vm_slo_check`, `vm_metrics`

## Recommended execution sequence

1. Baseline:
   - run status/metrics checks and gather current state.
2. Prepare safety:
   - snapshot/config export before disruptive actions.
3. Apply change:
   - perform minimal scoped mutation.
4. Verify:
   - repeat state checks and confirm expected health.
5. Report:
   - summarize VM IDs, commands/actions, and outcomes.

## Minimal examples

Status:

```json
{"tool":"vm_state","arguments":{"vmid":"101","action":"status","actor":"codex"}}
```

Guest service check:

```json
{"tool":"vm_service","arguments":{"vmid":"101","action":"status","service_name":"nginx","actor":"codex"}}
```

Snapshot then risky change:

```json
{"tool":"vm_snapshot","arguments":{"vmid":"101","action":"create","name":"pre-change","actor":"codex","audit_tag":"change-req-42"}}
```

```json
{"tool":"vm_config","arguments":{"vmid":"101","action":"set","params":{"memory":"4096"},"actor":"codex","audit_tag":"change-req-42"}}
```
