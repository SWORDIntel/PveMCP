# PveMCP Medical Triage Workflow Framework

PveMCP’s Medical Triage framework is a modular automation system designed to codify infrastructure health into repeatable, auditable, and autonomous "clinical" workflows that leverage our 67 native tools as building blocks for intelligent operations.

It requires a dedicated `src/pvemcp/workflows/` directory to host machine-readable JSON recipes, an orchestration engine (exposed via `vm_run_workflow`) capable of sequential tool-chaining and state verification, and a library of schemas mapping common infrastructure anomalies to diagnostic and remediation chains. By organizing tasks into four pillars—Triage for rapid diagnosis, Surgery for autonomous remediation, Preventative Care for proactive hardening, and Forensics for root-cause investigation—the system elevates infrastructure management from reactive scripting to a strategic, learning-based model.

Crucially, this framework is architected to leverage our cumulative conversation history as a primary data source, enabling autonomous workflows to contextualize live diagnostic findings against past incidents, previously identified system patterns, and established operational baselines to prevent recurring failures and fine-tune remediation strategies based on historical outcomes. By continuously feeding the AI agent’s decision-making loop with real-time telemetry from the `audit.log` and the unified `memory.json` store, the system transcends static automation to achieve dynamic, self-evolving operational awareness.

The orchestration engine does not merely execute rigid scripts; it interprets recipe logic as a set of goal-oriented primitives, allowing the AI to conditionally branch, retry, or pause based on live feedback, all while strictly adhering to a "fail-closed" security philosophy that mandates `danger_mode` validation for every transformative action. Furthermore, this loop enables the system to treat infrastructure as a continuous learning environment: successful remediations are codified into new recipes, and failed attempts are recorded in the history buffer, enabling the AI to refine its tactical approach over time and ultimately transforming the infrastructure into a self-documenting, resilient platform where the agent evolves in lockstep with the environment’s changing complexity, ensuring every autonomous action is fully logged, verifiable, and natively traceable within the PveMCP audit system for complete forensic post-mortem analysis.

---

## Workflow Pillars

| Pillar | Focus |
| :--- | :--- |
| **⚡ Triage** | Rapid diagnosis of anomalies (e.g., node connectivity checks, log analysis). |
| **⚙️ Surgery** | Autonomous remediation actions (e.g., service restart, config rollback). |
| **🛡️ Preventative Care** | Proactive hardening (e.g., config bisection, disk reclamation). |
| **🔍 Forensics** | Root-cause analysis (e.g., RAM dumping, audit trail replaying). |

---

## Recipe Format

Workflows are defined as structured JSON objects in `src/pvemcp/workflows/`:

```json
{
  "name": "ServiceDriftDiagnosis",
  "pillar": "Triage",
  "steps": [
    {"tool": "vm_slo_check", "params": {"vmid": "9211"}},
    {"tool": "vm_etc_diff", "params": {"vmid": "9211"}}
  ]
}
```
