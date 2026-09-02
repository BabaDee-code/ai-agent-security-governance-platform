# AI Agent Security Governance Platform

![CI](https://github.com/BabaDee-code/ai-agent-security-governance-platform/actions/workflows/ci.yml/badge.svg)

A portfolio-grade security governance platform for AI agents. This project demonstrates how to evaluate AI agent risk, enforce tool-access policy, detect sensitive data exposure, identify prompt-injection indicators, require approvals for high-risk actions, and generate audit-ready decision records.

## What this project shows

- AI agent risk scoring and governance controls
- Tool permission policy enforcement
- Prompt-injection indicator detection
- Sensitive data exposure checks
- Approval workflow logic for high-risk agent actions
- Audit logging for agent decisions
- Unit tests and CI validation

## Repository structure

```text
src/agent_guard/            AI agent governance engine
data/sample_requests.json   Sample agent action requests
policies/tool_policy.yml    Tool access policy examples
tests/                      Unit tests
.github/workflows/ci.yml    Automated test workflow
docs/governance-model.md    Architecture and governance model
```

## Run locally

```bash
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\\Scripts\\activate
pip install -r requirements-dev.txt
pytest -q
PYTHONPATH=src python -m agent_guard.evaluate data/sample_requests.json policies/tool_policy.yml
```

On Windows PowerShell, use `$env:PYTHONPATH = "src"` before the final command.

## Example decision

```json
{
  "request_id": "AGENT-1001",
  "decision": "requires_approval",
  "risk_score": 75,
  "reason": "high-risk tool requires human approval",
  "controls": ["TOOL_LEAST_PRIVILEGE", "HUMAN_IN_THE_LOOP", "AUDIT_LOGGING"]
}
```

## Security controls represented

- Least-privilege tool access
- Sensitive data protection
- Prompt-injection risk detection
- Human approval for high-risk actions
- Auditability and traceability
- Policy-as-code for AI agent governance

## Portfolio talking points

This project demonstrates how I would secure agentic AI systems by placing a governance and policy enforcement layer between the agent and its tools. It shows practical AI security engineering across access control, risk scoring, approval workflows, and audit evidence.
