# AI Agent Security Governance Model

## Objective

Create a security control layer for AI agents before they access tools, data, or business workflows.

## Core governance controls

| Control | Purpose |
|---|---|
| Tool least privilege | Restrict tools based on the agent role |
| Prompt-injection detection | Identify unsafe instructions in direct prompts and untrusted retrieved/tool data before action |
| Sensitive data protection | Detect data that should not be exposed or processed without controls |
| Human-in-the-loop approval | Require review for high-risk actions |
| Audit logging | Preserve decision evidence for investigations and governance |
| Risk scoring | Convert agent context into an explainable decision |

## Prompt and data trust boundaries

Agentic systems do not receive instructions only from the user prompt. RAG documents, search results, MCP/tool responses, ticket text, and other retrieved content can cross into the model context from systems with different trust levels. That content must be treated as untrusted input rather than implicitly trusted context.

The engine therefore evaluates two injection surfaces independently:

- `DIRECT_PROMPT_INJECTION_DETECTION` records suspicious instructions originating in the request prompt.
- `INDIRECT_PROMPT_INJECTION_DETECTION` records suspicious instructions found in retrieved or tool-provided `data`.

Both contribute independently to the deterministic risk score so a request containing signals across multiple trust boundaries is escalated more strongly and the audit record preserves where the signals originated.

This implementation intentionally uses transparent heuristic indicators for portfolio demonstration and deterministic testing. Production controls should combine this layer with structured tool schemas, content provenance, instruction/data separation, model-specific defenses, output validation, least-privilege credentials, and telemetry-driven detection. Heuristics alone cannot reliably identify every prompt-injection technique.

## Decision outcomes

- `allow`: request meets governance policy
- `allow_with_monitoring`: moderate-risk request should be logged with enhanced monitoring
- `requires_approval`: high-risk request requires human review
- `deny`: request violates role/tool policy

## Employer-facing explanation

This project demonstrates how AI security can be operationalized as policy-as-code. It is designed for agentic AI pipelines where agents need access to tools, workflows, or sensitive data, but must be governed with least privilege, risk scoring, explicit trust boundaries, and auditable controls.
