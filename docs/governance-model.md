# AI Agent Security Governance Model

## Objective

Create a security control layer for AI agents before they access tools, data, or business workflows.

## Core governance controls

| Control | Purpose |
|---|---|
| Tool least privilege | Restrict tools based on the agent role |
| Prompt-injection detection | Identify unsafe prompt patterns before action |
| Sensitive data protection | Detect data that should not be exposed or processed without controls |
| Data boundary enforcement | Require approval before sensitive data reaches tools designated as restricted trust boundaries |
| Human-in-the-loop approval | Require review for high-risk actions |
| Audit logging | Preserve decision evidence for investigations and governance |
| Risk scoring | Convert agent context into an explainable decision |

## Tool trust boundaries

Tool authorization and data authorization are separate decisions. An agent may be permitted to invoke a tool while still being prohibited from sending sensitive data to that tool without review.

The `sensitive_data_tools` policy identifies tool boundaries where detected sensitive data requires human approval. This is useful for externally hosted services, broad search tools, third-party integrations, or other destinations where enterprise policy requires explicit review before sensitive information leaves a controlled processing boundary.

Tools not listed in `sensitive_data_tools` may process detected sensitive data under enhanced monitoring when the role is authorized to use them. This models an internal security workflow where sensitive identifiers can be necessary for investigation while still generating an auditable control signal.

## Decision outcomes

- `allow`: request meets governance policy
- `allow_with_monitoring`: moderate-risk request should be logged with enhanced monitoring
- `requires_approval`: high-risk action or restricted sensitive-data transfer requires human review
- `deny`: request violates role/tool policy

## Employer-facing explanation

This project demonstrates how AI security can be operationalized as policy-as-code. It separates agent tool authorization from data-flow authorization, applies least privilege and trust-boundary controls, and produces deterministic decisions that can be tested and audited. The model is designed for agentic AI pipelines where agents need access to tools, workflows, or sensitive data without receiving unrestricted authority to move that data across system boundaries.
