from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

SENSITIVE_PATTERNS = {
    "email": re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+[.][A-Za-z]{2,}"),
    "ssn_like": re.compile(r"(?:^|[^0-9])[0-9]{3}-[0-9]{2}-[0-9]{4}(?:[^0-9]|$)"),
    "api_key_like": re.compile(r"(?i)(api[_-]?key|secret|token)[ \t]*[:=][ \t]*[A-Za-z0-9_-]{12,}"),
}

PROMPT_INJECTION_INDICATORS = [
    "ignore previous instructions",
    "reveal your system prompt",
    "bypass policy",
    "disable safety",
    "exfiltrate",
]


@dataclass(frozen=True)
class AgentDecision:
    request_id: str
    decision: str
    risk_score: int
    reason: str
    controls: list[str]

    def to_dict(self) -> dict[str, Any]:
        return {
            "request_id": self.request_id,
            "decision": self.decision,
            "risk_score": self.risk_score,
            "reason": self.reason,
            "controls": self.controls,
        }


def evaluate_agent_request(request: dict[str, Any], policy: dict[str, Any]) -> AgentDecision:
    """Evaluate an AI agent tool request against governance policy.

    The engine is intentionally deterministic so every agent decision can be
    explained, tested, logged, and reviewed during governance or incident review.
    """
    request_id = str(request.get("request_id", "unknown"))
    tool_name = str(request.get("tool_name", "unknown"))
    prompt = str(request.get("prompt", ""))
    data = str(request.get("data", ""))
    agent_role = str(request.get("agent_role", "unknown"))

    allowed_tools = set(policy.get("roles", {}).get(agent_role, {}).get("allowed_tools", []))
    high_risk_tools = set(policy.get("high_risk_tools", []))

    controls = ["AUDIT_LOGGING", "TOOL_LEAST_PRIVILEGE"]
    risk_score = 0

    if tool_name not in allowed_tools:
        return AgentDecision(
            request_id,
            "deny",
            90,
            "tool is not authorized for this agent role",
            controls + ["ROLE_BASED_ACCESS_CONTROL"],
        )

    if _contains_prompt_injection(prompt):
        risk_score += 50
        controls.append("PROMPT_INJECTION_DETECTION")

    if _contains_sensitive_data(data):
        risk_score += 40
        controls.append("SENSITIVE_DATA_PROTECTION")

    if tool_name in high_risk_tools:
        # High-risk tools can affect business systems, users, tickets, or endpoints.
        # They should require human approval even when the prompt itself appears benign.
        risk_score += 70
        controls.append("HUMAN_IN_THE_LOOP")

    risk_score = min(100, risk_score)

    if risk_score >= 70:
        return AgentDecision(request_id, "requires_approval", risk_score, "high-risk agent action requires human approval", controls)

    if risk_score >= 40:
        return AgentDecision(request_id, "allow_with_monitoring", risk_score, "moderate risk action allowed with enhanced monitoring", controls)

    return AgentDecision(request_id, "allow", risk_score, "request satisfies AI agent governance policy", controls)


def _contains_sensitive_data(text: str) -> bool:
    return any(pattern.search(text) for pattern in SENSITIVE_PATTERNS.values())


def _contains_prompt_injection(text: str) -> bool:
    lowered = text.lower()
    return any(indicator in lowered for indicator in PROMPT_INJECTION_INDICATORS)
