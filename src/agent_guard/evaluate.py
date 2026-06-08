from __future__ import annotations

import json
import sys
from pathlib import Path

import yaml

from .engine import evaluate_agent_request


def main(requests_path: str, policy_path: str) -> None:
    requests = json.loads(Path(requests_path).read_text(encoding="utf-8"))
    policy = yaml.safe_load(Path(policy_path).read_text(encoding="utf-8"))
    decisions = [evaluate_agent_request(request, policy).to_dict() for request in requests]
    print(json.dumps(decisions, indent=2))


if __name__ == "__main__":
    if len(sys.argv) != 3:
        raise SystemExit("Usage: python -m agent_guard.evaluate data/sample_requests.json policies/tool_policy.yml")
    main(sys.argv[1], sys.argv[2])
