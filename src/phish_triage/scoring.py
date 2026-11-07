"""Turn rule findings into a score and a verdict."""

from __future__ import annotations

from .rules import Finding

HIGH_THRESHOLD = 6
MEDIUM_THRESHOLD = 3


def score_findings(findings: list[Finding]) -> int:
    return sum(finding.weight for finding in findings)


def verdict_for(score: int) -> str:
    if score >= HIGH_THRESHOLD:
        return "high"
    if score >= MEDIUM_THRESHOLD:
        return "medium"
    return "low"
