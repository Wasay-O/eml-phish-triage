"""Command-line interface for phish-triage."""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict

from .parser import parse_email
from .rules import run_rules
from .scoring import score_findings, verdict_for


def build_report(path) -> dict:
    email = parse_email(path)
    findings = run_rules(email)
    score = score_findings(findings)
    return {
        "file": email.source_path,
        "subject": email.subject,
        "from": email.from_addr,
        "verdict": verdict_for(score),
        "score": score,
        "findings": [asdict(finding) for finding in findings],
        "links": [asdict(link) for link in email.links],
        "attachments": [asdict(attachment) for attachment in email.attachments],
    }


def format_text(report: dict) -> str:
    lines = [
        f"File:     {report['file']}",
        f"Subject:  {report['subject']}",
        f"From:     {report['from']}",
        f"Verdict:  {report['verdict'].upper()} (score {report['score']})",
        "",
    ]
    if report["findings"]:
        lines.append("Why:")
        for finding in report["findings"]:
            lines.append(f"  +{finding['weight']:<2} {finding['rule']}: {finding['reason']}")
    else:
        lines.append("No rules fired.")

    if report["attachments"]:
        lines += ["", "Attachments:"]
        for attachment in report["attachments"]:
            lines.append(f"  {attachment['filename']} ({attachment['content_type']}, {attachment['size']} bytes)")
            lines.append(f"    sha256: {attachment['sha256']}")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="phish-triage",
        description="Explainable triage for suspicious .eml files. Read-only: never opens links or attachments.",
    )
    parser.add_argument("path", help="path to a .eml file")
    parser.add_argument("--json", action="store_true", help="print JSON instead of text")
    args = parser.parse_args(argv)

    try:
        report = build_report(args.path)
    except OSError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    print(json.dumps(report, indent=2) if args.json else format_text(report))
    return 1 if report["verdict"] == "high" else 0
