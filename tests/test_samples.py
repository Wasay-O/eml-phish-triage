from pathlib import Path

import pytest

from phish_triage.cli import build_report
from phish_triage.parser import parse_email

SAMPLES = Path(__file__).resolve().parents[1] / "samples"


@pytest.mark.parametrize(
    ("name", "expected_verdict"),
    [
        ("benign_newsletter.eml", "low"),
        ("phish_lookalike.eml", "high"),
        ("phish_attachment.eml", "high"),
    ],
)
def test_sample_verdicts(name, expected_verdict):
    assert build_report(SAMPLES / name)["verdict"] == expected_verdict


def test_parser_reads_headers_auth_and_attachments():
    email = parse_email(SAMPLES / "phish_lookalike.eml")
    assert email.from_addr == "helpdesk@micr0soft.test"
    assert email.reply_to == "collect@example.net"
    assert email.auth_results == {"spf": "fail", "dkim": "none", "dmarc": "fail"}
    assert [a.filename for a in email.attachments] == ["Invoice_March.xlsm"]
    assert len(email.attachments[0].sha256) == 64


def test_parser_collects_anchor_links():
    email = parse_email(SAMPLES / "phish_lookalike.eml")
    # The visible text names one domain, but the href points at a raw IP address.
    link = next(link for link in email.links if link.display_text.startswith("https://portal.microsoft.com"))
    assert link.host == "203.0.113.45"
