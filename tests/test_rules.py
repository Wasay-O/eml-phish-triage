from phish_triage.parser import Attachment, Link, ParsedEmail
from phish_triage.rules import (
    check_attachments,
    check_authentication,
    check_links,
    check_lookalike_sender,
    check_urgency,
    levenshtein,
)
from phish_triage.scoring import verdict_for


def make_email(**overrides) -> ParsedEmail:
    email = ParsedEmail(from_addr="person@example.org")
    for key, value in overrides.items():
        setattr(email, key, value)
    return email


def test_levenshtein_known_values():
    assert levenshtein("kitten", "sitting") == 3
    assert levenshtein("micr0soft", "microsoft") == 1
    assert levenshtein("same", "same") == 0


def test_failed_auth_is_flagged():
    email = make_email(auth_results={"spf": "fail", "dkim": "pass", "dmarc": "softfail"})
    rules = {f.rule for f in check_authentication(email)}
    assert rules == {"spf_fail", "dmarc_softfail"}


def test_missing_auth_results_is_low_weight():
    findings = check_authentication(make_email(auth_results={}))
    assert [f.rule for f in findings] == ["no_auth_results"]
    assert findings[0].weight == 1


def test_trusted_subdomain_is_not_a_lookalike():
    assert check_lookalike_sender(make_email(from_addr="alerts@mail.google.com")) == []


def test_digit_substitution_is_a_lookalike():
    findings = check_lookalike_sender(make_email(from_addr="it@micr0soft.test"))
    assert [f.rule for f in findings] == ["lookalike_sender"]


def test_brand_inside_other_domain_is_flagged():
    findings = check_lookalike_sender(make_email(from_addr="billing@microsoft-support.test"))
    assert [f.rule for f in findings] == ["brand_in_sender_domain"]


def test_display_text_mismatch_is_flagged():
    email = make_email(links=[
        Link(href="http://203.0.113.45/login", display_text="https://portal.microsoft.com/verify", host="203.0.113.45"),
    ])
    rules = [f.rule for f in check_links(email)]
    assert "display_url_mismatch" in rules
    assert "ip_address_link" in rules


def test_matching_display_text_is_not_flagged():
    email = make_email(links=[
        Link(href="https://example.org/blog", display_text="https://example.org/blog", host="example.org"),
    ])
    assert check_links(email) == []


def test_risky_and_macro_attachments_have_different_rules():
    email = make_email(attachments=[
        Attachment(filename="Invoice.pdf.exe", content_type="", size=1, sha256=""),
        Attachment(filename="report.XLSM", content_type="", size=1, sha256=""),
        Attachment(filename="notes.txt", content_type="", size=1, sha256=""),
    ])
    assert [f.rule for f in check_attachments(email)] == ["risky_attachment", "macro_attachment"]


def test_urgency_language_is_detected():
    email = make_email(subject="Urgent: verify your account")
    assert [f.rule for f in check_urgency(email)] == ["urgency_language"]


def test_verdict_thresholds():
    assert verdict_for(0) == "low"
    assert verdict_for(3) == "medium"
    assert verdict_for(6) == "high"
