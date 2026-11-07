"""Rule checks. Each check returns Findings; scoring.py turns them into a verdict."""

from __future__ import annotations

import os
import re
from dataclasses import dataclass

from .parser import ParsedEmail, domain_of

# Brand domains that legitimate mail is expected to come from. Edit for your environment.
TRUSTED_DOMAINS = (
    "microsoft.com",
    "google.com",
    "paypal.com",
    "apple.com",
    "cloudflare.com",
)
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly"}
RISKY_EXTENSIONS = {
    ".exe", ".js", ".vbs", ".iso", ".img", ".lnk", ".hta", ".scr",
    ".bat", ".cmd", ".ps1", ".html", ".htm",
}
MACRO_EXTENSIONS = {".docm", ".xlsm", ".pptm", ".dotm", ".xltm"}
URGENCY_PHRASES = (
    "verify your account",
    "password expires",
    "account suspended",
    "urgent action",
    "confirm your identity",
    "unusual sign-in",
    "within 24 hours",
)
FAILED_AUTH_RESULTS = {"fail", "softfail", "permerror"}
DOMAIN_TEXT_RE = re.compile(r"^(?:https?://)?((?:[a-z0-9-]+\.)+[a-z]{2,})(?:/\S*)?$", re.IGNORECASE)
IPV4_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
MIN_LOOKALIKE_LENGTH = 5


@dataclass
class Finding:
    rule: str
    weight: int
    reason: str


def levenshtein(a: str, b: str) -> int:
    """Edit distance between two strings (insertions, deletions, substitutions)."""
    if len(a) < len(b):
        a, b = b, a
    previous = list(range(len(b) + 1))
    for i, char_a in enumerate(a, start=1):
        current = [i]
        for j, char_b in enumerate(b, start=1):
            current.append(
                min(
                    previous[j] + 1,                        # deletion
                    current[j - 1] + 1,                     # insertion
                    previous[j - 1] + (char_a != char_b),   # substitution
                )
            )
        previous = current
    return previous[-1]


def _label(domain: str) -> str:
    """The second-level label: 'micr0soft' for 'micr0soft.test'. Simplified on purpose."""
    parts = domain.split(".")
    return parts[-2] if len(parts) >= 2 else domain


def check_authentication(email: ParsedEmail) -> list[Finding]:
    if not email.auth_results:
        return [Finding("no_auth_results", 1, "No Authentication-Results header, so SPF/DKIM/DMARC could not be checked.")]
    findings = []
    for mechanism, result in sorted(email.auth_results.items()):
        if result in FAILED_AUTH_RESULTS:
            findings.append(Finding(f"{mechanism}_{result}", 3, f"{mechanism.upper()} result is '{result}'."))
    return findings


def check_sender_addresses(email: ParsedEmail) -> list[Finding]:
    findings = []
    reply_domain = domain_of(email.reply_to)
    if reply_domain and reply_domain != email.from_domain:
        findings.append(Finding(
            "reply_to_mismatch", 2,
            f"Reply-To domain ({reply_domain}) differs from From domain ({email.from_domain}).",
        ))
    return_domain = domain_of(email.return_path)
    if return_domain and return_domain != email.from_domain:
        findings.append(Finding(
            "return_path_mismatch", 1,
            f"Return-Path domain ({return_domain}) differs from From domain ({email.from_domain}).",
        ))
    return findings


def check_lookalike_sender(email: ParsedEmail) -> list[Finding]:
    sender = email.from_domain
    if not sender:
        return []
    for trusted in TRUSTED_DOMAINS:
        if sender == trusted or sender.endswith("." + trusted):
            return []  # genuinely from a trusted domain

    sender_label = _label(sender)
    for trusted in TRUSTED_DOMAINS:
        brand = _label(trusted)
        if len(brand) < MIN_LOOKALIKE_LENGTH:
            continue
        if sender_label != brand and levenshtein(sender_label, brand) <= 2 and len(sender_label) >= MIN_LOOKALIKE_LENGTH:
            return [Finding("lookalike_sender", 4, f"Sender domain '{sender}' looks like '{trusted}'.")]
        if brand in sender:
            return [Finding(
                "brand_in_sender_domain", 3,
                f"Sender domain '{sender}' contains the brand '{brand}' but is not '{trusted}'.",
            )]
    return []


def check_links(email: ParsedEmail) -> list[Finding]:
    findings: list[Finding] = []
    seen: set[tuple[str, str]] = set()

    def add(rule: str, weight: int, reason: str, key: str) -> None:
        if (rule, key) not in seen:
            seen.add((rule, key))
            findings.append(Finding(rule, weight, reason))

    for link in email.links:
        host = link.host
        if not host:
            continue
        if IPV4_RE.match(host):
            add("ip_address_link", 3, f"Link points to a raw IP address: {host}.", host)
        if "xn--" in host:
            add("punycode_link", 2, f"Link uses a punycode (xn--) host: {host}.", host)
        if host in SHORTENERS:
            add("url_shortener", 1, f"Link uses a URL shortener: {host}.", host)

        match = DOMAIN_TEXT_RE.match(link.display_text)
        if match:
            shown = match.group(1).lower()
            if not (host == shown or host.endswith("." + shown)):
                add(
                    "display_url_mismatch", 3,
                    f"Link text shows '{shown}' but the link goes to '{host}'.",
                    f"{shown}->{host}",
                )
    return findings


def check_attachments(email: ParsedEmail) -> list[Finding]:
    findings = []
    for attachment in email.attachments:
        extension = os.path.splitext(attachment.filename.lower())[1]
        if extension in RISKY_EXTENSIONS:
            findings.append(Finding(
                "risky_attachment", 4,
                f"Attachment '{attachment.filename}' has a risky type ({extension}).",
            ))
        elif extension in MACRO_EXTENSIONS:
            findings.append(Finding(
                "macro_attachment", 3,
                f"Attachment '{attachment.filename}' is a macro-enabled Office file ({extension}).",
            ))
    return findings


def check_urgency(email: ParsedEmail) -> list[Finding]:
    text = f"{email.subject}\n{email.text_body}\n{email.html_body}".lower()
    hits = [phrase for phrase in URGENCY_PHRASES if phrase in text]
    if hits:
        return [Finding("urgency_language", 2, "Urgent or account-threat wording: " + ", ".join(hits) + ".")]
    return []


def run_rules(email: ParsedEmail) -> list[Finding]:
    """Run every rule and return all findings, in a stable order."""
    findings: list[Finding] = []
    for check in (
        check_authentication,
        check_sender_addresses,
        check_lookalike_sender,
        check_links,
        check_attachments,
        check_urgency,
    ):
        findings.extend(check(email))
    return findings
