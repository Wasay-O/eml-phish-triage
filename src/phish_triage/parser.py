"""Read a .eml file into a ParsedEmail.

This module only reads bytes and parses them. It never opens attachments,
follows links, or touches the network.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from email import policy
from email.parser import BytesParser
from email.utils import parseaddr
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import urlsplit

AUTH_RE = re.compile(r"\b(spf|dkim|dmarc)=([a-z]+)", re.IGNORECASE)
BARE_URL_RE = re.compile(r"https?://[^\s<>\"']+", re.IGNORECASE)


@dataclass
class Link:
    href: str
    display_text: str
    host: str


@dataclass
class Attachment:
    filename: str
    content_type: str
    size: int
    sha256: str


@dataclass
class ParsedEmail:
    source_path: str = ""
    subject: str = ""
    date: str = ""
    from_addr: str = ""
    reply_to: str = ""
    return_path: str = ""
    auth_results: dict[str, str] = field(default_factory=dict)
    text_body: str = ""
    html_body: str = ""
    links: list[Link] = field(default_factory=list)
    attachments: list[Attachment] = field(default_factory=list)

    @property
    def from_domain(self) -> str:
        return domain_of(self.from_addr)


def domain_of(address: str) -> str:
    """Return the lowercase domain part of an email address, or '' if there is none."""
    if "@" not in address:
        return ""
    return address.rsplit("@", 1)[-1].strip().lower()


def host_of(url: str) -> str:
    """Return the lowercase host of a URL, accepting URLs without a scheme."""
    candidate = url.strip() if "://" in url else "//" + url.strip()
    try:
        return urlsplit(candidate).hostname or ""
    except ValueError:
        return ""


class _AnchorParser(HTMLParser):
    """Collects (href, visible text) pairs from <a> tags."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.anchors: list[tuple[str, str]] = []
        self._href: str | None = None
        self._text: list[str] = []

    def handle_starttag(self, tag, attrs):
        if tag == "a":
            self._href = dict(attrs).get("href") or ""
            self._text = []

    def handle_data(self, data):
        if self._href is not None:
            self._text.append(data)

    def handle_endtag(self, tag):
        if tag == "a" and self._href is not None:
            self.anchors.append((self._href, "".join(self._text).strip()))
            self._href = None


def parse_email(path: str | Path) -> ParsedEmail:
    """Parse the .eml file at `path`."""
    path = Path(path)
    msg = BytesParser(policy=policy.default).parsebytes(path.read_bytes())

    email = ParsedEmail(
        source_path=str(path),
        subject=str(msg.get("Subject", "")),
        date=str(msg.get("Date", "")),
        from_addr=parseaddr(str(msg.get("From", "")))[1].lower(),
        reply_to=parseaddr(str(msg.get("Reply-To", "")))[1].lower(),
        return_path=parseaddr(str(msg.get("Return-Path", "")))[1].lower(),
    )

    combined_auth = " ".join(str(h) for h in msg.get_all("Authentication-Results", []))
    email.auth_results = {
        m.group(1).lower(): m.group(2).lower() for m in AUTH_RE.finditer(combined_auth)
    }

    text_parts: list[str] = []
    html_parts: list[str] = []
    for part in msg.walk():
        if part.is_multipart():
            continue
        content_type = part.get_content_type()
        filename = part.get_filename()
        if filename or part.get_content_disposition() == "attachment":
            payload = part.get_payload(decode=True) or b""
            email.attachments.append(
                Attachment(
                    filename=filename or "(unnamed)",
                    content_type=content_type,
                    size=len(payload),
                    sha256=hashlib.sha256(payload).hexdigest(),
                )
            )
        elif content_type == "text/plain":
            text_parts.append(part.get_content())
        elif content_type == "text/html":
            html_parts.append(part.get_content())

    email.text_body = "\n".join(text_parts)
    email.html_body = "\n".join(html_parts)

    anchors = _AnchorParser()
    anchors.feed(email.html_body)
    email.links = [Link(href=h, display_text=t, host=host_of(h)) for h, t in anchors.anchors]
    email.links += [
        Link(href=url, display_text=url, host=host_of(url))
        for url in BARE_URL_RE.findall(email.text_body)
    ]
    return email
