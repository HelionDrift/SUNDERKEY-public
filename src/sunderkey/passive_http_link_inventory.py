"""Proposal-only same-origin link inventory from one completed HTTP response."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from html.parser import HTMLParser
from urllib.parse import urljoin, urlsplit

from .assessment_transport_contracts import HttpRequestIntent
from .authorized_http_runtime import ExchangeStatus, HttpExchangeReceipt

AUTHORITY_EFFECT = "none"
QUALIFICATION_EFFECT = "none"
NETWORK_CALL_PERFORMED = False
MAX_HTML_BYTES = 1024 * 1024
MAX_RAW_LINKS = 2048
MAX_LINKS = 256
_QUERY_NAME = re.compile(r"[A-Za-z0-9_.-]{1,64}\Z")
_LINK_ATTRIBUTES = {"a": "href", "link": "href", "script": "src", "form": "action"}


class PassiveLinkInventoryError(ValueError):
    """The source evidence or observed HTML is not safe to inventory."""


class _LinkParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.links: list[tuple[str, str]] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        name = _LINK_ATTRIBUTES.get(tag)
        if name is None:
            return
        for key, value in attrs:
            if key == name and value is not None:
                self.links.append((tag, value))
                if len(self.links) > MAX_RAW_LINKS:
                    raise PassiveLinkInventoryError("HTML link count exceeds the hard limit")
                return


def _origin(url: str) -> tuple[str, str]:
    if not isinstance(url, str) or len(url) > 2048 or not url.isascii():
        raise PassiveLinkInventoryError("source URL is invalid")
    try:
        parts = urlsplit(url)
    except ValueError as exc:
        raise PassiveLinkInventoryError("source URL is invalid") from exc
    if (
        parts.scheme != "https"
        or not parts.hostname
        or parts.netloc != parts.hostname
        or parts.fragment
        or any(ord(char) < 33 or ord(char) > 126 for char in url)
    ):
        raise PassiveLinkInventoryError("source URL must have a canonical HTTPS origin")
    return f"https://{parts.hostname}", parts.hostname


def _candidate(
    raw: str, tag: str, source_url: str, origin: str, host: str
) -> tuple[str, str, tuple[str, ...]] | None:
    if (
        not raw
        or len(raw) > 2048
        or not raw.isascii()
        or "\\" in raw
        or any(ord(char) < 33 or ord(char) > 126 for char in raw)
    ):
        return None
    try:
        resolved = urlsplit(urljoin(source_url, raw))
    except ValueError:
        return None
    if resolved.scheme != "https" or resolved.netloc != host:
        return None
    path = resolved.path or "/"
    if not path.startswith("/") or len(path) > 2048:
        return None
    names: set[str] = set()
    if resolved.query:
        for component in resolved.query.split("&"):
            name = component.split("=", 1)[0]
            if not _QUERY_NAME.fullmatch(name):
                return None
            names.add(name)
    return tag, origin + path, tuple(sorted(names))


@dataclass(frozen=True, slots=True)
class PassiveLinkCandidate:
    tag: str
    url_without_query: str
    query_parameter_names: tuple[str, ...]

    def to_dict(self) -> dict[str, object]:
        return {
            "tag": self.tag,
            "url_without_query": self.url_without_query,
            "query_parameter_names": list(self.query_parameter_names),
        }


@dataclass(frozen=True, slots=True)
class PassiveLinkInventory:
    source_receipt_id: str
    source_receipt_sha256: str
    source_intent_sha256: str
    response_body_sha256: str
    candidate_links: tuple[PassiveLinkCandidate, ...]
    rejected_link_count: int
    inventory_sha256: str

    def to_dict(self) -> dict[str, object]:
        return {
            "source_receipt_id": self.source_receipt_id,
            "source_receipt_sha256": self.source_receipt_sha256,
            "source_intent_sha256": self.source_intent_sha256,
            "response_body_sha256": self.response_body_sha256,
            "candidate_links": [item.to_dict() for item in self.candidate_links],
            "rejected_link_count": self.rejected_link_count,
            "inventory_sha256": self.inventory_sha256,
            "authority_effect": AUTHORITY_EFFECT,
            "qualification_effect": QUALIFICATION_EFFECT,
            "network_call_performed": NETWORK_CALL_PERFORMED,
        }


def extract_passive_link_inventory(
    *,
    intent: HttpRequestIntent,
    receipt: HttpExchangeReceipt,
    response_body: bytes,
    maximum_links: int = MAX_LINKS,
) -> PassiveLinkInventory:
    """Extract proposals, never new scope, admission, or a request schedule."""

    if not isinstance(intent, HttpRequestIntent) or not isinstance(receipt, HttpExchangeReceipt):
        raise PassiveLinkInventoryError("typed HTTP intent and receipt are required")
    if receipt.status is not ExchangeStatus.COMPLETED or receipt.response_mime_type != "text/html":
        raise PassiveLinkInventoryError("a completed HTML exchange is required")
    if receipt.intent_sha256 != intent.intent_sha256:
        raise PassiveLinkInventoryError("intent does not match the exchange receipt")
    if (
        not isinstance(response_body, bytes)
        or len(response_body) > MAX_HTML_BYTES
        or len(response_body) != receipt.response_size_bytes
        or "sha256:" + hashlib.sha256(response_body).hexdigest() != receipt.response_body_sha256
    ):
        raise PassiveLinkInventoryError("response body does not match the exchange receipt")
    if isinstance(maximum_links, bool) or not isinstance(maximum_links, int):
        raise PassiveLinkInventoryError("maximum_links is invalid")
    if not 1 <= maximum_links <= MAX_LINKS:
        raise PassiveLinkInventoryError("maximum_links is outside the allowed range")
    origin, host = _origin(intent.url)
    try:
        html = response_body.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise PassiveLinkInventoryError("HTML response must be UTF-8") from exc
    parser = _LinkParser()
    parser.feed(html)
    parser.close()
    candidates: set[tuple[str, str, tuple[str, ...]]] = set()
    rejected = 0
    for tag, raw in parser.links:
        candidate = _candidate(raw, tag, intent.url, origin, host)
        if candidate is None:
            rejected += 1
        else:
            candidates.add(candidate)
            if len(candidates) > maximum_links:
                raise PassiveLinkInventoryError("accepted link count exceeds the limit")
    links = tuple(PassiveLinkCandidate(*item) for item in sorted(candidates))
    payload = {
        "source_receipt_id": receipt.receipt_id,
        "source_receipt_sha256": receipt.receipt_sha256,
        "source_intent_sha256": intent.intent_sha256,
        "response_body_sha256": receipt.response_body_sha256,
        "candidate_links": [item.to_dict() for item in links],
        "rejected_link_count": rejected,
    }
    digest = "sha256:" + hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode(
            "ascii"
        )
    ).hexdigest()
    return PassiveLinkInventory(
        source_receipt_id=receipt.receipt_id,
        source_receipt_sha256=receipt.receipt_sha256,
        source_intent_sha256=intent.intent_sha256,
        response_body_sha256=receipt.response_body_sha256,
        candidate_links=links,
        rejected_link_count=rejected,
        inventory_sha256=digest,
    )
