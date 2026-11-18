"""Shared validation helpers for external text contracts."""

from __future__ import annotations

import json
import re
from typing import Any

ASCII_TEXT_PATTERN = re.compile(r"[\t\n\r\x20-\x7e]+")
VISIBLE_ASCII_PATTERN = re.compile(r"[\x21-\x7e]")


def is_ascii_text(value: Any) -> bool:
    return (
        isinstance(value, str)
        and ASCII_TEXT_PATTERN.fullmatch(value) is not None
        and VISIBLE_ASCII_PATTERN.search(value) is not None
    )


class DuplicateJsonKeyError(ValueError):
    """Raised when strict JSON input repeats an object key."""


def _unique_json_object(
    pairs: list[tuple[str, Any]],
) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise DuplicateJsonKeyError(
                f"Duplicate JSON object key: {key}"
            )
        result[key] = value
    return result


def loads_json_without_duplicate_keys(text: str) -> Any:
    """Parse JSON while rejecting duplicate object keys at every depth."""

    return json.loads(text, object_pairs_hook=_unique_json_object)
