"""Bounded, type-preserving canonical JSON for exact artifact replay."""

from __future__ import annotations

import json
import math
from typing import Any

MAX_JSON_DEPTH = 24
MAX_JSON_NODES = 100_000


class JsonContractIntegrityError(ValueError):
    """An artifact is not a bounded tree of exact JSON primitives."""


def canonical_json_bytes(value: Any, *, max_bytes: int) -> bytes:
    """Reject coercible Python objects before producing canonical ASCII JSON.

    Object key order is immaterial. List order and Boolean, integer, and float
    representations remain distinct. Shared containers are permitted, but
    cycles are not. The iterative walk bounds nesting before serialization.
    """
    if type(max_bytes) is not int or max_bytes < 1:
        raise JsonContractIntegrityError("the JSON byte limit must be a positive integer")
    active: set[int] = set()
    pending: list[tuple[Any, int, bool]] = [(value, 0, False)]
    nodes = 0
    minimum_bytes = 0
    while pending:
        item, depth, leaving = pending.pop()
        if leaving:
            active.remove(id(item))
            continue
        nodes += 1
        if nodes > MAX_JSON_NODES or depth > MAX_JSON_DEPTH:
            raise JsonContractIntegrityError("JSON nesting or node limit exceeded")
        kind = type(item)
        if kind in (dict, list):
            if id(item) in active:
                raise JsonContractIntegrityError("JSON containers cannot be cyclic")
            if len(item) > MAX_JSON_NODES - nodes:
                raise JsonContractIntegrityError("JSON node limit exceeded")
            active.add(id(item))
            pending.append((item, depth, True))
            minimum_bytes += 2 + max(0, len(item) - 1)
            if kind is dict:
                for key, child in item.items():
                    if type(key) is not str:
                        raise JsonContractIntegrityError("JSON object keys must be exact strings")
                    minimum_bytes += len(key) + 3
                    pending.append((child, depth + 1, False))
            else:
                pending.extend((child, depth + 1, False) for child in item)
        elif kind is str:
            minimum_bytes += len(item) + 2
        elif kind is int:
            if item.bit_length() > max_bytes * 4:
                raise JsonContractIntegrityError("JSON integer exceeds the byte limit")
            minimum_bytes += 1
        elif kind is float:
            if not math.isfinite(item):
                raise JsonContractIntegrityError("JSON numbers must be finite")
            minimum_bytes += 1
        elif kind is bool:
            minimum_bytes += 4 if item else 5
        elif item is None:
            minimum_bytes += 4
        else:
            raise JsonContractIntegrityError("JSON contains a non-primitive Python value")
        if minimum_bytes > max_bytes:
            raise JsonContractIntegrityError("JSON byte limit exceeded")
    try:
        encoded = json.dumps(
            value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
            allow_nan=False,
        ).encode("ascii")
    except (TypeError, ValueError, OverflowError, RecursionError) as exc:
        raise JsonContractIntegrityError("JSON cannot be canonically serialized") from exc
    if len(encoded) > max_bytes:
        raise JsonContractIntegrityError("JSON byte limit exceeded")
    return encoded
