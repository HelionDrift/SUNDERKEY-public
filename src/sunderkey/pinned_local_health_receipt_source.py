"""Read explicit, digest-pinned local target-health receipt files once."""

from __future__ import annotations

import ctypes
import hashlib
import json
import os
import re
import stat
from dataclasses import dataclass
from pathlib import Path

from .target_health_capture import MAX_DOCUMENT_BYTES, MAX_SOURCE_CALLS

_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
MAX_RELATIVE_PATH_BYTES = 240
MAX_MANIFEST_BYTES = 65_536
_WINDOWS_RESERVED = frozenset(
    {"CON", "PRN", "AUX", "NUL"}
    | {f"COM{index}" for index in range(1, 10)}
    | {f"LPT{index}" for index in range(1, 10)}
)


class PinnedLocalHealthReceiptSourceError(ValueError):
    """The explicit local source, pin, or file bytes were refused."""


def _is_redirect(path: Path) -> bool:
    junction_check = getattr(path, "is_junction", None)
    return path.is_symlink() or (junction_check is not None and junction_check())


@dataclass(frozen=True, slots=True)
class LocalHealthReceiptPin:
    """One caller-supplied filename and expected raw-byte digest."""

    relative_path: str
    sha256: str

    def __post_init__(self) -> None:
        path = self.relative_path
        if (
            type(path) is not str
            or not path
            or len(path.encode("utf-8", errors="surrogatepass")) > MAX_RELATIVE_PATH_BYTES
            or path.startswith("/")
            or "\\" in path
            or ":" in path
            or "\x00" in path
            or any(segment in ("", ".", "..") for segment in path.split("/"))
            or any(
                not segment.isascii() or not segment.isprintable() for segment in path.split("/")
            )
            or any(
                segment.endswith((".", " "))
                or segment.upper().split(".", 1)[0].rstrip(" ") in _WINDOWS_RESERVED
                or any(character in '<>"|?*' for character in segment)
                for segment in path.split("/")
            )
        ):
            raise PinnedLocalHealthReceiptSourceError("Relative file path is invalid")
        if type(self.sha256) is not str or _DIGEST.fullmatch(self.sha256) is None:
            raise PinnedLocalHealthReceiptSourceError("Raw-byte digest pin is invalid")


def parse_local_health_receipt_manifest(raw: bytes) -> tuple[LocalHealthReceiptPin, ...]:
    """Parse a closed, untrusted pin list without reading files or selecting a root."""
    if type(raw) is not bytes or not 1 <= len(raw) <= MAX_MANIFEST_BYTES:
        raise PinnedLocalHealthReceiptSourceError("Manifest byte bound is invalid")

    def object_pairs(pairs: list[tuple[str, object]]) -> dict:
        result = {}
        for key, value in pairs:
            if key in result:
                raise PinnedLocalHealthReceiptSourceError("Duplicate manifest field refused")
            result[key] = value
        return result

    def reject_number(value: str) -> None:
        raise PinnedLocalHealthReceiptSourceError("Manifest floats are refused")

    try:
        document = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=object_pairs,
            parse_float=reject_number,
            parse_constant=reject_number,
        )
    except PinnedLocalHealthReceiptSourceError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError, ValueError) as exc:
        raise PinnedLocalHealthReceiptSourceError("Manifest JSON is invalid") from exc
    if type(document) is not dict or document.keys() != {"schema_version", "pins"}:
        raise PinnedLocalHealthReceiptSourceError("Manifest fields are invalid")
    if type(document["schema_version"]) is not int or document["schema_version"] != 1:
        raise PinnedLocalHealthReceiptSourceError("Manifest schema version is invalid")
    entries = document["pins"]
    if type(entries) is not list or not 1 <= len(entries) <= MAX_SOURCE_CALLS:
        raise PinnedLocalHealthReceiptSourceError("Manifest pin count is invalid")
    pins = []
    for entry in entries:
        if type(entry) is not dict or entry.keys() != {"relative_path", "sha256"}:
            raise PinnedLocalHealthReceiptSourceError("Manifest pin fields are invalid")
        pins.append(LocalHealthReceiptPin(entry["relative_path"], entry["sha256"]))
    folded = [pin.relative_path.casefold() for pin in pins]
    if len(set(folded)) != len(folded):
        raise PinnedLocalHealthReceiptSourceError("Duplicate local file paths refused")
    return tuple(pins)


class PinnedLocalHealthReceiptSource:
    """One-pass local source for the injected target-health capture port.

    The caller owns the directory and authenticates the pin list separately.
    No directory enumeration, polling, network request, deletion, or retry occurs.
    """

    def __init__(self, *, root: str | Path, pins: tuple[LocalHealthReceiptPin, ...]) -> None:
        if not isinstance(root, (str, Path)):
            raise PinnedLocalHealthReceiptSourceError("Explicit local root is required")
        candidate = Path(root)
        if not candidate.is_absolute():
            raise PinnedLocalHealthReceiptSourceError("Local root must be absolute")
        self._check_local_root(candidate)
        try:
            resolved = candidate.resolve(strict=True)
        except (OSError, RuntimeError) as exc:
            raise PinnedLocalHealthReceiptSourceError("Local root is unavailable") from exc
        self._check_local_root(resolved)
        if not resolved.is_dir():
            raise PinnedLocalHealthReceiptSourceError("Local root must be a directory")
        if type(pins) is not tuple or not 1 <= len(pins) <= MAX_SOURCE_CALLS:
            raise PinnedLocalHealthReceiptSourceError("Explicit pin count is invalid")
        if any(type(pin) is not LocalHealthReceiptPin for pin in pins):
            raise PinnedLocalHealthReceiptSourceError("Exact native pin wrappers required")
        folded = [pin.relative_path.casefold() for pin in pins]
        if len(set(folded)) != len(folded):
            raise PinnedLocalHealthReceiptSourceError("Duplicate local file paths refused")
        self._root = resolved
        self._pins = pins
        self._next = 0
        self._failed = False

    @staticmethod
    def _check_local_root(root: Path) -> None:
        if str(root).startswith(("//", "\\\\")):
            raise PinnedLocalHealthReceiptSourceError("UNC root is not local")
        current = Path(root.anchor)
        for segment in root.parts[1:]:
            current = current / segment
            if _is_redirect(current):
                raise PinnedLocalHealthReceiptSourceError("Root redirect is not local")
        if os.name == "nt":
            drive_type = ctypes.windll.kernel32.GetDriveTypeW(str(root.anchor))
            if drive_type not in (2, 3, 6):
                raise PinnedLocalHealthReceiptSourceError("Root is not a known local drive")

    def read_receipt(self, *, maximum_bytes: int) -> bytes | None:
        """Return exact pinned bytes, then advance; any failure is terminal."""
        if type(maximum_bytes) is not int or not 1 <= maximum_bytes <= MAX_DOCUMENT_BYTES:
            raise PinnedLocalHealthReceiptSourceError("Receipt byte limit is invalid")
        if self._failed:
            raise PinnedLocalHealthReceiptSourceError("Source is terminal after failure")
        if self._next == len(self._pins):
            return None
        pin = self._pins[self._next]
        self._failed = True
        candidate = self._root.joinpath(*pin.relative_path.split("/"))
        try:
            current = self._root
            for segment in pin.relative_path.split("/"):
                current = current / segment
                if _is_redirect(current):
                    raise PinnedLocalHealthReceiptSourceError("Redirected source path refused")
            resolved = candidate.resolve(strict=True)
            if not resolved.is_relative_to(self._root):
                raise PinnedLocalHealthReceiptSourceError("Source path escapes local root")
            if not stat.S_ISREG(candidate.stat().st_mode):
                raise PinnedLocalHealthReceiptSourceError("Receipt source is not a regular file")
            with candidate.open("rb") as stream:
                stat_result = os.fstat(stream.fileno())
                if not stat.S_ISREG(stat_result.st_mode):
                    raise PinnedLocalHealthReceiptSourceError(
                        "Receipt source is not a regular file"
                    )
                if stat_result.st_size > maximum_bytes:
                    raise PinnedLocalHealthReceiptSourceError("Receipt source exceeds byte limit")
                raw = stream.read(maximum_bytes + 1)
                second = os.fstat(stream.fileno())
        except PinnedLocalHealthReceiptSourceError:
            raise
        except (OSError, RuntimeError, ValueError) as exc:
            raise PinnedLocalHealthReceiptSourceError("Local source read failed") from exc
        if (
            not raw
            or len(raw) > maximum_bytes
            or stat_result.st_size != second.st_size
            or stat_result.st_mtime_ns != second.st_mtime_ns
        ):
            raise PinnedLocalHealthReceiptSourceError(
                "Local source was empty, oversized or changed"
            )
        digest = "sha256:" + hashlib.sha256(raw).hexdigest()
        if digest != pin.sha256:
            raise PinnedLocalHealthReceiptSourceError("Raw-byte digest pin mismatch")
        self._next += 1
        self._failed = False
        return raw


__all__ = [
    "LocalHealthReceiptPin",
    "PinnedLocalHealthReceiptSource",
    "PinnedLocalHealthReceiptSourceError",
    "parse_local_health_receipt_manifest",
]
