"""Repository text checks for prohibited punctuation and invisible controls."""

from __future__ import annotations

import re
import subprocess
import unicodedata
import zipfile
from dataclasses import dataclass
from pathlib import Path
from xml.etree import ElementTree

from .errors import ContentPolicyError

TEXT_SUFFIXES = {
    ".json",
    ".jsonl",
    ".md",
    ".py",
    ".sh",
    ".toml",
    ".txt",
    ".yaml",
    ".yml",
}

FORBIDDEN_CODE_POINTS = {
    0x2014: "em dash",
    0x202A: "bidirectional embedding",
    0x202B: "bidirectional embedding",
    0x202C: "bidirectional formatting",
    0x202D: "bidirectional override",
    0x202E: "bidirectional override",
    0x2066: "bidirectional isolate",
    0x2067: "bidirectional isolate",
    0x2068: "bidirectional isolate",
    0x2069: "bidirectional isolate",
    0xFEFF: "byte order mark",
}

CORE_PROPERTY_TAGS = {
    "{http://purl.org/dc/elements/1.1/}creator": "document creator metadata",
    "{http://schemas.openxmlformats.org/package/2006/metadata/core-properties}"
    "lastModifiedBy": "last-modified-by metadata",
}


@dataclass(frozen=True)
class ContentFinding:
    path: Path
    line: int
    column: int
    code_point: int
    reason: str

    def render(self, root: Path) -> str:
        try:
            display_path = self.path.relative_to(root)
        except ValueError:
            display_path = self.path
        if self.code_point == 0:
            return f"{display_path}:{self.line}:{self.column}: {self.reason}"
        return f"{display_path}:{self.line}:{self.column}: U+{self.code_point:04X} {self.reason}"


def scan_text(path: Path, text: str) -> list[ContentFinding]:
    findings: list[ContentFinding] = []
    line = 1
    column = 1
    for character in text:
        code_point = ord(character)
        reason = FORBIDDEN_CODE_POINTS.get(code_point)
        if reason is None and unicodedata.category(character) == "Cf":
            reason = "invisible format control"
        if reason is not None:
            findings.append(
                ContentFinding(
                    path=path,
                    line=line,
                    column=column,
                    code_point=code_point,
                    reason=reason,
                )
            )
        if character == "\n":
            line += 1
            column = 1
        else:
            column += 1
    return findings


def scan_file(path: Path) -> list[ContentFinding]:
    if path.name.startswith("~$") and path.suffix.lower() == ".docx":
        return [
            ContentFinding(
                path=path,
                line=1,
                column=1,
                code_point=0,
                reason="Office lock file",
            )
        ]
    if path.suffix.lower() == ".docx":
        return scan_docx(path)
    if path.suffix.lower() not in TEXT_SUFFIXES:
        return []
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise ContentPolicyError(f"Could not read text file: {path}") from exc
    return scan_text(path, text)


def scan_docx(path: Path) -> list[ContentFinding]:
    findings: list[ContentFinding] = []
    try:
        with zipfile.ZipFile(path) as archive:
            members = sorted(
                name
                for name in archive.namelist()
                if name.endswith(".xml") or name.endswith(".rels")
            )
            for member in members:
                try:
                    text = archive.read(member).decode("utf-8")
                except UnicodeDecodeError as exc:
                    raise ContentPolicyError(
                        f"Could not decode document XML: {path}!{member}"
                    ) from exc
                findings.extend(scan_text(path, text))
                hidden_markers = {
                    "<w:vanish": "hidden Word text",
                    "<w:webHidden": "web-hidden Word text",
                    "<v:textpath": "VML text path or watermark",
                }
                for marker, reason in hidden_markers.items():
                    if marker in text:
                        findings.append(
                            ContentFinding(
                                path=path,
                                line=1,
                                column=1,
                                code_point=0,
                                reason=f"{reason} in {member}",
                            )
                        )
                tracked_markers = {
                    "ins": "tracked Word insertion",
                    "del": "tracked Word deletion",
                }
                for element_name, reason in tracked_markers.items():
                    if re.search(
                        rf"<w:{element_name}(?:\s|>)",
                        text,
                    ):
                        findings.append(
                            ContentFinding(
                                path=path,
                                line=1,
                                column=1,
                                code_point=0,
                                reason=f"{reason} in {member}",
                            )
                        )
                if member.startswith("word/comments"):
                    findings.append(
                        ContentFinding(
                            path=path,
                            line=1,
                            column=1,
                            code_point=0,
                            reason=f"Word comments part in {member}",
                        )
                    )
                if member == "docProps/custom.xml":
                    findings.append(
                        ContentFinding(
                            path=path,
                            line=1,
                            column=1,
                            code_point=0,
                            reason="custom document properties",
                        )
                    )
                if member == "docProps/core.xml":
                    try:
                        root = ElementTree.fromstring(text)
                    except ElementTree.ParseError as exc:
                        raise ContentPolicyError(
                            f"Could not parse document core properties: {path}"
                        ) from exc
                    for tag, reason in CORE_PROPERTY_TAGS.items():
                        element = root.find(tag)
                        if (
                            element is not None
                            and element.text is not None
                            and element.text.strip()
                        ):
                            findings.append(
                                ContentFinding(
                                    path=path,
                                    line=1,
                                    column=1,
                                    code_point=0,
                                    reason=reason,
                                )
                            )
    except (OSError, zipfile.BadZipFile) as exc:
        raise ContentPolicyError(f"Could not read Word document: {path}") from exc
    return findings


def discover_repository_files(root: str | Path) -> tuple[Path, ...]:
    repository_root = Path(root).resolve()
    command = [
        "git",
        "ls-files",
        "--cached",
        "--others",
        "--exclude-standard",
        "-z",
    ]
    result = subprocess.run(
        command,
        cwd=repository_root,
        check=False,
        capture_output=True,
    )
    if result.returncode != 0:
        message = result.stderr.decode("utf-8", errors="replace").strip()
        raise ContentPolicyError(f"Could not list repository files: {message}")
    return tuple(
        repository_root / item.decode("utf-8") for item in result.stdout.split(b"\0") if item
    )


def scan_repository(root: str | Path) -> tuple[ContentFinding, ...]:
    repository_root = Path(root).resolve()
    findings: list[ContentFinding] = []
    for path in discover_repository_files(repository_root):
        if path.is_file():
            findings.extend(scan_file(path))
    return tuple(findings)


def require_clean_repository_text(root: str | Path) -> None:
    repository_root = Path(root).resolve()
    findings = scan_repository(repository_root)
    if findings:
        details = "\n".join(finding.render(repository_root) for finding in findings)
        raise ContentPolicyError(f"Repository content policy failed:\n{details}")
