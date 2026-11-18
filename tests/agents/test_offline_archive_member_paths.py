"""Archive member path projections do not perform or prove extraction."""

from __future__ import annotations

import copy
import unittest
from pathlib import Path

from sunderkey import offline_specialist_components as components
from sunderkey.offline_archive_member_paths import (
    ArchiveMemberPathError,
    ArchiveMemberPaths,
    analyze_supplied_archive_member_paths,
    verify_supplied_archive_member_paths,
)

ROOT = Path(__file__).resolve().parents[2]


def _entry(entry_id: str, name: str, kind: str = "file") -> dict:
    return {"entry_id": entry_id, "member_name": name, "kind": kind}


def model(profile: str = "posix-lexical-v1") -> dict:
    return {
        "schema_version": 1,
        "semantics_profile": "supplied-archive-member-paths-v1",
        "extraction_profile": profile,
        "root_ref": "root:sha256:" + "a" * 64,
        "entries": [
            _entry("safe", "docs/readme.txt"),
            _entry("collision", "docs/./readme.txt"),
            _entry("parent", "../other.txt"),
            _entry("absolute", "/root.txt"),
            _entry("link", "links/current", "symlink"),
            _entry("encoded", "%2e%2e/item.txt"),
            _entry("contained", "a/../b.txt"),
        ],
    }


class ArchiveMemberPathTests(unittest.TestCase):
    def test_posix_projection_and_replay(self) -> None:
        source = model()
        original = copy.deepcopy(source)
        report = analyze_supplied_archive_member_paths(source)
        self.assertEqual(source, original)
        findings = report.to_dict()["findings"]
        self.assertEqual(
            [row["disposition"] for row in findings],
            [
                "declared_destination_collision_candidate",
                "declared_destination_collision_candidate",
                "declared_parent_escape",
                "declared_absolute_member",
                "unknown_symlink_target",
                "unknown_name_transform",
                "lexically_contained",
            ],
        )
        self.assertEqual(findings[0]["collision_with_entry_ids"], ["collision"])
        self.assertEqual(findings[6]["normalized_segments"], ["b.txt"])
        self.assertFalse(report.to_dict()["flags"]["escape_or_overwrite_proven"])
        self.assertEqual(set(report.to_dict()["operational_effects"].values()), {"none"})
        self.assertEqual(
            verify_supplied_archive_member_paths(report, model=source).to_json(),
            report.to_json(),
        )

    def test_windows_specific_ambiguity_and_casefold_candidate(self) -> None:
        source = model("windows-lexical-v1")
        source["entries"] = [
            _entry("drive", "C:\\temp\\file.txt"),
            _entry("rooted", "\\\\server\\share\\file.txt"),
            _entry("parent", "..\\file.txt"),
            _entry("first", "Dir\\Report.txt"),
            _entry("second", "dir/report.TXT"),
            _entry("device", "aux.txt"),
            _entry("trailing", "data\\file. "),
        ]
        findings = analyze_supplied_archive_member_paths(source).to_dict()["findings"]
        self.assertEqual(
            [row["disposition"] for row in findings],
            [
                "declared_drive_prefix",
                "declared_absolute_member",
                "declared_parent_escape",
                "declared_destination_collision_candidate",
                "declared_destination_collision_candidate",
                "unknown_name_transform",
                "unknown_name_transform",
            ],
        )
        self.assertEqual(findings[3]["collision_with_entry_ids"], ["second"])

    def test_invalid_and_tampered_models_refused(self) -> None:
        source = model()
        source["entries"][1]["entry_id"] = "safe"
        with self.assertRaises(ArchiveMemberPathError):
            analyze_supplied_archive_member_paths(source)
        source = model()
        source["entries"][0]["member_name"] = "bad\x00name"
        with self.assertRaises(ArchiveMemberPathError):
            analyze_supplied_archive_member_paths(source)
        source = model()
        source["entries"][0]["kind"] = object()
        with self.assertRaises(ArchiveMemberPathError):
            analyze_supplied_archive_member_paths(source)
        source = model()
        report = analyze_supplied_archive_member_paths(source)
        tampered = report.to_dict()
        tampered["flags"]["escape_or_overwrite_proven"] = True
        with self.assertRaises(ArchiveMemberPathError):
            ArchiveMemberPaths(tampered)
        source["entries"][0]["member_name"] = "different.txt"
        with self.assertRaises(ArchiveMemberPathError):
            verify_supplied_archive_member_paths(report, model=source)

    def test_closed_component_dispatch_and_resource_denial(self) -> None:
        request = components.load_offline_specialist_component_request(
            ROOT / "examples" / "offline-archive-member-paths-component.json"
        )
        catalog = components.load_offline_specialist_component_catalog(repository_root=ROOT)
        result = components.run_offline_specialist_component(
            request, catalog=catalog, repository_root=ROOT
        )
        self.assertEqual(
            result["analysis"]["findings"][0]["disposition"],
            "declared_parent_escape",
        )
        self.assertFalse(result["positive_use_approved"])
        self.assertEqual(
            components.verify_offline_specialist_component_result(
                result, request=request, catalog=catalog, repository_root=ROOT
            ),
            result,
        )
        request["resources"]["filesystem"] = ["forbidden"]
        with self.assertRaises(components.OfflineSpecialistComponentError):
            components.run_offline_specialist_component(
                request, catalog=catalog, repository_root=ROOT
            )


if __name__ == "__main__":
    unittest.main()
