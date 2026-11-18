"""Explicit digest-pinned local receipt files satisfy the injected source port."""

from __future__ import annotations

import hashlib
import json
import socket
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from sunderkey.pinned_local_health_receipt_source import (
    LocalHealthReceiptPin,
    PinnedLocalHealthReceiptSource,
    PinnedLocalHealthReceiptSourceError,
    parse_local_health_receipt_manifest,
)
from sunderkey.target_adapter_conformance import AdapterStopState
from sunderkey.target_health_capture import capture_target_health_receipts
from sunderkey.target_health_custody import SQLiteTargetHealthCustody
from tests.agents import test_target_health_custody_phase198 as phase198
from tests.agents.test_target_health_capture import CustodyPort, EnvelopeSigner, receipt_bytes


def _pin(path: str, raw: bytes) -> LocalHealthReceiptPin:
    return LocalHealthReceiptPin(path, "sha256:" + hashlib.sha256(raw).hexdigest())


class PinnedLocalHealthReceiptSourceTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)

    def test_exact_pinned_bytes_are_read_once_without_file_mutation(self):
        first = b'{"receipt":"first"}'
        second = b'{"receipt":"second"}'
        (self.root / "first.json").write_bytes(first)
        (self.root / "second.json").write_bytes(second)
        source = PinnedLocalHealthReceiptSource(
            root=self.root, pins=(_pin("first.json", first), _pin("second.json", second))
        )
        with patch.object(socket, "create_connection", side_effect=AssertionError("network")):
            self.assertEqual(source.read_receipt(maximum_bytes=64), first)
            self.assertEqual(source.read_receipt(maximum_bytes=64), second)
            self.assertIsNone(source.read_receipt(maximum_bytes=64))
            self.assertIsNone(source.read_receipt(maximum_bytes=64))
        self.assertEqual((self.root / "first.json").read_bytes(), first)
        self.assertEqual((self.root / "second.json").read_bytes(), second)

    def test_bounded_closed_manifest_parses_pins_without_choosing_root(self):
        digest = _pin("first.json", b"receipt").sha256
        manifest = json.dumps(
            {
                "schema_version": 1,
                "pins": [{"relative_path": "first.json", "sha256": digest}],
            },
            separators=(",", ":"),
        ).encode("utf-8")
        self.assertEqual(
            parse_local_health_receipt_manifest(manifest),
            (_pin("first.json", b"receipt"),),
        )
        for invalid in (
            b'{"schema_version":1,"pins":[],"pins":[]}',
            b'{"schema_version":true,"pins":[]}',
            b'{"schema_version":1.0,"pins":[]}',
            b'{"schema_version":1,"pins":[],"root":"/"}',
            b"\xff",
            b" " * 65_537,
        ):
            with (
                self.subTest(invalid=invalid[:60]),
                self.assertRaises(PinnedLocalHealthReceiptSourceError),
            ):
                parse_local_health_receipt_manifest(invalid)
        duplicate = json.dumps(
            {
                "schema_version": 1,
                "pins": [
                    {"relative_path": "first.json", "sha256": digest},
                    {"relative_path": "FIRST.json", "sha256": digest},
                ],
            }
        ).encode("utf-8")
        with self.assertRaises(PinnedLocalHealthReceiptSourceError):
            parse_local_health_receipt_manifest(duplicate)

    def test_paths_and_pin_list_are_closed_before_file_read(self):
        raw = b"receipt"
        for path in (
            "../out",
            "/absolute",
            "sub\\file",
            "sub//file",
            "sub/./file",
            "a:b",
            "CON.txt",
            "report.json.",
            "name?.json",
        ):
            with self.subTest(path=path), self.assertRaises(PinnedLocalHealthReceiptSourceError):
                _pin(path, raw)
        pin = _pin("item.json", raw)
        with self.assertRaises(PinnedLocalHealthReceiptSourceError):
            PinnedLocalHealthReceiptSource(root=Path("relative"), pins=(pin,))
        with self.assertRaises(PinnedLocalHealthReceiptSourceError):
            PinnedLocalHealthReceiptSource(root="//server/share", pins=(pin,))
        with self.assertRaises(PinnedLocalHealthReceiptSourceError):
            PinnedLocalHealthReceiptSource(root=self.root, pins=(pin, pin))
        with self.assertRaises(PinnedLocalHealthReceiptSourceError):
            PinnedLocalHealthReceiptSource(root=self.root, pins=())
        with self.assertRaises(PinnedLocalHealthReceiptSourceError):
            LocalHealthReceiptPin("item.json", "sha256:not-a-digest")

    def test_mismatch_and_oversize_fail_terminal_without_next_file(self):
        first = b"first"
        second = b"second"
        (self.root / "first.json").write_bytes(first)
        (self.root / "second.json").write_bytes(second)
        source = PinnedLocalHealthReceiptSource(
            root=self.root,
            pins=(_pin("first.json", b"different"), _pin("second.json", second)),
        )
        with self.assertRaisesRegex(PinnedLocalHealthReceiptSourceError, "pin mismatch"):
            source.read_receipt(maximum_bytes=64)
        with self.assertRaisesRegex(PinnedLocalHealthReceiptSourceError, "terminal"):
            source.read_receipt(maximum_bytes=64)
        source = PinnedLocalHealthReceiptSource(root=self.root, pins=(_pin("first.json", first),))
        with self.assertRaisesRegex(PinnedLocalHealthReceiptSourceError, "byte limit"):
            source.read_receipt(maximum_bytes=2)
        with self.assertRaisesRegex(PinnedLocalHealthReceiptSourceError, "terminal"):
            source.read_receipt(maximum_bytes=64)
        self.assertEqual((self.root / "second.json").read_bytes(), second)

    def test_directory_and_symlink_are_refused(self):
        folder = self.root / "folder"
        folder.mkdir()
        source = PinnedLocalHealthReceiptSource(root=self.root, pins=(_pin("folder", b"content"),))
        with self.assertRaises(PinnedLocalHealthReceiptSourceError):
            source.read_receipt(maximum_bytes=64)
        target = self.root / "target.json"
        target.write_bytes(b"content")
        link = self.root / "link.json"
        try:
            link.symlink_to(target)
        except (OSError, NotImplementedError):
            return
        source = PinnedLocalHealthReceiptSource(
            root=self.root, pins=(_pin("link.json", b"content"),)
        )
        with self.assertRaisesRegex(PinnedLocalHealthReceiptSourceError, "Redirected"):
            source.read_receipt(maximum_bytes=64)

    def test_valid_receipt_composes_with_existing_signed_custody(self):
        factory = phase198.ContractFactory()
        clock = phase198.FixedClock("2026-09-21T12:00:10Z")
        policy = factory.make_policy()
        store = SQLiteTargetHealthCustody(
            self.root / "custody.sqlite3", trust_root=factory.root, trusted_clock=clock
        )
        store.publish_policy(policy)
        receipt = factory.make_receipt(observed_at="2026-09-21T12:00:05Z", monotonic_tick=10)
        raw = receipt_bytes(receipt)
        (self.root / "receipt.json").write_bytes(raw)
        source = PinnedLocalHealthReceiptSource(root=self.root, pins=(_pin("receipt.json", raw),))
        with patch.object(socket, "create_connection", side_effect=AssertionError("network")):
            result = capture_target_health_receipts(
                trust_root=factory.root,
                policy=policy,
                source=source,
                signer=EnvelopeSigner(factory.collector_keys[1]),
                custody=CustodyPort(store),
                stop_state=AdapterStopState(),
                clock=clock,
                maximum_source_calls=3,
                maximum_receipt_bytes=65536,
                maximum_total_bytes=131072,
                deadline=phase198.instant("2026-09-21T12:01:00Z"),
            )
        self.assertEqual(result.reason, "source_exhausted")
        self.assertEqual(len(result.publications), 1)
        self.assertEqual(result.publications[0].envelope.receipt.to_dict(), receipt.to_dict())
        self.assertEqual(result.source_calls, 2)
        self.assertFalse(result.to_dict()["network_call_performed"])

    def test_mismatched_file_pin_cannot_reach_signing_or_append(self):
        factory = phase198.ContractFactory()
        clock = phase198.FixedClock("2026-09-21T12:00:10Z")
        policy = factory.make_policy()
        store = SQLiteTargetHealthCustody(
            self.root / "custody.sqlite3", trust_root=factory.root, trusted_clock=clock
        )
        store.publish_policy(policy)
        receipt = factory.make_receipt(observed_at="2026-09-21T12:00:05Z", monotonic_tick=10)
        raw = receipt_bytes(receipt)
        (self.root / "receipt.json").write_bytes(raw)
        source = PinnedLocalHealthReceiptSource(
            root=self.root, pins=(_pin("receipt.json", b"different"),)
        )
        signer = EnvelopeSigner(factory.collector_keys[1])
        custody = CustodyPort(store)
        result = capture_target_health_receipts(
            trust_root=factory.root,
            policy=policy,
            source=source,
            signer=signer,
            custody=custody,
            stop_state=AdapterStopState(),
            clock=clock,
            maximum_source_calls=3,
            maximum_receipt_bytes=65536,
            maximum_total_bytes=131072,
            deadline=phase198.instant("2026-09-21T12:01:00Z"),
        )
        self.assertEqual(result.reason, "source_failed")
        self.assertEqual(result.publications, ())
        self.assertEqual(signer.calls, [])
        self.assertEqual(custody.envelopes, [])


if __name__ == "__main__":
    unittest.main()
