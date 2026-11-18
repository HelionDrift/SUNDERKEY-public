"""Independent octet, extent, sender-observation and replay controls for PDVs."""

from __future__ import annotations

import base64
import copy
import hashlib
import itertools
import json
import unittest
from unittest.mock import patch

from sunderkey import offline_dicom_pdv_analysis as dicom

ERROR = dicom.DicomPdvError


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def wire_item(context=1, control=1, fragment=b"AB", *, item_length=None):
    contents = bytes((context, control)) + fragment
    length = len(contents) if item_length is None else item_length
    return length.to_bytes(4, "big") + contents


def wire_pdu(*items, reserved=0, payload_length=None):
    payload = b"".join(items)
    length = len(payload) if payload_length is None else payload_length
    return bytes((4, reserved)) + length.to_bytes(4, "big") + payload


def source(raw, *, source_id="synthetic-independent"):
    return {
        "schema_version": 1,
        "source_id": source_id,
        "pdu_base64": base64.b64encode(raw).decode("ascii"),
    }


def readdress(document):
    body = copy.deepcopy(document)
    body.pop("analysis_id")
    body.pop("analysis_sha256")
    digest = hashlib.sha256((dicom.DOMAIN + "\n" + canonical(body)).encode("ascii")).hexdigest()
    return {
        **body,
        "analysis_id": "DPV-" + digest[:32].upper(),
        "analysis_sha256": "sha256:" + digest,
    }


class DicomPdvTests(unittest.TestCase):
    def before_hash(self, operation):
        with patch.object(dicom.hashlib, "sha256") as digest:
            with self.assertRaises(ERROR):
                operation()
            digest.assert_not_called()

    def test_literal_synthetic_fixture_identity_and_offsets(self):
        report = dicom.analyze_supplied_dicom_pdv(dicom.component_fixture()).to_dict()
        self.assertEqual(report["analysis_id"], "DPV-620C558446BDE998DC57C80CE6A4A5EA")
        self.assertEqual(
            report["analysis_sha256"],
            "sha256:620c558446bde998dc57c80ce6a4a5ea8147e1baef6ef785e56ed1707a1b6508",
        )
        self.assertEqual(
            report["source_model_sha256"],
            "sha256:da8c8de1eb6a6cc417d75dd16723b29e66c3557baacbb4e4bba58ff4b9730227",
        )
        self.assertEqual(
            report["source_pdu_sha256"],
            "sha256:b90eb598538f360ce14afab160bfb7d58e8ad50c306fd3bddf797eb6fac0716c",
        )
        self.assertEqual(report["analysis_status"], "bounded_structure_observed")
        self.assertEqual(
            report["pdu_header"],
            {
                "pdu_type": 4,
                "reserved_byte": 0,
                "declared_payload_length": 16,
                "actual_pdu_bytes": 22,
                "pdv_count": 2,
            },
        )
        self.assertEqual(
            [
                (row["item_start"], row["item_end"], row["fragment_start"], row["fragment_end"])
                for row in report["pdv_items"]
            ],
            [(6, 14, 12, 14), (14, 22, 20, 22)],
        )
        self.assertEqual(
            [row["fragment_kind"] for row in report["pdv_items"]], ["command", "data_set"]
        )
        self.assertEqual([row["last_fragment"] for row in report["pdv_items"]], [False, True])
        self.assertEqual(report["sender_deviation_observations"], [])
        self.assertTrue(report["flags"]["offline_only"])
        self.assertFalse(report["flags"]["patient_content_interpreted"])
        self.assertEqual(set(report["effects"].values()), {"none"})

    def test_all_public_roundtrips_and_separate_original(self):
        original = dicom.component_fixture()
        retained = copy.deepcopy(original)
        report = dicom.analyze_supplied_dicom_pdv(original)
        text = report.to_json()
        document = report.to_dict()
        operations = (
            lambda: dicom.DicomPdvAnalysis(text),
            lambda: dicom.DicomPdvAnalysis.from_dict(document),
            lambda: dicom.DicomPdvAnalysis.from_json(text),
            lambda: dicom.analyze_supplied_dicom_pdv_bytes(
                model_bytes=canonical(original).encode("ascii")
            ),
            lambda: dicom.verify_supplied_dicom_pdv_analysis(report, model=original),
        )
        for operation in operations:
            self.assertEqual(operation().to_json(), text)
        self.assertEqual(report.analysis_id, document["analysis_id"])
        self.assertEqual(report.analysis_sha256, document["analysis_sha256"])
        original["source_id"] = "changed"
        document["pdv_items"].clear()
        self.assertEqual(report.to_json(), text)
        self.assertEqual(report.to_dict()["source_model"], retained)

    def test_independent_octet_matrix_preserves_controls_and_extents(self):
        count = 0
        for context, control, fragment_size, reserved in itertools.product(
            (0, 1, 2, 3, 255), (0, 1, 2, 3, 4, 0xFF), range(25), (0, 0xA5)
        ):
            fragment = b"X" * fragment_size
            raw = wire_pdu(wire_item(context, control, fragment), reserved=reserved)
            document = dicom.analyze_supplied_dicom_pdv(source(raw)).to_dict()
            row = document["pdv_items"][0]
            self.assertEqual(row["presentation_context_id"], context)
            self.assertEqual(row["control_byte"], control)
            self.assertEqual(row["item_start"], 6)
            self.assertEqual(row["item_end"], len(raw))
            self.assertEqual(row["fragment_start"], 12)
            self.assertEqual(row["fragment_end"], len(raw))
            self.assertEqual(row["fragment_bytes"], fragment_size)
            self.assertEqual(row["fragment_kind"], "command" if control & 1 else "data_set")
            self.assertIs(row["last_fragment"], bool(control & 2))
            self.assertEqual(row["control_reserved_bits"], control & 0xFC)
            expected_deviation = bool(
                reserved
                or context == 0
                or context % 2 == 0
                or control & 0xFC
                or fragment_size == 0
                or fragment_size % 2
            )
            self.assertEqual(
                document["analysis_status"] == "sender_deviations_observed",
                expected_deviation,
            )
            count += 1
        self.assertEqual(count, 1500)

    def test_receiver_ignored_reserved_values_are_observed_not_refused(self):
        raw = wire_pdu(wire_item(1, 0xFD, b"AB"), reserved=0xC1)
        report = dicom.analyze_supplied_dicom_pdv(source(raw)).to_dict()
        self.assertEqual(report["pdu_header"]["reserved_byte"], 0xC1)
        self.assertEqual(report["pdv_items"][0]["control_reserved_bits"], 0xFC)
        self.assertIn(
            "pdu_reserved_byte_nonzero_sender_observation", report["sender_deviation_observations"]
        )
        self.assertIn(
            "control_reserved_bits_nonzero_sender_observation",
            report["sender_deviation_observations"],
        )

    def test_context_and_fragment_sender_deviations_are_retained(self):
        raw = wire_pdu(wire_item(2, 1, b"A"), wire_item(3, 2, b""))
        row = dicom.analyze_supplied_dicom_pdv(source(raw)).to_dict()
        reasons = row["sender_deviation_observations"]
        self.assertIn("even_or_zero_presentation_context_id_sender_observation", reasons)
        self.assertIn("odd_fragment_byte_count_sender_observation", reasons)
        self.assertIn("empty_fragment_sender_observation", reasons)
        self.assertIn("mixed_context_ids_sender_observation", reasons)
        self.assertFalse(row["flags"]["association_state_verified"])

    def test_multiple_same_context_items_and_one_item_are_supported(self):
        for items in (
            (wire_item(1, 1, b"AB"),),
            (wire_item(1, 1, b"AB"), wire_item(1, 1, b"CD")),
        ):
            row = dicom.analyze_supplied_dicom_pdv(source(wire_pdu(*items))).to_dict()
            self.assertEqual(row["pdu_header"]["pdv_count"], len(items))
            self.assertEqual(row["analysis_status"], "bounded_structure_observed")

    def test_pdu_type_and_header_extents_refuse_before_digest(self):
        for raw in (
            b"",
            b"\x04",
            b"\x05\x00\x00\x00\x00\x00" + wire_item(),
            wire_pdu(),
            wire_pdu(wire_item(), payload_length=7),
            wire_pdu(wire_item(), payload_length=9),
            wire_pdu(wire_item()) + b"\x00",
        ):
            self.before_hash(lambda raw=raw: dicom.analyze_supplied_dicom_pdv(source(raw)))

    def test_item_length_and_control_extents_refuse_before_digest(self):
        for raw in (
            wire_pdu(b"\x00"),
            wire_pdu(b"\x00\x00\x00\x00"),
            wire_pdu(b"\x00\x00\x00\x01\x01"),
            wire_pdu(wire_item(item_length=1)),
            wire_pdu(wire_item(item_length=100)),
            wire_pdu(wire_item() + b"\x00"),
        ):
            self.before_hash(lambda raw=raw: dicom.analyze_supplied_dicom_pdv(source(raw)))

    def test_big_endian_length_not_little_endian_or_unscoped_suffix(self):
        first = wire_item(1, 1, b"AB")
        pdu = wire_pdu(first)
        self.assertEqual(int.from_bytes(pdu[2:6], "big"), len(pdu) - 6)
        for raw in (
            pdu[:2] + pdu[2:6][::-1] + pdu[6:],
            pdu[:6] + pdu[6:10][::-1] + pdu[10:],
            pdu + first,
        ):
            self.before_hash(lambda raw=raw: dicom.analyze_supplied_dicom_pdv(source(raw)))

    def test_128_pdv_true_limit_and_129_denial(self):
        item = wire_item(1, 3, b"AB")
        accepted = wire_pdu(*([item] * 128))
        self.assertEqual(
            dicom.analyze_supplied_dicom_pdv(source(accepted)).to_dict()["pdu_header"]["pdv_count"],
            128,
        )
        self.before_hash(
            lambda: dicom.analyze_supplied_dicom_pdv(source(wire_pdu(*([item] * 129))))
        )

    def test_true_pdu_byte_limit_and_one_over(self):
        fragment = b"X" * (dicom.MAX_PDU_BYTES - 12)
        accepted = wire_pdu(wire_item(1, 3, fragment))
        self.assertEqual(len(accepted), dicom.MAX_PDU_BYTES)
        self.assertEqual(
            dicom.analyze_supplied_dicom_pdv(source(accepted)).to_dict()["pdu_header"][
                "actual_pdu_bytes"
            ],
            dicom.MAX_PDU_BYTES,
        )
        self.before_hash(lambda: dicom.analyze_supplied_dicom_pdv(source(accepted + b"X")))

    def test_base64_native_aliases_and_invalid_octets_deny_pre_hash(self):
        fixture = dicom.component_fixture()
        for encoding in ("!", fixture["pdu_base64"] + "=", fixture["pdu_base64"][:-1]):
            bad = {**fixture, "pdu_base64": encoding}
            self.before_hash(lambda bad=bad: dicom.analyze_supplied_dicom_pdv(bad))

        class Text(str):
            pass

        for changed in (
            {**fixture, "schema_version": True},
            {**fixture, "schema_version": 1.0},
            {**fixture, "source_id": Text("synthetic")},
            {**fixture, "pdu_base64": Text(fixture["pdu_base64"])},
            {**fixture, "extra": 1},
        ):
            self.before_hash(lambda changed=changed: dicom.analyze_supplied_dicom_pdv(changed))

    def test_cyclic_source_and_non_native_bytes_refuse(self):
        cyclic = dicom.component_fixture()
        cyclic["extra"] = cyclic
        self.before_hash(lambda: dicom.analyze_supplied_dicom_pdv(cyclic))
        raw = canonical(dicom.component_fixture()).encode("ascii")

        class Bytes(bytes):
            pass

        for supplied in (bytearray(raw), memoryview(raw), Bytes(raw)):
            self.before_hash(
                lambda supplied=supplied: dicom.analyze_supplied_dicom_pdv_bytes(
                    model_bytes=supplied
                )
            )

    def test_raw_duplicate_float_integer_alias_and_depth_before_decoder(self):
        raw = canonical(dicom.component_fixture())
        for text in (
            raw.replace('"schema_version":1', '"schema_version":1,"schema_version":1', 1),
            raw.replace('"schema_version":1', '"schema_version":1.0', 1),
            raw.replace('"schema_version":1', '"schema_version":--1', 1),
            raw.replace('"schema_version":1', '"schema_version":9223372036854775808', 1),
        ):
            self.before_hash(
                lambda text=text: dicom.analyze_supplied_dicom_pdv_bytes(
                    model_bytes=text.encode("ascii")
                )
            )
        with patch.object(dicom.json, "loads") as decoder:
            self.before_hash(
                lambda: dicom.analyze_supplied_dicom_pdv_bytes(model_bytes=b"[" * 13 + b"]" * 13)
            )
            decoder.assert_not_called()

    def test_source_content_swap_and_separate_original_refusal(self):
        original = dicom.component_fixture()
        report = dicom.analyze_supplied_dicom_pdv(original)
        changed = source(wire_pdu(wire_item(1, 1, b"ZZ")), source_id=original["source_id"])
        other = dicom.analyze_supplied_dicom_pdv(changed)
        self.assertNotEqual(report.analysis_id, other.analysis_id)
        self.assertEqual(
            dicom.DicomPdvAnalysis.from_json(other.to_json()).to_json(), other.to_json()
        )
        with self.assertRaises(ERROR):
            dicom.verify_supplied_dicom_pdv_analysis(other, model=original)

    def test_cohashed_false_offsets_status_flags_and_effects_refuse(self):
        original = dicom.analyze_supplied_dicom_pdv(dicom.component_fixture()).to_dict()
        for field, replacement in (
            ("analysis_status", "sender_deviations_observed"),
            ("pdv_items", []),
            ("pdu_header", {**original["pdu_header"], "pdv_count": 1}),
            ("sender_deviation_observations", ["untrue"]),
            ("flags", {**original["flags"], "clinical_use_approved": True}),
            ("effects", {**original["effects"], "execution": "allow"}),
        ):
            forged = copy.deepcopy(original)
            forged[field] = replacement
            forged = readdress(forged)
            self.before_hash(lambda forged=forged: dicom.DicomPdvAnalysis.from_dict(forged))

    def test_late_native_wrapper_mutation_fails_closed(self):
        report = dicom.analyze_supplied_dicom_pdv(dicom.component_fixture())
        forged = object.__new__(dicom.DicomPdvAnalysis)
        object.__setattr__(
            forged, "document_json", report.to_json().replace("bounded_structure_observed", "allow")
        )
        self.before_hash(forged.to_dict)
        self.before_hash(
            lambda: dicom.verify_supplied_dicom_pdv_analysis(
                forged, model=dicom.component_fixture()
            )
        )

    def test_all_eight_public_operations_exact_and_minus_one_before_sha(self):
        original = dicom.component_fixture()
        report = dicom.analyze_supplied_dicom_pdv(original)
        text = report.to_json()
        document = report.to_dict()
        operations = (
            lambda: dicom.analyze_supplied_dicom_pdv(original),
            lambda: dicom.analyze_supplied_dicom_pdv_bytes(
                model_bytes=canonical(original).encode("ascii")
            ),
            lambda: dicom.DicomPdvAnalysis(text),
            lambda: dicom.DicomPdvAnalysis.from_dict(document),
            lambda: dicom.DicomPdvAnalysis.from_json(text),
            report.to_dict,
            report.to_json,
            lambda: dicom.verify_supplied_dicom_pdv_analysis(report, model=original),
        )
        for operation in operations:
            totals = []
            original_charge = dicom._Budget.charge

            def observe(budget, amount):
                original_charge(budget, amount)
                totals.append(budget.used)

            with patch.object(dicom._Budget, "charge", observe):
                operation()
            exact = max(totals)
            with patch.object(dicom, "MAX_WORK", exact - 1):
                self.before_hash(operation)
            with patch.object(dicom, "MAX_WORK", exact):
                self.assertIsNotNone(operation())

    def test_declared_ownership_and_no_qualification(self):
        document = dicom.analyze_supplied_dicom_pdv(dicom.component_fixture()).to_dict()
        self.assertEqual(document["profile_id"], "AOE-GD-D25-S12")
        self.assertEqual(document["work_package_id"], "IWP2-AOE-GD-D25-S12")
        self.assertEqual(document["wave_id"], "IW2-012")
        self.assertEqual(document["group_owner_id"], "AOE-HQ-06")
        self.assertEqual(document["independent_validator_id"], "AOE-HQ-33")
        self.assertEqual(document["roadmap_package_ids"], ["A7.4"])
        self.assertFalse(document["flags"]["qualification_claimed"])


if __name__ == "__main__":
    unittest.main()
