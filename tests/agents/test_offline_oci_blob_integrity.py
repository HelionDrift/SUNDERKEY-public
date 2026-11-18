"""Actual supplied bytes, independent tiny DAG checks and bounded hostile intake."""

from __future__ import annotations

import base64
import copy
import hashlib
import itertools
import json
import unittest
from unittest.mock import patch

from sunderkey import offline_oci_blob_integrity as m


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _blob(content, media):
    digest = "sha256:" + hashlib.sha256(content).hexdigest()
    return (
        {"mediaType": media, "digest": digest, "size": len(content)},
        {"digest": digest, "content_base64": base64.b64encode(content).decode("ascii")},
    )


def _document(document, media):
    return _blob(_canonical(document).encode("ascii"), media)


def _index(descriptors, blobs, **extras):
    root, blob = _document(
        {"schemaVersion": 2, "mediaType": m.INDEX_MEDIA_TYPE, "manifests": descriptors, **extras},
        m.INDEX_MEDIA_TYPE,
    )
    return {"schema_version": 1, "root_descriptor": root, "blobs": [*blobs, blob]}


def component_fixture():
    """Fresh synthetic public-only bytes; the layer is not claimed to be a valid tar."""
    config, config_blob = _blob(b'{"architecture":"amd64","os":"linux"}', m.CONFIG_MEDIA_TYPE)
    layer, layer_blob = _blob(
        b"synthetic opaque layer\x00\xff", "application/vnd.oci.image.layer.v1.tar"
    )
    first, first_blob = _document(
        {
            "schemaVersion": 2,
            "mediaType": m.MANIFEST_MEDIA_TYPE,
            "config": config,
            "layers": [layer],
        },
        m.MANIFEST_MEDIA_TYPE,
    )
    second, second_blob = _document(
        {
            "schemaVersion": 2,
            "mediaType": m.MANIFEST_MEDIA_TYPE,
            "config": config,
            "layers": [layer, layer],
        },
        m.MANIFEST_MEDIA_TYPE,
    )
    return _index([first, second], [config_blob, layer_blob, first_blob, second_blob])


def _readdress(document):
    body = copy.deepcopy(document)
    body.pop("analysis_id")
    body.pop("analysis_sha256")
    digest = (
        "sha256:"
        + hashlib.sha256(
            b"sunderkey.offline-oci-blob-analysis.v1\n" + _canonical(body).encode("ascii")
        ).hexdigest()
    )
    body["analysis_id"] = "OBA-" + digest[7:39].upper()
    body["analysis_sha256"] = digest
    return body


def _oracle(model):
    """Independent breadth-first descriptor closure using raw byte lookup."""
    contents = {row["digest"]: base64.b64decode(row["content_base64"]) for row in model["blobs"]}
    outstanding = [model["root_descriptor"]]
    expanded = set()
    reached = set()
    references = 0
    sizes = []
    while outstanding:
        descriptor = outstanding.pop(0)
        references += 1
        content = contents[descriptor["digest"]]
        if len(content) != descriptor["size"]:
            raise AssertionError("Oracle positive fixture has a wrong size")
        if "sha256:" + hashlib.sha256(content).hexdigest() != descriptor["digest"]:
            raise AssertionError("Oracle positive fixture has a wrong digest")
        sizes.append(len(content))
        reached.add(descriptor["digest"])
        if descriptor["mediaType"] not in {m.INDEX_MEDIA_TYPE, m.MANIFEST_MEDIA_TYPE}:
            continue
        if descriptor["digest"] in expanded:
            continue
        expanded.add(descriptor["digest"])
        document = json.loads(content)
        if descriptor["mediaType"] == m.INDEX_MEDIA_TYPE:
            outstanding.extend(document["manifests"])
        else:
            outstanding.append(document["config"])
            outstanding.extend(document["layers"])
    return references, len(reached), len(expanded), sizes


def _body(model):
    return m.analyze_supplied_oci_blob_graph(model).to_dict()


class OciBlobIntegrityTests(unittest.TestCase):
    def test_component_fixture_literal_identity_and_complete_shared_graph(self):
        model = component_fixture()
        body = _body(model)
        self.assertEqual("pass", body["verdict"])
        self.assertTrue(body["supported_graph_closure_verified"])
        self.assertEqual((8, 5, 3), _oracle(model)[:3])
        self.assertEqual(8, len(body["references"]))
        self.assertEqual(5, body["reachable_blob_count"])
        self.assertEqual(3, body["parsed_document_count"])
        self.assertEqual(3, body["maximum_graph_depth"])
        self.assertEqual("OBA-53F87EC0AFA3BA907E9365E6029D40B1", body["analysis_id"])
        self.assertEqual(
            "sha256:53f87ec0afa3ba907e9365e6029d40b18f230d50e84c3cd12fab4fa975b2ef95",
            body["analysis_sha256"],
        )
        self.assertEqual(
            "sha256:82e9446d6eab5a8605e8dd9814e4da619bd697fb1f052626203c0fc0d302d49c",
            body["source_model_sha256"],
        )

    def test_native_and_bytes_roundtrips_replay_every_original_blob(self):
        model = component_fixture()
        report = m.analyze_supplied_oci_blob_graph(model)
        body = report.to_dict()
        self.assertEqual(model, body["source_model"])
        for item in body["source_model"]["blobs"]:
            expected = next(row for row in model["blobs"] if row["digest"] == item["digest"])
            self.assertEqual(expected["content_base64"], item["content_base64"])
        self.assertEqual(body, m.OciBlobAnalysis.from_dict(body).to_dict())
        self.assertEqual(body, m.OciBlobAnalysis.from_json(report.to_json()).to_dict())
        self.assertEqual(
            body,
            m.analyze_supplied_oci_blob_graph_bytes(
                model_bytes=_canonical(model).encode("ascii")
            ).to_dict(),
        )
        self.assertEqual(body, m.verify_supplied_oci_blob_analysis(report, model=model).to_dict())

    def test_independent_tiny_dag_oracle_and_repeated_children(self):
        config, config_blob = _blob(b"{}", m.CONFIG_MEDIA_TYPE)
        layer, layer_blob = _blob(b"opaque", "application/vnd.oci.image.layer.v1.tar+gzip")
        cases = 0
        for counts in itertools.product(range(4), repeat=2):
            manifest_rows = []
            blobs = [config_blob, layer_blob]
            by_digest = {row["digest"] for row in blobs}
            for count in counts:
                descriptor, blob = _document(
                    {"schemaVersion": 2, "config": config, "layers": [layer] * count},
                    m.MANIFEST_MEDIA_TYPE,
                )
                manifest_rows.extend([descriptor] * 2)
                if blob["digest"] not in by_digest:
                    blobs.append(blob)
                    by_digest.add(blob["digest"])
            model = _index(manifest_rows, blobs)
            observed = _body(model)
            reference_count, reached, parsed, sizes = _oracle(model)
            self.assertEqual("pass", observed["verdict"])
            self.assertEqual(reference_count, len(observed["references"]))
            self.assertEqual(reached, observed["reachable_blob_count"])
            self.assertEqual(parsed, observed["parsed_document_count"])
            self.assertEqual(sizes, [row["declared_bytes"] for row in observed["references"]])
            cases += 1
        self.assertEqual(16, cases)

    def test_empty_index_and_empty_opaque_bytes_are_supported(self):
        body = _body(_index([], []))
        self.assertEqual("pass", body["verdict"])
        self.assertEqual((1, 1), (len(body["references"]), body["maximum_graph_depth"]))
        config, config_blob = _blob(b"", m.CONFIG_MEDIA_TYPE)
        root, root_blob = _document(
            {"schemaVersion": 2, "config": config, "layers": []}, m.MANIFEST_MEDIA_TYPE
        )
        body = _body(
            {"schema_version": 1, "root_descriptor": root, "blobs": [config_blob, root_blob]}
        )
        self.assertEqual("pass", body["verdict"])
        self.assertEqual(0, body["references"][1]["declared_bytes"])

    def test_missing_referenced_blob_cannot_claim_closure(self):
        model = component_fixture()
        model["blobs"].pop(1)
        body = _body(model)
        self.assertEqual("fail", body["verdict"])
        self.assertFalse(body["supported_graph_closure_verified"])
        self.assertIn(
            "referenced_blob_missing", {row["code"] for row in body["integrity_failures"]}
        )

    def test_actual_swapped_bytes_are_not_trusted_or_json_consumed(self):
        model = _index([], [])
        model["blobs"][0]["content_base64"] = base64.b64encode(b"malformed!").decode("ascii")
        with patch.object(m.json, "loads", side_effect=AssertionError("unverified bytes decoded")):
            report = m.analyze_supplied_oci_blob_graph(model)
        body = report.to_dict()
        self.assertEqual("fail", body["verdict"])
        self.assertEqual(0, body["parsed_document_count"])
        self.assertIn(
            "descriptor_sha256_mismatch", {row["code"] for row in body["integrity_failures"]}
        )

    def test_descriptor_size_checked_before_json_consumption(self):
        model = _index([], [])
        model["root_descriptor"]["size"] += 1
        with patch.object(m.json, "loads", side_effect=AssertionError("wrong-size bytes decoded")):
            report = m.analyze_supplied_oci_blob_graph(model)
        self.assertEqual("fail", report.to_dict()["verdict"])

    def test_conflicting_sizes_fail_and_media_interpretations_stay_unassessed(self):
        descriptor, blob = _document({"schemaVersion": 2, "manifests": []}, m.INDEX_MEDIA_TYPE)
        changed = {**descriptor, "size": descriptor["size"] + 1}
        body = _body(_index([descriptor, changed], [blob]))
        self.assertIn(
            "conflicting_descriptor_size", {row["code"] for row in body["integrity_failures"]}
        )
        self.assertEqual("fail", body["verdict"])
        config, config_blob = _blob(b"{}", m.CONFIG_MEDIA_TYPE)
        layer = {**config, "mediaType": "application/vnd.oci.image.layer.v1.tar"}
        root, root_blob = _document(
            {"schemaVersion": 2, "config": config, "layers": [layer]}, m.MANIFEST_MEDIA_TYPE
        )
        body = _body(
            {"schema_version": 1, "root_descriptor": root, "blobs": [config_blob, root_blob]}
        )
        self.assertEqual("incomplete", body["verdict"])
        self.assertEqual([], body["integrity_failures"])
        self.assertIn(
            "descriptor_media_interpretation_unassessed",
            {row["code"] for row in body["unassessed"]},
        )

    def test_raw_json_byte_spelling_changes_actual_content_address(self):
        document = {"schemaVersion": 2, "mediaType": m.INDEX_MEDIA_TYPE, "manifests": []}
        compact_root, compact_blob = _document(document, m.INDEX_MEDIA_TYPE)
        pretty_root, pretty_blob = _blob(
            json.dumps(document, indent=2).encode("ascii"), m.INDEX_MEDIA_TYPE
        )
        self.assertNotEqual(compact_root["digest"], pretty_root["digest"])
        compact = {"schema_version": 1, "root_descriptor": compact_root, "blobs": [compact_blob]}
        pretty = {"schema_version": 1, "root_descriptor": pretty_root, "blobs": [pretty_blob]}
        self.assertEqual("pass", _body(compact)["verdict"])
        self.assertEqual("pass", _body(pretty)["verdict"])
        wrong = {"schema_version": 1, "root_descriptor": compact_root, "blobs": [pretty_blob]}
        self.assertEqual("fail", _body(wrong)["verdict"])

    def test_optional_descriptor_features_are_retained_but_not_followed(self):
        extras = {
            "urls": ["https://example.test/not-fetched"],
            "data": "e30=",
            "annotations": {"example.test/note": "declared"},
            "platform": {"os": "linux", "architecture": "amd64"},
            "artifactType": "application/vnd.example.artifact",
            "futureField": {"nested": True},
        }
        for key, value in extras.items():
            with self.subTest(key=key):
                model = _index([], [])
                model["root_descriptor"][key] = value
                body = _body(model)
                self.assertEqual("incomplete", body["verdict"])
                self.assertEqual([], body["integrity_failures"])
                self.assertEqual(value, body["source_model"]["root_descriptor"][key])
                self.assertIn(
                    "descriptor_feature_unassessed", {row["code"] for row in body["unassessed"]}
                )

    def test_artifact_subject_annotations_and_unknown_media_are_incomplete(self):
        for key, value in (
            ("artifactType", "application/vnd.example.artifact"),
            (
                "subject",
                {"mediaType": m.MANIFEST_MEDIA_TYPE, "size": 1, "digest": "sha256:" + "1" * 64},
            ),
            ("annotations", {"example.test/note": "declared"}),
            ("futureField", True),
        ):
            with self.subTest(key=key):
                body = _body(_index([], [], **{key: value}))
                self.assertEqual("incomplete", body["verdict"])
                self.assertEqual([], body["integrity_failures"])
                self.assertIn(
                    "document_feature_unassessed", {row["code"] for row in body["unassessed"]}
                )
        model = _index([], [])
        model["root_descriptor"]["mediaType"] = "application/vnd.example.future+json"
        body = _body(model)
        self.assertEqual("incomplete", body["verdict"])
        self.assertEqual(0, body["parsed_document_count"])

    def test_unknown_algorithm_and_noncurrent_schema_are_not_universal_invalidity(self):
        model = {
            "schema_version": 1,
            "root_descriptor": {
                "mediaType": m.INDEX_MEDIA_TYPE,
                "digest": "sha512:" + "a" * 128,
                "size": 0,
            },
            "blobs": [],
        }
        body = _body(model)
        self.assertEqual("incomplete", body["verdict"])
        self.assertEqual([], body["integrity_failures"])
        self.assertEqual("digest_algorithm_unassessed", body["unassessed"][0]["code"])
        root, blob = _document({"schemaVersion": 3, "manifests": []}, m.INDEX_MEDIA_TYPE)
        body = _body({"schema_version": 1, "root_descriptor": root, "blobs": [blob]})
        self.assertEqual("incomplete", body["verdict"])
        self.assertIn("schema_version_unassessed", {row["code"] for row in body["unassessed"]})

    def test_native_model_aliases_fail_before_content_or_address_hash(self):
        for field, wrong in itertools.product(("schema_version", "size"), (True, 1.0, "1")):
            model = _index([], [])
            if field == "size":
                model["root_descriptor"]["size"] = wrong
            else:
                model[field] = wrong
            with (
                self.subTest(field=field, wrong=wrong),
                patch.object(m.hashlib, "sha256", side_effect=AssertionError("premature hash")),
                self.assertRaises(m.OciBlobAnalysisError),
            ):
                m.analyze_supplied_oci_blob_graph(model)

    def test_incomplete_foreign_and_subclass_native_families_are_rejected(self):
        class ForeignDict(dict):
            pass

        class ForeignList(list):
            pass

        class ForeignString(str):
            pass

        class ForeignInt(int):
            pass

        samples = [ForeignDict(_index([], [])), [], None, object()]
        for changes in (
            {"schema_version": ForeignInt(1)},
            {"root_descriptor": ForeignDict(_index([], [])["root_descriptor"])},
            {"blobs": ForeignList(_index([], [])["blobs"])},
        ):
            samples.append({**_index([], []), **changes})
        model = _index([], [])
        model["blobs"][0]["content_base64"] = ForeignString(model["blobs"][0]["content_base64"])
        samples.append(model)
        for sample in samples:
            with self.subTest(sample=type(sample)), self.assertRaises(m.OciBlobAnalysisError):
                m.analyze_supplied_oci_blob_graph(sample)
        with self.assertRaises(m.OciBlobAnalysisError):
            m.verify_supplied_oci_blob_analysis(
                object.__new__(m.OciBlobAnalysis), model=_index([], [])
            )

    def test_closed_fields_duplicate_blob_addresses_and_digest_grammar(self):
        variants = []
        model = _index([], [])
        variants.append({**model, "extra": True})
        variants.append({key: value for key, value in model.items() if key != "blobs"})
        variants.append({**model, "blobs": model["blobs"] * 2})
        variants.append({**model, "blobs": [{**model["blobs"][0], "extra": True}]})
        for wrong in (
            "sha256:" + "A" * 64,
            "sha256:abcd",
            "sha256:" + "a" * 63,
            "SHA256:" + "a" * 64,
        ):
            variants.append(
                {**model, "root_descriptor": {**model["root_descriptor"], "digest": wrong}}
            )
        for variant in variants:
            with self.subTest(variant=variant.keys()), self.assertRaises(m.OciBlobAnalysisError):
                m.analyze_supplied_oci_blob_graph(variant)

    def test_canonical_base64_and_typed_bytes_intake(self):
        for encoded in ("e30", "e30=\n", "e30==", "e31=", "_w==", "====", "e30= "):
            model = _index([], [])
            model["blobs"][0]["content_base64"] = encoded
            with self.subTest(encoded=encoded), self.assertRaises(m.OciBlobAnalysisError):
                m.analyze_supplied_oci_blob_graph(model)
        for wrong in (
            _canonical(_index([], [])),
            bytearray(b"{}"),
            memoryview(b"{}"),
            b"",
            b"\xff",
        ):
            with self.subTest(kind=type(wrong)), self.assertRaises(m.OciBlobAnalysisError):
                m.analyze_supplied_oci_blob_graph_bytes(model_bytes=wrong)

    def test_duplicate_raw_fields_and_native_oci_schema_slots(self):
        model = _index([], [])
        raw = _canonical(model).replace(
            '"schema_version":1', '"schema_version":1,"schema_version":1'
        )
        with self.assertRaises(m.OciBlobAnalysisError):
            m.analyze_supplied_oci_blob_graph_bytes(model_bytes=raw.encode("ascii"))
        for content in (
            b'{"schemaVersion":2,"schemaVersion":2,"manifests":[]}',
            b'{"schemaVersion":true,"manifests":[]}',
            b'{"schemaVersion":2.0,"manifests":[]}',
            b'{"schemaVersion":2,"mediaType":true,"manifests":[]}',
            b'{"schemaVersion":2,"manifests":{}}',
            b'{"schemaVersion":2,"manifests":[]} trailing',
        ):
            root, blob = _blob(content, m.INDEX_MEDIA_TYPE)
            with (
                self.subTest(content=content),
                patch.object(
                    m, "_address", side_effect=AssertionError("invalid OCI source addressed")
                ),
                self.assertRaises(m.OciBlobAnalysisError),
            ):
                m.analyze_supplied_oci_blob_graph(
                    {"schema_version": 1, "root_descriptor": root, "blobs": [blob]}
                )

    def test_descriptor_alias_in_actual_coherently_rehashed_json_is_rejected(self):
        child, child_blob = _document({"schemaVersion": 2, "manifests": []}, m.INDEX_MEDIA_TYPE)
        for wrong in (True, 1.0, "1", -1):
            model = _index([{**child, "size": wrong}], [child_blob])
            with self.subTest(wrong=wrong), self.assertRaises(m.OciBlobAnalysisError):
                m.analyze_supplied_oci_blob_graph(model)

    def test_raw_budget_and_integer_grammar_before_decoder(self):
        for raw in (
            "[" * 16 + "1" + "]" * 16,
            "[" * 16 + '"scalar"' + "]" * 16,
            "[" + ",".join("0" for _ in range(m.MAX_NATIVE_NODES)) + "]",
            "0" * (m.MAX_MODEL_BYTES + 1),
            "--1",
            "---1",
            "--0",
            "+1",
            "01",
            "-01",
            "1.0",
            "NaN",
            "1e1",
            str(1 << 63),
            "9" * 10000,
        ):
            with (
                self.subTest(length=len(raw)),
                patch.object(m.json, "loads", side_effect=AssertionError("unbounded raw decode")),
                self.assertRaises(m.OciBlobAnalysisError),
            ):
                m.analyze_supplied_oci_blob_graph_bytes(model_bytes=raw.encode("ascii"))

    def test_native_shared_graph_cycle_large_integer_and_escape_budgets_before_hash(self):
        shared = ["x"]
        for _ in range(14):
            shared = [shared, shared]
        cyclic = []
        cyclic.append(cyclic)
        values = [shared, cyclic, {"x": 1 << 100000}, {"x": "x" * (m.MAX_BASE64_CHARACTERS + 1)}]
        values.append({str(i): '"\\' * 1000 for i in range(300)})
        for value in values:
            with (
                self.subTest(kind=type(value)),
                patch.object(
                    m.json, "dumps", side_effect=AssertionError("unbounded serialization")
                ),
                patch.object(m.hashlib, "sha256", side_effect=AssertionError("premature hash")),
                self.assertRaises(m.OciBlobAnalysisError),
            ):
                m.analyze_supplied_oci_blob_graph(value)

    def test_blob_and_aggregate_bounds_precede_any_decode_or_digest(self):
        oversized = base64.b64encode(b"x" * (m.MAX_BLOB_BYTES + 1)).decode("ascii")
        model = _index([], [])
        model["blobs"][0]["content_base64"] = oversized
        full_blob = base64.b64encode(b"x" * m.MAX_BLOB_BYTES).decode("ascii")
        aggregate = {
            "schema_version": 1,
            "root_descriptor": model["root_descriptor"],
            "blobs": [
                {"digest": "sha256:" + f"{i:064x}", "content_base64": full_blob} for i in range(3)
            ],
        }
        # The native model cap independently rejects this aggregate before decode.
        for candidate in (model, aggregate):
            with (
                patch.object(m.base64, "b64decode", side_effect=AssertionError("early decode")),
                patch.object(m.hashlib, "sha256", side_effect=AssertionError("early hash")),
                self.assertRaises(m.OciBlobAnalysisError),
            ):
                m.analyze_supplied_oci_blob_graph(candidate)

    def test_exact_blob_ceiling_and_aggregate_allocation_ceiling(self):
        config, config_blob = _blob(b"x" * m.MAX_BLOB_BYTES, m.CONFIG_MEDIA_TYPE)
        root, root_blob = _document(
            {"schemaVersion": 2, "config": config, "layers": []}, m.MANIFEST_MEDIA_TYPE
        )
        self.assertEqual(
            "pass",
            _body(
                {"schema_version": 1, "root_descriptor": root, "blobs": [config_blob, root_blob]}
            )["verdict"],
        )
        first, first_blob = _blob(b"a" * (m.MAX_TOTAL_BLOB_BYTES // 2), m.CONFIG_MEDIA_TYPE)
        second, second_blob = _blob(b"b" * (m.MAX_TOTAL_BLOB_BYTES // 2), m.CONFIG_MEDIA_TYPE)
        # Root aliases one supplied blob as unsupported graph content: exact bytes
        # can still be observed without parsing either opaque blob as OCI JSON.
        root = {**first, "mediaType": "application/vnd.example.opaque"}
        exact = {"schema_version": 1, "root_descriptor": root, "blobs": [first_blob, second_blob]}
        self.assertEqual(m.MAX_TOTAL_BLOB_BYTES, _body(exact)["decoded_blob_bytes"])
        extra = {"digest": "sha256:" + "f" * 64, "content_base64": "eA=="}
        with (
            patch.object(m.base64, "b64decode", side_effect=AssertionError("unbounded allocation")),
            self.assertRaises(m.OciBlobAnalysisError),
        ):
            m.analyze_supplied_oci_blob_graph({**exact, "blobs": [*exact["blobs"], extra]})
        self.assertNotEqual(first["digest"], second["digest"])

    def test_pending_reference_bound_rejects_before_source_addresses(self):
        # A short unsupported type keeps the exact reference-ceiling source blob
        # inside the separate per-blob byte ceiling. No child JSON is interpreted.
        child, blob = _blob(b"opaque", "a/b")
        for count, succeeds in ((m.MAX_REFERENCES - 1, True), (m.MAX_REFERENCES, False)):
            model = _index([child] * count, [blob])
            with self.subTest(count=count):
                if succeeds:
                    body = _body(model)
                    self.assertEqual(m.MAX_REFERENCES, len(body["references"]))
                    self.assertEqual(1, body["parsed_document_count"])
                    self.assertEqual("incomplete", body["verdict"])
                else:
                    with (
                        patch.object(
                            m, "_address", side_effect=AssertionError("oversized graph addressed")
                        ),
                        self.assertRaises(m.OciBlobAnalysisError),
                    ):
                        m.analyze_supplied_oci_blob_graph(model)

    def test_exact_supplied_blob_count_and_one_over_before_hash(self):
        extras = [_blob(f"opaque:{i}".encode("ascii"), "a/b")[1] for i in range(m.MAX_BLOBS - 1)]
        model = _index([], extras)
        body = _body(model)
        self.assertEqual("pass", body["verdict"])
        self.assertEqual(m.MAX_BLOBS, len(body["blob_observations"]))
        self.assertEqual(1, body["reachable_blob_count"])
        extra = _blob(b"one more", "a/b")[1]
        with (
            patch.object(
                m.hashlib, "sha256", side_effect=AssertionError("oversized source hashed")
            ),
            self.assertRaises(m.OciBlobAnalysisError),
        ):
            m.analyze_supplied_oci_blob_graph({**model, "blobs": [*model["blobs"], extra]})

    def test_shared_dag_longest_depth_is_not_first_shorter_visit(self):
        descriptor, blob = _document({"schemaVersion": 2, "manifests": []}, m.INDEX_MEDIA_TYPE)
        blobs = [blob]
        leaf = descriptor
        for _ in range(m.MAX_GRAPH_DEPTH - 2):
            descriptor, blob = _document(
                {"schemaVersion": 2, "manifests": [descriptor]}, m.INDEX_MEDIA_TYPE
            )
            blobs.append(blob)
        model = _index([leaf, descriptor], blobs)
        self.assertEqual(m.MAX_GRAPH_DEPTH, _body(model)["maximum_graph_depth"])
        too_deep_root, too_deep_blob = _document(
            {"schemaVersion": 2, "manifests": [model["root_descriptor"]]}, m.INDEX_MEDIA_TYPE
        )
        with self.assertRaises(m.OciBlobAnalysisError):
            m.analyze_supplied_oci_blob_graph(
                {
                    "schema_version": 1,
                    "root_descriptor": too_deep_root,
                    "blobs": [*model["blobs"], too_deep_blob],
                }
            )

    def test_output_and_processing_budgets_precede_source_report_addressing(self):
        model = component_fixture()
        body = _body(model)
        with (
            patch.object(m, "MAX_REPORT_BYTES", len(_canonical(body)) - 1),
            patch.object(m, "_address", side_effect=AssertionError("over-budget output addressed")),
            self.assertRaises(m.OciBlobAnalysisError),
        ):
            m.analyze_supplied_oci_blob_graph(model)
        with (
            patch.object(m, "MAX_WORK", 1),
            patch.object(
                m.base64, "b64decode", side_effect=AssertionError("over-budget work decoded")
            ),
            self.assertRaises(m.OciBlobAnalysisError),
        ):
            m.analyze_supplied_oci_blob_graph(model)

    def test_original_sources_and_every_export_are_detached(self):
        model = component_fixture()
        original = copy.deepcopy(model)
        report = m.analyze_supplied_oci_blob_graph(model)
        body = report.to_dict()
        model["blobs"][0]["content_base64"] = ""
        body["source_model"]["blobs"].clear()
        body["effects"]["provider"] = "allowed"
        body["flags"]["source_authenticated"] = True
        body["references"][0]["size_matches"] = False
        exported = report.to_dict()
        self.assertEqual(original, exported["source_model"])
        self.assertEqual("none", exported["effects"]["provider"])
        self.assertFalse(exported["flags"]["source_authenticated"])
        self.assertTrue(exported["references"][0]["size_matches"])
        second = _body(original)
        self.assertEqual(exported, second)

    def test_cohashed_false_integrity_trace_source_and_effect_promotions_reject(self):
        body = _body(component_fixture())
        variants = []
        for field, wrong in (
            ("supported_graph_closure_verified", 1),
            ("reachable_blob_count", True),
            ("verdict", "fail"),
            ("maximum_graph_depth", 1.0),
        ):
            variants.append({**body, field: wrong})
        changed = copy.deepcopy(body)
        changed["references"][0]["size_matches"] = False
        variants.append(changed)
        changed = copy.deepcopy(body)
        changed["blob_observations"][0]["actual_sha256"] = "sha256:" + "0" * 64
        variants.append(changed)
        changed = copy.deepcopy(body)
        changed["flags"]["signed_origin_verified"] = True
        variants.append(changed)
        changed = copy.deepcopy(body)
        changed["effects"]["registry"] = "allowed"
        variants.append(changed)
        changed = copy.deepcopy(body)
        changed["source_model"]["blobs"][0]["content_base64"] = "e30="
        variants.append(changed)
        variants.append({**body, "unknown": True})
        for variant in variants:
            with self.subTest(fields=variant.keys()), self.assertRaises(m.OciBlobAnalysisError):
                m.OciBlobAnalysis.from_dict(_readdress(variant))

    def test_truthfully_rebuilt_different_model_cannot_verify_against_original(self):
        original = component_fixture()
        different = _index([], [])
        different_report = m.analyze_supplied_oci_blob_graph(different)
        self.assertEqual("pass", different_report.to_dict()["verdict"])
        with self.assertRaises(m.OciBlobAnalysisError):
            m.verify_supplied_oci_blob_analysis(different_report, model=original)

    def test_forged_wrapper_export_and_duplicate_report_json_reject(self):
        body = _body(component_fixture())
        forged = object.__new__(m.OciBlobAnalysis)
        object.__setattr__(
            forged, "_document_json", _canonical(_readdress({**body, "verdict": "fail"}))
        )
        with self.assertRaises(m.OciBlobAnalysisError):
            forged.to_dict()
        raw = _canonical(body).replace(
            '"schema_version":1', '"schema_version":1,"schema_version":1', 1
        )
        with self.assertRaises(m.OciBlobAnalysisError):
            m.OciBlobAnalysis.from_json(raw)

    def test_no_authority_currentness_signing_or_runtime_effects(self):
        body = _body(component_fixture())
        self.assertEqual("AOE-GC-D17-S10", body["profile_id"])
        self.assertEqual("army.gc.d17.s10", body["capability_id"])
        self.assertEqual("IW2-022", body["wave_id"])
        self.assertEqual("AOE-HQ-19", body["independent_validator_id"])
        self.assertTrue(all(value == "none" for value in body["effects"].values()))
        self.assertTrue(all(value is False for value in body["flags"].values()))
        self.assertEqual(component_fixture(), body["source_model"])


if __name__ == "__main__":
    unittest.main()
