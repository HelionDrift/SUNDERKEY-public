"""Exact addressed replay using existing inert action and target fixtures."""

from __future__ import annotations

import hashlib
import json
import unittest
from datetime import UTC, datetime

import sunderkey
from sunderkey import action_admission_contracts as action
from sunderkey import authenticated_target_contracts as target
from tests.agents import test_action_admission_contracts_phase165 as action_fixture
from tests.agents import test_authenticated_target_contracts_phase166 as target_fixture


def _native_json(value: object) -> str:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
    )


def _records() -> tuple[tuple[object, ...], tuple[object, ...]]:
    request = action_fixture.valid_request()
    session = target_fixture.session()
    prepared = target_fixture.prepared_request()
    cases = (
        target.PrincipalAuthorizationCase(
            "caseref:owner-read",
            "principalref:owner",
            "sessionref:owner",
            target_fixture.digest("1"),
            target_fixture.digest("2"),
            target_fixture.digest("3"),
            True,
        ),
        target.PrincipalAuthorizationCase(
            "caseref:viewer-write",
            "principalref:viewer",
            "sessionref:viewer",
            target_fixture.digest("4"),
            target_fixture.digest("2"),
            target_fixture.digest("5"),
            False,
        ),
    )
    return (
        (request, action.evaluate_action_admission(request, evaluated_at="2026-09-20T12:00:00Z")),
        (
            session,
            target.MultiPrincipalAuthorizationPlan(
                "tenantref:acme",
                "missionref:assessment-44",
                "scoperef:signed-v3",
                "targetref:app-one",
                cases,
                "2026-09-20T10:00:00Z",
                "2026-09-20T18:00:00Z",
            ),
            target_fixture.admission(session),
            prepared,
            target.normalize_authenticated_response(
                prepared,
                status_code=200,
                header_value_sha256={"Set-Cookie": target_fixture.digest("e")},
                body_sha256=target_fixture.digest("f"),
                body_size_bytes=128,
                received_at="2026-09-20T10:17:00Z",
            ),
            target.record_session_termination(
                session,
                reason=target.TerminationReason.LOGOUT,
                evidence_refs=("evidenceref:logout-response",),
                logout_observed=True,
                revocation_observed=False,
                terminated_at="2026-09-20T12:01:00Z",
            ),
        ),
    )


IDENTITY_FIELDS = {
    "ActionAdmissionRequest": ("request_id", "request_sha256"),
    "ActionAdmissionDecision": ("decision_id", "decision_sha256"),
    "AuthenticatedSessionContract": ("contract_id", "contract_sha256"),
    "MultiPrincipalAuthorizationPlan": ("plan_id", "plan_sha256"),
    "SessionAdmission": ("admission_id", "admission_sha256"),
    "PreparedAuthenticatedRequest": ("request_id", "request_sha256"),
    "NormalizedAuthenticatedResponse": ("response_id", "response_sha256"),
    "SessionTerminationEvidence": ("termination_id", "termination_sha256"),
}

GOLDENS = {
    "ActionAdmissionRequest": (
        "AAR-53349103AA8175757F393A72537D4E29",
        "sha256:53349103aa8175757f393a72537d4e296e39aeaebf1636a87f3ac82ae285f8a3",
    ),
    "ActionAdmissionDecision": (
        "AAD-C2B4E6AB0C78227071C5A604FB164336",
        "sha256:c2b4e6ab0c78227071c5a604fb1643363b52336407a922422aad00009cf3aca5",
    ),
    "AuthenticatedSessionContract": (
        "ASC-58A82B799B4BF03A71732C9D11A76B6C",
        "sha256:58a82b799b4bf03a71732c9d11a76b6cd2c1e6b24289400ded9b57152e98e028",
    ),
    "MultiPrincipalAuthorizationPlan": (
        "MAP-60F41767A5F3FA51AD0CFE32D3C1249A",
        "sha256:60f41767a5f3fa51ad0cfe32d3c1249a65f207a698b19958c5e47f0761fa57bb",
    ),
    "SessionAdmission": (
        "ASA-078CDFF72B2429755E4AF5DAE844042D",
        "sha256:078cdff72b2429755e4af5dae844042de6274aad038c5bc7d9bf67e63b1bda92",
    ),
    "PreparedAuthenticatedRequest": (
        "AQR-EB3F1D350112D4113076DBD81497CCAD",
        "sha256:eb3f1d350112d4113076dbd81497ccad190cf6119dcb8dd36ec86122fa953a96",
    ),
    "NormalizedAuthenticatedResponse": (
        "ANR-E94324CBA47B99B3AA63C64A9EDC271C",
        "sha256:e94324cba47b99b3aa63c64a9edc271cd2c92b20db8794ed2e4bbb3ac16b7ca3",
    ),
    "SessionTerminationEvidence": (
        "ATE-9DA04A9523640D40BF6E3DB362FE2E95",
        "sha256:9da04a9523640d40bf6e3db362fe2e956cf162c2051b04d4b762d521eac207e2",
    ),
}


class ActionTargetExactReplayTests(unittest.TestCase):
    def setUp(self) -> None:
        self.actions, self.targets = _records()

    @staticmethod
    def _action_entrypoints(record: object):
        return (
            ("from_dict", type(record).from_dict),
            ("from_json", lambda raw: type(record).from_json(_native_json(raw))),
            ("parse_contract", lambda raw: action.parse_contract(_native_json(raw))),
            (
                "package_parse_contract",
                lambda raw: sunderkey.parse_action_admission_contract(_native_json(raw)),
            ),
        )

    def _assert_changed_addressed_body(self, record: object, raw: dict[str, object]) -> None:
        id_field, hash_field = IDENTITY_FIELDS[type(record).__name__]
        body = {key: value for key, value in raw.items() if key not in {id_field, hash_field}}
        domain = record.KIND if record in self.actions else record.DOMAIN
        digest = (
            "sha256:"
            + hashlib.sha256(
                _native_json({"content": body, "domain": domain}).encode("ascii")
            ).hexdigest()
        )
        self.assertNotEqual(digest, raw[hash_field])
        self.assertEqual(raw[id_field], record.to_dict()[id_field])
        self.assertEqual(raw[hash_field], record.to_dict()[hash_field])

    def test_eight_original_identities_and_all_public_round_trips_are_preserved(self) -> None:
        for record in self.actions + self.targets:
            raw = record.to_dict()
            name = type(record).__name__
            with self.subTest(record=name):
                self.assertEqual(tuple(raw[key] for key in IDENTITY_FIELDS[name]), GOLDENS[name])
                self.assertIs(type(raw["schema_version"]), int)
                entrypoints = (
                    self._action_entrypoints(record)
                    if record in self.actions
                    else (
                        ("parse_contract", target.parse_contract),
                        ("package_parse_contract", sunderkey.parse_authenticated_target_contract),
                    )
                )
                for entrypoint, parse in entrypoints:
                    for document in (raw, dict(reversed(tuple(raw.items())))):
                        with self.subTest(entrypoint=entrypoint):
                            self.assertEqual(
                                _native_json(parse(document).to_dict()), _native_json(raw)
                            )
                effects = dict(action.NO_EFFECTS if record in self.actions else target.NO_EFFECTS)
                self.assertEqual(raw["effects"], effects)
                self.assertTrue(all(value == "none" for value in effects.values()))

    def _assert_action_schema_rejected(self, record: object) -> None:
        for replacement in (True, 1.0):
            raw = record.to_dict()
            raw["schema_version"] = replacement
            before = _native_json(raw)
            self.assertEqual(raw, record.to_dict())
            self.assertNotEqual(before, _native_json(record.to_dict()))
            self._assert_changed_addressed_body(record, raw)
            for name, parse in self._action_entrypoints(record):
                with self.subTest(native_type=type(replacement).__name__, entrypoint=name):
                    with self.assertRaises(action.ActionAdmissionContractError):
                        parse(raw)
                    self.assertEqual(_native_json(raw), before)

    def test_request_schema_substitution_rejects_all_public_action_entrypoints(self) -> None:
        self._assert_action_schema_rejected(self.actions[0])

    def test_decision_schema_substitution_rejects_all_public_action_entrypoints(self) -> None:
        self._assert_action_schema_rejected(self.actions[1])

    def test_all_six_target_schema_substitutions_reject_public_dispatchers(self) -> None:
        for record in self.targets:
            for replacement in (True, 1.0):
                raw = record.to_dict()
                raw["schema_version"] = replacement
                before = _native_json(raw)
                self.assertEqual(raw, record.to_dict())
                self.assertNotEqual(before, _native_json(record.to_dict()))
                self._assert_changed_addressed_body(record, raw)
                for name, parse in (
                    ("parse_contract", target.parse_contract),
                    ("package_parse_contract", sunderkey.parse_authenticated_target_contract),
                ):
                    with self.subTest(
                        record=type(record).__name__,
                        native_type=type(replacement).__name__,
                        entrypoint=name,
                    ):
                        with self.assertRaises(target.AuthenticatedTargetContractError):
                            parse(raw)
                        self.assertEqual(_native_json(raw), before)

    def test_existing_integer_and_boolean_guards_remain_strict(self) -> None:
        for replacement in (True, 1.0):
            raw = self.actions[0].to_dict()
            raw["budget"]["action_request_cost"] = replacement
            with self.subTest(field="action_request_cost", value=replacement):
                with self.assertRaises(action.ActionAdmissionContractError):
                    action.ActionAdmissionRequest.from_dict(raw)
        for record, path, replacement in (
            (self.targets[0], ("context", "fence_epoch"), 7.0),
            (self.targets[1], ("cases", 0, "expected_allowed"), 1),
            (self.targets[4], ("status_code",), 200.0),
            (self.targets[5], ("logout_observed",), 1),
        ):
            raw = record.to_dict()
            selected = raw
            for key in path[:-1]:
                selected = selected[key]
            selected[path[-1]] = replacement
            with self.subTest(record=type(record).__name__, field=path):
                with self.assertRaises(target.AuthenticatedTargetContractError):
                    target.parse_contract(raw)

    def test_effects_missing_extra_and_false_digest_inputs_are_not_repaired(self) -> None:
        for record in self.actions + self.targets:
            error = (
                action.ActionAdmissionContractError
                if record in self.actions
                else target.AuthenticatedTargetContractError
            )
            parse = type(record).from_dict if record in self.actions else target.parse_contract
            for mutation in ("effects", "missing", "extra", "digest"):
                raw = record.to_dict()
                if mutation == "effects":
                    raw["effects"][next(iter(raw["effects"]))] = "authorized"
                elif mutation == "missing":
                    raw.pop("schema_version")
                elif mutation == "extra":
                    raw["unexpected"] = False
                else:
                    raw[IDENTITY_FIELDS[type(record).__name__][1]] = "sha256:" + "0" * 64
                before = _native_json(raw)
                with self.subTest(record=type(record).__name__, mutation=mutation):
                    with self.assertRaises(error):
                        parse(raw)
                    self.assertEqual(_native_json(raw), before)

    def test_valid_local_admission_outcomes_and_none_effects_are_unchanged(self) -> None:
        parsed = action.ActionAdmissionRequest.from_dict(self.actions[0].to_dict())
        allowed = action.evaluate_action_admission(parsed, evaluated_at="2026-09-20T12:00:00Z")
        denied = action.evaluate_action_admission(parsed, evaluated_at="2026-09-20T12:06:00Z")
        self.assertIs(allowed.status, action.AdmissionStatus.ADMITTED_CONTRACT_ONLY)
        self.assertEqual(allowed.to_json(), self.actions[1].to_json())
        self.assertIs(denied.status, action.AdmissionStatus.DENIED)
        session = target.parse_contract(self.targets[0].to_dict())
        evaluated_at = datetime(2026, 9, 20, 10, 15, tzinfo=UTC)
        admitted = target.evaluate_session_admission(
            session,
            session.context,
            evaluated_at=evaluated_at,
            observed_fencing_token_sha256=target_fixture.digest("f"),
        )
        revoked = target.evaluate_session_admission(
            session,
            session.context,
            evaluated_at=evaluated_at,
            observed_fencing_token_sha256=target_fixture.digest("f"),
            revoked_lease_refs=(session.lease.lease_ref,),
        )
        self.assertIs(admitted.status, target.AdmissionStatus.ADMITTED)
        self.assertEqual(_native_json(admitted.to_dict()), _native_json(self.targets[2].to_dict()))
        self.assertIs(revoked.status, target.AdmissionStatus.DENIED)
        for record in (allowed, denied, admitted, revoked):
            self.assertTrue(all(value == "none" for value in record.to_dict()["effects"].values()))
