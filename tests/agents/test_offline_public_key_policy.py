"""Offline RSA and EC public-key parsing and supplied-policy comparison."""

from __future__ import annotations

import base64
import copy
import unittest

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from sunderkey.offline_public_key_policy import (
    PublicKeyPolicyError,
    PublicKeyPolicyReport,
    analyze_supplied_public_key_policy,
    component_fixture,
    verify_supplied_public_key_policy,
)


class PublicKeyPolicyTests(unittest.TestCase):
    def test_real_ec_spki_bytes_compared_to_supplied_policy(self) -> None:
        report = analyze_supplied_public_key_policy(component_fixture()).to_dict()
        self.assertEqual(report["keys"][0]["family"], "ec")
        self.assertEqual(report["keys"][0]["curve_name"], "secp256r1")
        self.assertEqual(report["signals"], [{
            "key_id": "toy_ec_public", "issue": "outside_supplied_ec_curves",
        }])
        self.assertFalse(report["private_key_loaded"])
        self.assertFalse(report["signature_verified"])
        self.assertFalse(report["qualification_claimed"])
        self.assertNotIn("MFkwEw", str(report))

    def test_matching_ec_policy_has_no_declared_difference(self) -> None:
        model = component_fixture()
        model["policy"]["allowed_ec_curves"] = ["secp256r1"]
        report = analyze_supplied_public_key_policy(model).to_dict()
        self.assertEqual(report["signals"], [])
        self.assertEqual(report["disposition"], "no_supplied_public_key_policy_difference")

    def test_rsa_public_parameters_are_parsed_from_spki(self) -> None:
        private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        der = private.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
        )
        model = component_fixture()
        model["keys"][0]["spki_der_b64"] = base64.b64encode(der).decode("ascii")
        model["policy"]["min_rsa_bits"] = 4096
        model["policy"]["allowed_rsa_exponents"] = [3]
        report = analyze_supplied_public_key_policy(model).to_dict()
        self.assertEqual(report["keys"][0]["family"], "rsa")
        self.assertEqual(report["keys"][0]["modulus_bits"], 2048)
        self.assertEqual(report["keys"][0]["public_exponent"], 65537)
        self.assertEqual({x["issue"] for x in report["signals"]}, {
            "below_supplied_rsa_minimum", "outside_supplied_rsa_exponents",
        })
        private_der = private.private_bytes(
            serialization.Encoding.DER,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        model["keys"][0]["spki_der_b64"] = base64.b64encode(private_der).decode("ascii")
        with self.assertRaises(PublicKeyPolicyError):
            analyze_supplied_public_key_policy(model)

    def test_incomplete_policy_and_inventory_remain_unknown(self) -> None:
        model = component_fixture()
        model["keys"][0]["policy_assertions_complete"] = False
        model["inventory_complete"] = False
        report = analyze_supplied_public_key_policy(model).to_dict()
        self.assertEqual(report["signals"], [])
        self.assertEqual(report["disposition"], "unknown")

    def test_rejects_noncanonical_spki_and_bad_policy_types(self) -> None:
        model = component_fixture()
        model["keys"][0]["spki_der_b64"] += "A"
        with self.assertRaises(PublicKeyPolicyError):
            analyze_supplied_public_key_policy(model)
        model = component_fixture()
        model["policy"]["min_rsa_bits"] = True
        with self.assertRaises(PublicKeyPolicyError):
            analyze_supplied_public_key_policy(model)
        model = component_fixture()
        model["keys"].append(copy.deepcopy(model["keys"][0]))
        with self.assertRaises(PublicKeyPolicyError):
            analyze_supplied_public_key_policy(model)

    def test_replay_requires_original_public_bytes_and_policy(self) -> None:
        model = component_fixture()
        report = analyze_supplied_public_key_policy(model)
        self.assertEqual(
            verify_supplied_public_key_policy(report, model=copy.deepcopy(model)).to_json(),
            report.to_json(),
        )
        changed = copy.deepcopy(model)
        changed["policy"]["allowed_ec_curves"] = ["secp256r1"]
        with self.assertRaises(PublicKeyPolicyError):
            verify_supplied_public_key_policy(report, model=changed)
        with self.assertRaises(PublicKeyPolicyError):
            PublicKeyPolicyReport(report.to_dict())


if __name__ == "__main__":
    unittest.main()
