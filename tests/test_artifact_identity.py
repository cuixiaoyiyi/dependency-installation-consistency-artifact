"""Local inert wheel fixtures; no downloads, installs, imports or payload execution."""
from __future__ import annotations

from dataclasses import replace
import hashlib
import json
from pathlib import Path
import struct
import tempfile
import unittest
import warnings
import zipfile

from drc.artifact_identity import verify_local_wheel, WheelVerificationLimits


def metadata(name="demo-pkg", version="1.0", requirements=(), python=">=3.8", extra_headers=""):
    text = f"Metadata-Version: 2.1\nName: {name}\nVersion: {version}\n"
    if python is not None: text += "Requires-Python: " + python + "\n"
    text += "".join("Requires-Dist: " + requirement + "\n" for requirement in requirements)
    return (text + extra_headers + "\nDescription is not executable.\n").encode()


class LocalWheelIdentityTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.path = self.root / "demo_pkg-1.0-py3-none-any.whl"

    def wheel(self, core=None, *, entries=None, comment=b""):
        core = metadata() if core is None else core
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", UserWarning)
            with zipfile.ZipFile(self.path, "w", compression=zipfile.ZIP_STORED) as wheel:
                wheel.comment = comment
                for name, body in entries if entries is not None else [("demo_pkg-1.0.dist-info/METADATA", core)]:
                    wheel.writestr(name, body)
        return hashlib.sha256(self.path.read_bytes()).hexdigest()

    def verify(self, core=None, **kwargs):
        core = metadata() if core is None else core
        digest = self.wheel(core)
        return verify_local_wheel(self.path, digest, kwargs.pop("advertised_metadata", core), **kwargs)

    def check(self, certificate, predicate):
        return next(c for c in certificate.checks if c.predicate == predicate)

    def test_valid_identity_and_metadata_certificate_is_json_serializable(self):
        certificate = self.verify()
        self.assertEqual(certificate.status, "pass", certificate.to_dict())
        self.assertTrue(certificate.complete)
        record = json.loads(json.dumps(certificate.to_dict()))
        self.assertFalse(record["resolver_defect_assessed"])
        self.assertEqual(record["scope"], "local-input-consistency")
        self.assertEqual(record["archive"]["size_bytes"], self.path.stat().st_size)

    def test_name_version_dependency_order_and_specifier_normalization(self):
        internal = metadata("Demo.Pkg", "1.0.0", ["requests[security]>=2.0,<3", "idna>=3"])
        advertised = metadata("demo_pkg", "1.0", ["IDNA >= 3.0", "Requests[Security]<3,>=2.0.0"])
        result = self.verify(internal, advertised_metadata=advertised)
        self.assertEqual(result.status, "pass", result.to_dict())

    def test_descriptive_header_differences_do_not_change_declared_comparison(self):
        result = self.verify(metadata(extra_headers="Summary: first description\n"),
                             advertised_metadata=metadata(extra_headers="Summary: another description\n"))
        self.assertEqual(result.status, "pass", result.to_dict())

    def test_missing_expected_hash_still_computes_exact_archive_digest(self):
        digest = self.wheel()
        result = verify_local_wheel(self.path, None, metadata())
        self.assertEqual(result.archive["sha256"], digest)
        self.assertEqual(result.status, "unknown")
        self.assertFalse(result.complete)
        self.assertEqual(self.check(result, "filename_internal.name").status, "pass")

    def test_missing_advertised_metadata_does_not_claim_correspondence(self):
        result = verify_local_wheel(self.path, self.wheel())
        self.assertEqual(result.status, "unknown")
        self.assertFalse(result.complete)
        self.assertEqual(self.check(result, "advertised.correspondence").status, "unknown")

    def test_wrong_expected_digest_is_an_input_violation(self):
        self.wheel()
        result = verify_local_wheel(self.path, "0" * 64, metadata())
        self.assertEqual(self.check(result, "archive.sha256").status, "violation")
        self.assertFalse(result.to_dict()["resolver_defect_assessed"])

    def test_malformed_expected_digest_is_unknown_not_a_wheel_defect(self):
        self.wheel()
        result = verify_local_wheel(self.path, "not-a-sha256", metadata())
        self.assertEqual(result.status, "unknown")
        self.assertEqual(self.check(result, "archive.sha256").status, "unknown")

    def test_filename_and_internal_name_mismatch(self):
        result = self.verify(metadata(name="other-project"))
        self.assertEqual(self.check(result, "filename_internal.name").status, "violation")

    def test_filename_and_internal_version_mismatch(self):
        result = self.verify(metadata(version="2.0"))
        self.assertEqual(self.check(result, "filename_internal.version").status, "violation")

    def test_internal_and_advertised_identity_mismatch(self):
        result = self.verify(advertised_metadata=metadata(name="other-project", version="2.0"))
        self.assertEqual(self.check(result, "internal_advertised.name").status, "violation")
        self.assertEqual(self.check(result, "internal_advertised.version").status, "violation")

    def test_distinct_dependency_names_violate_correspondence(self):
        result = self.verify(metadata(requirements=["idna>=3"]), advertised_metadata=metadata(requirements=["requests>=2"]))
        check = self.check(result, "requires_dist.correspondence")
        self.assertEqual(check.status, "violation")
        self.assertIsNotNone(check.witness)

    def test_dependency_version_constraint_difference_has_a_witness(self):
        result = self.verify(metadata(requirements=["idna>=2"]), advertised_metadata=metadata(requirements=["idna>=3"]))
        check = self.check(result, "requires_dist.correspondence")
        self.assertEqual(check.status, "violation")
        self.assertNotEqual(check.witness["internal_accepts"], check.witness["advertised_accepts"])

    def test_conditional_dependency_constraint_difference_has_active_environment(self):
        result = self.verify(metadata(requirements=['idna>=2; python_version >= "3.8"']),
                             advertised_metadata=metadata(requirements=['idna>=3; python_version >= "3.8"']))
        check = self.check(result, "requires_dist.correspondence")
        self.assertEqual(check.status, "violation")
        self.assertIn("python_version", check.witness["environment"])

    def test_logically_equivalent_marker_reordering_stays_unknown(self):
        result = self.verify(metadata(requirements=['idna>=3; python_version >= "3.8" and sys_platform == "linux"']),
                             advertised_metadata=metadata(requirements=['idna>=3; sys_platform == "linux" and python_version >= "3.8"']))
        self.assertEqual(self.check(result, "requires_dist.correspondence").status, "unknown")
        self.assertEqual(result.status, "unknown")

    def test_python_constraint_difference_has_a_version_witness(self):
        result = self.verify(metadata(python=">=3.8"), advertised_metadata=metadata(python=">=3.9"))
        check = self.check(result, "requires_python.correspondence")
        self.assertEqual(check.status, "violation")
        self.assertNotEqual(check.witness["internal_accepts"], check.witness["advertised_accepts"])

    def test_redundant_python_constraint_is_unknown_rather_than_false_violation(self):
        result = self.verify(metadata(python=">=3.8,>=3.9"), advertised_metadata=metadata(python=">=3.9"))
        self.assertEqual(self.check(result, "requires_python.correspondence").status, "unknown")
        self.assertFalse(any(c.status == "violation" for c in result.checks))

    def test_malformed_and_duplicate_identity_headers_are_rejected(self):
        for core in (b"Metadata-Version: 2.1\nVersion: 1.0\n\n", metadata(extra_headers="Name: duplicate-project\n")):
            with self.subTest(core=core):
                result = self.verify(core)
                self.assertEqual(self.check(result, "internal.parse").status, "violation")
                self.assertFalse(result.complete)

    def test_malformed_dependency_and_python_declarations_are_rejected(self):
        for core in (metadata(requirements=["not a requirement !!!"]), metadata(python="nonsense")):
            with self.subTest(core=core):
                self.assertEqual(self.check(self.verify(core), "internal.parse").status, "violation")

    def test_duplicate_or_multiple_metadata_entries_are_rejected(self):
        for names in (("demo_pkg-1.0.dist-info/METADATA",) * 2,
                      ("demo_pkg-1.0.dist-info/METADATA", "other-1.0.dist-info/METADATA")):
            with self.subTest(names=names):
                digest = self.wheel(entries=[(name, metadata()) for name in names])
                result = verify_local_wheel(self.path, digest, metadata())
                self.assertEqual(self.check(result, "archive.metadata_entry").status, "violation")
                self.assertFalse(result.complete)

    def test_missing_metadata_entry_is_an_input_violation(self):
        digest = self.wheel(entries=[("inert.txt", b"data only")])
        result = verify_local_wheel(self.path, digest, metadata())
        self.assertEqual(self.check(result, "archive.metadata_entry").status, "violation")

    def test_non_zip_bytes_are_rejected_without_raising(self):
        data = b"not a zip archive"
        self.path.write_bytes(data)
        result = verify_local_wheel(self.path, hashlib.sha256(data).hexdigest(), metadata())
        self.assertEqual(self.check(result, "archive.structure").status, "violation")

    def test_corrupt_entry_crc_is_rejected_without_raising(self):
        self.wheel()
        data = bytearray(self.path.read_bytes())
        name_len, extra_len = struct.unpack_from("<2H", data, 26)
        data[30 + name_len + extra_len] ^= 1
        self.path.write_bytes(data)
        result = verify_local_wheel(self.path, hashlib.sha256(data).hexdigest(), metadata())
        self.assertEqual(self.check(result, "archive.structure").status, "violation")

    def test_metadata_and_archive_size_limits_produce_incomplete_evidence(self):
        digest = self.wheel()
        limits = replace(WheelVerificationLimits(), max_metadata_bytes=16)
        result = verify_local_wheel(self.path, digest, metadata(), limits=limits)
        self.assertEqual(result.status, "unknown")
        self.assertEqual(result.archive["sha256"], digest)
        limits = replace(WheelVerificationLimits(), max_archive_bytes=16)
        result = verify_local_wheel(self.path, digest, metadata(), limits=limits)
        self.assertEqual(result.status, "unknown")
        self.assertIsNone(result.archive["sha256"])
        self.assertTrue(result.archive["size_is_lower_bound"])

    def test_entry_and_count_budgets_are_enforced_without_extraction(self):
        digest = self.wheel(entries=[("demo_pkg-1.0.dist-info/METADATA", metadata()), ("data.txt", b"x" * 4096)])
        for limits in (replace(WheelVerificationLimits(), max_entry_bytes=1024), replace(WheelVerificationLimits(), max_entries=1)):
            with self.subTest(limits=limits):
                result = verify_local_wheel(self.path, digest, metadata(), limits=limits)
                self.assertEqual(result.status, "unknown")
                self.assertFalse(result.complete)
        self.assertFalse((self.root / "data.txt").exists())

    def test_inspection_is_read_only(self):
        digest = self.wheel()
        original = self.path.read_bytes()
        verify_local_wheel(self.path, digest, metadata())
        self.assertEqual(self.path.read_bytes(), original)
        self.assertEqual(list(self.root.iterdir()), [self.path])

    def test_absent_archive_produces_unknown(self):
        result = verify_local_wheel(self.path, None, metadata())
        self.assertEqual(result.status, "unknown")
        self.assertFalse(result.complete)


if __name__ == "__main__":
    unittest.main()
