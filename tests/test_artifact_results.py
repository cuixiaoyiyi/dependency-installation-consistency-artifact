"""Checks for interpreting the public implementation-and-data release."""
import hashlib
from pathlib import Path
import tempfile
import unittest

from artifact_tools.reproduce_results import mechanism_measurements, verify_report_references


class SavedResultTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)

    def file(self, name, content=b"saved observation"):
        target = self.root / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(content)
        return hashlib.sha256(content).hexdigest()

    def test_input_alias_is_checked_without_original_issue_directory(self):
        digest = self.file("inputs/ultralytics-extra/inputs.json")
        reference = "1110ISSUEs/02-ultralytics-extra-inputs/inputs.json"
        result = verify_report_references({"references_sha256": {reference: digest}}, self.root)
        self.assertEqual(result["included_verified"], 1)
        self.assertEqual(result["omitted_reference_paths"], [])
        self.assertEqual(result["verified_references"][0]["included_path"], "inputs/ultralytics-extra/inputs.json")

    def test_removed_narrative_reference_is_listed_separately(self):
        reference = "1110ISSUEs/02-ultralytics__ultralytics.md"
        result = verify_report_references({"references_sha256": {reference: "0" * 64}}, self.root)
        self.assertEqual(result["included_verified"], 0)
        self.assertEqual(result["omitted_reference_paths"], [reference])

    def test_missing_experimental_reference_is_not_silently_omitted(self):
        with self.assertRaises(FileNotFoundError):
            verify_report_references({"references_sha256": {"work/observations.json": "0" * 64}}, self.root)

    def test_relocated_input_with_different_bytes_is_rejected(self):
        self.file("inputs/ultralytics-extra/inputs.json")
        with self.assertRaisesRegex(ValueError, "Reference hash mismatch"):
            verify_report_references({"references_sha256": {"1110ISSUEs/02-ultralytics-extra-inputs/inputs.json": "0" * 64}}, self.root)

    def test_synthetic_case_does_not_add_a_real_root_or_count_repetitions(self):
        source = {"independent_mechanisms": 1, "runs": [{"independent_reaudit_passed": True, "checks_reported_true": 19, "checks_reported_total": 19}] * 3}
        extra = {"status": "confirmed_real_project_incompatible_provider_declaration_and_extra_removal_failure", "counts": {"locally_confirmed_failure_families_in_this_case": 1}, "canonical_root": "ultralytics"}
        self.assertEqual(mechanism_measurements(source, extra), {"MechanismCount": 2, "RealRootCount": 1})

    def test_incomplete_source_witness_is_rejected(self):
        source = {"independent_mechanisms": 1, "runs": [{"independent_reaudit_passed": True, "checks_reported_true": 18, "checks_reported_total": 19}]}
        with self.assertRaisesRegex(ValueError, "recorded checks"):
            mechanism_measurements(source, {})


if __name__ == "__main__":
    unittest.main()
