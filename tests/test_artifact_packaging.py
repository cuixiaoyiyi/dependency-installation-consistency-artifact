"""Required data must appear in the published manifest, even when present locally."""
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from artifact_tools.verify_files import verify_required_files


class RequiredFilePackagingTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        (self.root / "data").mkdir()
        self.manifest = {"files": []}
        records = []
        for name, raw in (("fixtures/runs/pip-report.json", b'{"environment":{}}'), ("implementation/analysis.py", b"pass\n")):
            target = self.root / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(raw)
            digest = hashlib.sha256(raw).hexdigest()
            records.append({"artifact": name, "sha256": digest})
            self.manifest["files"].append({"path": name, "sha256": digest})
        (self.root / "data/regression-inputs.json").write_text(json.dumps(records[:1]), encoding="utf-8")
        (self.root / "data/implementation-sources.json").write_text(json.dumps({"files": records[1:]}), encoding="utf-8")

    def test_complete_manifest_and_matching_required_files_pass(self):
        self.assertEqual(verify_required_files(self.root, self.manifest), [])

    def test_local_file_does_not_hide_missing_manifest_entry_for_either_index(self):
        for entry in self.manifest["files"]:
            with self.subTest(path=entry["path"]):
                reduced = {"files": [item for item in self.manifest["files"] if item is not entry]}
                failures = verify_required_files(self.root, reduced)
                self.assertTrue(any(row["path"] == entry["path"] and row["error"] == "required indexed file absent from manifest" for row in failures))

    def test_missing_required_file_fails_even_when_manifest_lists_it(self):
        entry = self.manifest["files"][0]
        (self.root / entry["path"]).unlink()
        failures = verify_required_files(self.root, self.manifest)
        self.assertTrue(any(row["error"] == "required indexed file missing" for row in failures))

    def test_changed_file_bytes_fail_against_required_input_hash(self):
        entry = self.manifest["files"][0]
        (self.root / entry["path"]).write_bytes(b"changed observation")
        failures = verify_required_files(self.root, self.manifest)
        self.assertTrue(any(row["error"] == "required indexed file hash mismatch" for row in failures))

    def test_manifest_hash_must_match_required_input_index(self):
        self.manifest["files"][1]["sha256"] = "0" * 64
        failures = verify_required_files(self.root, self.manifest)
        self.assertTrue(any(row["error"] == "indexed hash differs from manifest" for row in failures))


if __name__ == "__main__":
    unittest.main()
