"""Evidence-boundary regressions for missing hashes and pylock sdist entries."""
from __future__ import annotations

from pathlib import Path
import tempfile
import unittest

from drc.contracts import assess_contracts
from drc.frontend.lockfile import pylock
from drc.intent.evidence_graph import build_intents
from drc.intent.structured_evidence import structured_evidence
from drc.model import Artifact, Context, ProjectIR
from drc.oracle import (
    compare_artifacts, summarize, INSUFFICIENT_EVIDENCE, SAME,
    SAME_VERSION_DIFF_HASH_SAME_REGISTRY,
)


class MissingHashIdentityTests(unittest.TestCase):
    def artifact(self, url, digest):
        return Artifact(
            name="demo", version="1.0", url=url, filename="demo-1.0-py3-none-any.whl",
            kind="wheel", sha256=digest, registry="pypi",
            selected_artifact_verified=True,
        )

    def test_equal_filename_at_distinct_urls_with_missing_digest_is_unknown(self):
        for left_hash, right_hash in (
            (None, None), (None, "a" * 64), ("a" * 64, None),
            ("", "a" * 64), ("a" * 64, ""),
        ):
            with self.subTest(left_hash=left_hash, right_hash=right_hash):
                diff = compare_artifacts(
                    self.artifact("https://files.pythonhosted.org/old/demo.whl", left_hash),
                    self.artifact("https://files.pythonhosted.org/new/demo.whl", right_hash),
                )
                self.assertEqual(diff.cls, INSUFFICIENT_EVIDENCE)
                self.assertFalse(diff.benign)
                counts = summarize([diff])
                self.assertEqual(counts["stable"], 0)
                self.assertEqual(counts["ambiguous"], 0)
                self.assertEqual(counts["insufficient_evidence"], 1)

    def test_common_verified_hash_still_establishes_content_identity(self):
        diff = compare_artifacts(
            self.artifact("https://files.pythonhosted.org/old/demo.whl", "a" * 64),
            self.artifact("https://files.pythonhosted.org/new/demo.whl", "a" * 64),
        )
        self.assertEqual(diff.cls, SAME)
        self.assertTrue(diff.benign)

    def test_known_distinct_hashes_are_not_hidden_by_equal_filename(self):
        diff = compare_artifacts(
            self.artifact("https://files.pythonhosted.org/old/demo.whl", "a" * 64),
            self.artifact("https://files.pythonhosted.org/new/demo.whl", "b" * 64),
        )
        self.assertEqual(diff.cls, SAME_VERSION_DIFF_HASH_SAME_REGISTRY)
        self.assertFalse(diff.benign)


class PylockArchiveHashTests(unittest.TestCase):
    wheel_url = "https://files.pythonhosted.org/demo-1.0-py3-none-any.whl"
    sdist_url = "https://files.pythonhosted.org/demo-1.0.tar.gz"
    wheel_hash = "a" * 64
    sdist_hash = "b" * 64

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.path = self.root / "pylock.toml"

    def write_lock(self, *, wheel=True, wheel_hash=True, url_less_wheel=False):
        text = 'lock-version = "1.0"\n[[packages]]\nname = "demo"\nversion = "1.0"\nindex = "https://pypi.org/simple"\n'
        if wheel:
            text += '[[packages.wheels]]\nurl = "' + self.wheel_url + '"\n'
            if wheel_hash: text += 'hashes = {sha256 = "' + self.wheel_hash + '"}\n'
        if url_less_wheel:
            text += '[[packages.wheels]]\npath = "local.whl"\nhashes = {sha256 = "' + "c" * 64 + '"}\n'
        text += '[packages.sdist]\nurl = "' + self.sdist_url + '"\nhashes = {sha256 = "' + self.sdist_hash + '"}\n'
        self.path.write_text(text, encoding="utf-8")
        return pylock(self.path, "pylock.toml")

    def test_mixed_lock_keeps_wheel_and_sdist_url_hash_pairs(self):
        entry = self.write_lock().packages["demo"]
        self.assertEqual(list(zip(entry["urls"], entry["hashes"])), [
            (self.wheel_url, self.wheel_hash), (self.sdist_url, self.sdist_hash),
        ])

    def test_sdist_only_lock_retains_its_hash(self):
        entry = self.write_lock(wheel=False).packages["demo"]
        self.assertEqual(entry["urls"], [self.sdist_url])
        self.assertEqual(entry["hashes"], [self.sdist_hash])

    def test_missing_wheel_hash_does_not_shift_the_sdist_hash(self):
        entry = self.write_lock(wheel_hash=False, url_less_wheel=True).packages["demo"]
        self.assertEqual(entry["urls"], [self.wheel_url, self.sdist_url])
        self.assertEqual(entry["hashes"], [None, self.sdist_hash])

    def assessment(self, digest):
        lock = self.write_lock()
        ir = ProjectIR("offline/pylock", str(self.root), locks=[lock])
        intents = build_intents(structured_evidence(ir), ["demo"])
        ctx = Context(
            "locked-sdist", "pip", ["demo==1.0"], faithfulness="verified", request_complete=True,
            project_extras=[], scope=".", lock_mode="frozen", lock_file="pylock.toml",
        )
        # An independently supplied fixture observation; no adapter's evidence
        # booleans or production coverage is changed by these contract controls.
        artifact = Artifact(
            "demo", "1.0", self.sdist_url, "demo-1.0.tar.gz", "sdist", digest, "pypi",
            selected_artifact_verified=True, registry_verified=True,
        )
        return assess_contracts(ir, intents, ctx, artifact)

    def test_valid_sdist_in_mixed_enforced_lock_is_not_a_hash_violation(self):
        assessment = self.assessment(self.sdist_hash)
        self.assertEqual(assessment.status, "pass", assessment.to_dict())
        self.assertEqual(assessment.violations, [])

    def test_hash_outside_enforced_lock_is_still_a_violation(self):
        assessment = self.assessment("d" * 64)
        self.assertEqual(assessment.status, "violation")
        self.assertEqual(assessment.violations[0]["reason"], "selected-hash-outside-enforced-lock")


if __name__ == "__main__":
    unittest.main()
