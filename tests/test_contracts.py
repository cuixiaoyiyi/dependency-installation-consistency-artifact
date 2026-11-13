"""Offline counterexamples and controls for scoped resolution contracts."""
from __future__ import annotations

import pathlib
import tempfile
import unittest

from drc.contracts import assess_contracts, comparison_eligibility
from drc.intent.structured_evidence import Evidence, E4, structured_evidence
from drc.intent.evidence_graph import build_intents
from drc.model import Artifact, Context, LockInfo, ProjectIR, Resolution, SourceBinding


class ScopedContractTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = pathlib.Path(self.temp.name)
        self.ir = ProjectIR("offline/fixture", str(self.root))

    def context(self, **values):
        ctx = Context("ctx", "uv", ["torch==2.8.0"])
        for key, value in {
            "faithfulness": "verified", "request_complete": True, "scope": ".", "project_file": "pyproject.toml",
            "project_extras": [], "source_bindings_enabled": True,
            "lock_mode": "off", "lock_file": "", "marker_environment": {},
            "snapshot_id": "offline-universe-1", "snapshot_mode": "replay", **values,
        }.items():
            setattr(ctx, key, value)
        return ctx

    def artifact(self, registry="pytorch:cu128", **values):
        artifact = Artifact("torch", "2.8.0+cu128", "https://download.pytorch.org/whl/cu128/torch.whl",
                            "torch.whl", "wheel", "a" * 64, registry)
        artifact.selected_artifact_verified = True
        artifact.registry_verified = True
        for key, value in values.items():
            setattr(artifact, key, value)
        return artifact

    def binding(self, registry="cu128", *, extra=None, marker=None, scope=".", known=True):
        file = "pyproject.toml" if scope == "." else scope + "/pyproject.toml"
        binding = SourceBinding("torch", f"https://download.pytorch.org/whl/{registry}", registry, "uv", file, 1)
        for key, value in {"extra": extra, "marker": marker, "scope": scope, "conditions_known": known}.items():
            setattr(binding, key, value)
        self.ir.bindings.append(binding)
        return binding

    def intents(self):
        return build_intents(structured_evidence(self.ir), ["torch"])

    def assess(self, ctx=None, artifact=None):
        return assess_contracts(self.ir, self.intents(), ctx or self.context(), artifact or self.artifact())

    def test_explicit_source_correct_channel_passes(self):
        self.binding()
        self.assertEqual(self.assess().status, "pass")

    def test_same_registry_family_wrong_cuda_channel_violates(self):
        self.binding()
        assessment = self.assess(artifact=self.artifact("pytorch:cu126"))
        self.assertEqual(assessment.status, "violation")
        self.assertEqual(assessment.violations[0]["expected"]["registry"], "pytorch:cu128")

    def test_conditional_alternatives_do_not_form_global_allow_list(self):
        self.binding("cu128", extra="cu128")
        self.binding("cpu", extra="cpu")
        intents = self.intents()
        self.assertFalse(intents["torch"].conflicting)
        assessment = self.assess(self.context(project_extras=["cu128"]), self.artifact("pytorch:cpu"))
        self.assertEqual(assessment.status, "violation")

    def test_inactive_extra_does_not_constrain_default_install(self):
        self.binding(extra="cu128")
        self.assertEqual(self.assess(artifact=self.artifact("pypi")).violations, [])
        self.assertEqual(self.assess(artifact=self.artifact("pypi")).checks[0].status, "not_applicable")

    def test_unknown_extras_are_not_inferred(self):
        self.binding(extra="cu128")
        self.assertEqual(self.assess(self.context(project_extras=None), self.artifact("pypi")).status, "unknown")

    def test_marker_false_is_not_a_source_contract(self):
        self.binding(marker='sys_platform == "win32"')
        assessment = self.assess(self.context(platform="linux-x86_64"), self.artifact("pypi"))
        self.assertEqual(assessment.violations, [])
        self.assertEqual(assessment.checks[0].status, "not_applicable")

    def test_marker_uses_target_python(self):
        self.binding(marker='python_version >= "3.12"')
        self.assertEqual(self.assess(self.context(python_version="3.12"), self.artifact("pypi")).status, "violation")
        self.assertEqual(self.assess(self.context(python_version="3.11"), self.artifact("pypi")).violations, [])

    def test_missing_marker_variable_never_uses_host_default(self):
        self.binding(marker='platform_machine == "x86_64"')
        self.assertEqual(self.assess(artifact=self.artifact("pypi")).status, "unknown")

    def test_unknown_alternative_cannot_create_spurious_violation(self):
        self.binding("cu128")
        self.binding("cpu", marker='platform_machine == "aarch64"')
        self.assertEqual(self.assess(artifact=self.artifact("pytorch:cpu")).status, "unknown")

    def test_uv_binding_is_not_an_implicit_pip_contract(self):
        self.binding()
        assessment = self.assess(self.context(resolver="pip", source_bindings_enabled=False), self.artifact("pypi"))
        self.assertEqual(assessment.violations, [])
        self.assertEqual(assessment.checks[0].status, "not_applicable")

    def test_nested_project_binding_does_not_constrain_root(self):
        self.binding(scope="examples/demo")
        self.assertEqual(self.assess(artifact=self.artifact("pypi")).violations, [])

    def test_projected_request_cannot_confirm_violation(self):
        self.binding()
        self.assertEqual(self.assess(self.context(faithfulness="projected"), self.artifact("pypi")).status, "unknown")

    def test_unverified_candidate_file_cannot_confirm_violation(self):
        self.binding()
        self.assertEqual(self.assess(artifact=self.artifact("pypi", selected_artifact_verified=False)).status, "unknown")

    def test_verified_file_url_is_not_verified_index_attribution(self):
        self.binding()
        self.assertEqual(self.assess(artifact=self.artifact("pypi", registry_verified=False)).status, "unknown")

    def test_incomplete_request_cannot_confirm_violation(self):
        self.binding()
        self.assertEqual(self.assess(self.context(request_complete=False), self.artifact("pypi")).status, "unknown")

    def test_legacy_binding_conditions_are_unknown(self):
        self.binding(known=False)
        self.assertEqual(self.assess(artifact=self.artifact("pypi")).status, "unknown")

    def test_legacy_uv_extra_is_recovered_from_actual_toml(self):
        (self.root / "pyproject.toml").write_text('[tool.uv.sources]\ntorch = [{ index = "cu128", extra = "cu128" }]\n', encoding="utf-8")
        self.binding(known=False)
        self.assertEqual(self.assess(artifact=self.artifact("pypi")).violations, [])
        self.assertEqual(self.assess(self.context(project_extras=["cu128"]), self.artifact("pypi")).status, "violation")

    def test_llm_quote_and_multiple_context_votes_are_not_contracts(self):
        evidence = [Evidence("torch", E4, 1, "pytorch:cu128", None, "README.md", 1, "quoted instruction", source="llm")]
        intent = build_intents(evidence, ["torch"])
        assessment = assess_contracts(self.ir, intent, self.context(), self.artifact("pypi"))
        self.assertEqual(assessment.status, "unknown")
        self.assertEqual(assessment.violations, [])

    def add_lock(self, *, duplicate=False):
        text = 'version = 1\n[[package]]\nname = "torch"\nversion = "2.8.0+cu128"\n'
        if duplicate:
            text += '[[package]]\nname = "torch"\nversion = "2.8.0+cpu"\n'
        (self.root / "uv.lock").write_text(text, encoding="utf-8")
        self.ir.locks.append(LockInfo("uv.lock", "uv.lock", {"torch": {
            "registry": "pytorch:cu128", "version": "2.8.0+cu128", "hashes": ["sha256:" + "a" * 64],
        }}))

    def test_lock_presence_alone_does_not_bind_unlocked_context(self):
        self.add_lock()
        self.assertEqual(self.assess(artifact=self.artifact("pypi")).violations, [])

    def test_enforced_exact_lock_checks_source_version_and_hash(self):
        self.add_lock()
        ctx = self.context(lock_mode="frozen", lock_file="uv.lock")
        self.assertEqual(self.assess(ctx).status, "pass")
        self.assertEqual(self.assess(ctx, self.artifact(sha256="b" * 64)).status, "violation")
        self.assertEqual(self.assess(ctx, self.artifact(version="2.9.0+cu128")).status, "violation")
        self.assertEqual(self.assess(ctx, self.artifact("pypi")).status, "violation")

    def test_independent_lock_hash_violation_survives_unknown_index_attribution(self):
        self.add_lock()
        ctx = self.context(lock_mode="frozen", lock_file="uv.lock")
        artifact = self.artifact(sha256="b" * 64, registry_verified=False)
        self.assertEqual(self.assess(ctx, artifact).status, "violation")

    def test_different_or_unidentified_lock_does_not_bind(self):
        self.add_lock()
        for lock_file in ("other/uv.lock", ""):
            with self.subTest(lock_file=lock_file):
                self.assertEqual(self.assess(self.context(lock_mode="locked", lock_file=lock_file), self.artifact("pypi")).violations, [])

    def test_flattened_universal_lock_branches_are_unknown(self):
        self.add_lock(duplicate=True)
        self.assertEqual(self.assess(self.context(lock_mode="locked", lock_file="uv.lock"), self.artifact("pypi")).status, "unknown")

    def test_matching_frozen_inputs_are_comparable_without_soundness_claim(self):
        ca, cb = self.context(), self.context()
        cb.id = "other"
        eligibility = comparison_eligibility(ca, cb)
        self.assertTrue(eligibility.eligible, eligibility.reasons)
        self.assertFalse(eligibility.to_dict()["theoretical_soundness_claim"])

    def test_policy_target_or_requirement_changes_are_not_stability_tests(self):
        original = self.context()
        changes = [
            {"resolver": "pip"}, {"requirements": ["torch>=2.8.0"]},
            {"constraints": ["torch<2.9"]}, {"platform": "win-amd64"},
            {"python_version": "3.11"}, {"project_extras": ["cpu"]},
            {"index_strategy": "unsafe-best-match"},
            {"extra_index_urls": ["https://download.pytorch.org/whl/cpu"]},
            {"sources": {"torch": "cpu"}}, {"lock_mode": "frozen", "lock_file": "uv.lock"},
        ]
        for change in changes:
            with self.subTest(change=change):
                other = self.context(**change)
                self.assertFalse(comparison_eligibility(original, other).eligible)

    def test_comparison_needs_frozen_candidate_snapshot(self):
        ca, cb = self.context(snapshot_id=None), self.context(snapshot_id=None)
        self.assertFalse(comparison_eligibility(ca, cb).eligible)

    def test_shared_recording_session_is_not_a_frozen_snapshot(self):
        ca, cb = self.context(snapshot_mode="record"), self.context(snapshot_mode="record")
        self.assertFalse(comparison_eligibility(ca, cb).eligible)

    def resolution(self, ctx, **snapshot_changes):
        result = Resolution(ctx.id, ctx.resolver, True, {"torch": self.artifact()}, 0, "offline", resolver_version="test-version")
        result.snapshot = {"id": "snapshot-1", "mode": "replay", "proxy_verified": True,
                           "complete": True, "sealed": True, "frozen": True,
                           "integrity_verified": True, "manifest_sha256": "fixture-sha256", **snapshot_changes}
        return result

    def test_verified_replayed_resolutions_are_comparable(self):
        ca, cb = self.context(), self.context()
        ra, rb = self.resolution(ca), self.resolution(cb)
        eligibility = comparison_eligibility(ca, cb, ra, rb)
        self.assertTrue(eligibility.eligible, eligibility.reasons)

    def test_same_snapshot_label_with_different_or_incomplete_evidence_is_not_comparable(self):
        ca, cb = self.context(), self.context()
        for change in ({"manifest_sha256": "different"}, {"sealed": False},
                       {"integrity_verified": False}, {"complete": False}, {"proxy_verified": False}):
            with self.subTest(change=change):
                self.assertFalse(comparison_eligibility(ca, cb, self.resolution(ca), self.resolution(cb, **change)).eligible)

    def test_unverified_lock_candidate_cannot_support_a_stability_claim(self):
        ca, cb = self.context(), self.context()
        ra, rb = self.resolution(ca), self.resolution(cb)
        rb.artifacts["torch"].selected_artifact_verified = False
        self.assertFalse(comparison_eligibility(ca, cb, ra, rb).eligible)

    def test_single_context_contract_does_not_need_comparable_pair(self):
        self.binding()
        ca, cb = self.context(), self.context(resolver="pip")
        self.assertFalse(comparison_eligibility(ca, cb).eligible)
        self.assertEqual(self.assess(ca, self.artifact("pypi")).status, "violation")


if __name__ == "__main__":
    unittest.main()
