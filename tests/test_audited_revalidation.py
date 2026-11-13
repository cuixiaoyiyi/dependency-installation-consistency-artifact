"""Regression coverage for re-evaluating historical evidence without upgrading it."""
from __future__ import annotations

import json
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from drc.contexts import ReqSet, RTO, generate_rtos
from drc.frontend import parse_project
from drc.model import Artifact, Context, Dependency, ProjectIR, Resolution
from drc.oracle import Diff, diff_resolutions, ONLY_IN_A
from drc.pipeline import _classify, _prioritize
from drc.report.reliability import assess_case
from revalidate_audited_cases import _context_changes, _read_resolution


class CapturedEvidenceRegressions(unittest.TestCase):
    def test_uv_pip_retains_scoped_indexes_without_project_source_bindings(self):
        with tempfile.TemporaryDirectory(dir=ROOT / "work") as directory:
            source = Path(directory)
            (source / "pyproject.toml").write_text(
                '[project]\nname="sample"\nversion="1"\ndependencies=["child"]\n'
                '[[tool.uv.index]]\nname="private"\nurl="https://private.example/simple"\n'
                '[tool.uv.sources]\nchild={index="private"}\n', encoding="utf-8")
            (source / "install.sh").write_text('uv pip install child\n', encoding="utf-8")
            ir = parse_project(source)
            ir.install_paths[0].working_directory = "."
            contexts = [context for request in generate_rtos(ir, source) for context in request.contexts
                        if context.derived_from.startswith("install-path:")]
            self.assertEqual(len(contexts), 1)
            self.assertEqual(contexts[0].named_indexes[0]["url"], "https://private.example/simple")
            self.assertEqual(contexts[0].sources, {})

    def test_plain_public_index_project_can_be_included_in_a_predefined_comparison_sample(self):
        with tempfile.TemporaryDirectory(dir=ROOT / "work") as directory:
            source = Path(directory)
            (source / "pyproject.toml").write_text(
                '[project]\nname="sample"\nversion="1"\ndependencies=["child==1"]\n', encoding="utf-8")
            ir = parse_project(source)
            requests = generate_rtos(ir, source, include_plain_declared=True)
            self.assertTrue(requests)
            contexts = requests[0].contexts
            self.assertEqual({context.resolver for context in contexts if context.derived_from == "declared"}, {"pip", "uv"})
            self.assertTrue(all(context.requirements == ["child==1"] for context in contexts))

    def test_extra_evaluation_context_does_not_hide_a_verified_target_graph_difference(self):
        environment = {"python_full_version": "3.11.16", "implementation_name": "cpython"}
        artifact = Artifact("child", "1", "", "", "unselected", None, "pypi")
        left = Resolution("a", "uv", True, {"child": artifact}, 0, "lock",
                          graph_projection={"status": "verified", "environment": {**environment, "extra": ""},
                                            "selected": [{"name": "child"}]})
        right = Resolution("b", "pip", True, {}, 0, "report",
                           graph_projection={"status": "verified", "environment": environment, "selected": []})
        self.assertEqual(diff_resolutions(left, right)[0].cls, ONLY_IN_A)

    def test_other_subproject_declaration_does_not_make_a_transitive_package_direct(self):
        project = ProjectIR("demo", ".", dependencies=[Dependency("certifi", "certifi==1", "other/requirements.txt", 1)])
        left = Context("a", "pip", ["huggingface_hub"])
        right = Context("b", "uv", ["huggingface_hub"])
        request = RTO("r", ReqSet("r", ["huggingface_hub"], "install-path:docker"), "index-policy", [left, right])
        result = _classify(Diff("certifi", "DIFF_VERSION_DIFF_REGISTRY", None, None),
                           left, right, {}, project, request)
        self.assertFalse(result["direct"])
        request.reqset.requirements = ["certifi>=1"]
        self.assertTrue(_classify(Diff("certifi", "DIFF_VERSION_DIFF_REGISTRY", None, None),
                                  left, right, {}, project, request)["direct"])

    def test_budget_prefers_observed_command_over_uninvoked_project_projection(self):
        projected = RTO("declared", ReqSet("r", ["demo"], "pyproject:runtime:pyproject.toml"), "declared",
                        [Context("declared", "pip", ["demo"], derived_from="declared")])
        command = RTO("observed", ReqSet("ip", ["demo", "child"], "install-path:readme"), "install",
                      [Context("readme", "pip", ["demo", "child"], derived_from="install-path:readme")])
        self.assertIs(_prioritize([projected, command], ProjectIR("demo", "."))[0], command)

    def test_incomplete_file_selection_is_not_reported_as_an_observed_difference(self):
        record = {"cls": "INSUFFICIENT_EVIDENCE", "a": {"context": "old-a"}, "b": {"context": "old-b"}}
        result = assess_case(record, {})
        self.assertFalse(result["observed_difference"])
        self.assertFalse(result["developer_ready"])
        self.assertEqual(result["classification"], "insufficient_evidence")

    def test_new_source_context_does_not_certify_old_unconstrained_execution(self):
        saved = {"id": "old", "requirements": ["torch"], "constraints": [],
                 "derived_from": "declared", "resolver": "pip"}
        regenerated = dict(saved, requirements=["torch==2.8.0"], request_complete=True,
                           faithfulness="verified", origin={"command": "pip install torch==2.8.0"})
        changes = _context_changes(saved, regenerated)
        self.assertEqual(changes["requirements"]["recorded"], ["torch"])
        self.assertEqual(changes["requirements"]["regenerated"], ["torch==2.8.0"])
        record = {"cls": "DIFF_VERSION_DIFF_REGISTRY", "a": {"context": "old"}, "b": {"context": "old"}}
        self.assertFalse(assess_case(record, {"old": saved})["developer_ready"])
        self.assertNotIn("origin", saved)

    def test_old_artifact_summary_cannot_replace_a_missing_original_pip_report(self):
        with tempfile.TemporaryDirectory(dir=ROOT / "work") as directory:
            run = Path(directory)
            (run / "resolution.json").write_text(json.dumps({"ok": True, "artifacts": {"old": {}}}), encoding="utf-8")
            result = _read_resolution(run, Context("legacy", "pip", ["old"]), {})
            self.assertFalse(result.ok)
            self.assertIn("pip report missing", result.error)
            self.assertEqual(result.artifacts, {})


if __name__ == "__main__":
    unittest.main()
