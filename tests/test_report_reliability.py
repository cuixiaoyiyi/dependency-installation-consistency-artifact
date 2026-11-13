"""Offline regressions for evidence gates, truthful labels, and immutable audits."""
from __future__ import annotations
import copy
import csv
import hashlib
import json
import pathlib
import sys
import tempfile
import unittest
import io
from contextlib import redirect_stdout
from types import SimpleNamespace
from unittest.mock import patch

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "scripts"))
from drc.report import render_issue, write_case_bundle
from drc.report.reliability import assess_case, context_label
from audit_existing_results import audit_results, write_audit
import make_issues
import make_issues_v2
from drc import cli


def context(identifier="a"):
    return {"id": identifier, "resolver": "pip", "requirements": ["widget==1.0"],
            "derived_from": "install-path:readme", "faithfulness": "faithful", "request_complete": True,
            "origin": {"file": "README.md", "line": 8, "command": "python -m pip install -r requirements.txt"},
            "limitations": [], "platform": "linux-x86_64", "python_version": "3.11",
            "snapshot_id": "frozen-one", "snapshot_mode": "replay", "project_extras": []}


def case():
    artifact = {"name": "widget", "version": "1.0", "filename": "widget.whl", "sha256": "abc", "url": "https://example.org/widget.whl", "registry": "example"}
    return {"case_id": "widget-1", "package": "widget", "cls": "SAME_VERSION_DIFF_REGISTRY",
            "type": "C-IntentViolation", "severity": 3, "direct": True, "reqset_origin": "project:runtime",
            "a": {"context": "a", "derived_from": "declared", "factors": {}, "artifact": artifact},
            "b": {"context": "b", "derived_from": "declared", "factors": {}, "artifact": dict(artifact, registry="elsewhere", sha256="def")},
            "triage": {"label": "NEEDS_EXPLANATION", "reason": "Different files"}}


def verified_case():
    value = case()
    value["comparability"] = {"verified": True, "evidence": ["Both original commands target the same declared runtime request and frozen index snapshot"]}
    value["contract_violation"] = {"verified": True, "kind": "relational", "contract": "Both supported entry points must use the hash locked in requirements.txt", "evidence": ["requirements.txt:5 and replayed resolution.json"]}
    return value


class ReportReliabilityTests(unittest.TestCase):
    def setUp(self):
        (ROOT / "work").mkdir(exist_ok=True)
        self.temp = tempfile.TemporaryDirectory(dir=ROOT / "work", prefix="report-test-")
        self.addCleanup(self.temp.cleanup)
        self.directory = pathlib.Path(self.temp.name)

    def test_legacy_oracle_label_is_not_verification(self):
        value = case()
        contexts = {"a": {"id": "a", "derived_from": "declared", "resolver": "pip"}, "b": {"id": "b", "derived_from": "declared", "resolver": "uv"}}
        assessed = assess_case(value, contexts)
        self.assertFalse(assessed["developer_ready"])
        self.assertEqual(assessed["classification"], "difference_observed")
        self.assertFalse(make_issues.real(value))
        text = render_issue(value, contexts, "owner/repo", "commit")
        self.assertIn("internal review", text)
        self.assertNotIn("both correspond to how this project is installed", text)
        self.assertNotIn("reviewed by a researcher", text)

    def test_declared_label_never_invents_install_command(self):
        side = {"context": "a", "derived_from": "declared"}
        contexts = {"a": {"derived_from": "declared", "resolver": "uv", "sources": {"torch": "cu129"}}}
        for label in (context_label(side, contexts), make_issues.ctx_short(side, contexts, {}), make_issues_v2.path_label(side, contexts, {})):
            self.assertIn("extracted requirement set", label)
            self.assertNotIn("uv sync", label)
            self.assertNotIn("install .", label)
        command = make_issues_v2.cmd(side, contexts, ["torch"], "a")
        self.assertIn("No faithful original command", command)
        self.assertNotIn("uv lock", command)

    def test_snapshot_filter_retains_shared_frozen_replay(self):
        value = case()
        value["cls"] = "DIFF_VERSION_SAME_REGISTRY"
        value["a"]["artifact"]["registry"] = "pypi"
        value["b"]["artifact"]["registry"] = "pypi"
        contexts = {"a": context(), "b": dict(context("b"), resolver="uv")}
        self.assertFalse(make_issues.snapshot_skew(value, contexts))
        contexts["b"].pop("snapshot_id")
        self.assertTrue(make_issues.snapshot_skew(value, contexts))

    def test_original_path_and_limits_are_preserved(self):
        contexts = {"a": context(), "b": context("b")}
        contexts["a"]["limitations"] = ["Prior environment state not captured"]
        text = render_issue(case(), contexts, "owner/repo", "commit")
        self.assertIn("README.md", text)
        self.assertIn("python -m pip install -r requirements.txt", text)
        self.assertIn("Prior environment state not captured", text)
        self.assertIn("3.11", text)
        self.assertNotIn("CPython 3.12 (cross-platform", text)

    def test_relational_violation_requires_evidenced_comparison(self):
        contexts = {"a": context(), "b": context("b")}
        value = verified_case()
        self.assertTrue(assess_case(value, contexts)["developer_ready"])
        value["comparability"]["evidence"] = []
        self.assertFalse(assess_case(value, contexts)["developer_ready"])

    def test_single_context_contract_does_not_require_second_context(self):
        value = case()
        value["contract_violation"] = {"verified": True, "kind": "single-context", "side": "a", "contract": "widget must come from the explicitly selected index", "evidence": ["Binding and successful faithful replay"]}
        self.assertTrue(assess_case(value, {"a": context()})["developer_ready"])
        value["contract_violation"].pop("side")
        self.assertFalse(assess_case(value, {"a": context()})["developer_ready"])

    def test_synthetic_or_incomplete_requests_cannot_be_developer_ready(self):
        for change in ({"derived_from": "synthetic:F1"}, {"request_complete": False}, {"faithfulness": "unverified"}, {"limitations": ["flattened extra"]}):
            contexts = {"a": context(), "b": dict(context("b"), **change)}
            self.assertFalse(assess_case(verified_case(), contexts)["developer_ready"], change)

    def test_unverified_bundle_is_observation_and_existing_evidence_is_protected(self):
        contexts = {"a": context(), "b": context("b")}
        directory = write_case_bundle(self.directory / "bundles", case(), contexts, {}, "owner/repo", "commit")
        self.assertTrue((directory / "observation.md").exists())
        self.assertFalse((directory / "issue.md").exists())
        original = (directory / "case.json").read_bytes()
        with self.assertRaises(FileExistsError):
            write_case_bundle(self.directory / "bundles", verified_case(), contexts, {}, "owner/repo", "commit")
        self.assertEqual(original, (directory / "case.json").read_bytes())

    def test_verified_bundle_is_review_draft_without_invented_impact(self):
        contexts = {"a": context(), "b": context("b")}
        directory = write_case_bundle(self.directory / "bundles", verified_case(), contexts, {}, "owner/repo", "commit")
        self.assertTrue((directory / "issue.md").exists())
        text = (directory / "issue.md").read_text()
        self.assertIn("User-visible impact has not been verified", text)
        self.assertNotIn("GPU code may", text)

    def test_manifest_audit_exposes_stripped_pin_and_condition_without_mutating_results(self):
        results, corpus = self.directory / "results", self.directory / "corpus"
        project, repo = results / "owner__repo", corpus / "owner__repo"
        project.mkdir(parents=True)
        repo.mkdir(parents=True)
        contexts = [{"id": "a", "resolver": "pip", "requirements": ["widget"], "derived_from": "declared"}, {"id": "b", "resolver": "uv", "requirements": ["widget"], "sources": {"widget": "gpu"}, "derived_from": "declared"}]
        (project / "rtos.json").write_text(json.dumps([{"contexts": contexts}]))
        (project / "cases_triaged.json").write_text(json.dumps([case()]))
        (repo / "pyproject.toml").write_text('[project]\ndependencies=["widget==2.8.0"]\n[tool.uv.sources]\nwidget=[{index="gpu",extra="cuda"}]\n')
        before = {path: hashlib.sha256(path.read_bytes()).hexdigest() for path in project.iterdir()}
        report = audit_results(results, corpus)
        self.assertEqual(report["summary"]["cases"], 1)
        self.assertEqual(report["summary"]["developer_ready"], 0)
        self.assertTrue(any("does not satisfy" in warning for warning in report["cases"][0]["audit_warnings"]))
        self.assertTrue(any("conditional source" in warning for warning in report["cases"][0]["audit_warnings"]))
        output = self.directory / "audit"
        paths = write_audit(report, output, (results, corpus))
        self.assertEqual(len(paths), 3)
        with (output / "audit.csv").open(encoding="utf-8-sig", newline="") as stream:
            row = next(csv.DictReader(stream))
        self.assertEqual(row["original_oracle_label"], "C-IntentViolation")
        self.assertEqual(row["contract_status"], "unverified")
        self.assertEqual(before, {path: hashlib.sha256(path.read_bytes()).hexdigest() for path in project.iterdir()})
        with self.assertRaises(ValueError):
            write_audit(report, results / "output", (results,))
        with self.assertRaises(FileExistsError):
            write_audit(report, output)

    def test_generators_reject_unverified_drafts_before_rendering(self):
        results = self.directory / "results"
        project = results / "owner__repo"
        project.mkdir(parents=True)
        (project / "rtos.json").write_text(json.dumps([{"contexts": [context(), context('b')]}]))
        previous = make_issues.RESULTS_ROOT
        self.addCleanup(setattr, make_issues, "RESULTS_ROOT", previous)
        make_issues.RESULTS_ROOT = results
        with self.assertRaises(ValueError):
            make_issues.build("owner__repo", [case()], {"owner__repo": {"repo": "owner/repo", "commit": "abc"}})

    def test_post_roundtrip_copies_contexts_and_preserves_input_evidence(self):
        from drc import triage as triage_module
        source, output = self.directory / "inputs", self.directory / "post"
        project = source / "owner__repo"
        project.mkdir(parents=True)
        (project / "findings.json").write_text(json.dumps([verified_case()]))
        (project / "rtos.json").write_text(json.dumps([{"contexts": [context(), context('b')]}]))
        (project / "ir.json").write_text(json.dumps({"install_paths": []}))
        before = {p: p.read_bytes() for p in project.rglob('*') if p.is_file()}
        args = SimpleNamespace(results_dir=str(source), out=str(output), project=None, max_per_project=0,
                               include_consequential=False, force=False, no_content=True, minimize=True, max_probes=2)
        def triage_mock(value, do_content):
            (triage_module.CACHE / 'cache-sentinel').write_text('new cache')
            return {"label": "NEEDS_EXPLANATION", "reason": "Retained for review"}
        previous_cache = triage_module.CACHE
        with patch.object(cli, 'ROOT', self.directory), patch('drc.triage.triage_case', side_effect=triage_mock), patch('drc.minimize.minimize_case', return_value={"status": "not-run"}) as minimize, redirect_stdout(io.StringIO()):
            cli.cmd_post(args)
        self.assertEqual(previous_cache, triage_module.CACHE)
        self.assertEqual(output / 'owner__repo', minimize.call_args.args[2])
        self.assertTrue((output / '_cache/artifacts/cache-sentinel').exists())
        copied = output / 'owner__repo'
        self.assertEqual((project / 'rtos.json').read_bytes(), (copied / 'rtos.json').read_bytes())
        self.assertEqual((project / 'ir.json').read_bytes(), (copied / 'ir.json').read_bytes())
        report = audit_results(output, self.directory / 'corpus')
        self.assertEqual(report['summary']['developer_ready'], 1)
        with patch.object(make_issues, 'RESULTS_ROOT', output):
            text, *_ = make_issues.build('owner__repo', json.loads((copied / 'cases_triaged.json').read_text()), {'owner__repo': {'repo': 'owner/repo', 'commit': 'abc'}})
        self.assertIn('Verified contract violation', text)
        self.assertEqual(before, {p: p.read_bytes() for p in project.rglob('*') if p.is_file()})
        with patch.object(cli, 'ROOT', self.directory), self.assertRaises(FileExistsError):
            cli.cmd_post(args)

    def test_stats_defaults_to_read_only_and_historical_output_is_rejected(self):
        with patch('drc.stats.build_stats', return_value={'projects_analyzed': 0}) as build, redirect_stdout(io.StringIO()):
            cli.cmd_stats(SimpleNamespace(out=None))
        build.assert_called_once_with(cli.ROOT, write=False)
        with patch.object(cli, 'ROOT', self.directory), self.assertRaises(ValueError):
            cli._validate_output(self.directory / 'results' / 'new')
        with self.assertRaises(ValueError):
            cli._validate_output(self.directory / 'input' / 'nested', (self.directory / 'input',))

    def test_existing_corpus_experiment_does_not_overwrite_error_record(self):
        directory = self.directory / 'batch' / 'owner__repo'
        directory.mkdir(parents=True)
        marker = directory / 'error.txt'
        marker.write_text('original evidence')
        args = SimpleNamespace(out=str(directory.parent), force=True, no_llm=True, max_contexts=1, max_rtos=1,
                               snapshot_id='test', snapshot_mode='record', exploratory_live=False)
        with patch('drc.pipeline.ProjectRun') as run:
            run.return_value.run.side_effect = FileExistsError('saved experiment')
            _, status, _ = cli._one({'dir': 'owner__repo', 'repo': 'owner/repo'}, args)
        self.assertEqual(status, 'preserved')
        self.assertEqual(marker.read_text(), 'original evidence')

    def test_retriage_entry_point_is_read_only_until_explicit_invocation(self):
        import retriage
        with patch('drc.cli.cmd_post') as post:
            retriage.main(['--results-dir', str(self.directory / 'input'), '--out', str(self.directory / 'new-post'), '--no-content'])
        args = post.call_args.args[0]
        self.assertEqual(args.results_dir, str(self.directory / 'input'))
        self.assertEqual(args.out, str(self.directory / 'new-post'))
        self.assertFalse(args.force)


if __name__ == "__main__":
    unittest.main()
