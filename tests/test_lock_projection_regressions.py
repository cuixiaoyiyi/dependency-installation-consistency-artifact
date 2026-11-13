"""Regression coverage for target-specific lock graphs and reported presence."""
from __future__ import annotations

from dataclasses import fields
import json
from pathlib import Path
import subprocess
import tempfile
import tomllib
import unittest
from unittest.mock import patch

from packaging.markers import default_environment

from drc import resolvers
from drc.model import Artifact, Context, Resolution
from drc.oracle import compare_artifacts, diff_resolutions, INSUFFICIENT_EVIDENCE, ONLY_IN_A
from drc.resolvers import project_uv_lock


ROOT = Path(__file__).resolve().parents[1]
ENVIRONMENT = {**default_environment(), "implementation_name": "cpython", "implementation_version": "3.11.16",
               "platform_python_implementation": "CPython", "python_version": "3.11", "python_full_version": "3.11.16",
               "sys_platform": "linux", "os_name": "posix", "platform_system": "Linux", "platform_machine": "x86_64"}
SOURCE = {"registry": "https://pypi.org/simple"}


def package(name, dependencies=(), *, version="1.0", source=None, **kwargs):
    return {"name": name, "version": version, "source": SOURCE if source is None else source,
            "dependencies": list(dependencies), **kwargs}


def lock(dependencies, packages):
    return {"requires-python": ">=3.8", "package": [
        package("drc-probe", dependencies, source={"virtual": "."}), *packages]}


def context(requirements, **kwargs):
    return Context("target", "uv", requirements, python_version="3.11", marker_environment=dict(ENVIRONMENT),
                   request_complete=True, **kwargs)


class LockProjectionTests(unittest.TestCase):
    def test_target_graph_excludes_inactive_markers_and_unreachable_packages(self):
        data = lock([{"name": "pyzmq"}], [package("pyzmq", [{"name": "cffi", "marker": "implementation_name == 'pypy'"}]),
                                           package("cffi"), package("unreachable")])
        artifacts, evidence = project_uv_lock(data, context(["pyzmq"]))
        self.assertEqual(evidence["status"], "verified", evidence)
        self.assertEqual(set(artifacts), {"pyzmq"})
        self.assertIn("implementation_name", artifacts["pyzmq"].requires_dist[0])
        self.assertFalse(artifacts["pyzmq"].selected_artifact_verified)

    def test_requested_extras_propagate_only_to_their_dependencies(self):
        data = lock([{"name": "pytest-cov"}], [package("pytest-cov", [{"name": "coverage", "extra": ["toml"]}]),
            package("coverage", **{"optional-dependencies": {
                "toml": [{"name": "tomli", "marker": "python_full_version < '3.11.3'"}],
                "unused": [{"name": "unwanted"}]}}), package("tomli"), package("unwanted")])
        artifacts, evidence = project_uv_lock(data, context(["pytest-cov"]))
        self.assertEqual(evidence["status"], "verified", evidence)
        self.assertEqual(set(artifacts), {"pytest-cov", "coverage"})
        older = {**ENVIRONMENT, "python_full_version": "3.11.2", "implementation_version": "3.11.2"}
        artifacts, evidence = project_uv_lock(data, context(["pytest-cov"]), older)
        self.assertEqual(evidence["status"], "verified", evidence)
        self.assertIn("tomli", artifacts)
        self.assertNotIn("unwanted", artifacts)

    def test_root_extra_and_optional_marker_are_both_required(self):
        data = lock([], [package("gpu")])
        data["package"][0]["optional-dependencies"] = {"cuda": [{"name": "gpu", "marker": "sys_platform == 'linux'"}]}
        artifacts, evidence = project_uv_lock(data, context(["gpu"], project_extras=["cuda"]))
        self.assertEqual(evidence["status"], "verified", evidence)
        self.assertIn("gpu", artifacts)
        artifacts, evidence = project_uv_lock(data, context([], project_extras=[]))
        self.assertEqual(evidence["status"], "verified", evidence)
        self.assertEqual(artifacts, {})

    def test_repeated_root_requirements_union_their_requested_extras(self):
        data = lock([{"name": "demo", "extra": ["a", "b"]}], [package("demo", **{"optional-dependencies": {
            "a": [{"name": "first"}], "b": [{"name": "second"}]}}), package("first"), package("second")])
        artifacts, evidence = project_uv_lock(data, context(["demo[a]", "demo[b]"]))
        self.assertEqual(evidence["status"], "verified", evidence)
        self.assertEqual(set(artifacts), {"demo", "first", "second"})

    def test_fork_selection_preserves_version_and_exact_source(self):
        source = {"registry": "https://cuda.invalid/simple"}
        data = lock([{"name": "demo", "version": "1.0", "source": source}], [
            package("demo", source=source, **{"resolution-markers": ["sys_platform == 'linux'"]}),
            package("demo", source={"registry": "https://cpu.invalid/simple"}),
            package("demo", version="2.0", source=source)])
        artifacts, evidence = project_uv_lock(data, context(["demo==1.0"]))
        self.assertEqual(evidence["status"], "verified", evidence)
        self.assertEqual(evidence["selected"][0]["source"], source)
        self.assertEqual(artifacts["demo"].version, "1.0")
        data["package"][0]["dependencies"] = [{"name": "demo"}]
        artifacts, evidence = project_uv_lock(data, context(["demo"]))
        self.assertEqual(evidence["status"], "unknown")
        self.assertEqual(artifacts["demo"].selection_evidence, "uv-lock-fork-unverified")

    def test_fork_resolution_markers_select_one_version(self):
        data = lock([{"name": "demo"}], [
            package("demo", version="1.0", **{"resolution-markers": ["python_full_version < '3.11.3'"]}),
            package("demo", version="2.0", **{"resolution-markers": ["python_full_version >= '3.11.3'"]})])
        artifacts, evidence = project_uv_lock(data, context(["demo"]))
        self.assertEqual(evidence["status"], "verified", evidence)
        self.assertEqual(artifacts["demo"].version, "2.0")

    def test_unknown_marker_variable_remains_unknown_without_host_fallback(self):
        data = lock([{"name": "demo"}], [package("demo", [{"name": "cffi", "marker": "implementation_name == 'pypy'"}]), package("cffi")])
        ctx = context(["demo"])
        del ctx.marker_environment["implementation_name"]
        artifacts, evidence = project_uv_lock(data, ctx)
        self.assertEqual(evidence["status"], "unknown")
        self.assertIn("cffi", artifacts)
        self.assertTrue(any("marker-not-evaluable" in reason for reason in evidence["reasons"]))

    def test_root_and_constraint_mismatches_are_not_certified(self):
        data = lock([{"name": "demo"}], [package("demo")])
        for ctx in (context(["other"]), context(["demo>=2"]), context(["demo"], constraints=["demo>=2"])):
            with self.subTest(requirements=ctx.requirements, constraints=ctx.constraints):
                _, evidence = project_uv_lock(data, ctx)
                self.assertEqual(evidence["status"], "unknown")

    def test_legacy_missing_root_does_not_manufacture_verified_presence(self):
        artifacts, evidence = project_uv_lock({"package": [package("demo")]}, context(["demo"]))
        self.assertEqual(evidence["status"], "unknown")
        self.assertIn("demo", artifacts)
        self.assertEqual(compare_artifacts(artifacts["demo"], None).cls, INSUFFICIENT_EVIDENCE)

    def test_adapter_projects_graph_and_uses_exact_interpreter_target(self):
        ctx = context(["demo"])
        text = '''version = 1
requires-python = "==3.11.16"
[[package]]
name = "drc-probe"
version = "0.0.0"
source = {virtual = "."}
dependencies = [{name = "demo"}]
[[package]]
name = "demo"
version = "1.0"
source = {registry = "https://pypi.org/simple"}
'''
        def fake_run(cmd, cwd, *args):
            generated = tomllib.loads((cwd / "pyproject.toml").read_text())
            self.assertEqual(generated["project"]["requires-python"], "==3.11.16")
            self.assertIn('implementation_name == "cpython"', generated["tool"]["uv"]["environments"][0])
            (cwd / "uv.lock").write_text(text)
            return subprocess.CompletedProcess(cmd, 0, "", ""), "uv lock (offline regression)"
        with tempfile.TemporaryDirectory() as directory, patch.object(resolvers, "_preflight", return_value=""), \
                patch.object(resolvers, "_prepare_snapshot", return_value={}), \
                patch.object(resolvers, "_resolver_version"), patch.object(resolvers, "_run", side_effect=fake_run), \
                patch.object(resolvers, "_target_marker_environment", return_value=ENVIRONMENT):
            result = resolvers.run_uv(ctx, Path(directory))
        self.assertEqual(result.graph_projection["status"], "verified", result.graph_projection)
        self.assertEqual(set(result.artifacts), {"demo"})
        self.assertFalse(result.artifacts["demo"].selected_artifact_verified)

    def test_project_lock_commands_are_refused_before_extracted_replay(self):
        for origin, mode in (({"project_request": True}, "unknown"), ({"command_kind": "uv sync"}, "unknown"), ({}, "frozen")):
            with self.subTest(origin=origin, mode=mode), patch.object(resolvers, "_run") as run:
                result = resolvers.run_uv(context(["demo"], origin=origin, lock_mode=mode), ROOT / "work/unused-lock-test")
                self.assertFalse(result.ok)
                self.assertIn("project/lock replay", result.error)
                run.assert_not_called()

    @unittest.skipUnless((ROOT / "work/issue-audit-20261110/marker-checks.json").exists(), "saved research evidence is unavailable")
    def test_seven_saved_false_positive_locks_project_to_native_target(self):
        records = json.loads((ROOT / "work/issue-audit-20261110/marker-checks.json").read_text())
        allowed = {field.name for field in fields(Context)}
        self.assertEqual(len(records), 7)
        for row in records:
            with self.subTest(issue=row["issue"], package=row["package"]):
                base = ROOT / "reports" / row["project"] / row["case_id"]
                contexts = [json.loads((base / f"context_{side}.json").read_text()) for side in ("a", "b")]
                original = next(value for value in contexts if value["resolver"] == "uv")
                ctx = Context(**{key: value for key, value in original.items() if key in allowed})
                report_path = next((ROOT / "results/projects" / row["project"] / "runs").glob("*pip*/pip-report.json"))
                native = json.loads(report_path.read_text())["environment"]
                data = tomllib.loads((ROOT / row["raw_lock"].replace("\\", "/")).read_text())
                artifacts, evidence = project_uv_lock(data, ctx, native)
                self.assertEqual(evidence["status"], "verified", evidence["reasons"])
                self.assertNotIn(row["package"], artifacts)
                self.assertTrue(artifacts)


class PresenceEvidenceTests(unittest.TestCase):
    def artifact(self, verified=True):
        return Artifact("demo", "1.0", "https://example.invalid/demo.whl", "demo.whl", "wheel", "a" * 64,
                        "pypi", selected_artifact_verified=verified)

    def resolution(self, artifacts, *, verified=True, environment=None):
        return Resolution("test", "uv", True, artifacts, 0, "offline", graph_projection={
            "status": "verified" if verified else "unknown", "environment": dict(ENVIRONMENT if environment is None else environment),
            "selected": [{"name": name} for name in artifacts]})

    def test_unknown_unselected_single_sided_candidate_is_insufficient(self):
        self.assertEqual(compare_artifacts(self.artifact(False), None).cls, INSUFFICIENT_EVIDENCE)
        left = self.resolution({"demo": self.artifact()}, verified=False)
        right = Resolution("legacy", "pip", True, {}, 0, "offline")
        self.assertEqual(diff_resolutions(left, right)[0].cls, INSUFFICIENT_EVIDENCE)

    def test_verified_file_and_verified_absence_preserve_positive_difference(self):
        left = self.resolution({"demo": self.artifact()}, verified=False)
        right = self.resolution({})
        self.assertEqual(diff_resolutions(left, right)[0].cls, ONLY_IN_A)
        self.assertEqual(compare_artifacts(self.artifact(), None).cls, ONLY_IN_A)

    def test_verified_graph_membership_can_establish_graph_difference(self):
        left = self.resolution({"demo": self.artifact(False)})
        right = self.resolution({})
        self.assertEqual(diff_resolutions(left, right)[0].cls, ONLY_IN_A)
        right.graph_projection["environment"]["implementation_name"] = "pypy"
        self.assertEqual(diff_resolutions(left, right)[0].cls, INSUFFICIENT_EVIDENCE)


class PipReportTargetTests(unittest.TestCase):
    def report(self, environment):
        return {"environment": environment, "install": [{
            "metadata": {"name": "demo", "version": "1.0"}, "requested": True,
            "download_info": {"url": "https://example.invalid/demo-1.0-py3-none-any.whl",
                              "archive_info": {"hashes": {"sha256": "a" * 64}}}}]}

    def test_complete_native_report_verifies_graph_and_preserves_selected_file(self):
        ctx = Context("pip", "pip", ["demo"], python_version="3.11.16")
        artifacts, evidence = resolvers.project_pip_report(self.report(dict(ENVIRONMENT)), ctx)
        self.assertEqual(evidence["status"], "verified", evidence)
        self.assertTrue(artifacts["demo"].selected_artifact_verified)
        self.assertEqual(evidence["selected"][0]["sha256"], "a" * 64)

    def test_each_missing_target_field_prevents_verified_absence(self):
        for key in ENVIRONMENT:
            with self.subTest(key=key):
                environment = dict(ENVIRONMENT)
                del environment[key]
                artifacts, evidence = resolvers.project_pip_report(self.report(environment), context(["demo"]))
                self.assertEqual(evidence["status"], "unknown", evidence)
                self.assertTrue(artifacts["demo"].selected_artifact_verified)
                self.assertTrue(any("target-environment-incomplete" in reason for reason in evidence["reasons"]))

    def test_wrong_minor_or_explicit_patch_is_not_a_verified_target(self):
        for requested in ("3.12", "3.11.15"):
            with self.subTest(requested=requested):
                ctx = Context("pip", "pip", ["demo"], python_version=requested)
                artifacts, evidence = resolvers.project_pip_report(self.report(dict(ENVIRONMENT)), ctx)
                self.assertEqual(evidence["status"], "unknown", evidence)
                self.assertIn("target-python-does-not-match-request", evidence["reasons"])
                self.assertTrue(artifacts["demo"].selected_artifact_verified)

    def test_os_and_arch_must_match_the_context_for_both_adapters(self):
        data = lock([{"name": "demo"}], [package("demo")])
        for key, value in (("sys_platform", "win32"), ("os_name", "nt"),
                           ("platform_system", "Windows"), ("platform_machine", "aarch64")):
            with self.subTest(key=key):
                environment = {**ENVIRONMENT, key: value}
                _, pip_evidence = resolvers.project_pip_report(self.report(environment), context(["demo"]))
                _, uv_evidence = project_uv_lock(data, context(["demo"]), environment)
                for evidence in (pip_evidence, uv_evidence):
                    self.assertEqual(evidence["status"], "unknown", evidence)
                    self.assertIn("target-platform-does-not-match-request", evidence["reasons"])

    def test_python_marker_fields_must_describe_one_complete_version(self):
        for environment, expected in (({**ENVIRONMENT, "python_full_version": "3.11"}, "target-python-patch-version-missing"),
                                      ({**ENVIRONMENT, "python_version": "3.12"}, "target-python-marker-fields-disagree")):
            with self.subTest(environment=environment):
                _, evidence = resolvers.project_pip_report(self.report(environment), context(["demo"]))
                self.assertEqual(evidence["status"], "unknown", evidence)
                self.assertIn(expected, evidence["reasons"])


if __name__ == "__main__":
    unittest.main()
