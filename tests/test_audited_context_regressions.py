"""Regressions for the input mismatches identified in the submitted reports."""
import os
os.environ.setdefault("DRC_EXEC", "host")

import pathlib
import shutil
import tempfile
import unittest

from drc.contexts import generate_rtos, project_index_config, requirement_sets, target_environment
from drc.frontend import parse_project
from drc.frontend.requirements import parse_requirements_file
from drc.frontend.shell import extract_install_paths


CORPUS = pathlib.Path(__file__).resolve().parents[1] / "corpus" / "repos"


class AuditedContextRegressions(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self.temporary.name)

    def tearDown(self):
        self.temporary.cleanup()

    def write(self, name, text):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
        return path

    def observed(self, ir, budget=14):
        return [context for rto in generate_rtos(ir, self.root, budget_contexts=budget)
                for context in rto.contexts if context.origin.get("kind") == "install-path"]

    def copy_original(self, repository, filenames):
        source = CORPUS / repository
        if not source.is_dir():
            self.skipTest("the audited original corpus is unavailable")
        for filename in filenames:
            destination = self.root / filename
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source / filename, destination)

    def test_one_invocation_combines_literal_files_and_constraints(self):
        self.write("one.txt", "--extra-index-url https://one.invalid/simple\none==1\n")
        self.write("nested.txt", "nested[feature]==2; sys_platform == 'linux'\n")
        self.write("two.txt", "-rnested.txt\ntwo==2\n")
        self.write("limits.txt", "one<2\n")
        ir = parse_project(self.root)
        ir.install_paths = extract_install_paths(
            "pip install pytest==8 literal[extra]==3 -r one.txt -r two.txt -c limits.txt",
            "install.sh", "script", "combined", working_directory=".")
        contexts = self.observed(ir)
        self.assertEqual(len(contexts), 1)
        context = contexts[0]
        self.assertEqual(set(context.requirements), {
            "pytest==8", "literal[extra]==3", "one==1", "two==2",
            'nested[feature]==2; sys_platform == "linux"'})
        self.assertEqual(context.constraints, ["one<2"])
        self.assertEqual(context.extra_index_urls, ["https://one.invalid/simple"])
        self.assertEqual(context.origin["requirement_files"], ["one.txt", "two.txt"])
        self.assertTrue(context.request_complete)

    def test_missing_file_keeps_other_parts_but_cannot_be_verified(self):
        self.write("present.txt", "preserved==1\n")
        ir = parse_project(self.root)
        ir.install_paths = extract_install_paths(
            "pip install literal==2 -r present.txt -r absent.txt", "install.sh", "script", "missing",
            working_directory=".")
        context = self.observed(ir)[0]
        self.assertEqual(set(context.requirements), {"literal==2", "preserved==1"})
        self.assertFalse(context.request_complete)
        self.assertNotEqual(context.faithfulness, "verified")
        self.assertTrue(any("absent.txt" in limitation for limitation in context.limitations))

    def test_command_and_file_index_order_is_preserved_or_marked_unknown(self):
        self.write("requirements.txt", "--index-url https://file.invalid/simple\n--extra-index-url https://file-extra.invalid/simple\ndemo==1\n")
        ir = parse_project(self.root)
        ir.install_paths = extract_install_paths(
            "pip install -r requirements.txt --index-url https://command.invalid/simple --extra-index-url https://command-extra.invalid/simple",
            "install.sh", "script", "indexes", working_directory=".")
        context = self.observed(ir)[0]
        self.assertEqual(context.requirements, ["demo==1"])
        self.assertEqual(context.extra_index_urls, ["https://command-extra.invalid/simple", "https://file-extra.invalid/simple"])
        self.assertFalse(context.request_complete)
        self.assertTrue(any("ordered replay" in limitation for limitation in context.limitations))

    def test_include_order_preserves_index_priority_and_original_line(self):
        self.write("child.txt", "--extra-index-url https://child.invalid/simple\nchild==1\n")
        parent = self.write("requirements.txt", "-rchild.txt\n--extra-index-url https://parent.invalid/simple\nparent==1\n")
        parsed = parse_requirements_file(parent, self.root)
        self.assertEqual([index.url for index in parsed["indexes"]], [
            "https://child.invalid/simple", "https://parent.invalid/simple"])
        self.assertEqual([(dependency.file, dependency.line) for dependency in parsed["deps"]], [
            ("child.txt", 2), ("requirements.txt", 3)])

    def test_extra_and_project_dependencies_join_the_same_literal_request(self):
        self.write("pyproject.toml", '''[project]
name = "application"
version = "1"
dependencies = ["runtime==1"]
[project.optional-dependencies]
cpu = ["torch==2.8.0"]
docs = ["sphinx==8"]
''')
        self.write("other.txt", "other==4\n")
        ir = parse_project(self.root)
        ir.install_paths = extract_install_paths(
            "pip install -e '.[cpu,docs]' literal==3 -r other.txt", "install.sh", "script", "project",
            working_directory=".")
        context = self.observed(ir)[0]
        self.assertEqual(set(context.requirements), {"runtime==1", "torch==2.8.0", "sphinx==8", "literal==3", "other==4"})
        self.assertEqual(context.project_extras, ["cpu", "docs"])
        self.assertTrue(context.origin["project_request"])
        self.assertNotEqual(context.faithfulness, "verified")

    def test_original_lock_is_identified_without_certifying_a_new_probe(self):
        self.write("pyproject.toml", '[project]\nname="app"\nversion="1"\ndependencies=["demo==1"]\n')
        self.write("uv.lock", 'version=1\n[[package]]\nname="demo"\nversion="1"\nsource={registry="https://pypi.org/simple"}\n')
        ir = parse_project(self.root)
        ir.install_paths = extract_install_paths("uv sync --frozen", "install.sh", "script", "frozen", working_directory=".")
        context = self.observed(ir, budget=1)[0]
        self.assertEqual(context.lock_mode, "frozen")
        self.assertEqual(context.lock_file, "uv.lock")
        self.assertEqual(context.project_file, "pyproject.toml")
        self.assertEqual(context.requirements, ["demo==1"])
        self.assertEqual(context.origin["command_kind"], "uv sync")
        self.assertNotEqual(context.faithfulness, "verified")

    def test_observed_context_survives_a_one_context_budget(self):
        ir = parse_project(self.root)
        ir.install_paths = extract_install_paths(
            "pip install demo==1 --index-url https://custom.invalid/simple --no-deps",
            "install.sh", "script", "limited", working_directory=".")
        rtos = generate_rtos(ir, self.root, budget_contexts=1)
        self.assertEqual(len(rtos), 1)
        self.assertEqual(len(rtos[0].contexts), 1)
        context = rtos[0].contexts[0]
        self.assertEqual(context.origin["kind"], "install-path")
        self.assertEqual(context.resolver, "pip")
        self.assertTrue(context.no_deps)

    def test_configuration_projection_never_asserts_an_unobserved_installer(self):
        ir = parse_project(self.root)
        ir.install_paths = extract_install_paths(
            "uv pip install torch==2 --index-url https://download.pytorch.org/whl/cu128",
            "install.sh", "script", "uv-only", working_directory=".")
        contexts = [context for rto in generate_rtos(ir, self.root) for context in rto.contexts]
        self.assertEqual({context.resolver for context in contexts if context.origin.get("kind") == "install-path"}, {"uv"})
        self.assertTrue(all(context.faithfulness != "verified" for context in contexts if context.resolver == "pip"))
        self.assertFalse(any("pip install ." in context.description for context in contexts))

    def test_preceding_state_limits_faithfulness_without_losing_the_request(self):
        ir = parse_project(self.root)
        ir.install_paths = extract_install_paths("pip install demo==1", "install.sh", "script", "state", working_directory=".")
        ir.install_paths[0].limitations.append("prior installed environment requires original-sequence replay")
        context = self.observed(ir)[0]
        self.assertEqual(context.requirements, ["demo==1"])
        self.assertTrue(context.request_complete)
        self.assertNotEqual(context.faithfulness, "verified")

    def test_subproject_strategy_does_not_overwrite_root_strategy(self):
        self.write("pyproject.toml", '[project]\nname="root"\nversion="1"\ndependencies=["root-dep"]\n[tool.uv]\nindex-strategy="first-index"\n')
        self.write("child/pyproject.toml", '[project]\nname="child"\nversion="1"\ndependencies=["child-dep"]\n[tool.uv]\nindex-strategy="unsafe-best-match"\n')
        ir = parse_project(self.root)
        self.assertEqual(project_index_config(ir, ".")["uv_strategy"], "first-index")
        self.assertEqual(project_index_config(ir, "child")["uv_strategy"], "unsafe-best-match")

    def test_three_conflicting_sources_do_not_restore_an_arbitrary_binding(self):
        self.write("pyproject.toml", '''[project]
name="app"
version="1"
dependencies=["demo"]
[tool.uv.sources]
demo=[{index="one"},{index="two"},{index="three"}]
[[tool.uv.index]]
name="one"
url="https://one.invalid/simple"
[[tool.uv.index]]
name="two"
url="https://two.invalid/simple"
[[tool.uv.index]]
name="three"
url="https://three.invalid/simple"
''')
        config = project_index_config(parse_project(self.root), marker_environment=target_environment("3.11"))
        self.assertNotIn("demo", config["sources"])
        self.assertIn("multiple active sources for demo", config["limitations"])

    def test_original_videoagent_docker_request_does_not_inherit_root_indexes(self):
        self.copy_original("HKUDS__VideoAgent", ["requirements.txt", "tools/fish-speech/dockerfile"])
        contexts = self.observed(parse_project(self.root))
        context = next(context for context in contexts if context.requirements == ["huggingface_hub"])
        self.assertIsNone(context.index_url)
        self.assertEqual(context.extra_index_urls, [])
        self.assertNotEqual(context.faithfulness, "verified")

    def test_original_evaluation_model_requirements_do_not_inherit_sibling_indexes(self):
        self.copy_original("Vchitect__Evaluation-Agent", [
            "eval_agent/eval_models/show1/requirements.txt", "eval_agent/eval_models/VC09/requirements.txt"])
        ir = parse_project(self.root)
        reqset = next(reqset for reqset in requirement_sets(ir, self.root) if reqset.origin.endswith("show1/requirements.txt"))
        config = project_index_config(ir, reqset.scope, reqset, target_environment("3.11"), tool="pip")
        self.assertEqual(config["extras"], [])
        self.assertFalse(any(context.extra_index_urls for rto in generate_rtos(ir, self.root)
                             if rto.reqset.id == reqset.id for context in rto.contexts))

    def test_original_abogen_keeps_rocm_cuda_extra_selection(self):
        self.copy_original("denizsafak__abogen", ["pyproject.toml"])
        ir = parse_project(self.root)
        sets = requirement_sets(ir, self.root)
        for extra, suffix in (("rocm", "/nightly/rocm6.4"), ("cuda", "/cu128")):
            reqset = next(reqset for reqset in sets if reqset.project_extras == [extra])
            config = project_index_config(ir, reqset.scope, reqset, target_environment("3.11"))
            self.assertTrue(config["sources"]["torch"].endswith(suffix))
            self.assertFalse(any("kokoro" in limitation for limitation in config["limitations"]))

    def test_original_fish_documentation_keeps_project_pins_and_selected_extra(self):
        self.copy_original("fishaudio__fish-speech", ["pyproject.toml", "docs/zh/install.md"])
        contexts = self.observed(parse_project(self.root))
        context = next(context for context in contexts if "uv sync --python 3.12 --extra cu129" in context.origin["command"])
        self.assertIn("torch==2.8.0", context.requirements)
        self.assertIn("torchaudio==2.8.0", context.requirements)
        self.assertEqual(context.project_extras, ["cu129"])
        index_name = context.sources["torch"]
        self.assertTrue(next(index["url"] for index in context.named_indexes if index["name"] == index_name).endswith("/cu129"))
        self.assertNotEqual(context.faithfulness, "verified")
        self.assertTrue(any("override-dependencies" in limitation for limitation in context.limitations))

    def test_original_vsgan_torchvision_invocation_preserves_no_deps(self):
        self.copy_original("styler00dollar__VSGAN-tensorrt-docker", ["Dockerfile"])
        context = next(context for context in self.observed(parse_project(self.root))
                       if context.resolver == "pip" and context.requirements == ["torchvision"]
                       and "--force-reinstall --no-deps" in context.origin["command"])
        self.assertTrue(context.no_deps)
        self.assertEqual(context.index_url, "https://download.pytorch.org/whl/cu130")
        self.assertNotIn("cuda-pathfinder", context.requirements)
        self.assertNotEqual(context.faithfulness, "verified")


if __name__ == "__main__":
    unittest.main()
