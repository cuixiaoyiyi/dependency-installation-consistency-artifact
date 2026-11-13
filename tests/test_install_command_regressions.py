"""Regressions for requests that the submitted-issue audit reconstructed incorrectly."""
from pathlib import Path
import tempfile
import unittest

from drc.frontend.ci import dockerfile, github_workflow, script_file
from drc.frontend.shell import extract_install_paths, parse_install_command


ROOT = Path(__file__).resolve().parents[1]


class InstallCommandRegressions(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def write(self, name, text):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
        return path

    def test_compile_files_and_unsafe_option_values_are_not_package_requests(self):
        command = (
            'uv pip compile "ray/requirements.txt" "ray/cloud-requirements.txt" '
            '--requirements "ray/tests.txt" -rmore.txt -c constraints.txt '
            '--constraint=other.txt --python-version 3.12 '
            '--python-platform x86_64-manylinux_2_31 '
            '--unsafe-package setuptools --unsafe-package ray '
            '--index-strategy unsafe-best-match --no-header -o lock.txt 2>&1'
        )
        parsed = parse_install_command(command)
        self.assertEqual(parsed["packages"], [])
        self.assertEqual(parsed["req_files"], [
            "ray/requirements.txt", "ray/cloud-requirements.txt", "ray/tests.txt", "more.txt",
        ])
        self.assertEqual(parsed["constraint_files"], ["constraints.txt", "other.txt"])
        self.assertEqual(parsed["index_strategy"], "unsafe-best-match")
        self.assertTrue(any("--unsafe-package=ray" in item for item in parsed["limitations"]))
        self.assertTrue(any("--python-version=3.12" in item for item in parsed["limitations"]))
        self.assertTrue(any("x86_64-manylinux_2_31" in item for item in parsed["limitations"]))

    def test_multiple_files_and_explicit_packages_are_retained_together(self):
        paths = extract_install_paths(
            'pip install demo==1 --requirements first.txt -r second.txt -c limits.txt',
            "install.sh", "script", "install", working_directory=".",
        )
        self.assertEqual(paths[0].packages, ["demo==1"])
        self.assertEqual(paths[0].req_files, ["first.txt", "second.txt"])
        self.assertEqual(paths[0].constraint_files, ["limits.txt"])
        self.assertEqual(paths[0].limitations, [])

    def test_unknown_option_cannot_turn_its_value_into_a_dependency(self):
        for command in (
            "pip install --future-policy strict demo",
            "pip install --future-policy=strict demo",
        ):
            with self.subTest(command=command):
                parsed = parse_install_command(command)
                self.assertTrue(parsed["limitations"])
                if "=" not in command:
                    self.assertEqual(parsed["packages"], [])
        paths = extract_install_paths(
            "pip install demo==1 --future-policy strict other", "x.sh", "script", "x",
        )
        self.assertEqual(paths[0].packages, ["demo==1"])
        self.assertTrue(paths[0].limitations)

    def test_missing_option_value_is_explicitly_incomplete(self):
        for option in ("-r", "--requirements", "-c", "--unsafe-package", "--python-version"):
            with self.subTest(option=option):
                parsed = parse_install_command("pip install demo " + option)
                self.assertEqual(parsed["packages"], ["demo"])
                self.assertTrue(any("missing value" in item for item in parsed["limitations"]))

    def test_empty_option_value_is_explicitly_incomplete(self):
        for option in ("--index-url", "--requirements", "--constraint", "--editable", "--unsafe-package"):
            for suffix in ("=", ' ""'):
                with self.subTest(option=option, suffix=suffix):
                    parsed = parse_install_command("pip install demo " + option + suffix)
                    self.assertEqual(parsed["packages"], ["demo"])
                    self.assertTrue(any("missing value" in item for item in parsed["limitations"]))

    def test_redirection_does_not_split_or_add_a_request(self):
        paths = extract_install_paths(
            'pip install "demo>=1; python_version < \'3.12\'" > build.log 2>&1 && pip install child',
            "x.sh", "script", "x", working_directory=".",
        )
        self.assertEqual(len(paths), 2)
        self.assertEqual(paths[0].packages, ["demo>=1; python_version < '3.12'"])
        self.assertEqual(paths[1].packages, ["child"])
        self.assertTrue(any("sequential" in item for item in paths[1].limitations))

    def test_end_of_options_preserves_positionals_and_does_not_activate_flags(self):
        parsed = parse_install_command("pip install -- demo")
        self.assertEqual(parsed["packages"], ["demo"])
        self.assertEqual(parsed["limitations"], [])
        parsed = parse_install_command("pip install -- --pre")
        self.assertFalse(parsed["pre"])
        self.assertTrue(parsed["limitations"])

    def test_unquoted_shell_comparison_is_not_claimed_as_a_version_constraint(self):
        parsed = parse_install_command("pip install demo>=2")
        self.assertEqual(parsed["packages"], ["demo"])
        self.assertTrue(any("redirection" in item for item in parsed["limitations"]))

    def test_uv_tool_and_project_extras_have_distinct_positions(self):
        parsed = parse_install_command("uv tool install demo[cuda] --python 3.12")
        self.assertEqual(parsed["packages"], ["demo[cuda]"])
        parsed = parse_install_command("uv sync --locked --extra cpu --extra=docs")
        self.assertEqual(parsed["extras_of_project"], ["cpu", "docs"])
        self.assertEqual(parsed["lock_mode"], "locked")
        self.assertEqual(parsed["limitations"], [])

    def test_non_current_local_target_is_not_assumed_to_be_the_root_project(self):
        for command in ("pip install ./child[cpu]", "pip install -e ./child[cpu]"):
            with self.subTest(command=command):
                parsed = parse_install_command(command)
                self.assertTrue(parsed["editable_local"])
                self.assertEqual(parsed["extras_of_project"], ["cpu"])
                self.assertTrue(any("original-path" in item for item in parsed["limitations"]))

    def test_prior_installs_and_uninstalls_are_not_replaced_with_a_fresh_environment(self):
        paths = extract_install_paths(
            'pip install torch==2.8.0\npip uninstall -y torch\npip install -e ".[cpu]"',
            "x.sh", "script", "x", working_directory=".",
        )
        self.assertEqual(len(paths), 2)
        self.assertTrue(any("sequential" in item for item in paths[1].limitations))

    def test_script_environment_is_scanned_in_order(self):
        path = self.write("x.sh", "pip install demo\nexport PIP_INDEX_URL=https://later/simple\npip install other\n")
        paths = script_file(path, "x.sh")
        self.assertIsNone(paths[0].index_url)
        self.assertEqual(paths[1].index_url, "https://later/simple")

    def test_windows_matrix_and_setup_python_are_not_replayed_as_linux_defaults(self):
        path = self.write(".github/workflows/test.yml", '''jobs:
  release:
    runs-on: windows-latest
    strategy:
      matrix:
        python: ["3.10", "3.12"]
    steps:
      - uses: actions/setup-python@v5
        with:
          python-version: ${{ matrix.python }}
      - run: pip install torch==2.8.0
      - if: runner.os == 'Windows'
        run: pip install -e .
''')
        paths = github_workflow(path, ".github/workflows/test.yml")
        self.assertEqual(len(paths), 2)
        self.assertTrue(any("windows-latest" in item for item in paths[0].limitations))
        self.assertTrue(any("matrix" in item for item in paths[0].limitations))
        self.assertTrue(any("CI Python" in item for item in paths[0].limitations))
        self.assertTrue(any("condition" in item for item in paths[1].limitations))
        self.assertTrue(any("earlier CI steps" in item for item in paths[1].limitations))

    def test_docker_stages_do_not_leak_index_environment(self):
        path = self.write("Dockerfile", '''FROM python:3.10 AS build
ENV PIP_INDEX_URL=https://build/simple
RUN pip install build
FROM python:3.12
RUN pip install demo --no-deps
''')
        paths = dockerfile(path, "Dockerfile")
        self.assertEqual(len(paths), 2)
        self.assertEqual(paths[0].index_url, "https://build/simple")
        self.assertIsNone(paths[1].index_url)
        self.assertTrue(paths[1].no_deps)
        self.assertTrue(any("python:3.12" in item for item in paths[1].limitations))

    def test_global_docker_arg_is_not_an_implicit_run_environment(self):
        path = self.write("Dockerfile", '''ARG PIP_INDEX_URL=https://global/simple
FROM python:3.12
RUN pip install first
ARG PIP_INDEX_URL
RUN pip install second
ARG PIP_INDEX_URL=https://stage/simple
RUN pip install third
''')
        paths = dockerfile(path, "Dockerfile")
        self.assertEqual([item.index_url for item in paths], [None, None, "https://stage/simple"])
        self.assertTrue(any("ARG redeclaration" in item for item in paths[1].limitations))

    def test_audited_ray_scripts_do_not_create_a_bare_ray_requirement(self):
        for repo in ("mitkox__vllm-turboquant", "guqiong96__Lvllm"):
            with self.subTest(repo=repo):
                path = ROOT / "corpus" / "repos" / repo / ".buildkite/scripts/check-ray-compatibility.sh"
                if not path.exists():
                    self.skipTest("audited corpus snapshot is unavailable")
                paths = script_file(path, ".buildkite/scripts/check-ray-compatibility.sh")
                compiled = [item for item in paths if item.command_kind == "uv pip compile"]
                self.assertEqual(len(compiled), 1)
                self.assertEqual(compiled[0].packages, [])
                self.assertFalse(compiled[0].editable_local)
                self.assertTrue(compiled[0].limitations)
                self.assertIn("--unsafe-package ray", compiled[0].command)

    def test_audited_vsgan_command_keeps_no_deps(self):
        path = ROOT / "corpus/repos/styler00dollar__VSGAN-tensorrt-docker/Dockerfile"
        if not path.exists():
            self.skipTest("audited corpus snapshot is unavailable")
        paths = dockerfile(path, "Dockerfile")
        matched = [item for item in paths if "torchvision" in item.packages and "--no-deps" in item.command]
        self.assertTrue(matched)
        self.assertTrue(all(item.no_deps for item in matched))
        self.assertFalse(any("cuda-pathfinder" in item.packages for item in matched))


if __name__ == "__main__":
    unittest.main()
