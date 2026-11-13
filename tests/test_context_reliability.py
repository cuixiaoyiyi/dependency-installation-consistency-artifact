import os
os.environ.setdefault('DRC_EXEC', 'host')
import pathlib
import tempfile
import unittest
from unittest.mock import patch

from drc.frontend import parse_project
from drc.frontend.requirements import parse_requirements_file, parse_requirements_text
from drc.frontend.shell import extract_install_paths
from drc.contexts import requirement_sets, generate_rtos, project_index_config, target_environment
from drc.model import Artifact
from drc.oracle import compare_artifacts, SAME_VERSION_DIFF_HASH_SAME_REGISTRY, INSUFFICIENT_EVIDENCE


class ContextReliability(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self.tmp.name)
    def tearDown(self):
        self.tmp.cleanup()
    def write(self, name, text):
        p = self.root / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding='utf-8')
        return p

    def test_conditional_sources_are_not_last_wins(self):
        self.write('pyproject.toml', '''[project]
name = "demo"
version = "0.1"
dependencies = ["torch==2.8.0"]
[project.optional-dependencies]
cpu = ["torchaudio==2.8.0"]
cu129 = ["torchaudio==2.8.0"]
[tool.uv.sources]
torch = [{index="cpu",extra="cpu"},{index="cuda",extra="cu129"}]
[[tool.uv.index]]
name="cpu"
url="https://download.pytorch.org/whl/cpu"
explicit=true
[[tool.uv.index]]
name="cuda"
url="https://download.pytorch.org/whl/cu129"
explicit=true
''')
        ir = parse_project(self.root)
        sets = requirement_sets(ir, self.root)
        self.assertEqual({b.extra for b in ir.bindings}, {'cpu', 'cu129'})
        for rs in sets:
            cfg = project_index_config(ir, rs.scope, rs, target_environment('3.11'))
            if rs.project_extras == ['cpu']:
                self.assertEqual(cfg['sources']['torch'], 'https://download.pytorch.org/whl/cpu')
            elif rs.project_extras == ['cu129']:
                self.assertEqual(cfg['sources']['torch'], 'https://download.pytorch.org/whl/cu129')
            else:
                self.assertNotIn('torch', cfg['sources'])
        contexts = [c for r in generate_rtos(ir, self.root) for c in r.contexts]
        self.assertTrue(contexts)
        self.assertTrue(all('torch==2.8.0' in c.requirements for c in contexts))
        self.assertFalse(any(c.faithfulness == 'verified' for c in contexts))
        self.assertFalse(any(c.named_indexes for c in contexts if c.resolver == 'pip'))

    def test_subprojects_do_not_share_runtime_or_sources(self):
        self.write('pyproject.toml', '[project]\nname="root"\nversion="1"\ndependencies=["root-lib==1"]\n')
        self.write('child/pyproject.toml', '[project]\nname="child"\nversion="1"\ndependencies=["child-lib==2"]\n')
        sets = requirement_sets(parse_project(self.root), self.root)
        self.assertEqual(len(sets), 2)
        self.assertEqual({tuple(s.requirements) for s in sets}, {('root-lib==1',), ('child-lib==2',)})

    def test_request_not_silently_truncated(self):
        self.write('requirements.txt', '\n'.join(f'dep{i}==1' for i in range(130)))
        rs = requirement_sets(parse_project(self.root), self.root)[0]
        self.assertEqual(len(rs.requirements), 130)

    def test_markers_keep_quotes(self):
        r = parse_requirements_text('demo>=1; sys_platform == "linux" --hash=sha256:abc', 'requirements.txt')
        self.assertEqual(r['deps'][0].spec, 'demo>=1; sys_platform == "linux"')
        self.assertEqual(r['deps'][0].hashes, ['sha256:abc'])

    def test_recursive_flags_constraints_and_missing_refs(self):
        p = self.write('requirements.txt', '-r nested.txt\n-c constraints.txt\n')
        self.write('nested.txt', '--no-index\n--require-hashes\ndemo==1\n')
        self.write('constraints.txt', '-c more.txt\ndemo<2\n')
        self.write('more.txt', 'dep==3\n')
        r = parse_requirements_file(p, self.root)
        self.assertTrue(r['flags']['no_index'])
        self.assertTrue(r['flags']['require_hashes'])
        self.assertEqual(set(r['constraints']), {'demo<2', 'dep==3'})
        self.write('nested.txt', '-r missing.txt\n')
        self.assertTrue(parse_requirements_file(p, self.root)['limitations'])

    def test_env_does_not_leak_backward_or_from_inline_assignment(self):
        text = 'pip install demo\nexport PIP_INDEX_URL=https://one/simple\npip install demo\nPIP_INDEX_URL=https://two/simple pip install demo\npip install demo\n'
        ips = extract_install_paths(text, 'x.sh', 'script', 'x', working_directory='.')
        self.assertEqual([p.index_url for p in ips], [None, 'https://one/simple', 'https://two/simple', 'https://one/simple'])

    def test_ci_working_directory_preserved(self):
        self.write('.github/workflows/test.yml', 'jobs:\n  test:\n    defaults:\n      run:\n        working-directory: child\n    steps:\n      - run: pip install demo==1 --no-deps --no-index\n')
        ir = parse_project(self.root)
        ip = ir.install_paths[0]
        self.assertEqual(ip.working_directory, 'child')
        self.assertTrue(ip.no_deps and ip.no_index)

    def test_quoted_marker_is_not_a_shell_separator(self):
        ips = extract_install_paths('pip install "demo; python_version < \'3.11\'" --extra-index-url https://x/simple', 'x', 'ci', 'x', working_directory='.')
        self.assertEqual(len(ips), 1)
        self.assertIn('python_version', ips[0].packages[0])
        self.assertEqual(ips[0].extra_index_urls, ['https://x/simple'])

    def test_environment_resolution_flags_and_constraints_are_preserved(self):
        ips = extract_install_paths('PIP_NO_INDEX=1 PIP_PRE=1 PIP_CONSTRAINT=constraints.txt pip install demo', 'x', 'ci', 'x', working_directory='.')
        self.assertTrue(ips[0].no_index and ips[0].pre)
        self.assertEqual(ips[0].constraint_files, ['constraints.txt'])

    def test_mixed_or_unresolved_requests_never_become_verified(self):
        self.write('extras.txt', '--extra-index-url https://x/simple\nextra==1\n')
        self.write('.github/workflows/test.yml', 'jobs:\n  test:\n    steps:\n      - run: pip install demo -r extras.txt\n      - run: pip install demo "$OPTIONAL" --extra-index-url https://x/simple\n')
        ir = parse_project(self.root)
        ctxs = [c for r in generate_rtos(ir, self.root) for c in r.contexts if c.derived_from.startswith('install-path:')]
        self.assertTrue(ctxs)
        self.assertTrue(all(c.faithfulness != 'verified' for c in ctxs))

    def test_requirement_indexes_do_not_leak_to_siblings(self):
        self.write('requirements.txt', '--extra-index-url https://one/simple\ndemo==1\n')
        self.write('child/requirements.txt', '--extra-index-url https://two/simple\nother==1\n')
        ir = parse_project(self.root)
        for rs in requirement_sets(ir, self.root):
            cfg = project_index_config(ir, rs.scope, rs, target_environment('3.11'), tool='pip')
            self.assertEqual(cfg['extras'], ['https://two/simple'] if rs.scope == 'child' else ['https://one/simple'])

    def test_multiple_primary_indexes_are_not_merged_or_verified(self):
        self.write('requirements.txt', '--index-url https://one/simple\n--index-url https://two/simple\ndemo==1\n')
        ir = parse_project(self.root)
        rs = requirement_sets(ir, self.root)[0]
        cfg = project_index_config(ir, rs.scope, rs, target_environment('3.11'), tool='pip')
        self.assertEqual(cfg['primary'], 'https://two/simple')
        self.assertEqual(cfg['extras'], [])
        self.assertTrue(cfg['limitations'])
        self.assertFalse(rs.request_complete)

    def test_file_comparison_requires_observed_selection(self):
        a = Artifact('demo', '1', 'https://x/a.whl', 'a.whl', 'wheel', 'a', 'pypi')
        b = Artifact('demo', '1', 'https://x/b.whl', 'b.whl', 'wheel', 'b', 'pypi')
        self.assertEqual(compare_artifacts(a, b).cls, INSUFFICIENT_EVIDENCE)
        a.selected_artifact_verified = b.selected_artifact_verified = True
        self.assertEqual(compare_artifacts(a, b).cls, SAME_VERSION_DIFF_HASH_SAME_REGISTRY)
        b.url = a.url
        self.assertEqual(compare_artifacts(a, b).cls, SAME_VERSION_DIFF_HASH_SAME_REGISTRY)

    def test_forked_lock_and_absent_artifacts_are_unknown(self):
        a = Artifact('demo', '1', '', '', 'unknown', None, 'pypi', selection_evidence='uv-lock-fork-unverified')
        b = Artifact('demo', '2', '', '', 'unknown', None, 'pypi')
        self.assertEqual(compare_artifacts(a, b).cls, INSUFFICIENT_EVIDENCE)
        self.assertEqual(compare_artifacts(None, None).cls, INSUFFICIENT_EVIDENCE)

if __name__ == '__main__':
    unittest.main()
