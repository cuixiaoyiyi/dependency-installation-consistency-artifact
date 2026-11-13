import os
os.environ.setdefault('DRC_EXEC', 'host')
import pathlib
import tempfile
import unittest
from unittest.mock import patch
import json
from drc.model import Artifact, Context, Resolution
from drc.pipeline import ProjectRun, _classify
from drc.oracle import Diff
from drc.contexts import ReqSet, RTO
from drc.model import ProjectIR


class PipelineReliability(unittest.TestCase):
    def test_experiment_manifest_and_unverified_contrasts_are_separate(self):
        with tempfile.TemporaryDirectory() as td:
            base = pathlib.Path(td)
            source = base / 'source'; source.mkdir()
            (source / 'requirements.txt').write_text('--extra-index-url https://custom.example/simple\ndemo==1\n', encoding='utf-8')
            output = base / 'run'
            def resolve(c, wd):
                wd.mkdir(parents=True, exist_ok=True)
                a = Artifact('demo', '1', 'https://x/demo.whl', 'demo.whl', 'wheel', 'same', 'pypi',
                             selected_artifact_verified=True)
                return Resolution(c.id, c.resolver, True, {'demo': a}, .01, 'controlled test', resolver_version='test', snapshot={'id': c.snapshot_id})
            with patch('drc.pipeline.run_resolver', side_effect=resolve), patch('drc.pipeline.pypi_exists', side_effect=AssertionError('live namespace check forbidden')):
                summary = ProjectRun('demo', source, output, llm=False, max_contexts=3, max_rtos=1).run()
            self.assertEqual(summary['schema'], 'drc-reliability-v2')
            self.assertTrue((output / 'contracts.json').exists())
            manifest = json.loads((output / 'experiment_manifest.json').read_text())
            self.assertIn('requirements.txt', manifest['source_files_sha256'])
            self.assertEqual(summary['verified_contract_contexts'], 0)
            with self.assertRaises(FileExistsError):
                ProjectRun('demo', source, output, llm=False).run()

    def test_strong_legacy_intent_label_does_not_automatically_prove_breach(self):
        class Intent:
            allowed_registries = ['pytorch:cpu']
            tier = 1
            evidence = [{'tier': 1, 'registry': 'pytorch:cpu', 'file': 'uv.lock'}]
            conflicting = False
            note = ''
        ca = Context('a', 'pip', ['demo'])
        cb = Context('b', 'uv', ['demo'])
        a = Artifact('demo', '1', '', '', 'wheel', None, 'pypi').to_dict()
        b = Artifact('demo', '2', '', '', 'wheel', None, 'pytorch:cpu').to_dict()
        case = _classify(Diff('demo', 'DIFF_VERSION_DIFF_REGISTRY', a, b), ca, cb, {'demo': Intent()}, ProjectIR('demo', '.'), RTO('r', ReqSet('r', ['demo'], 'test'), 'test', [ca, cb]))
        self.assertEqual(case['type'], 'B-ResolutionAmbiguity')
        self.assertFalse(case['contract_violation']['verified'])

if __name__ == '__main__':
    unittest.main()
