"""Entry-point checks; installations are never launched by this test module."""
import base64
import contextlib
import hashlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from artifact_tools import replay_cases, run_drc
from artifact_tools._runtime import python_path


class ArtifactEntrypointTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)

    def inputs(self, final_differs=False):
        root = self.root / "inputs"
        files = []
        for state in replay_cases.STATES:
            folder = root / state
            folder.mkdir(parents=True)
            manifest = '[project]\nname="example"\nversion="0"\nrequires-python="==3.11.16"\ndependencies=[]\n'
            lock = 'version=1\n' + ('revision=2\n' if final_differs and state == "base-restored" else '')
            for filename, value in (("pyproject.toml", manifest), ("uv.lock", lock)):
                (folder / filename).write_text(value)
                files.append({"stage": state, "file": filename, "sha256": hashlib.sha256(value.encode()).hexdigest()})
        (root / "inputs.json").write_text(json.dumps({"files": files, "target": "CPython3.11.16 Linux x86_64", "uv": "0.13.7"}))
        return root

    def test_drc_default_is_plan_without_process_or_output(self):
        project = self.root / "project"
        project.mkdir()
        out = self.root / "new-run"
        stream = io.StringIO()
        with patch("subprocess.run", side_effect=AssertionError("dry-run spawned a process")), contextlib.redirect_stdout(stream):
            code = run_drc.main([str(project), "--out", str(out)])
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(stream.getvalue())["mode"], "dry-run")
        self.assertFalse(out.exists())

    def test_selected_venv_interpreter_path_is_preserved(self):
        import sys
        selected = self.root / "venv/bin/python"
        selected.parent.mkdir(parents=True)
        selected.symlink_to(sys.executable)
        self.assertEqual(python_path(selected), selected.absolute())

    def test_drc_refuses_existing_output(self):
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            run_drc.main([str(self.root), "--out", str(self.root)])

    def test_m1_default_does_not_execute_reproducer(self):
        stream = io.StringIO()
        out = self.root / "m1"
        with patch("subprocess.run", side_effect=AssertionError("dry-run spawned a process")), contextlib.redirect_stdout(stream):
            code = replay_cases.main(["m1", "--out", str(out)])
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(stream.getvalue())["mode"], "dry-run")
        self.assertFalse(out.exists())

    def test_m2_default_checks_every_input_without_installation(self):
        inputs = self.inputs()
        out, stream = self.root / "m2", io.StringIO()
        with patch("subprocess.run", side_effect=AssertionError("dry-run spawned a process")), contextlib.redirect_stdout(stream):
            code = replay_cases.main(["m2", "--inputs", str(inputs), "--out", str(out)])
        self.assertEqual(code, 0)
        self.assertEqual(len(json.loads(stream.getvalue())["input_files"]), 6)
        self.assertFalse(out.exists())

    def test_m2_tampered_lock_is_rejected(self):
        inputs = self.inputs()
        (inputs / "extra/uv.lock").write_text("version=9\n")
        with self.assertRaisesRegex(ValueError, "hash mismatch"):
            replay_cases.validate_inputs(inputs)

    def test_m2_changed_final_contract_is_rejected_even_with_valid_hashes(self):
        with self.assertRaisesRegex(ValueError, "final base inputs"):
            replay_cases.validate_inputs(self.inputs(final_differs=True))

    def test_m2_incomplete_state_is_rejected(self):
        inputs = self.inputs()
        (inputs / "base-restored/uv.lock").unlink()
        with self.assertRaises(FileNotFoundError):
            replay_cases.validate_inputs(inputs)

    def test_retained_metadata_does_not_hide_missing_provider_payload(self):
        site = self.root / "site"
        info = site / "opencv_python-1.dist-info"
        info.mkdir(parents=True)
        target = site / "cv2/example.bin"
        target.parent.mkdir()
        target.write_bytes(b"provider")
        expected = "sha256=" + base64.urlsafe_b64encode(hashlib.sha256(b"provider").digest()).decode().rstrip("=")
        (info / "RECORD").write_text(f"cv2/example.bin,{expected},8\n")
        inventory = {"installed": [{"name": "opencv-python", "dist_info": str(info)}]}
        paths = replay_cases.record_paths(inventory, "opencv-python")
        self.assertTrue(replay_cases.payload_observation(paths, inventory)[0]["matches_normal_record"])
        target.unlink()
        observed = replay_cases.payload_observation(paths, inventory)[0]
        self.assertFalse(observed["exists"])
        self.assertFalse(observed["matches_normal_record"])
        self.assertEqual(len(inventory["installed"]), 1)


if __name__ == "__main__":
    unittest.main()
