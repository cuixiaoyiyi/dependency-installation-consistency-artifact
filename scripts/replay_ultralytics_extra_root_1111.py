"""Focused independent real-install replay of a frozen official extras witness."""
import argparse
from datetime import datetime, timezone
from email.parser import BytesParser
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import sys
import tomllib
import zipfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from packaging.utils import canonicalize_name
from scripts.validate_foundational_installs_1111 import COLLECT

BASE = ROOT / "work/stateful-workflows-20261111/review"
SOURCE = BASE / "ultralytics-extra-actual-01"
OUT = BASE / "ultralytics-extra-independent-root-01"
spec = importlib.util.spec_from_file_location("readonly_independent_meta_checker", BASE / "review_saved_partial_stages.py")
checker = importlib.util.module_from_spec(spec)
spec.loader.exec_module(checker)
spec = importlib.util.spec_from_file_location("bounded_frozen_command_helpers", ROOT / "scripts/real_source_switch_workflows_1111.py")
helper = importlib.util.module_from_spec(spec)
spec.loader.exec_module(helper)
PYTHON, UV = helper.NATIVE, helper.UV
SMOKE = "import cv2,numpy as np,json; a=cv2.cvtColor(np.zeros((2,2,3),dtype=np.uint8),cv2.COLOR_BGR2GRAY); assert a.shape==(2,2); print(json.dumps({'version':cv2.__version__,'file':cv2.__file__}))"


def sha(path):
    return helper.sha(path)


def dump(path, value):
    helper.dump(path, value)


def prepare():
    inputs = [SOURCE / "protocol.json", SOURCE / "preparation/base.json", SOURCE / "preparation/extra.json"]
    inputs += [SOURCE / "stages" / stage / filename for stage in ("base", "extra", "base-restored") for filename in ("pyproject.toml", "uv.lock")]
    inputs += [SOURCE / "stages/base-restored/installed.json", SOURCE / "commands/base-restored-sync/command.json"]
    assert all(path.is_file() for path in inputs), "The frozen source stages are not available yet"
    assert helper.load(SOURCE / "commands/base-restored-sync/command.json")["exit"] == 0
    removed = helper.load(SOURCE / "stages/base-restored/installed.json")
    names = {canonicalize_name(d["name"]) for d in removed["installed"]}
    assert "opencv-python" in names and "opencv-python-headless" not in names
    OUT.mkdir(exist_ok=False)
    protocol = {
        "registered_at_utc": helper.now(), "script_sha256": sha(__file__),
        "inputs": {str(path): sha(path) for path in inputs},
        "helpers": {str(path): sha(path) for path in (Path(helper.__file__), Path(checker.__file__), ROOT / "scripts/validate_foundational_installs_1111.py")},
        "sequence": ["empty environment full base sync", "same environment full extra sync", "remove extra using frozen base-restored manifest/lock", "same final inputs reinstall only retained opencv-python"],
        "independence": "Root authored and executes this focused replay in a new project/environment. Every dependency is installed by uv from the original official frozen lock. The first run's official verified content cache is shared, so this is not a cold-cache replication. No no-deps, wheel/metadata edits, manual child insertion or copied installed environment.",
        "start_gate": "The first run's actual removal sync has exit0 and a saved inventory retaining normal OpenCV while removing headless. Its long full-payload audit may still be underway; this independent sequence tests the concrete outcome itself. No positivity or completed first-run controls are inferred from this start gate.",
        "scope": "Verify full actual installed metadata and both checkers; independently verify original archive SHA and the OpenCV cv2 payload bytes and API. Other dependencies' complete payloads are audited in the first full run, not claimed as independently hashed again here. Full first-run same-final fresh and full-reinstall controls remain required for final admission.",
        "limits": {"sync_seconds_each": 1800, "checker_seconds_each": 300, "smoke_seconds_each": 120, "minimum_free_bytes": 60 * 1024**3},
        "counting": "Independent repetition of the same one real root and same known shared-file mechanism. Not a new uv root cause, another affected project, or public submission. Project attribution and novelty require separate review.",
    }
    dump(OUT / "protocol.json", protocol)


def execute():
    protocol = helper.load(OUT / "protocol.json")
    assert sha(__file__) == protocol["script_sha256"]
    assert all(sha(path) == expected for path, expected in {**protocol["inputs"], **protocol["helpers"]}.items())
    assert not (OUT / "started.json").exists()
    dump(OUT / "started.json", {"at_utc": helper.now()})
    project, target = OUT / "project", OUT / "environment"
    project.mkdir()
    env = {k: v for k, v in os.environ.items() if not k.startswith(("PIP_", "UV_")) and k not in ("PYTHONPATH", "PYTHONHOME", "VIRTUAL_ENV", "CONDA_PREFIX")}
    env.update(HOME=str(OUT / "home"), XDG_CONFIG_HOME=str(OUT / "config"), UV_CACHE_DIR=str(SOURCE / "cache-warm"), UV_PROJECT_ENVIRONMENT=str(target), UV_LINK_MODE="copy", UV_PYTHON_DOWNLOADS="never", UV_NO_INPUT="1", PYTHONDONTWRITEBYTECODE="1", PIP_CONFIG_FILE=os.devnull, PIP_DISABLE_PIP_VERSION_CHECK="1")
    result = {"started_at_utc": helper.now(), "protocol_sha256": sha(OUT / "protocol.json"), "stages": [], "status": "unknown", "confirmed_defects": 0}

    def command(label, args, timeout, folder, required=True):
        row = helper.command(args, folder, label, env, timeout)
        if required and row["returncode"]:
            raise RuntimeError("Independent replay command failed: " + label)
        return row

    def capture(label, folder):
        command("inventory", [target / "bin/python", "-B", "-I", "-c", COLLECT], 300, folder)
        inventory = json.loads((folder / "inventory.stdout").read_bytes())
        dump(folder / "installed.json", inventory)
        installed = {canonicalize_name(d["name"]): d for d in inventory["installed"]}
        requests = tomllib.loads((project / "pyproject.toml").read_text())["project"]["dependencies"]
        root_graph = checker.check(requests, installed, inventory["environment"])
        all_graph = checker.check([d["name"] + "==" + d["version"] for d in inventory["installed"]] + requests, installed, inventory["environment"])
        pip = command("pip-check", [PYTHON, "-B", "-m", "pip", "--python", target / "bin/python", "check"], 300, folder, False)
        uv = command("uv-check", [UV, "--no-config", "pip", "check", "--python", target / "bin/python"], 300, folder, False)
        smoke = command("cv2-smoke", [target / "bin/python", "-B", "-I", "-c", SMOKE], 120, folder, False)
        yolo = command("yolo-import", [target / "bin/python", "-B", "-I", "-c", "from ultralytics import YOLO; print(YOLO.__module__)"], 120, folder, False)
        info = Path(installed["opencv-python"]["dist_info"])
        payload = []
        normal_version = installed["opencv-python"]["version"]
        for path, expected in normal_cv2_by_version[normal_version].items():
            actual = info.parent / path
            assert actual.resolve().is_relative_to(target.resolve())
            exists = actual.is_file()
            payload.append({"path": path, "exists": exists, "matches_original_normal": exists and sha(actual) == expected})
        row = {"label": label, "installed_count": len(installed), "names_versions": {name: d["version"] for name, d in installed.items()}, "root_closure": root_graph, "all_base_closure": all_graph, "pip_check_exit": pip["returncode"], "uv_check_exit": uv["returncode"], "cv2_smoke_exit": smoke["returncode"], "yolo_import_exit": yolo["returncode"], "normal_cv2_payload": payload,
               "normal_cv2_missing": sum(not d["exists"] for d in payload), "normal_cv2_mismatches": sum(not d["matches_original_normal"] for d in payload), "manifest_sha256": sha(project / "pyproject.toml"), "lock_sha256": sha(project / "uv.lock")}
        dump(folder / "observation.json", row)
        result["stages"].append(row)
        dump(OUT / "progress.json", result)
        print(json.dumps({key: row[key] for key in ("label", "installed_count", "normal_cv2_missing", "cv2_smoke_exit", "yolo_import_exit")}), flush=True)
        return row

    def clean(row):
        return not row["root_closure"]["violations"] and not row["all_base_closure"]["violations"] and row["pip_check_exit"] == row["uv_check_exit"] == row["cv2_smoke_exit"] == 0 and not row["normal_cv2_mismatches"]

    try:
        worlds = [helper.load(SOURCE / "preparation" / (stage + ".json"))["wheels"] for stage in ("base", "extra")]
        archives = {row["archive_path"]: row for rows in worlds for row in rows}
        for path, wheel in archives.items():
            assert sha(path) == wheel["sha256"]
            provenance = wheel["official_provenance"]
            assert sha(provenance["path"]) == provenance["sha256"]
            if provenance["kind"] == "official_pypi_release":
                original = helper.load(provenance["path"])
                assert any(row["url"] == wheel["url"] and row["filename"] == wheel["filename"] and row["digests"]["sha256"] == wheel["sha256"] and row["size"] == wheel["bytes"] for row in original["urls"])
            else:
                assert provenance["kind"] == "official_pytorch_cpu_simple"
                from urllib.parse import urlsplit, unquote
                anchor = provenance["anchor"]["href"]
                assert urlsplit(anchor).fragment == "sha256=" + wheel["sha256"] and unquote(urlsplit(anchor).path.rsplit("/", 1)[-1]) == wheel["filename"]
                assert anchor in Path(provenance["path"]).read_text()
        normal_cv2_by_version = {}
        for normal in (row for row in archives.values() if row["name"] == "opencv-python"):
            with zipfile.ZipFile(normal["archive_path"]) as wheel:
                normal_cv2_by_version[normal["version"]] = {name: hashlib.sha256(wheel.read(name)).hexdigest() for name in wheel.namelist() if name.startswith("cv2/") and not name.endswith("/")}
                metadata = BytesParser().parsebytes(wheel.read(next(name for name in wheel.namelist() if name.endswith(".dist-info/METADATA"))))
                assert canonicalize_name(metadata["Name"]) == "opencv-python" and metadata["Version"] == normal["version"]
        dump(OUT / "original-cv2-payload.json", {"payload_by_version": normal_cv2_by_version, "verified_complete_original_archives": len(archives)})
        folder = OUT / "00-empty"
        folder.mkdir()
        command("create", [PYTHON, "-m", "venv", "--without-pip", target], 300, folder)
        command("inventory", [target / "bin/python", "-B", "-I", "-c", COLLECT], 300, folder)
        assert not json.loads((folder / "inventory.stdout").read_bytes())["installed"]
        for label in ("base", "extra", "base-restored", "repair-opencv-only"):
            folder = OUT / label
            folder.mkdir()
            source_label = "base-restored" if label == "repair-opencv-only" else label
            for filename in ("pyproject.toml", "uv.lock"):
                shutil.copyfile(SOURCE / "stages" / source_label / filename, project / filename)
                shutil.copyfile(project / filename, folder / filename)
            assert shutil.disk_usage(OUT).free > protocol["limits"]["minimum_free_bytes"]
            argv = [UV, "--no-config", "sync", "--project", project, "--python", PYTHON, "--no-python-downloads", "--no-build", "--locked", "--no-install-project", "--no-default-groups"]
            if label == "repair-opencv-only":
                argv += ["--reinstall-package", "opencv-python"]
            command("sync", argv, 1800, folder)
            for filename in ("pyproject.toml", "uv.lock"):
                assert sha(project / filename) == protocol["inputs"][str(SOURCE / "stages" / source_label / filename)]
            row = capture(label, folder)
            if label == "base":
                assert clean(row), "Independent full base is not healthy"
            elif label == "extra":
                assert not row["root_closure"]["violations"] and row["pip_check_exit"] == row["uv_check_exit"] == 0
        initial, extra, removed, repaired = result["stages"]
        equal = (removed["manifest_sha256"], removed["lock_sha256"]) == (repaired["manifest_sha256"], repaired["lock_sha256"])
        repeated = clean(initial) and clean(repaired) and equal and "opencv-python" in removed["names_versions"] and "opencv-python-headless" not in removed["names_versions"] and removed["normal_cv2_missing"] > 0 and removed["cv2_smoke_exit"] != 0
        result.update(status="independent_real_witness_repeated_first_full_controls_pending" if repeated else "independent_sequence_no_admitted_deletion_witness", same_final_inputs=equal)
    except Exception as exc:
        result.update(status="unknown_or_unsupported_independent_replay", reason=repr(exc))
    result["finished_at_utc"] = helper.now()
    dump(OUT / "results.json", result)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--prepare", action="store_true")
    args = parser.parse_args()
    prepare() if args.prepare else execute()
