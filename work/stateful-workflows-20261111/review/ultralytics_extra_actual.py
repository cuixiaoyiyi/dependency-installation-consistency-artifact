"""Complete official Ultralytics runtime-extra transition; immutable per-run evidence."""
from datetime import datetime, timezone
from email.parser import BytesParser
from html.parser import HTMLParser
import argparse
from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import time
import tomllib
import urllib.request
from urllib.parse import unquote, urlsplit, urldefrag
import zipfile

from packaging.markers import default_environment
from packaging.requirements import Requirement
from packaging.tags import sys_tags
from packaging.utils import canonicalize_name, parse_wheel_filename

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT))
from drc.model import Context
from drc.resolvers.lock_projection import project_uv_lock
from scripts.review_recovery_1111 import check_metadata
from scripts.stateful_fast_file_audit_1111 import audit_files
from scripts.validate_foundational_installs_1111 import COLLECT

PYTHON = ROOT / "work/runtime-linux/bin/python"
UV = ROOT / "work/runtime-linux/bin/uv"
MAX_STATE = 16 * 1024**3
MIN_FREE = 60 * 1024**3
SMOKE = "import cv2,numpy as np,json; a=cv2.cvtColor(np.zeros((2,2,3),dtype=np.uint8),cv2.COLOR_BGR2GRAY); assert a.shape==(2,2); print(json.dumps({'cv2_version':cv2.__version__,'cv2_file':cv2.__file__,'cvtColor_shape':list(a.shape)}))"


def now(): return datetime.now(timezone.utc).isoformat()
def digest(path):
    h = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for block in iter(lambda: stream.read(4 * 1024**2), b""):
            h.update(block)
    return h.hexdigest()
def load(path): return json.loads(Path(path).read_bytes())
def dump(path, value):
    path = Path(path); path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_suffix(path.suffix + ".tmp")
    temp.write_text(json.dumps(value, indent=2) + "\n"); temp.replace(path)


def env(out, cache):
    result = {key: value for key, value in os.environ.items() if not key.startswith(("PIP_", "UV_", "DRC_")) and key not in {"PYTHONPATH", "PYTHONHOME", "VIRTUAL_ENV", "CONDA_PREFIX"}}
    result.update(HOME=str(out / "home"), XDG_CONFIG_HOME=str(out / "config"), PIP_CONFIG_FILE=os.devnull, PIP_DISABLE_PIP_VERSION_CHECK="1", PIP_CACHE_DIR=str(out / "pip-cache"), UV_CACHE_DIR=str(cache), UV_PYTHON_DOWNLOADS="never", UV_LINK_MODE="copy", UV_NO_PROGRESS="1", PYTHONNOUSERSITE="1", PYTHONDONTWRITEBYTECODE="1", NO_COLOR="1", YOLO_AUTOINSTALL="false", YOLO_CONFIG_DIR=str(out / "ultralytics-config"))
    return result


def command(out, label, argv, environment, cwd=None, timeout=900, required=True):
    folder = out / "commands" / label; folder.mkdir(parents=True, exist_ok=False)
    began = time.monotonic()
    with (folder / "stdout").open("wb") as stdout, (folder / "stderr").open("wb") as stderr:
        process = subprocess.Popen(list(map(str, argv)), cwd=cwd or out, env=environment, stdout=stdout, stderr=stderr, start_new_session=True)
        timed_out = False
        try: code = process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL); code = process.wait(); timed_out = True
    record = {"argv": list(map(str, argv)), "cwd": str(cwd or out), "exit": code, "timeout": timed_out, "seconds": round(time.monotonic() - began, 3), "stdout_sha256": digest(folder / "stdout"), "stderr_sha256": digest(folder / "stderr"), "environment_controls": {key: environment.get(key) for key in ["UV_CACHE_DIR", "UV_PROJECT_ENVIRONMENT", "UV_LINK_MODE", "PIP_CONFIG_FILE", "PYTHONDONTWRITEBYTECODE", "YOLO_AUTOINSTALL"]}}
    dump(folder / "command.json", record)
    print(json.dumps({"step": label, "exit": code, "seconds": record["seconds"]}), flush=True)
    if required and code: raise RuntimeError("command failed: " + label)
    return record, (folder / "stdout").read_text(errors="replace")


def capture(url, path, cap=8 * 1024**2):
    path = Path(path)
    if path.exists():
        record = load(str(path) + ".http.json"); assert digest(path) == record["sha256"]; return load(path) if path.suffix == ".json" else path.read_bytes()
    with urllib.request.urlopen(urllib.request.Request(url, headers={"User-Agent": "ultralytics-stateful-extra-review/1111"}), timeout=90) as response:
        raw = response.read(cap + 1); assert len(raw) <= cap
        record = {"url": url, "final_url": response.url, "status": response.status, "headers": dict(response.headers), "at_utc": now(), "bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}
    path.parent.mkdir(parents=True, exist_ok=True); path.write_bytes(raw); dump(str(path) + ".http.json", record)
    return json.loads(raw) if path.suffix == ".json" else raw


def manifest(extra):
    req = "ultralytics" + ("[extra]" if extra else "") + "==8.4.208"
    # These are exact active requirements from the authentic current native root
    # METADATA. Direct repetition activates the official named CPU index only.
    requirements = [req, "torch>=1.8.0", "torchvision>=0.9.0"]
    return ('[project]\nname="ultralytics-official-extra-control"\nversion="0.0.0"\nrequires-python="==3.11.16"\ndependencies=' + json.dumps(requirements) + '\n\n[tool.uv]\npackage=false\nenvironments=[\'sys_platform == "linux" and platform_machine == "x86_64" and python_full_version == "3.11.16"\']\n\n[tool.uv.sources]\ntorch={index="pytorch-cpu"}\ntorchvision={index="pytorch-cpu"}\n\n[[tool.uv.index]]\nname="pytorch-cpu"\nurl="https://download.pytorch.org/whl/cpu"\nexplicit=true\n\n[[tool.uv.index]]\nname="pypi"\nurl="https://pypi.org/simple"\ndefault=true\n')


def active_lock(project, environment):
    original = tomllib.loads((project / "uv.lock").read_text())
    data = deepcopy(original)
    virtual = [item for item in data["package"] if item.get("source") == {"virtual": "."}]
    assert len(virtual) == 1
    virtual[0]["name"] = "drc-probe"
    requests = tomllib.loads((project / "pyproject.toml").read_text())["project"]["dependencies"]
    context = Context("ultralytics-full-extra", "uv", requests, python_version="3.11.16", platform="linux-x86_64", marker_environment=environment)
    _, evidence = project_uv_lock(data, context, environment)
    assert evidence["status"] == "verified", evidence
    native = {tag: index for index, tag in enumerate(sys_tags())}
    candidates = []
    for selected in evidence["selected"]:
        matches = [node for node in original["package"] if node["name"] == selected["name"] and node.get("version") == selected["version"] and node.get("source") == selected["source"]]
        assert len(matches) == 1
        choices = []
        for wheel in matches[0].get("wheels", []):
            url = wheel.get("url") or matches[0]["source"].get("url")
            if not url: continue
            filename = unquote(urlsplit(url).path.rsplit("/", 1)[-1])
            try: wheel_tags = parse_wheel_filename(filename)[3]
            except Exception: continue
            ranks = [native[tag] for tag in wheel_tags if tag in native]
            if ranks: choices.append((min(ranks), url, wheel, filename))
        if not choices: raise RuntimeError("no native wheel in complete selected lock: " + selected["name"])
        _, url, wheel, filename = min(choices, key=lambda row: (row[0], row[1]))
        assert wheel.get("hash", "").startswith("sha256:")
        size = wheel.get("size")
        size_source = "lockfile"
        if size is None:
            # Official PyTorch Simple does not publish wheel sizes into uv.lock.
            # A body-free HEAD establishes the full native payload bound before
            # any archive download; no dependency is omitted from the budget.
            with urllib.request.urlopen(urllib.request.Request(url, method="HEAD", headers={"User-Agent": "complete-extra-size-preflight/1111"}), timeout=60) as response:
                size = int(response.headers["Content-Length"])
                record = {"url": url, "final_url": response.url, "method": "HEAD", "status": response.status, "headers": dict(response.headers), "at_utc": now(), "size": size, "body_bytes_read": 0}
            head_path = project.parent / "size-head" / (filename + ".json")
            if not head_path.exists(): dump(head_path, record)
            size_source = str(head_path)
        assert size > 0
        candidates.append({"name": selected["name"], "version": selected["version"], "source": selected["source"], "url": url, "filename": filename, "bytes": size, "size_source": size_source, "sha256": wheel["hash"].split(":", 1)[1]})
    size = sum(row["bytes"] for row in candidates)
    assert size <= MAX_STATE and shutil.disk_usage(project).free >= MIN_FREE
    return {"requests": requests, "active_graph": evidence, "candidates": candidates, "selected_compressed_bytes": size, "max_state_bytes": MAX_STATE, "free_bytes": shutil.disk_usage(project).free}


class Links(HTMLParser):
    def __init__(self): super().__init__(); self.rows = []
    def handle_starttag(self, tag, attrs):
        if tag == "a": self.rows.append(dict(attrs))


def existing_archives():
    result = {}
    for pattern in ["work/expanded-validation-20261111/foundational-installs/runs/*/wheelhouse/*.whl", "work/stateful-workflows-20261111/foundational/cases/*/artifacts/wheelhouse/*.whl", "work/stateful-workflows-20261111/published/run1/cases/*/artifacts/wheelhouse/*.whl"]:
        for path in ROOT.glob(pattern): result.setdefault(path.name, []).append(path)
    return result


def prepare_archives(out, label, budget, reuse):
    began = time.monotonic(); rows = []; transferred = 0
    for row in budget["candidates"]:
        if time.monotonic() - began > 900: raise RuntimeError("artifact preparation900-second budget exhausted")
        host = urlsplit(row["url"]).hostname
        provenance = {}
        if host == "files.pythonhosted.org":
            release = out / "official-release-json" / (row["name"] + "--" + row["version"] + ".json")
            data = capture("https://pypi.org/pypi/" + row["name"] + "/" + row["version"] + "/json", release)
            matches = [file for file in data["urls"] if file["url"] == row["url"] and file["filename"] == row["filename"]]
            assert len(matches) == 1 and matches[0]["digests"]["sha256"] == row["sha256"] and matches[0]["size"] == row["bytes"]
            provenance = {"kind": "official_pypi_release", "path": str(release), "sha256": digest(release)}
        elif host in {"download.pytorch.org", "download-r2.pytorch.org"}:
            index_path = out / "official-cpu-index" / (row["name"] + ".html")
            raw = capture("https://download.pytorch.org/whl/cpu/" + row["name"] + "/", index_path)
            parser = Links(); parser.feed(raw.decode())
            matches = [anchor for anchor in parser.rows if unquote(urlsplit(anchor.get("href", "")).path.rsplit("/", 1)[-1]) == row["filename"] and urlsplit(anchor["href"]).fragment == "sha256=" + row["sha256"]]
            assert matches, row
            provenance = {"kind": "official_pytorch_cpu_simple", "path": str(index_path), "sha256": digest(index_path), "anchor": matches[0]}
        else: raise RuntimeError("unregistered artifact publisher: " + str(host))
        archive = out / "artifacts" / row["filename"]
        source = None
        if archive.exists(): assert archive.stat().st_size == row["bytes"] and digest(archive) == row["sha256"]
        else:
            archive.parent.mkdir(parents=True, exist_ok=True)
            source = next((path for path in reuse.get(row["filename"], []) if path.stat().st_size == row["bytes"] and digest(path) == row["sha256"]), None)
            if source: shutil.copyfile(source, archive)
            else:
                temp = archive.with_name(archive.name + ".partial")
                with urllib.request.urlopen(urllib.request.Request(row["url"], headers={"User-Agent": "complete-extra-artifact-proof/1111"}), timeout=90) as response, temp.open("wb") as stream:
                    count = 0; hasher = hashlib.sha256()
                    while block := response.read(4 * 1024**2):
                        if time.monotonic() - began > 900: raise RuntimeError("artifact preparation900-second budget exhausted")
                        count += len(block); transferred += len(block); assert count <= row["bytes"] and transferred <= MAX_STATE
                        hasher.update(block); stream.write(block)
                    assert count == row["bytes"] and hasher.hexdigest() == row["sha256"]
                    dump(str(archive) + ".http.json", {"url": row["url"], "final_url": response.url, "status": response.status, "headers": dict(response.headers), "bytes": count, "sha256": hasher.hexdigest(), "at_utc": now()})
                temp.replace(archive)
        assert digest(archive) == row["sha256"]
        payload = {}
        with zipfile.ZipFile(archive) as wheel:
            for member in wheel.infolist():
                if member.is_dir() or member.filename.endswith(".dist-info/RECORD"): continue
                assert not member.filename.startswith("/") and ".." not in Path(member.filename).parts
                raw = wheel.read(member)
                payload[member.filename] = {"sha256": hashlib.sha256(raw).hexdigest(), "bytes": len(raw)}
            metadata_name = next(name for name in payload if name.endswith(".dist-info/METADATA"))
            raw_meta = wheel.read(metadata_name)
        meta = BytesParser().parsebytes(raw_meta)
        assert canonicalize_name(meta["Name"]) == row["name"] and meta["Version"] == row["version"]
        meta_path = out / "original-metadata" / (row["filename"] + ".METADATA"); meta_path.parent.mkdir(exist_ok=True); meta_path.write_bytes(raw_meta)
        rows.append({**row, "archive_path": str(archive), "official_provenance": provenance, "reused_readonly_source": str(source) if source else None, "metadata_sha256": payload[metadata_name]["sha256"], "payload": payload})
    dump(out / "preparation" / (label + ".json"), {"seconds": time.monotonic() - began, "downloaded_body_bytes": transferred, "wheels": rows})
    print(json.dumps({"prepared": label, "wheels": len(rows), "new_download_bytes": transferred}), flush=True)
    return rows


def capture_stage(out, label, target, environment, requests, wheels, project=None):
    stage = out / "stages" / label; stage.mkdir(parents=True, exist_ok=False)
    if project:
        for name in ["pyproject.toml", "uv.lock"]: shutil.copyfile(project / name, stage / name)
    _, text = command(out, label + "-inventory", [target / "bin/python", "-B", "-I", "-c", COLLECT], environment, timeout=180)
    inventory = json.loads(text); dump(stage / "installed.json", inventory)
    for dist in inventory["installed"]:
        stored = stage / "metadata" / canonicalize_name(dist["name"]); stored.mkdir(parents=True)
        for filename in ["METADATA", "WHEEL", "RECORD", "INSTALLER", "direct_url.json"]:
            source = Path(dist["dist_info"]) / filename
            if source.exists(): shutil.copyfile(source, stored / filename)
    artifacts = {canonicalize_name(item["name"]): item for item in inventory["installed"]}
    graph = check_metadata(requests, [], artifacts, inventory["environment"])
    all_graph = check_metadata([item["name"] + "==" + item["version"] for item in inventory["installed"]] + requests, [], artifacts, inventory["environment"])
    files = audit_files(inventory, wheels, target); dump(stage / "file-audit.json", files)
    pip_check, _ = command(out, label + "-pip-check", [PYTHON, "-B", "-m", "pip", "--python", target / "bin/python", "check"], environment, timeout=300, required=False)
    uv_check, _ = command(out, label + "-uv-check", [UV, "--no-config", "pip", "check", "--python", target / "bin/python"], environment, timeout=300, required=False)
    command(out, label + "-pip-inspect", [PYTHON, "-B", "-m", "pip", "--python", target / "bin/python", "inspect", "--local"], environment, timeout=300)
    smoke, _ = command(out, label + "-cv2-smoke", [target / "bin/python", "-B", "-I", "-c", SMOKE], environment, timeout=120, required=False)
    info = next(item for item in inventory["installed"] if canonicalize_name(item["name"]) == "opencv-python")
    site = Path(info["dist_info"]).parent
    normal = next(wheel for wheel in wheels if wheel["name"] == "opencv-python" and wheel["version"] == info["version"])
    cv2 = []
    for relative, expected in normal["payload"].items():
        if not relative.startswith("cv2/"): continue
        path = site / relative
        actual = {"exists": path.is_file()}
        if actual["exists"]: actual.update(sha256=digest(path), bytes=path.stat().st_size)
        cv2.append({"path": relative, "expected": expected, "actual": actual, "matches": actual.get("sha256") == expected["sha256"] and actual.get("bytes") == expected["bytes"]})
    result = {"label": label, "requests": requests, "names_versions": {name: value["version"] for name, value in artifacts.items()}, "root_closure": graph, "all_installed_base_closure": all_graph, "file_violations": files["violations"], "file_unknowns": files["unknown"], "pip_check_exit": pip_check["exit"], "uv_check_exit": uv_check["exit"], "cv2_smoke_exit": smoke["exit"], "normal_opencv_cv2_files": cv2, "normal_opencv_cv2_missing": [row["path"] for row in cv2 if not row["actual"]["exists"]], "normal_opencv_cv2_mismatches": [row["path"] for row in cv2 if not row["matches"]], "manifest_sha256": digest(project / "pyproject.toml") if project else None, "lock_sha256": digest(project / "uv.lock") if project else None}
    dump(stage / "results.json", result)
    print(json.dumps({"captured": label, "nodes": len(artifacts), "closure_conflicts": len(graph["constraint_conflicts"]), "file_violations": len(files["violations"]), "cv2_missing": len(result["normal_opencv_cv2_missing"]), "cv2_smoke_exit": smoke["exit"]}), flush=True)
    return result


def prepare(out):
    out.mkdir(parents=True, exist_ok=False)
    cohort = ROOT / "work/stateful-validation-20261111/cohort.json"
    row = next(item for item in load(cohort)["roots"] if item["canonical_name"] == "ultralytics")
    assert row["version"] == "8.4.208" and row["target_python"] == "3.11.16"
    protocol = {"schema": "ultralytics-full-official-extra-actual-workflow-v1", "registered_at_utc": now(), "script_sha256": digest(Path(__file__)), "root": "ultralytics==8.4.208", "extra": "extra", "cohort_sha256": digest(cohort), "native_python": str(PYTHON), "native_environment": row["marker_environment"], "uv_sha256": digest(UV), "consumer_input": "Repeat original active torch>=1.8.0 and torchvision>=0.9.0 directly to activate official named CPU source. Main exact pin and runtime extra unchanged; no dependency deletion, metadata edit, old Albumentations pin or no-deps.", "pure_pypi_difference": "Torch and torchvision come from their official CPU index instead of default PyPI GPU builds. All other packages use official PyPI; complete unmodified upstream artifacts only.", "max_compressed_bytes_each_state": MAX_STATE, "minimum_disk_free_bytes": MIN_FREE, "lock_and_preparation_seconds_each": 900, "sync_seconds_each": 1800, "artifact_proof": "Before each actual sync, choose target-active lock candidates, enforce complete16GiB bound and verify original full archives by official PyPI/CPU-index SHA. Full original payload/METADATA and installed RECORD are audited; no file is repaired between transition stages.", "sequence": ["lock/prepare complete base then empty-env full sync and baseline check+cv2 smoke", "lock/prepare same exact root with published extra; full warm sync", "remove only requested extra; relock and strict warm sync", "same final manifest/lock in empty fresh env with separate cold cache", "same final manifest/lock forced full reinstall in warm env", "if feasible complete pip install base, add extra, request base again against the identical prepared official wheel union; ordinary pip residuals are expected observations"], "admission": "Actual retained base cv2 file loss/import failure after extra removal, a healthy original base, exact final-input fresh/reinstall controls and independent repetition required. Attribute mutual-exclusive dependency declarations to the consumer project; do not invent a new uv root cause from known shared-file ownership limitations.", "limits": ["Wheel-only native coverage; missing native artifacts, budgets, commands, system libraries or builds remain unknown/unsupported, not a package-deletion defect.", "This is the explicit official CPU consumer configuration, not an unmodified pure-PyPI repository environment.", "OpenCV and Albumentations/Torch are dependency-chain nodes, not additional affected root projects.", "No public issue is sent, no old evidence or root source scripts/caches are modified."], "helper_sha256": {path: digest(ROOT / path) for path in ["scripts/stateful_fast_file_audit_1111.py", "scripts/stateful_real_workflows_1111.py", "scripts/validate_foundational_installs_1111.py", "scripts/review_recovery_1111.py", "drc/resolvers/lock_projection.py", "drc/model.py"]}}
    dump(out / "protocol.json", protocol)
    for name, url in [("ultralytics-quickstart", "https://raw.githubusercontent.com/ultralytics/ultralytics/v8.4.208/docs/en/quickstart.md"), ("ultralytics-pyproject", "https://raw.githubusercontent.com/ultralytics/ultralytics/v8.4.208/pyproject.toml"), ("uv-pytorch-0.13.7", "https://raw.githubusercontent.com/astral-sh/uv/0.13.7/docs/guides/integration/pytorch.md")]:
        capture(url, out / "official-docs" / (name + ".md"))
    print(json.dumps({"prepared_protocol": str(out / "protocol.json"), "sha256": digest(out / "protocol.json")}), flush=True)


def execute(out):
    protocol = load(out / "protocol.json")
    assert digest(Path(__file__)) == protocol["script_sha256"]
    assert all(digest(ROOT / path) == value for path, value in protocol["helper_sha256"].items())
    assert shutil.disk_usage(out).free >= MIN_FREE
    assert not (out / "run-started.json").exists()
    dump(out / "run-started.json", {"at_utc": now(), "protocol_sha256": digest(out / "protocol.json")})
    project = out / "project"; project.mkdir()
    warm, fresh = out / "environments/warm", out / "environments/fresh"
    environment = env(out, out / "cache-warm")
    for name, target in [("warm", warm), ("fresh", fresh)]: command(out, "create-" + name, [PYTHON, "-m", "venv", "--without-pip", target], environment)
    environment["UV_PROJECT_ENVIRONMENT"] = str(warm)
    stages, worlds = [], {}; reuse = existing_archives()
    result = {"schema": "ultralytics-full-extra-actual-results-v1", "started_at_utc": now(), "stages": stages, "new_mechanisms_confirmed": 0, "new_real_affected_roots_confirmed": 0}
    try:
        for label, extra in [("base", False), ("extra", True), ("base-restored", False)]:
            (project / "pyproject.toml").write_text(manifest(extra))
            command(out, label + "-lock", [UV, "--no-config", "lock", "--python", PYTHON, "--no-python-downloads", "--no-build", "--verbose"], environment, cwd=project)
            budget = active_lock(project, protocol["native_environment"]); dump(out / "budgets" / (label + ".json"), budget)
            wheels = prepare_archives(out, label, budget, reuse); worlds[label] = wheels
            before_lock = digest(project / "uv.lock")
            command(out, label + "-sync", [UV, "--no-config", "sync", "--python", PYTHON, "--no-python-downloads", "--no-build", "--locked", "--no-install-project", "--no-default-groups", "--verbose"], environment, cwd=project, timeout=1800)
            assert digest(project / "uv.lock") == before_lock
            stage = capture_stage(out, label, warm, environment, budget["requests"], wheels, project); stages.append(stage); dump(out / "progress.json", result)
            if label == "base" and (stage["root_closure"]["constraint_conflicts"] or stage["all_installed_base_closure"]["constraint_conflicts"] or stage["file_violations"] or stage["pip_check_exit"] or stage["uv_check_exit"] or stage["cv2_smoke_exit"]): raise RuntimeError("Initial complete base is not a healthy control")
            if label == "extra" and (stage["root_closure"]["constraint_conflicts"] or stage["pip_check_exit"] or stage["uv_check_exit"]): raise RuntimeError("Complete published extra has an unsatisfied metadata closure; not a deletion-transition certificate")
        final_budget = load(out / "budgets/base-restored.json")
        for label, target, cache, flags in [("fresh-final", fresh, out / "cache-fresh-cold", []), ("forced-reinstall-final", warm, out / "cache-warm", ["--reinstall"])]:
            configured = env(out, cache); configured["UV_PROJECT_ENVIRONMENT"] = str(target)
            before = (digest(project / "pyproject.toml"), digest(project / "uv.lock"))
            command(out, label + "-sync", [UV, "--no-config", "sync", "--python", PYTHON, "--no-python-downloads", "--no-build", "--locked", "--no-install-project", "--no-default-groups", "--verbose", *flags], configured, cwd=project, timeout=1800)
            assert before == (digest(project / "pyproject.toml"), digest(project / "uv.lock"))
            stages.append(capture_stage(out, label, target, configured, final_budget["requests"], worlds["base-restored"], project)); dump(out / "progress.json", result)
        # This is a controlled replay of every original official artifact in the
        # prepared union. No dependency is skipped; pip is permitted to retain
        # extra-only packages on the final ordinary base request.
        pipenv = out / "environments/pip-incremental"
        pip_environment = env(out, out / "pip-comparison-cache")
        command(out, "create-pip", [PYTHON, "-m", "venv", "--without-pip", pipenv], pip_environment)
        union = {row["filename"]: row for world in worlds.values() for row in world}
        for label, extra in [("pip-base", False), ("pip-extra", True), ("pip-base-request-again", False)]:
            requests = tomllib.loads(manifest(extra))["project"]["dependencies"]
            command(out, label + "-install", [PYTHON, "-B", "-m", "pip", "--python", pipenv / "bin/python", "install", "--no-index", "--find-links", out / "artifacts", "--no-compile", "--report", out / (label + "-report.json"), *requests], pip_environment, timeout=1800)
            stages.append(capture_stage(out, label, pipenv, pip_environment, requests, list(union.values()))); dump(out / "progress.json", result)
        result["status"] = "actual_workflow_complete_independent_admission_pending"
    except Exception as error:
        result.update(status="unknown_or_unsupported_complete_workflow", reason=str(error))
        import traceback
        result["traceback"] = traceback.format_exc()
    result["finished_at_utc"] = now()
    result["helper_hashes_unchanged"] = all(digest(ROOT / path) == value for path, value in protocol["helper_sha256"].items())
    dump(out / "results.json", result)
    print(json.dumps({"status": result["status"], "reason": result.get("reason"), "completed_stages": [stage["label"] for stage in stages]}), flush=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(); parser.add_argument("--out", type=Path, required=True); parser.add_argument("--prepare", action="store_true"); parser.add_argument("--run", action="store_true")
    args = parser.parse_args(); path = args.out.resolve()
    if args.prepare: prepare(path)
    elif args.run: execute(path)
    else: parser.error("select prepare or run")
