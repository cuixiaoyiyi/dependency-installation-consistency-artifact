"""Validate a replay plan, or explicitly execute the synthetic or Ultralytics case."""
from __future__ import annotations

import argparse
import base64
import csv
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tomllib

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from artifact_tools._runtime import command, digest, dump, environment, output_path, python_path, uv_path

STATES = ("base", "extra", "base-restored")
CV2_PROBE = "import cv2,numpy as np; a=cv2.cvtColor(np.zeros((2,2,3),dtype=np.uint8),cv2.COLOR_BGR2GRAY); assert a.shape==(2,2); print(cv2.__version__,cv2.__file__)"
YOLO_PROBE = "from ultralytics import YOLO; print('YOLO import passed')"


def validate_inputs(directory):
    directory = Path(directory).expanduser().resolve(strict=True)
    record = json.loads((directory / "inputs.json").read_text(encoding="utf-8-sig"))
    expected = {(item["stage"], item["file"]): item["sha256"] for item in record["files"]}
    files = []
    for state in STATES:
        for filename in ("pyproject.toml", "uv.lock"):
            source = directory / state / filename
            actual = digest(source)
            if actual != expected[(state, filename)]:
                raise ValueError(f"Input hash mismatch: {state}/{filename}")
            tomllib.loads(source.read_text(encoding="utf-8"))
            files.append({"state": state, "file": filename, "sha256": actual})
    for filename in ("pyproject.toml", "uv.lock"):
        if expected[("base", filename)] != expected[("base-restored", filename)]:
            raise ValueError("The final base inputs must match the initial base inputs.")
    return directory, record, files


def parser():
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("case", choices=("m1", "m2"))
    result.add_argument("--out", required=True, type=Path)
    result.add_argument("--python", type=Path)
    result.add_argument("--uv", type=Path)
    result.add_argument("--inputs", type=Path, default=ROOT / "inputs/ultralytics-extra")
    result.add_argument("--timeout-seconds", type=int, default=900)
    result.add_argument("--minimum-free-gib", type=float, default=60,
                        help="M2 startup free-space requirement; this is not a storage-use cap.")
    mode = result.add_mutually_exclusive_group()
    mode.add_argument("--execute", action="store_true", help="Run installations; the default only validates and prints the plan.")
    mode.add_argument("--dry-run", action="store_true", help="Validate inputs without installing packages or creating output.")
    return result


def make_plan(args):
    out, python = output_path(args.out), python_path(args.python)
    uv = uv_path(args.uv, python, required=args.execute)
    plan = {"case": args.case, "mode": "execute" if args.execute else "dry-run", "out": str(out),
            "python": str(python), "uv": str(uv) if uv else "not yet selected",
            "network": "localhost only" if args.case == "m1" else "official package downloads from the supplied locks"}
    if args.case == "m1":
        source = ROOT / "reproductions/source_reuse.py"
        plan.update(script=str(source), script_sha256=digest(source),
                    sequence=["initial lock and sync", "source rebind and relock", "warm sync", "fresh sync", "probe reinstall"],
                    scope="Original inert-wheel reproducer; no real affected project is added.")
    else:
        directory, record, files = validate_inputs(args.inputs)
        plan.update(inputs=str(directory), input_files=files, target=record["target"], recorded_uv=record["uv"],
                    sequence=["base", "extra", "base-restored", "fresh-final", "repair-opencv-only"],
                    minimum_free_gib=args.minimum_free_gib,
                    scope="Portable replay of the supplied manifests and locks, metadata closure, retained OpenCV RECORD paths, and selected runtime probes. This does not repeat every original wheel-byte audit.")
    return plan, out, python, uv


def validate_runtime(python, uv, case):
    if sys.platform != "linux":
        raise ValueError("Execute case replays from Linux or a WSL shell; dry-run is available on other hosts.")
    probe = subprocess.run([str(python), "-I", "-c",
        "import json,platform,sys; print(json.dumps({'version':platform.python_version(),'implementation':sys.implementation.name,'system':sys.platform,'machine':platform.machine()}))"],
        capture_output=True, text=True, check=True, timeout=15)
    target = json.loads(probe.stdout)
    if target["system"] != "linux" or target["machine"] != "x86_64":
        raise ValueError("The recorded case target is Linux x86_64.")
    if case == "m2" and (target["version"] != "3.11.16" or target["implementation"] != "cpython"):
        raise ValueError("M2 manifests require CPython 3.11.16; select that interpreter with --python.")
    version = subprocess.run([str(uv), "--version"], capture_output=True, text=True, check=True, timeout=15).stdout.strip()
    if version.split()[:2] != ["uv", "0.13.7"]:
        raise ValueError(f"Use the recorded uv 0.13.7 for this replay; found {version}.")
    target["uv"] = version
    return target


def record_paths(inventory, distribution):
    from packaging.utils import canonicalize_name
    dist = next((item for item in inventory["installed"] if canonicalize_name(item["name"]) == distribution), None)
    if dist is None:
        return {}
    info = Path(dist["dist_info"])
    rows = {}
    for relative, value, size in csv.reader((info / "RECORD").read_text(encoding="utf-8").splitlines()):
        if relative.startswith("cv2/") and value:
            rows[relative] = {"record_hash": value, "record_size": size, "installed_path": str(info.parent / relative)}
    return rows


def payload_observation(paths, inventory):
    from packaging.utils import canonicalize_name
    provider = next((item for item in inventory["installed"] if canonicalize_name(item["name"]) == "opencv-python"), None)
    parent = Path(provider["dist_info"]).parent if provider else None
    rows = []
    for relative, expected in sorted(paths.items()):
        target = parent / relative if parent else None
        exists = target is not None and target.is_file()
        actual = digest(target) if exists else None
        algorithm, wanted = expected["record_hash"].split("=", 1)
        actual_record = base64.urlsafe_b64encode(bytes.fromhex(actual)).decode().rstrip("=") if actual else None
        rows.append({"path": relative, "exists": exists, "sha256": actual,
                     "matches_normal_record": bool(exists and algorithm == "sha256" and actual_record == wanted),
                     "original_record_hash": expected["record_hash"]})
    return rows


def execute_m2(args, plan, out, python, uv, runtime):
    from packaging.utils import canonicalize_name
    from scripts.review_recovery_1111 import check_metadata
    from scripts.validate_foundational_installs_1111 import COLLECT

    ancestor = out.parent
    while not ancestor.exists():
        ancestor = ancestor.parent
    if shutil.disk_usage(ancestor).free < args.minimum_free_gib * 1024**3:
        raise ValueError("Insufficient free space for the requested M2 startup requirement.")
    out.mkdir(parents=True, exist_ok=False)
    project = out / "project"
    project.mkdir()
    warm, fresh = out / "environments/warm", out / "environments/fresh"
    inputs = Path(plan["inputs"])
    result = {"schema": "portable-ultralytics-replay-v1", "status": "incomplete", "plan": plan,
              "runtime": runtime, "stages": [], "confirmed_project_count": 0,
              "scope": plan["scope"]}
    normal_paths, shared_paths = {}, set()

    def stage(label, state, target, cache, reinstall=False):
        nonlocal normal_paths, shared_paths
        folder = out / "stages" / label
        folder.mkdir(parents=True, exist_ok=False)
        for filename in ("pyproject.toml", "uv.lock"):
            shutil.copyfile(inputs / state / filename, project / filename)
            shutil.copyfile(project / filename, folder / filename)
        env = environment(out, target, cache)
        argv = [uv, "--no-config", "sync", "--project", project, "--python", python,
                "--no-python-downloads", "--no-build", "--locked", "--no-install-project", "--no-default-groups"]
        if reinstall:
            argv += ["--reinstall-package", "opencv-python"]
        row = {"label": label, "manifest_sha256": digest(project / "pyproject.toml"),
               "lock_sha256": digest(project / "uv.lock"), "sync": command(argv, folder / "sync", env, args.timeout_seconds)}
        result["stages"].append(row)
        dump(out / "results.json", result)
        if row["sync"]["exit"] or row["sync"]["timeout"]:
            raise RuntimeError(f"Installation did not complete: {label}")
        target_python = target / "bin/python"
        observed = command([target_python, "-I", "-c", COLLECT], folder / "inventory", env, 60)
        if observed["exit"]:
            raise RuntimeError(f"Inventory collection failed: {label}")
        inventory = json.loads((folder / "inventory/stdout.txt").read_text())
        dump(folder / "installed.json", inventory)
        for dist in inventory["installed"]:
            stored = folder / "metadata" / canonicalize_name(dist["name"])
            stored.mkdir(parents=True)
            for filename in ("METADATA", "RECORD", "INSTALLER", "direct_url.json"):
                original = Path(dist["dist_info"]) / filename
                if original.is_file():
                    shutil.copyfile(original, stored / filename)
        installed = {canonicalize_name(item["name"]): item for item in inventory["installed"]}
        requests = tomllib.loads((project / "pyproject.toml").read_text())["project"]["dependencies"]
        row["root_closure"] = check_metadata(requests, [], installed, inventory["environment"])
        row["all_base_closure"] = check_metadata([item["name"] + "==" + item["version"] for item in inventory["installed"]] + requests,
                                                    [], installed, inventory["environment"])
        row["names_versions"] = {name: item["version"] for name, item in installed.items()}
        row["installed_count"] = len(installed)
        if not normal_paths:
            normal_paths = record_paths(inventory, "opencv-python")
            if not normal_paths:
                raise RuntimeError("The retained OpenCV provider has no inspected RECORD paths.")
        if label == "extra":
            shared_paths = set(normal_paths) & set(record_paths(inventory, "opencv-python-headless"))
            row["shared_cv2_record_paths"] = sorted(shared_paths)
        row["normal_cv2_payload"] = payload_observation(normal_paths, inventory)
        row["missing_normal_cv2_paths"] = [entry["path"] for entry in row["normal_cv2_payload"] if not entry["exists"]]
        for name, argv in {
            "pip_check": [python, "-m", "pip", "--python", target_python, "check"],
            "uv_check": [uv, "--no-config", "pip", "check", "--python", target_python],
            "pip_inspect": [python, "-m", "pip", "--python", target_python, "inspect", "--local"],
            "cv2_probe": [target_python, "-I", "-c", CV2_PROBE],
            "yolo_probe": [target_python, "-I", "-c", YOLO_PROBE],
        }.items():
            row[name] = command(argv, folder / name, env, min(args.timeout_seconds, 120))
        dump(folder / "observations.json", row)
        dump(out / "results.json", result)
        return row

    try:
        base = stage("base", "base", warm, out / "cache-warm")
        extra = stage("extra", "extra", warm, out / "cache-warm")
        final = stage("base-restored", "base-restored", warm, out / "cache-warm")
        fresh_final = stage("fresh-final", "base-restored", fresh, out / "cache-fresh")
        repaired = stage("repair-opencv-only", "base-restored", warm, out / "cache-warm", True)

        def closure_ok(row):
            return not row["root_closure"]["constraint_conflicts"] and not row["all_base_closure"]["constraint_conflicts"]

        def checkers_ok(row):
            return row["pip_check"]["exit"] == row["uv_check"]["exit"] == 0

        def runtime_ok(row):
            return row["cv2_probe"]["exit"] == row["yolo_probe"]["exit"] == 0

        checks = {
            "initial_base_healthy": closure_ok(base) and checkers_ok(base) and runtime_ok(base) and all(entry["matches_normal_record"] for entry in base["normal_cv2_payload"]),
            "extra_installs_both_providers": all(name in extra["names_versions"] for name in ("opencv-python", "opencv-python-headless")),
            "extra_runtime_healthy": closure_ok(extra) and checkers_ok(extra) and runtime_ok(extra),
            "removal_retains_only_normal_provider": "opencv-python" in final["names_versions"] and "opencv-python-headless" not in final["names_versions"],
            "final_metadata_and_checkers_pass": closure_ok(final) and checkers_ok(final),
            "retained_shared_paths_missing": bool(shared_paths) and bool(final["missing_normal_cv2_paths"]) and set(final["missing_normal_cv2_paths"]) <= shared_paths,
            "final_runtime_probes_fail": final["cv2_probe"]["exit"] != 0 and final["yolo_probe"]["exit"] != 0,
            "fresh_and_repair_healthy": all(closure_ok(row) and checkers_ok(row) and runtime_ok(row) and all(entry["matches_normal_record"] for entry in row["normal_cv2_payload"]) for row in (fresh_final, repaired)),
            "final_input_hashes_identical": len({(row["manifest_sha256"], row["lock_sha256"]) for row in (final, fresh_final, repaired)}) == 1,
            "final_distribution_versions_identical": final["names_versions"] == fresh_final["names_versions"] == repaired["names_versions"],
        }
        result.update(status="completed", checks=checks, reproduced_missing_provider_payload=all(checks.values()))
    except Exception as exc:
        result.update(status="incomplete", error=f"{type(exc).__name__}: {exc}")
        dump(out / "results.json", result)
        raise
    dump(out / "results.json", result)
    print(json.dumps({"status": result["status"], "out": str(out), "checks": result["checks"]}, indent=2))
    return 0 if result["reproduced_missing_provider_payload"] else 1


def main(argv=None):
    options = parser()
    args = options.parse_args(argv)
    try:
        if args.timeout_seconds <= 0 or args.minimum_free_gib < 0:
            raise ValueError("Timeout must be positive and the startup space requirement must not be negative.")
        plan, out, python, uv = make_plan(args)
        if not args.execute:
            print(json.dumps(plan, indent=2))
            return 0
        runtime = validate_runtime(python, uv, args.case)
        if args.case == "m1":
            code = subprocess.run([str(python), plan["script"], "--uv", str(uv), "--out", str(out)], stdin=subprocess.DEVNULL).returncode
            if code:
                return code
            result = json.loads((out / "results.json").read_text())
            return 0 if result.get("reproduced_closure_violation") else 1
        return execute_m2(args, plan, out, python, uv, runtime)
    except (ValueError, OSError, KeyError, RuntimeError, subprocess.SubprocessError) as exc:
        print(f"Replay stopped: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
