"""Preserved-pass recovery for an explicitly mismatched initial sync strategy."""
from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from scripts import stateful_real_workflows_1111 as original
from scripts.run_expanded_validation import digest, dump, now


def prepare(source, out):
    out.mkdir(parents=True, exist_ok=False)
    parent_protocol = json.loads((source / "protocol.json").read_text())
    assert digest(Path(original.__file__)) == parent_protocol["script_sha256"]
    shutil.copyfile(source / "cases.json", out / "cases.json")
    protocol = {"schema": "stateful-relock-explicit-strategy-recovery-v1", "registered_at_utc": now(),
                "source_out": str(source), "source_protocol_sha256": digest(source / "protocol.json"),
                "source_cases_sha256": digest(source / "cases.json"), "script_sha256": digest(Path(__file__)),
                "original_helper_sha256": digest(Path(original.__file__)), "core_hashes": parent_protocol["core_hashes"],
                "workers": 2, "per_workflow_seconds": 900, "parent_wait_seconds": 36000,
                "scope": "Every original registered root is retained. Only an original relock failure specifically at uv-before-relock is eligible for this method correction; all other coverage statuses are preserved.",
                "change": "The first strict sync receives --resolution lowest, matching the initial lock. Subsequent lock --upgrade and highest sync remain unchanged. Same original requests, target and official-wheel content universe.",
                "artifact_policy": "Copy already prepared official archives and manifest byte-for-byte into an independent recovery directory, verify SHA, no new download or metadata resolution. Preserve original world and all failed logs.",
                "limits": parent_protocol["limits"]}
    dump(out / "protocol.json", protocol)
    print(json.dumps({"protocol_sha256": digest(out / "protocol.json"), "source_roots": len(json.loads((out / "cases.json").read_text())["roots"])}), flush=True)


def worker(out, name):
    protocol = json.loads((out / "protocol.json").read_text())
    assert digest(Path(__file__)) == protocol["script_sha256"]
    assert digest(Path(original.__file__)) == protocol["original_helper_sha256"]
    source = Path(protocol["source_out"])
    row = next(r for r in json.loads((out / "cases.json").read_text())["roots"] if r["canonical_name"] == name)
    parent_artifacts = source / "cases" / name / "artifacts"
    destination = out / "cases" / name / "artifacts"
    destination.mkdir(parents=True, exist_ok=False)
    parents = {str(parent_artifacts / p): digest(parent_artifacts / p) for p in ("wheel-manifest.json", "results.json")}
    dump(out / "cases" / name / "parent-inputs.json", parents)
    for filename in ("wheel-manifest.json", "results.json"):
        shutil.copyfile(parent_artifacts / filename, destination / filename)
    wheels = json.loads((destination / "wheel-manifest.json").read_text())
    (destination / "wheelhouse").mkdir()
    for wheel in wheels:
        src, dst = parent_artifacts / "wheelhouse" / wheel["filename"], destination / "wheelhouse" / wheel["filename"]
        assert digest(src) == wheel["sha256"]
        shutil.copyfile(src, dst)
        assert digest(dst) == wheel["sha256"]
    previous_command = original.Recorder.command
    def explicit_initial_strategy(recorder, argv, label, *args, **kwargs):
        argv = list(argv)
        if label == "uv-before-relock":
            assert "sync" in argv and "--locked" in argv
            argv += ["--resolution", "lowest"]
        return previous_command(recorder, argv, label, *args, **kwargs)
    original.Recorder.command = explicit_initial_strategy
    original.workflow_worker(out, row, "relock")
    assert all(digest(Path(path)) == expected for path, expected in parents.items())
    assert all(digest(ROOT / path) == expected for path, expected in protocol["core_hashes"].items())


def run(out):
    protocol = json.loads((out / "protocol.json").read_text())
    source = Path(protocol["source_out"])
    assert digest(source / "protocol.json") == protocol["source_protocol_sha256"]
    assert digest(source / "cases.json") == protocol["source_cases_sha256"]
    assert not (out / "run-started.json").exists()
    dump(out / "run-started.json", {"at_utc": now()})
    (out / "logs").mkdir()
    cases = json.loads((out / "cases.json").read_text())
    def package(row):
        name = row["canonical_name"]
        parent = source / "cases" / name / "relock/results.json"
        began = time.monotonic()
        while not parent.exists():
            if time.monotonic() - began > protocol["parent_wait_seconds"]:
                return {"name": name, "status": "unknown_parent_not_finished"}
            time.sleep(5)
        old = json.loads(parent.read_text())
        if old.get("status") != "unknown_workflow_coverage" or old.get("reason") != "native command returned nonzero: uv-before-relock":
            return {"name": name, "status": "not_eligible_for_strategy_recovery", "parent_status": old.get("status")}
        log = out / "logs" / (name + ".log")
        with log.open("w") as stream:
            process = subprocess.Popen([str(original.DRIVER), str(Path(__file__)), "--out", str(out), "--worker", name], stdout=stream, stderr=subprocess.STDOUT, start_new_session=True)
            try:
                process.wait(timeout=protocol["per_workflow_seconds"] + 2)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait()
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        result = out / "cases" / name / "relock/results.json"
        if not result.exists():
            dump(result, {"name": name, "workflow": "relock", "status": "unknown_recovery_worker_or_budget", "returncode": process.returncode})
        actual = json.loads(result.read_text())
        return {"name": name, "status": actual["status"], "relock_installed_plan_changed": actual.get("relock_installed_plan_changed"), "relock_lock_bytes_changed": actual.get("relock_lock_bytes_changed")}
    completed = []
    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = {pool.submit(package, row): row for row in cases["roots"]}
        for future in as_completed(futures):
            try:
                result = future.result()
            except Exception as exc:
                result = {"name": futures[future]["canonical_name"], "status": "unknown_recovery_controller", "reason": str(exc)}
            completed.append(result)
            dump(out / "progress.json", {"finished": len(completed), "roots": len(cases["roots"]), "results": completed})
            print(json.dumps(result), flush=True)
    dump(out / "summary.json", {"schema": "stateful-relock-recovery-summary-v1", "finished_at_utc": now(), "results": completed,
         "protocol_sha256": digest(out / "protocol.json"), "original_protocol_unchanged": digest(source / "protocol.json") == protocol["source_protocol_sha256"],
         "core_unchanged": all(digest(ROOT / p) == s for p, s in protocol["core_hashes"].items()), "confirmed_defects": 0})


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-out", type=Path)
    parser.add_argument("--out", required=True, type=Path)
    parser.add_argument("--prepare", action="store_true")
    parser.add_argument("--run", action="store_true")
    parser.add_argument("--worker")
    args = parser.parse_args()
    out = args.out.resolve()
    if args.prepare:
        prepare(args.source_out.resolve(), out)
    elif args.worker:
        worker(out, args.worker)
    elif args.run:
        run(out)
    else:
        parser.error("choose --prepare or --run")
