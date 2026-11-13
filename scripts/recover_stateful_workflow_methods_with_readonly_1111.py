"""Methods recovery that does not reinstall independently read-only-validated chains."""
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
from scripts import stateful_fast_file_audit_1111 as fast
from scripts.run_expanded_validation import digest, dump, now

FAST_SHA = "b688b8eea4f80ccc5ac4fa18447fcbde097f585a422cb175e473083bb9ff910e"


def verified_readonly(path, source, source_protocol_sha):
    value = json.loads(path.read_text())
    assert value["status"] == "actual_operation_chain_completed_with_additional_readonly_validation"
    assert value["original_metadata_record_unchanged"] and value["core_unchanged"] and not value["related_processes_after"]
    proof_protocol_path = path.parents[2] / "protocol.json"
    assert digest(proof_protocol_path) == value["protocol_sha256"]
    proof_protocol = json.loads(proof_protocol_path.read_text())
    assert proof_protocol["source_out"] == str(source) and proof_protocol["source_protocol_sha256"] == source_protocol_sha
    assert all(digest(Path(p)) == s for p, s in value["parent_input_hashes"].items())
    return value


def prepare(source, out, readonly_results):
    out.mkdir(parents=True, exist_ok=False)
    parent = json.loads((source / "protocol.json").read_text())
    assert digest(Path(original.__file__)) == parent["script_sha256"]
    assert digest(Path(fast.__file__)) == FAST_SHA
    freeze = ROOT / "work/stateful-workflows-20261111/review/fast-file-audit-freeze.json"
    equivalence = ROOT / "work/stateful-workflows-20261111/review/file-auditor-equivalence-review.json"
    shutil.copyfile(source / "cases.json", out / "cases.json")
    protocol = {"schema": "stateful-equivalent-audit-and-strategy-recovery-v1", "registered_at_utc": now(),
                "source_out": str(source), "source_protocol_sha256": digest(source / "protocol.json"), "source_cases_sha256": digest(source / "cases.json"),
                "script_sha256": digest(Path(__file__)), "original_helper_sha256": digest(Path(original.__file__)), "fast_helper_sha256": FAST_SHA,
                "equivalence_evidence": {str(p): digest(p) for p in (freeze, equivalence)}, "core_hashes": parent["core_hashes"],
                "workflows": list(original.WORKFLOWS), "workers": 2, "per_workflow_seconds": 900, "parent_wait_seconds": 36000,
                "eligibility": "Retain every original root/workflow. One recovery only for budget/worker or workflow execution unknowns with all required variants prepared in a completely hash-verified parent world. Completed, candidate, selection-unsupported and incomplete-artifact rows are preserved rather than retested.",
                "changes": ["Equivalent file audit caches stable parent/path resolution, preserving real symlink and .. semantics; independent boundary and real-environment result equivalence is recorded.",
                            "Only the initial relock strict sync adds --resolution lowest to match the original lowest lock; subsequent upgrade/highest operations are unchanged."],
                "unchanged": "Requests, full target, selected extra, official archive SHA and complete prepared candidate universe; all real dependencies installed; pip already uses --no-compile and never --no-deps.",
                "artifact_policy": "No metadata query, new download or world trimming. Copy exactly every verified parent archive and original manifest, preserve parent inputs and all failed evidence.",
                "limits": parent["limits"]}
    approved = {}
    for path in readonly_results:
        path = path.resolve()
        value = verified_readonly(path, source, digest(source / "protocol.json"))
        approved[value["name"] + ":" + value["workflow"]] = {"path": str(path), "sha256": digest(path)}
    protocol["already_completed_readonly_validated_chains"] = approved
    protocol["readonly_dispatch_scope"] = "Preserve verified complete original operation chains plus their separately labeled additional read-only validation; do not install those workflows again. Other method-unknown workflows retain unchanged recovery eligibility and budgets."
    protocol["method_parent_script_sha256"] = "9a038c65892f7f599fa9d9ef2895d928b63e7839c8efda6a3adae0f827a53617"
    dump(out / "protocol.json", protocol)
    print(json.dumps({"protocol_sha256": digest(out / "protocol.json"), "script_sha256": protocol["script_sha256"]}), flush=True)


def worker(out, name, workflow):
    protocol = json.loads((out / "protocol.json").read_text())
    assert digest(Path(__file__)) == protocol["script_sha256"]
    assert digest(Path(original.__file__)) == protocol["original_helper_sha256"]
    assert digest(Path(fast.__file__)) == protocol["fast_helper_sha256"]
    row = next(r for r in json.loads((out / "cases.json").read_text())["roots"] if r["canonical_name"] == name)
    original.audit_files = fast.audit_files
    previous = original.Recorder.command
    def corrected(recorder, argv, label, *args, **kwargs):
        argv = list(argv)
        if label == "uv-before-relock":
            assert "sync" in argv and "--locked" in argv
            argv += ["--resolution", "lowest"]
        return previous(recorder, argv, label, *args, **kwargs)
    original.Recorder.command = corrected
    original.workflow_worker(out, row, workflow)


def run(out):
    protocol = json.loads((out / "protocol.json").read_text())
    source = Path(protocol["source_out"])
    assert digest(source / "protocol.json") == protocol["source_protocol_sha256"]
    assert digest(source / "cases.json") == protocol["source_cases_sha256"]
    assert digest(Path(__file__)) == protocol["script_sha256"]
    assert not (out / "run-started.json").exists()
    dump(out / "run-started.json", {"at_utc": now()})
    (out / "logs").mkdir()
    cases = json.loads((out / "cases.json").read_text())
    def package(row):
        name, results = row["canonical_name"], {}
        for workflow in protocol["workflows"]:
            key = name + ":" + workflow
            if key in protocol["already_completed_readonly_validated_chains"]:
                proof = protocol["already_completed_readonly_validated_chains"][key]
                assert digest(Path(proof["path"])) == proof["sha256"]
                verified_readonly(Path(proof["path"]), source, protocol["source_protocol_sha256"])
                results[workflow] = {"status": "not_reexecuted_readonly_validated_operation_chain", "proof": proof,
                                     "effective_evidence_label": "original_actual_chain_plus_additional_readonly_validation"}
                continue
            parent_result = source / "cases" / name / workflow / "results.json"
            started = time.monotonic()
            while not parent_result.exists():
                if time.monotonic() - started > protocol["parent_wait_seconds"]:
                    break
                time.sleep(5)
            if not parent_result.exists():
                results[workflow] = {"status": "unknown_parent_not_finished"}
                continue
            old = json.loads(parent_result.read_text())
            if old.get("status") not in {"unknown_workflow_coverage", "unknown_worker_or_budget"}:
                results[workflow] = {"status": "not_eligible_for_methods_recovery", "parent_status": old.get("status")}
                continue
            parent_artifacts = source / "cases" / name / "artifacts"
            parent_artifact_result = json.loads((parent_artifacts / "results.json").read_text())
            required = {"update": ("base", "old"), "extras": ("base", "extra"), "relock": ("base",)}[workflow]
            if any(parent_artifact_result.get("variants", {}).get(v, {}).get("status") != "prepared" for v in required):
                results[workflow] = {"status": "unknown_parent_world_not_complete", "parent_status": old.get("status")}
                continue
            manifest = json.loads((parent_artifacts / "wheel-manifest.json").read_text())
            expected = {w["filename"] for w in manifest}
            if {p.name for p in (parent_artifacts / "wheelhouse").glob("*.whl")} != expected:
                results[workflow] = {"status": "unknown_parent_world_has_unverified_archives"}
                continue
            destination = out / "cases" / name / "artifacts"
            if not destination.exists():
                destination.mkdir(parents=True)
                (destination / "wheelhouse").mkdir()
                parent_hashes = {str(parent_artifacts / p): digest(parent_artifacts / p) for p in ("results.json", "wheel-manifest.json")}
                for filename in ("results.json", "wheel-manifest.json"):
                    shutil.copyfile(parent_artifacts / filename, destination / filename)
                for wheel in manifest:
                    src, dst = parent_artifacts / "wheelhouse" / wheel["filename"], destination / "wheelhouse" / wheel["filename"]
                    assert digest(src) == wheel["sha256"]
                    shutil.copyfile(src, dst)
                    assert digest(dst) == wheel["sha256"]
                    parent_hashes[str(src)] = wheel["sha256"]
                dump(out / "cases" / name / "parent-inputs.json", parent_hashes)
            assert digest(destination / "wheel-manifest.json") == digest(parent_artifacts / "wheel-manifest.json")
            log = out / "logs" / (name + "--" + workflow + ".log")
            with log.open("w") as stream:
                process = subprocess.Popen([str(original.DRIVER), str(Path(__file__)), "--out", str(out), "--worker", name, "--workflow", workflow], stdout=stream, stderr=subprocess.STDOUT, start_new_session=True)
                try:
                    process.wait(timeout=protocol["per_workflow_seconds"] + 2)
                except subprocess.TimeoutExpired:
                    os.killpg(process.pid, signal.SIGKILL)
                    process.wait()
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
            result_path = out / "cases" / name / workflow / "results.json"
            if not result_path.exists():
                dump(result_path, {"name": name, "workflow": workflow, "status": "unknown_recovery_worker_or_budget", "returncode": process.returncode})
            new = json.loads(result_path.read_text())
            results[workflow] = {"status": new["status"], "relock_installed_plan_changed": new.get("relock_installed_plan_changed"), "relock_lock_bytes_changed": new.get("relock_lock_bytes_changed")}
        return {"name": name, "workflows": results}
    completed = []
    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = {pool.submit(package, row): row for row in cases["roots"]}
        for future in as_completed(futures):
            try:
                result = future.result()
            except Exception as exc:
                result = {"name": futures[future]["canonical_name"], "status": "unknown_recovery_controller", "reason": str(exc)}
            completed.append(result)
            dump(out / "progress.json", {"finished_roots": len(completed), "eligible_roots": len(cases["roots"]), "results": completed})
            print(json.dumps(result), flush=True)
    input_checks = {p: digest(Path(p)) == s for path in (out / "cases").glob("*/parent-inputs.json") for p, s in json.loads(path.read_text()).items()}
    result = {"schema": "stateful-methods-recovery-summary-v1", "finished_at_utc": now(), "results": completed,
              "protocol_sha256": digest(out / "protocol.json"), "parent_input_checks": input_checks,
              "parent_protocol_unchanged": digest(source / "protocol.json") == protocol["source_protocol_sha256"],
              "core_unchanged": all(digest(ROOT / p) == s for p, s in protocol["core_hashes"].items()), "confirmed_defects": 0}
    assert all(input_checks.values()) and result["parent_protocol_unchanged"] and result["core_unchanged"]
    dump(out / "summary.json", result)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-out", type=Path)
    parser.add_argument("--out", required=True, type=Path)
    parser.add_argument("--prepare", action="store_true")
    parser.add_argument("--run", action="store_true")
    parser.add_argument("--worker")
    parser.add_argument("--workflow", choices=original.WORKFLOWS)
    parser.add_argument("--readonly-result", action="append", default=[], type=Path)
    args = parser.parse_args()
    out = args.out.resolve()
    if args.prepare:
        prepare(args.source_out.resolve(), out, args.readonly_result)
    elif args.worker:
        worker(out, args.worker, args.workflow)
    elif args.run:
        run(out)
    else:
        parser.error("choose --prepare or --run")
