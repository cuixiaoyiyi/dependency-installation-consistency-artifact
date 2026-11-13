"""Bounded read-only validation of completed operations with timed-out bookkeeping."""
from __future__ import annotations

import argparse
import csv
from email.parser import BytesParser
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time
import tomllib

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from packaging.utils import canonicalize_name
from drc.model import Context
from drc.resolvers.lock_projection import project_uv_lock
from scripts import stateful_real_workflows_1111 as original
from scripts import stateful_fast_file_audit_1111 as fast
from scripts.review_recovery_1111 import check_metadata
from scripts.run_expanded_validation import digest, dump, now

LABELS = {"update": ("pip-old", "pip-updated", "uv-old", "uv-updated", "uv-fresh-final-lock"),
          "extras": ("uv-base", "uv-extra", "uv-base-restored", "uv-fresh-final-lock"),
          "relock": ("uv-before-relock", "uv-after-relock", "uv-fresh-final-lock")}


def related_processes(directory):
    prefix = str(directory.resolve()) + "/"
    rows = []
    for path in Path("/proc").iterdir():
        if not path.name.isdigit() or int(path.name) == os.getpid():
            continue
        try:
            args = (path / "cmdline").read_bytes().decode(errors="replace").split("\0")
            cwd = str((path / "cwd").resolve())
            if cwd == prefix.rstrip("/") or cwd.startswith(prefix) or any(prefix in arg for arg in args):
                rows.append({"pid": int(path.name), "cwd": cwd, "argv": args})
        except (OSError, PermissionError):
            continue
    return rows


def fingerprints(directory):
    result = {}
    for env in (directory / name for name in ("pip-incremental", "uv-warm", "uv-fresh")):
        for info in env.glob("lib/python*/site-packages/*.dist-info"):
            for name in ("METADATA", "RECORD"):
                path = info / name
                if path.exists():
                    result[str(path)] = digest(path)
    return result


def prepare(source, out, case_name, workflow):
    assert (case_name, workflow) == ("aider-chat", "relock"), "This registration is only for the already executed Aider relock chain"
    out.mkdir(parents=True, exist_ok=False)
    parent = json.loads((source / "protocol.json").read_text())
    protocol = {"schema": "completed-stateful-operations-readonly-validation-v1", "registered_at_utc": now(),
                "source_out": str(source), "source_protocol_sha256": digest(source / "protocol.json"),
                "source_cases_sha256": digest(source / "cases.json"), "script_sha256": digest(Path(__file__)),
                "fast_helper_sha256": digest(Path(fast.__file__)), "original_helper_sha256": digest(Path(original.__file__)),
                "per_review_seconds": 900, "core_hashes": parent["core_hashes"],
                "eligibility": "Only the corrected published aider-chat/relock method-unknown row whose complete ordered actual-operation chain already has exit0 command records. Every earlier state requires its original full recorded file/closure/check/inspect audit. Final inventory/METADATA/RECORD/lock must exist; missing final read-only pip/uv checks may be added in this separate review after the actual installation chain is already complete. Missing or later overwritten early states are not inferred from final environments.",
                "static_environment": "Confirm no related original process by /proc argv/cwd before and after; every extant original target METADATA/RECORD hash must stay identical. No install, sync, relock, cleanup, mutation or byte compilation is allowed.",
                "supplement": "Fast actual-file/RECORD verification and exact target/extra lock projection against the saved final environment. Only missing final pip-check/uv-check/inspect may run, with external pip, -B/PYTHONDONTWRITEBYTECODE, disabled config and new output/cache/home directories. Earlier audits are reused as recorded, never reconstructed from changed states.",
                "statistical_label": "actual_operation_chain_completed_with_additional_readonly_validation; original900 outcome remains untouched and this is not a new operation chain or an original-budget pass.",
                "limits": parent["limits"]}
    protocol["parent_readonly_implementation_sha256"] = "e52604caf77a801f82150a38b72a85bf2af7b5bc5ed0c2a86a1ec1bc84fdf725"
    protocol["registered_case"] = {"canonical_name": case_name, "workflow": workflow}
    protocol["authorized_scope"] = "Parent explicitly authorized this bounded read-only final audit, checkers and lock/world membership proof; retain original900 unknown and do not reinstall any state."
    assert protocol["fast_helper_sha256"] == "b688b8eea4f80ccc5ac4fa18447fcbde097f585a422cb175e473083bb9ff910e"
    dump(out / "protocol.json", protocol)
    print(json.dumps({"protocol_sha256": digest(out / "protocol.json"), "script_sha256": protocol["script_sha256"]}), flush=True)


def review_one(out, name, workflow):
    protocol = json.loads((out / "protocol.json").read_text())
    assert digest(Path(__file__)) == protocol["script_sha256"]
    assert digest(Path(fast.__file__)) == protocol["fast_helper_sha256"]
    source = Path(protocol["source_out"])
    assert digest(source / "protocol.json") == protocol["source_protocol_sha256"]
    assert digest(source / "cases.json") == protocol["source_cases_sha256"]
    assert digest(Path(original.__file__)) == protocol["original_helper_sha256"]
    assert all(digest(ROOT / p) == s for p, s in protocol["core_hashes"].items())
    case = next(r for r in json.loads((source / "cases.json").read_text())["roots"] if r["canonical_name"] == name)
    directory = source / "cases" / name / workflow
    target = out / name / workflow
    target.mkdir(parents=True, exist_ok=False)
    began = time.monotonic()
    result = {"name": name, "workflow": workflow, "status": "unknown_readonly_validation", "confirmed_defects": 0}
    before = None
    try:
        assert (name, workflow) == (protocol["registered_case"]["canonical_name"], protocol["registered_case"]["workflow"]), "Review case must match the frozen registration"
        parent_result = json.loads((directory / "results.json").read_text())
        assert parent_result["status"] in {"unknown_worker_or_budget", "unknown_workflow_coverage"}
        labels = LABELS[workflow]
        parent_hashes = {str(directory / "results.json"): digest(directory / "results.json")}
        master = json.loads((directory / "commands.json").read_text())
        parent_hashes[str(directory / "commands.json")] = digest(directory / "commands.json")
        order = [r["label"] for r in master]
        assert all(label in order for label in labels)
        assert [order.index(label) for label in labels] == sorted(order.index(label) for label in labels)
        for label in labels:
            path = directory / "commands" / label / "command.json"
            command = json.loads(path.read_text())
            assert command["exit"] == 0
            parent_hashes[str(path)] = digest(path)
        process_before = related_processes(directory)
        dump(target / "processes-before.json", process_before)
        assert not process_before
        before = fingerprints(directory)
        dump(target / "metadata-record-before.json", before)
        progress = json.loads((directory / "progress.json").read_text())
        earlier = {e["stage"]: e for e in progress["stages"]}
        for label in labels[:-1]:
            entry = earlier[label]
            assert entry["pip_check_exit"] == entry["uv_check_exit"] == entry["inspect_exit"] == 0
            assert not entry["root_constraint_violations"] and not entry["all_installed_constraint_violations"] and not entry["file_violations"]
            files = directory / "stages" / label / "file-audit.json"
            closure = directory / "stages" / label / "root-closure.json"
            assert files.exists() and closure.exists()
            prior_files = json.loads(files.read_text())
            assert not prior_files["violations"]
            assert not json.loads(closure.read_text())["constraint_conflicts"]
            parent_hashes[str(files)], parent_hashes[str(closure)] = digest(files), digest(closure)
            saved_inventory = json.loads((directory / "stages" / label / "installed.json").read_text())
            audited = {canonicalize_name(d["name"]): d for d in prior_files["distributions"]}
            assert len(audited) == len(saved_inventory["installed"])
            for dist in saved_inventory["installed"]:
                saved = directory / "stages" / label / "metadata" / canonicalize_name(dist["name"])
                assert (saved / "METADATA").is_file() and (saved / "RECORD").is_file()
                evidence = audited[canonicalize_name(dist["name"])]
                assert digest(saved / "METADATA") == evidence["metadata_sha256"]
                parsed = BytesParser().parsebytes((saved / "METADATA").read_bytes())
                assert canonicalize_name(parsed["Name"]) == canonicalize_name(dist["name"]) and parsed["Version"] == dist["version"]
                assert sum(bool(row[1]) for row in csv.reader((saved / "RECORD").read_text().splitlines())) == evidence["record_hashes_checked"]
                parent_hashes[str(saved / "METADATA")] = digest(saved / "METADATA")
                parent_hashes[str(saved / "RECORD")] = digest(saved / "RECORD")
        label = labels[-1]
        stage = directory / "stages" / label
        inventory_path = stage / "installed.json"
        inventory = json.loads(inventory_path.read_text())
        assert inventory["environment"] == case["marker_environment"]
        for dist in inventory["installed"]:
            saved = stage / "metadata" / canonicalize_name(dist["name"])
            for filename in ("METADATA", "RECORD"):
                assert digest(saved / filename) == digest(Path(dist["dist_info"]) / filename)
        result["additional_readonly_checks"] = []
        for suffix in ("pip-check", "uv-check"):
            command = directory / "commands" / (label + "-" + suffix) / "command.json"
            if command.exists():
                assert json.loads(command.read_text())["exit"] == 0
                parent_hashes[str(command)] = digest(command)
                continue
            readonly_env = original.environment(target)
            readonly_env["PYTHONDONTWRITEBYTECODE"] = "1"
            final_python = str(directory / "uv-fresh/bin/python")
            argv = ([str(original.DRIVER), "-B", "-m", "pip", "--python", final_python, "check"] if suffix == "pip-check" else
                    [str(original.UV), "--no-config", "pip", "check", "--python", final_python])
            with (target / (suffix + ".stdout.txt")).open("w") as stdout, (target / (suffix + ".stderr.txt")).open("w") as stderr:
                process = subprocess.Popen(argv, cwd=target, env=readonly_env, stdout=stdout, stderr=stderr)
                try:
                    code = process.wait(timeout=max(1, protocol["per_review_seconds"] - (time.monotonic() - began)))
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
                    raise RuntimeError("read-only checker exceeded bounded review budget")
            record = {"argv": argv, "exit": code, "bytecode_disabled": True, "new_cache_home": str(target)}
            dump(target / (suffix + ".command.json"), record)
            assert code == 0
            result["additional_readonly_checks"].append(record)
        for path in [stage / "installed.json", stage / "pyproject.toml", stage / "uv.lock", directory / "progress.json"]:
            parent_hashes[str(path)] = digest(path)
        for path in (stage / "metadata").glob("*/*"):
            if path.is_file(): parent_hashes[str(path)] = digest(path)
        world_path = source / "cases" / name / "artifacts/wheel-manifest.json"
        world = json.loads(world_path.read_text())
        parent_hashes[str(world_path)] = digest(world_path)
        for wheel in world:
            assert digest(world_path.parent / "wheelhouse" / wheel["filename"]) == wheel["sha256"]
        final_env = directory / "uv-fresh"
        files = fast.audit_files(inventory, world, final_env)
        dump(target / "final-file-audit.json", files)
        assert not files["violations"]
        manifest = tomllib.loads((stage / "pyproject.toml").read_text())
        request = manifest["project"]["dependencies"]
        assert request == [case["request"]]
        artifacts = {canonicalize_name(d["name"]): {"name": d["name"], "version": d["version"], "requires_dist": d["requires_dist"]} for d in inventory["installed"]}
        closure = check_metadata(request, [], artifacts, inventory["environment"])
        dump(target / "final-closure.json", closure)
        assert not closure["constraint_conflicts"]
        lock_path = stage / "uv.lock"
        data = tomllib.loads(lock_path.read_text())
        virtual = [p for p in data["package"] if p.get("source") == {"virtual": "."}]
        assert len(virtual) == 1 and virtual[0]["name"] == manifest["project"]["name"]
        virtual[0]["name"] = "drc-probe"
        context = Context("readonly-final-stage", "uv", request, python_version=case["target_python"], platform="linux-x86_64", marker_environment=case["marker_environment"], project_extras=[])
        projected, evidence = project_uv_lock(data, context, case["marker_environment"])
        assert evidence["status"] == "verified"
        assert {k: a.version for k, a in projected.items()} == {k: a["version"] for k, a in artifacts.items()}
        audited = {canonicalize_name(d["name"]): d for d in files["distributions"]}
        world_by_filename = {w["filename"]: w for w in world}
        for selected in evidence["selected"]:
            assert selected["source"] == {"registry": str(world_path.parent / "wheelhouse")}
            nodes = [p for p in data["package"] if canonicalize_name(p["name"]) == selected["name"] and p.get("version") == selected["version"] and p.get("source") == selected["source"]]
            assert len(nodes) == 1
            permitted = set()
            for wheel in nodes[0].get("wheels", []):
                path = Path(wheel.get("path", ""))
                assert path.is_absolute() and path.resolve().is_relative_to((world_path.parent / "wheelhouse").resolve())
                official = world_by_filename[path.name]
                assert digest(path) == official["sha256"]
                permitted.add(official["sha256"])
            assert audited[selected["name"]]["wheel_sha256"] in permitted
        dump(target / "final-target-lock-projection.json", evidence)
        inspect_path = directory / "commands" / (label + "-inspect") / "command.json"
        if inspect_path.exists() and json.loads(inspect_path.read_text())["exit"] == 0:
            inspected = json.loads(inspect_path.with_name("stdout.txt").read_text())
            result["inspect_source"] = "reused original successful inspect"
        else:
            env = original.environment(target)
            env["PYTHONDONTWRITEBYTECODE"] = "1"
            argv = [str(original.DRIVER), "-B", "-m", "pip", "--python", str(final_env / "bin/python"), "inspect", "--local"]
            with (target / "inspect.stdout.txt").open("w") as stdout, (target / "inspect.stderr.txt").open("w") as stderr:
                process = subprocess.Popen(argv, cwd=target, env=env, stdout=stdout, stderr=stderr)
                try:
                    code = process.wait(timeout=max(1, protocol["per_review_seconds"] - (time.monotonic() - began)))
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
                    raise RuntimeError("read-only inspect exceeded bounded review budget")
            dump(target / "inspect.command.json", {"argv": argv, "exit": code, "bytecode_disabled": True, "new_cache_home": str(target)})
            assert code == 0
            inspected = json.loads((target / "inspect.stdout.txt").read_text())
            result["inspect_source"] = "additional read-only external-pip inspect with bytecode disabled"
        assert inspected["environment"] == case["marker_environment"]
        assert {canonicalize_name(d["metadata"]["name"]): d["metadata"]["version"] for d in inspected["installed"]} == {k: a["version"] for k, a in artifacts.items()}
        result.update(status="actual_operation_chain_completed_with_additional_readonly_validation", original_actual_operations=len(labels),
                      earlier_stage_full_audits_reused=len(labels) - 1, final_file_audit=files, final_target_graph=evidence,
                      parent_outcome_preserved=parent_result["status"], parent_input_hashes=parent_hashes)
        assert all(digest(Path(p)) == s for p, s in parent_hashes.items())
    except Exception as exc:
        result.update(status="partial_or_unknown_readonly_validation", reason=str(exc))
    finally:
        after = fingerprints(directory)
        processes_after = related_processes(directory)
        result["original_metadata_record_unchanged"] = before is not None and before == after
        result["related_processes_after"] = processes_after
        dump(target / "metadata-record-after.json", after)
        if not result["original_metadata_record_unchanged"] or processes_after:
            result["status"] = "partial_or_unknown_readonly_validation"
        result["seconds"] = round(time.monotonic() - began, 3)
        result["protocol_sha256"] = digest(out / "protocol.json")
        result["core_unchanged"] = all(digest(ROOT / p) == s for p, s in protocol["core_hashes"].items())
        if not result["core_unchanged"] or result["seconds"] > protocol["per_review_seconds"]:
            result["status"] = "partial_or_unknown_readonly_validation"
        dump(target / "results.json", result)
        print(json.dumps({"name": name, "workflow": workflow, "status": result["status"], "seconds": result["seconds"], "metadata_record_unchanged": result["original_metadata_record_unchanged"]}), flush=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-out", type=Path)
    parser.add_argument("--out", required=True, type=Path)
    parser.add_argument("--prepare", action="store_true")
    parser.add_argument("--name")
    parser.add_argument("--workflow", choices=LABELS)
    parser.add_argument("--isolated-worker", action="store_true")
    args = parser.parse_args()
    if args.prepare:
        prepare(args.source_out.resolve(), args.out.resolve(), args.name, args.workflow)
    elif args.isolated_worker:
        review_one(args.out.resolve(), args.name, args.workflow)
    else:
        out = args.out.resolve()
        protocol = json.loads((out / "protocol.json").read_text())
        assert digest(Path(__file__)) == protocol["script_sha256"]
        log = out / (args.name + "--" + args.workflow + ".log")
        assert not log.exists()
        with log.open("w") as stream:
            process = subprocess.Popen([str(original.DRIVER), str(Path(__file__)), "--out", str(out), "--name", args.name,
                                        "--workflow", args.workflow, "--isolated-worker"], stdout=stream, stderr=subprocess.STDOUT, start_new_session=True)
            try:
                process.wait(timeout=protocol["per_review_seconds"] + 2)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait()
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        result_path = out / args.name / args.workflow / "results.json"
        if not result_path.exists():
            dump(result_path, {"name": args.name, "workflow": args.workflow, "status": "partial_or_unknown_readonly_validation",
                               "reason": "isolated read-only worker failed or exhausted its900-second budget", "returncode": process.returncode})
        print(json.dumps(json.loads(result_path.read_text()), ensure_ascii=False)[:1500])
