"""One registered continuation of interrupted foundational workflows.

Imports the immutable, independently reviewed preparation recovery rather than
editing either historical runner.  New budgets and dispatch are explicit.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import shutil
import signal
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from scripts import recover_stateful_preparation_1111 as parent
from scripts import stateful_real_workflows_1111 as base
from scripts import stateful_fast_file_audit_1111 as fast
from scripts.recover_stateful_workflow_methods_with_readonly_1111 import verified_readonly
from scripts.run_expanded_validation import digest, dump, now

PARENT_SHA = "a8e6c7021528e41a9829b51023cba5ed027597dbe90307b01bde83eaccb3c016"
PARENT_PATH = Path(parent.__file__)
FAST_SHA = "b688b8eea4f80ccc5ac4fa18447fcbde097f585a422cb175e473083bb9ff910e"
BASE_SHA = "adac69aa7d91832a8e11add933c20f859e98502da2397ec7dc78767cae0e943e"
READONLY_HELPER_SHA = "69a2baf39459be301132a4b7b04413e39ed1d4738da8f6ef19ed5699c3f6308b"


def check_helpers():
    assert digest(PARENT_PATH) == PARENT_SHA
    assert digest(Path(base.__file__)) == BASE_SHA
    assert digest(Path(fast.__file__)) == FAST_SHA
    assert digest(ROOT / "scripts/recover_stateful_workflow_methods_with_readonly_1111.py") == READONLY_HELPER_SHA


def prepare(args):
    check_helpers()
    assert args.interruption_record and args.readonly_result
    # The inherited functions resolve their child executable and script digest
    # through this binding.  Their original file remains unchanged on disk.
    parent.__file__ = str(Path(__file__).resolve())
    parent.prepare(args)
    out, source = args.out.resolve(), args.source_out.resolve()
    protocol = parent.load(out / "protocol.json")
    cases = parent.load(out / "cases.json")
    approved = {}
    for path in args.readonly_result:
        path = path.resolve()
        result = verified_readonly(path, source, digest(source / "protocol.json"))
        approved[result["name"] + ":" + result["workflow"]] = {"path": str(path), "sha256": digest(path)}
        protocol["inputs"][str(path)] = digest(path)
    for selected in cases["recovery_cases"]:
        name = selected["row"]["canonical_name"]
        skip = [wf for wf in selected["workflows_to_attempt"] if name + ":" + wf in approved]
        selected["workflows_not_reexecuted_readonly_validated"] = skip
        selected["workflows_to_attempt"] = [wf for wf in selected["workflows_to_attempt"] if wf not in skip]
        # The frozen selection keeps cover visible but this is a tooling extra,
        # not an admitted runtime workflow.  Never silently choose another extra.
        if name == "setuptools" and selected["row"]["workflow_selection"]["extras"].get("extra") == "cover":
            selected["workflows_to_attempt"] = [wf for wf in selected["workflows_to_attempt"] if wf != "extras"]
            selected["not_applicable_workflows"].append("extras_selected_tooling_semantics")
        selected["eligible"] = bool(selected["workflows_to_attempt"])
        selected["recovery_evidence_class"] = (
            "method_repair_same_complete_official_world" if selected["original_physical_world_complete"]
            else "preparation_continuation_same_requests_new_snapshot")
    dump(out / "cases.json", cases)
    protocol.update(
        schema="foundational-stateful-once-continuation-staged-budget-v1",
        finalized_at_utc=now(),
        script_sha256=digest(Path(__file__)),
        inherited_preparation_helper_sha256=PARENT_SHA,
        readonly_validation_helper_sha256=READONLY_HELPER_SHA,
        cases_sha256=digest(out / "cases.json"),
        already_completed_readonly_validated_chains=approved,
        eligible_preparation_roots=sum(r["eligible"] for r in cases["recovery_cases"]),
        artifact_preparation_seconds=900,
        per_workflow_seconds=3600,
        per_native_command_seconds=900,
        per_file_audit_seconds=900,
        workflows=list(base.WORKFLOWS),
        workflow_description="Original completed or independently read-only-validated actual chains are never reinstalled. Only explicitly interrupted or method/preparation-unknown workflows continue in new environments.",
        recovery_partition="This single continuation owns all eligible unfinished foundational workflows. Prior generic-method and relock recovery registrations remain unexecuted; no overlapping recovery pass runs. Original outcomes, read-only supplements and actual continuation are separately counted.",
        budget_addendum="Before any continuation execution: each native command at most900s, each file audit at most900s, whole workflow at most3600s with isolated worker process-group supervision; two workers. Preparation retains900s. Same requests, target, complete dependency semantics, official archive and transfer/union/expansion caps. Original900s outcomes and explicit interruption are preserved.",
        complete_world_reuse="For a completely verified original physical world with every needed variant prepared, copy the exact manifest, original preparation result and every archive by size/SHA. No metadata request or new artifact candidate. Incomplete preparation uses the unchanged inherited successful-report/snapshot-seed policy.",
    )
    dump(out / "protocol.json", protocol)
    print(json.dumps({"final_protocol_sha256": digest(out / "protocol.json"), "script_sha256": protocol["script_sha256"],
                      "jobs": {r["row"]["canonical_name"]: r["workflows_to_attempt"] for r in cases["recovery_cases"] if r["eligible"]}}), flush=True)


def worker(out, name, phase):
    check_helpers()
    protocol = parent.load(out / "protocol.json")
    assert digest(Path(__file__)) == protocol["script_sha256"]
    assert digest(out / "cases.json") == protocol["cases_sha256"]
    selected = next(r for r in parent.load(out / "cases.json")["recovery_cases"] if r["row"]["canonical_name"] == name)
    assert selected["eligible"]
    source = Path(protocol["parent_out"])
    for path, expected in protocol["inputs"].items():
        own = str(source / "cases" / name) + os.sep
        if path.startswith(own) or not path.startswith(str(source / "cases") + os.sep):
            assert digest(Path(path)) == expected
    parent.__file__ = str(Path(__file__).resolve())
    if phase == "artifacts" and selected["original_physical_world_complete"]:
        original = source / "cases" / name / "artifacts"
        prepared = parent.load(original / "results.json")
        needed = {"update": ("base", "old"), "extras": ("base", "extra"), "relock": ("base",)}
        if all(prepared.get("variants", {}).get(v, {}).get("status") == "prepared"
               for wf in selected["workflows_to_attempt"] for v in needed[wf]):
            assert parent.physical_world_complete(original)
            directory = out / "cases" / name / "artifacts"
            directory.mkdir(parents=True, exist_ok=False)
            (directory / "wheelhouse").mkdir()
            checks = {}
            for filename in ("results.json", "wheel-manifest.json"):
                shutil.copyfile(original / filename, directory / filename)
                checks[str(original / filename)] = digest(original / filename)
                assert digest(directory / filename) == checks[str(original / filename)]
            for wheel in parent.load(original / "wheel-manifest.json"):
                src, dst = original / "wheelhouse" / wheel["filename"], directory / "wheelhouse" / wheel["filename"]
                assert src.stat().st_size == wheel["bytes"] and digest(src) == wheel["sha256"]
                shutil.copyfile(src, dst)
                assert dst.stat().st_size == wheel["bytes"] and digest(dst) == wheel["sha256"]
                checks[str(src)] = wheel["sha256"]
            dump(directory / "complete-world-reuse.json", {"at_utc": now(), "fresh_resolver_invocation": False,
                 "fresh_network_transfer_bytes": 0, "parent_files_sha256": checks, "complete_world_unchanged": True})
            print(json.dumps({"phase": "artifacts", "reused_exact_complete_world": True}), flush=True)
            return
    if phase != "artifacts":
        OriginalRecorder = base.Recorder
        class StagedRecorder(OriginalRecorder):
            def __init__(self, directory, seconds=3600):
                super().__init__(directory, protocol["per_workflow_seconds"])
            def command(self, argv, label, **kwargs):
                deadline = self.deadline
                self.deadline = min(deadline, time.monotonic() + protocol["per_native_command_seconds"])
                try:
                    return super().command(argv, label, **kwargs)
                finally:
                    self.deadline = deadline
        base.Recorder = StagedRecorder
        def audit(inventory, wheels, envdir):
            previous = signal.getsignal(signal.SIGALRM)
            def expired(signum, frame):
                # Executor shutdown can wait for submitted reads after an
                # exception.  Kill this isolated worker group at the hard audit
                # deadline instead, retaining its raw partial stage evidence.
                assert os.getpgrp() == os.getpid()
                os.killpg(os.getpgrp(), signal.SIGKILL)
            signal.signal(signal.SIGALRM, expired)
            signal.alarm(protocol["per_file_audit_seconds"])
            try:
                return fast.audit_files(inventory, wheels, envdir)
            finally:
                signal.alarm(0)
                signal.signal(signal.SIGALRM, previous)
        parent.audit_files = audit
    parent.worker(out, name, phase)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--prepare", action="store_true")
    parser.add_argument("--run", action="store_true")
    parser.add_argument("--source-out", type=Path)
    parser.add_argument("--partial-review", type=Path)
    parser.add_argument("--interruption-record", type=Path)
    parser.add_argument("--readonly-result", action="append", type=Path, default=[])
    parser.add_argument("--out", required=True, type=Path)
    parser.add_argument("--worker")
    parser.add_argument("--phase", choices=("artifacts", *base.WORKFLOWS))
    args = parser.parse_args()
    if sys.platform != "linux" or sys.version_info[:3] != (3, 11, 16):
        parser.error("Use the fixed Linux CPython3.11.16 driver")
    if args.prepare:
        prepare(args)
    elif args.worker:
        worker(args.out.resolve(), args.worker, args.phase)
    elif args.run:
        # Reuse the immutable controller with an explicit per-phase timeout;
        # the replacement changes only its supervisor wait bound.
        check_helpers()
        parent.__file__ = str(Path(__file__).resolve())
        import inspect
        text = inspect.getsource(parent.execute)
        assert "p.wait(timeout=902)" in text
        text = text.replace("p.wait(timeout=902)", "p.wait(timeout=protocol['artifact_preparation_seconds' if phase=='artifacts' else 'per_workflow_seconds']+2)")
        namespace = dict(parent.__dict__)
        exec(compile(text, str(Path(__file__).resolve()) + ":inherited-controller", "exec"), namespace)
        namespace["execute"](args.out.resolve())
    else:
        parser.error("Choose --prepare or --run")


if __name__ == "__main__":
    main()
