"""Preregistered read-only native saved-inventory audit; never runs installers."""
import argparse
from collections import Counter
from datetime import datetime, timezone
from email.parser import BytesParser, Parser
import hashlib
import json
import os
from pathlib import Path
import signal
import time
import tomllib

from packaging.requirements import Requirement
from packaging.utils import canonicalize_name
from review_saved_partial_stages import check

ROOT = Path(__file__).resolve().parents[3]
HERE = Path(__file__).resolve().parent
SWEEP_HOME = HERE / "published-saved-inventory-sweep-v3"
SOURCES = ["run1", "corrected-continuation1", "staged-continuation2"]
WF = ("update", "extras", "relock")
RO = [
    ("akshare-completed-operations-readonly1/akshare/update/results.json", "akshare-readonly-root-gate.json"),
    ("aider-completed-relock-readonly1/aider-chat/relock/results.json", "aider-readonly-independent-gate.json"),
    ("diffusers-completed-update-readonly1/diffusers/update/results.json", "diffusers-readonly-independent-gate.json"),
]


def now(): return datetime.now(timezone.utc).isoformat()
def sha(raw): return hashlib.sha256(raw).hexdigest()
def ev(path):
    path = Path(path).resolve()
    return {"path": str(path.relative_to(ROOT)), "sha256": sha(path.read_bytes())}
def load(path): return json.loads(Path(path).read_bytes())
def dump(path, value):
    path = Path(path)
    assert not path.exists(), str(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2) + "\n")
def normalized(value): return os.path.normpath(str(value))


def register():
    assert not SWEEP_HOME.exists()
    sources, expected = [], None
    for name in SOURCES:
        path = ROOT / "work/stateful-workflows-20261111/published" / name
        protocol, cases = load(path / "protocol.json"), load(path / "cases.json")
        assert ev(path / "cases.json")["sha256"] == protocol["cases_sha256"]
        roots = cases["roots"]
        frozen = {r["canonical_name"]: {key: r[key] for key in ("request", "target_python", "runtime", "marker_environment", "workflow_selection")} for r in roots}
        assert len(frozen) == 33
        if expected is None: expected = frozen
        else: assert frozen == expected
        sources.append({"name": name, "directory": str(path.relative_to(ROOT)), "protocol": ev(path / "protocol.json"), "cases": ev(path / "cases.json")})
    baseline = ROOT / "work/stateful-workflows-20261111/foundational-effective/effective-ledger.json"
    core = {p: row["expected"] for p, row in load(baseline)["core29"]["files"].items()}
    assert len(core) == 29 and all(sha((ROOT / p).read_bytes()) == h for p, h in core.items())
    dump(SWEEP_HOME / "registration.json", {
        "schema": "independent-published-saved-inventory-sweep-registration-v1", "registered_at_utc": now(),
        "script": ev(Path(__file__).resolve()), "fixed_point_checker": ev(HERE / "review_saved_partial_stages.py"),
        "sources": sources, "core29_baseline": ev(baseline), "core29_expected": core,
        "method_revision": {"prior_output_failure": ev(HERE / "published-saved-inventory-sweep/checkpoint-20261111T075935/method-failure.json"), "prior_v2_path_boundary_failure": ev(HERE / "published-saved-inventory-sweep-v2/path-boundary-check.json"), "path_boundary_validation": ev(HERE / "published-saved-inventory-path-check-v3.json"), "scope": "Only evidence path normalization/provenance changed; metadata selection/validation functions remain AST-identical to original registered checker."},
        "scan_seconds": 900, "inventory_glob": "cases/*/*/stages/*/installed.json",
        "selection": "Freeze eligible inventory paths with mtime<=an explicit UTC cutoff before reading their bodies. Later/new paths remain outside that checkpoint, never negative. Required evidence written after the cutoff is unknown for that checkpoint.",
        "validation": "Actual non-dry install/sync exit0, inventory-collection exit0 and matching target executable; full frozen native environment equality; expected root/extra request and saved strict manifest; serialized and saved original METADATA Name/Version/Requires-Dist self-consistency; current-request extra fixed point for every installer, and all-installed-base for strict sync. Bind every input before/after SHA.",
        "candidate_rule": "A successful actual pip/uv operation with current-root closure violations is held as a candidate. Strict sync also holds all-installed-base violations. Ordinary pip unrelated orphan/base conflicts are observations. Other missing/drifting/unknown evidence remains explicit; candidates can also have incomplete evidence.",
        "final_requirement": "Final mode requires an immutable published-99-slots-closed-attestation-v1 with all_99_slots_closed=true, logical_slots=99, active_actual_workers=0, and bound effective_ledger plus staged_summary paths/SHA, supplied after Root/rounds formally closes the batch. It cannot be inferred from a checkpoint.",
        "readonly_composites": RO,
        "limits": ["No new installation, package selection, resolver retry, live-environment reconstruction or original artifact edit.", "Saved metadata self-consistency/closure does not replace wheel/RECORD/file integrity or target-lock/source audits, which are separate evidence.", "297 layer/workflow slots describe three retained layers of99 logical root/workflow pairs; they are not297 new workflows or projects.", "Read-only composite proofs bind existing logical chains and add zero actual installations.", "Missing/no-inventory coverage outcomes do not become healthy package verdicts."],
    })
    print(json.dumps({"registration": ev(SWEEP_HOME / "registration.json")}))


class Inputs:
    def __init__(self, cutoff): self.cutoff, self.before = cutoff, {}
    def read(self, path, row, kind="input"):
        path = Path(path)
        raw = path.read_bytes()
        key, h = str(path.relative_to(ROOT)), sha(raw)
        row.setdefault("bound_paths", []).append(key)
        if key in self.before and self.before[key] != h: row["unknown_reasons"].append("Source changed between reads: " + key)
        self.before.setdefault(key, h)
        if path.stat().st_mtime > self.cutoff: row["unknown_reasons"].append("Evidence written after checkpoint cutoff: " + key)
        return raw
    def json(self, path, row): return json.loads(self.read(path, row))
    def changes(self):
        changed = []
        for key, h in self.before.items():
            try: actual = sha((ROOT / key).read_bytes())
            except OSError: actual = None
            if actual != h: changed.append({"path": key, "before_sha256": h, "after_sha256": actual})
        return changed


def expected_request(case, label):
    if label in {"pip-old", "uv-old"}: return case["workflow_selection"]["update"]["from_request"]
    if label == "uv-extra": return case["workflow_selection"]["extras"]["extra_request"]
    if label in {"pip-updated", "uv-updated", "uv-base", "uv-base-restored", "uv-before-relock", "uv-after-relock", "uv-fresh-final-lock"}: return case["request"]
    raise ValueError("Unregistered stage label: " + label)


def metadata(meta, name, item):
    assert canonicalize_name(meta["Name"]) == name and meta["Version"] == item["version"], "METADATA Name/Version mismatch"
    assert meta.get_all("Requires-Dist", []) == item["requires_dist"], "METADATA Requires-Dist mismatch"


def stage_review(path, source, case, inputs, coverage):
    row = {"inventory": ev(path), "source_layer": source["name"], "root": path.parents[3].name,
           "workflow": path.parents[2].name, "stage": path.parent.name, "unknown_reasons": [], "bound_paths": [],
           "current_root_candidate": False, "strict_all_base_candidate": False, "actual_successful_operation": False,
           "present_in_final_aggregate_at_cutoff": path.parent.name in coverage.get("aggregated_stage_labels", []),
           "aggregate_observation": coverage.get("result")}
    stage, workflow, label = path.parent, path.parents[2], path.parent.name
    try:
        inv = inputs.json(path, row)
        assert inv["environment"] == case["marker_environment"], "Full native marker environment differs from frozen case"
        assert inv["environment"]["python_full_version"] == case["target_python"]
        command = inputs.json(workflow / "commands" / label / "command.json", row)
        argv = command["argv"]
        assert command.get("executed") is not False and command["exit"] == 0 and not command.get("timeout", False), "No successful actual operation"
        assert "--dry-run" not in argv and "--no-deps" not in argv
        strict = "sync" in argv and "--locked" in argv
        assert strict or ("install" in argv and "pip" in argv), "Unknown actual install operation"
        row["strict_uv_sync"] = strict
        assert argv.count("--python") == 1
        python_arg = argv[argv.index("--python") + 1]
        target = Path(inv["executable"]).parent.parent
        if strict:
            assert normalized(python_arg) == normalized(case["runtime"]), "Sync interpreter differs from frozen native runtime"
            assert normalized(command["environment_controls"]["UV_PROJECT_ENVIRONMENT"]) == normalized(target), "Sync target differs from saved inventory"
        else:
            assert normalized(python_arg) == normalized(inv["executable"]), "Pip target differs from saved inventory"
        collection = inputs.json(workflow / "commands" / (label + "-inventory") / "command.json", row)
        assert collection["exit"] == 0 and normalized(collection["argv"][0]) == normalized(inv["executable"])
        for folder, cmd in [(workflow / "commands" / label, command), (workflow / "commands" / (label + "-inventory"), collection)]:
            for stream in ("stdout", "stderr"):
                raw = inputs.read(folder / (stream + ".txt"), row)
                assert sha(raw) == cmd[stream + "_sha256"], "Actual command stream SHA differs"
                if folder.name.endswith("-inventory") and stream == "stdout": assert json.loads(raw) == inv
        row["actual_successful_operation"] = True
        expected = expected_request(case, label)
        requests = [expected]
        if strict:
            if (stage / "pyproject.toml").exists():
                manifest = tomllib.loads(inputs.read(stage / "pyproject.toml", row).decode())
                requests = manifest["project"]["dependencies"]
                if requests != [expected]: row["unknown_reasons"].append("Saved strict request differs from the frozen stage request")
                if manifest["project"].get("requires-python") != "==" + case["target_python"]: row["unknown_reasons"].append("Saved project Python constraint differs from frozen target")
            else: row["unknown_reasons"].append("Missing saved strict manifest; closure uses the separately frozen expected request only")
            if (stage / "uv.lock").exists(): inputs.read(stage / "uv.lock", row)
            else: row["unknown_reasons"].append("Missing saved strict lock; no target-lock/source certificate in this review")
        else:
            requests = [argv[-1]]
            if requests != [expected]: row["unknown_reasons"].append("Actual pip request differs from frozen stage request")
        row["requests"], row["expected_frozen_request"] = requests, expected
        installed = {canonicalize_name(item["name"]): item for item in inv["installed"]}
        assert len(installed) == len(inv["installed"]), "Duplicate canonical installed names"
        for name, item in installed.items():
            metadata(Parser().parsestr(item["metadata"]), name, item)
            original = stage / "metadata" / name / "METADATA"
            if original.exists(): metadata(BytesParser().parsebytes(inputs.read(original, row)), name, item)
            else: row["unknown_reasons"].append("Missing saved original METADATA: " + name)
        row["installed_distributions"] = len(installed)
        row["root_closure"] = check(requests, installed, inv["environment"])
        row["all_installed_base_closure"] = check([item["name"] + "==" + item["version"] for item in inv["installed"]] + requests, installed, inv["environment"])
        row["current_root_candidate"] = bool(row["root_closure"]["violations"])
        row["strict_all_base_candidate"] = bool(strict and row["all_installed_base_closure"]["violations"])
        row["pip_orphan_conflict_observations"] = row["all_installed_base_closure"]["violations"] if not strict else []
        if row["root_closure"]["source_unknowns"] or (strict and row["all_installed_base_closure"]["source_unknowns"]): row["unknown_reasons"].append("Direct URL identity requires separate original artifact review")
    except Exception as error:
        row["unknown_reasons"].append(type(error).__name__ + ": " + str(error))
    return row


def scan(args):
    regpath = SWEEP_HOME / "registration.json"
    reg = load(regpath)
    for item in [reg["script"], reg["fixed_point_checker"], reg["core29_baseline"]] + [s[k] for s in reg["sources"] for k in ("protocol", "cases")]:
        assert ev(ROOT / item["path"]) == item
    assert all(sha((ROOT / p).read_bytes()) == h for p, h in reg["core29_expected"].items())
    assert args.out and not args.out.exists()
    args.out.mkdir(parents=True)
    cutoff = datetime.fromisoformat(args.cutoff).timestamp() if args.cutoff else time.time()
    cutoff_iso = datetime.fromtimestamp(cutoff, timezone.utc).isoformat()
    closure = None
    if args.is_final:
        assert args.closure_attestation
        att = load(args.closure_attestation)
        assert att["schema"] == "published-99-slots-closed-attestation-v1" and att["all_99_slots_closed"] is True
        assert att["logical_slots"] == 99 and att["active_actual_workers"] == 0
        for key in ("effective_ledger", "staged_summary"):
            assert ev(ROOT / att[key]["path"]) == att[key]
        closure = {"attestation": ev(args.closure_attestation), **att}
    inputs, selected, later, coverage = Inputs(cutoff), [], [], []
    cases_by_source = {}
    for source in reg["sources"]:
        directory = ROOT / source["directory"]
        cases = {r["canonical_name"]: r for r in load(directory / "cases.json")["roots"]}
        cases_by_source[source["name"]] = cases
        for path in sorted((directory / "cases").glob("*/*/stages/*/installed.json")):
            item = {"source_layer": source["name"], "inventory": ev(path), "mtime_utc": datetime.fromtimestamp(path.stat().st_mtime, timezone.utc).isoformat()}
            (selected if path.stat().st_mtime <= cutoff else later).append(item)
    dump(args.out / "frozen-selection.json", {"cutoff_utc": cutoff_iso, "sources": reg["sources"], "eligible_inventories": selected, "later_inventories_excluded": later})
    rows, began, budget_exhausted = [], time.monotonic(), False
    def expired(signum, frame): raise TimeoutError("Preregistered900-second read-only scan budget exhausted")
    old_handler = signal.signal(signal.SIGALRM, expired)
    signal.alarm(reg["scan_seconds"])
    try:
        coverage_index = {}
        for source in reg["sources"]:
            for name in cases_by_source[source["name"]]:
                for wf in WF:
                    item = {"source_layer": source["name"], "root": name, "workflow": wf, "unknown_reasons": [], "bound_paths": []}
                    path = ROOT / source["directory"] / "cases" / name / wf / "results.json"
                    if path.exists() and path.stat().st_mtime <= cutoff:
                        try:
                            result = inputs.json(path, item)
                            item.update(result=ev(path), reported_status=result.get("status"), reason=result.get("reason"), aggregated_stage_labels=[s.get("stage") for s in result.get("stages", [])])
                        except Exception as exc: item["unknown_reasons"].append(str(exc))
                    else: item["reported_status"] = "no_final_result_at_cutoff"
                    item["saved_inventory_count_at_cutoff"] = sum(s["source_layer"] == source["name"] and Path(s["inventory"]["path"]).parents[3].name == name and Path(s["inventory"]["path"]).parents[2].name == wf for s in selected)
                    item["absence_is_negative_evidence"] = False
                    coverage.append(item); coverage_index[source["name"], name, wf] = item
        for selected_item in selected:
            path = ROOT / selected_item["inventory"]["path"]
            source = next(s for s in reg["sources"] if s["name"] == selected_item["source_layer"])
            case = cases_by_source[source["name"]][path.parents[3].name]
            row = stage_review(path, source, case, inputs, coverage_index[source["name"], path.parents[3].name, path.parents[2].name])
            if row["inventory"] != selected_item["inventory"]: row["unknown_reasons"].append("Inventory changed after frozen cutoff selection")
            rows.append(row)
            if row["current_root_candidate"] or row["strict_all_base_candidate"]: print(json.dumps({"candidate_requires_immediate_triage": row}), flush=True)
            if time.monotonic() - began > reg["scan_seconds"]: raise TimeoutError("Scan budget exhausted")
    except TimeoutError:
        budget_exhausted = True
    finally:
        signal.alarm(0); signal.signal(signal.SIGALRM, old_handler)
    observed = {r["inventory"]["path"] for r in rows}
    for item in selected:
        if item["inventory"]["path"] not in observed:
            rows.append({"inventory": item["inventory"], "source_layer": item["source_layer"], "unknown_reasons": ["Not reviewed within the bounded scan"], "bound_paths": [], "current_root_candidate": False, "strict_all_base_candidate": False})
    changed = inputs.changes()
    changed_paths = {r["path"] for r in changed}
    for row in rows + coverage:
        if set(row.get("bound_paths", [])) & changed_paths: row["unknown_reasons"].append("Bound source SHA drifted during read-only review")
        candidate = row.get("current_root_candidate") or row.get("strict_all_base_candidate")
        if "inventory" in row:
            row["status"] = "candidate_requires_independent_actual_triage" if candidate else "unknown_saved_stage_review" if row["unknown_reasons"] else "saved_metadata_current_request_and_strict_contract_satisfied" if row["strict_uv_sync"] else "pip_current_request_satisfied_orphan_conflicts_observation_only"
    ro = []
    for relative, gate_name in reg["readonly_composites"]:
        path = ROOT / "work/stateful-workflows-20261111/published" / relative
        gatepath = HERE / gate_name
        value, gate = load(path), load(gatepath)
        assert gate["status"] == "accepted_as_one_composite_workflow" and gate["result_sha256"] == ev(path)["sha256"]
        protocol = path.parents[2] / "protocol.json"
        assert ev(protocol)["sha256"] == value["protocol_sha256"]
        ro.append({"result": ev(path), "protocol": ev(protocol), "independent_gate": ev(gatepath), "new_actual_installations": 0, "counts_as_an_extra_logical_chain": False})
    core_after = all(sha((ROOT / p).read_bytes()) == h for p, h in reg["core29_expected"].items())
    registered_inputs_after = all(ev(ROOT / item["path"]) == item for item in [reg["script"], reg["fixed_point_checker"], reg["core29_baseline"]] + [s[k] for s in reg["sources"] for k in ("protocol", "cases")])
    newly_observed = []
    known = {i["inventory"]["path"] for i in selected + later}
    for source in reg["sources"]:
        newly_observed += [str(p.relative_to(ROOT)) for p in (ROOT / source["directory"] / "cases").glob("*/*/stages/*/installed.json") if str(p.relative_to(ROOT)) not in known]
    budget_exhausted = budget_exhausted or time.monotonic() - began > reg["scan_seconds"]
    counts = {"saved_inventory_observations": len(rows), "unaggregated_inventories": sum(not r.get("present_in_final_aggregate_at_cutoff", False) for r in rows), "candidate_rows": sum(r["current_root_candidate"] or r["strict_all_base_candidate"] for r in rows), "rows_with_unknowns": sum(bool(r["unknown_reasons"]) for r in rows), "status": dict(Counter(r["status"] for r in rows)), "source_layer_workflow_slots": len(coverage), "logical_root_workflow_pairs": 99, "layer_workflows_without_saved_inventory": sum(not r["saved_inventory_count_at_cutoff"] for r in coverage), "readonly_composite_proofs": len(ro), "new_actual_installations_performed_by_this_review": 0}
    report = {"schema": "independent-published-saved-inventory-sweep-v1", "is_final": args.is_final, "cutoff_utc": cutoff_iso, "finished_at_utc": now(), "seconds": round(time.monotonic() - began, 3), "registration": ev(regpath), "script": ev(Path(__file__).resolve()), "registered_sources": reg["sources"], "frozen_selection": ev(args.out / "frozen-selection.json"), "counts": counts, "rows": rows, "coverage_layer_rows": coverage, "readonly_composite_proofs": ro, "final_closure_attestation": closure, "core29_unchanged": core_after, "registered_inputs_unchanged": registered_inputs_after, "source_files_before_after_sha_unchanged": not changed, "source_changes": changed, "all_selected_inventory_paths_accounted_for": len(rows) == len(selected), "scan_budget_exhausted": budget_exhausted, "later_inventories_excluded": later, "new_inventory_paths_after_selection": newly_observed, "limits": reg["limits"] + ["Final/coverage labels describe the observed saved-stage audit only, not99 successful full workflows. No future or absent inventory is a negative."]}
    report["final_gate_passed"] = bool(args.is_final and closure and core_after and registered_inputs_after and not changed and not later and not newly_observed and not budget_exhausted and counts["candidate_rows"] == counts["rows_with_unknowns"] == 0)
    dump(args.out / "results.json", report)
    print(json.dumps({"output": ev(args.out / "results.json"), "is_final": args.is_final, "final_gate_passed": report["final_gate_passed"], "counts": counts}), flush=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(); parser.add_argument("--register", action="store_true"); parser.add_argument("--scan", action="store_true"); parser.add_argument("--out", type=Path); parser.add_argument("--cutoff"); parser.add_argument("--is-final", action="store_true"); parser.add_argument("--closure-attestation", type=Path)
    args = parser.parse_args()
    if args.register: register()
    elif args.scan: scan(args)
    else: parser.error("Use --register or --scan")
