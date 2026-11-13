"""Read-only layered effective ledger and actual state deltas; never installs."""
from __future__ import annotations
import argparse
from collections import Counter
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from packaging.utils import canonicalize_name
from scripts.run_expanded_validation import digest, dump, now


def load(path):
    return json.loads(path.read_text())


def witness(path):
    return {"path": str(path.relative_to(ROOT)), "sha256": digest(path)} if path.exists() else None


def completed(value):
    return value.get("status") in {"completed_actual_stateful_workflow", "actual_operation_chain_completed_with_additional_readonly_validation"}


def stages(directory):
    values, refs = {}, {}
    for path in sorted((directory / "stages").glob("*/installed.json")):
        value = load(path)
        values[path.parent.name] = {canonicalize_name(d["name"]): d["version"] for d in value["installed"]}
        refs[path.parent.name] = witness(path)
    return values, refs


def difference(before, after):
    return {"added": {n: after[n] for n in sorted(set(after) - set(before))},
            "removed": {n: before[n] for n in sorted(set(before) - set(after))},
            "changed_versions": {n: {"before": before[n], "after": after[n]} for n in sorted(set(before) & set(after)) if before[n] != after[n]},
            "name_version_map_changed": before != after}


def delta(directory, name, workflow):
    maps, refs = stages(directory)
    result = {"saved_inventory_witnesses": refs}
    if workflow == "update":
        for tool, old, new in (("pip", "pip-old", "pip-updated"), ("uv", "uv-old", "uv-updated")):
            if old in maps and new in maps:
                result[tool] = difference(maps[old], maps[new])
                result[tool]["root_before"] = maps[old].get(name)
                result[tool]["root_after"] = maps[new].get(name)
                result[tool]["root_version_actually_changed"] = maps[old].get(name) != maps[new].get(name)
    elif workflow == "extras":
        if {"uv-base", "uv-extra", "uv-base-restored"} <= set(maps):
            result["base_to_extra"] = difference(maps["uv-base"], maps["uv-extra"])
            result["extra_to_base"] = difference(maps["uv-extra"], maps["uv-base-restored"])
            result["base_name_versions_restored"] = maps["uv-base"] == maps["uv-base-restored"]
    elif {"uv-before-relock", "uv-after-relock"} <= set(maps):
        result["before_to_after_relock"] = difference(maps["uv-before-relock"], maps["uv-after-relock"])
        first, last = directory / "stages/uv-before-relock/uv.lock", directory / "stages/uv-after-relock/uv.lock"
        result["lock_bytes_changed"] = digest(first) != digest(last)
    if "uv-fresh-final-lock" in maps:
        last = {"update": "uv-updated", "extras": "uv-base-restored", "relock": "uv-after-relock"}[workflow]
        if last in maps:
            result["warm_fresh_name_versions_equal"] = maps[last] == maps["uv-fresh-final-lock"]
    return result


def operations(directory, workflow):
    labels = {"update": ("pip-old", "pip-updated", "uv-old", "uv-updated", "uv-fresh-final-lock"),
              "extras": ("uv-base", "uv-extra", "uv-base-restored", "uv-fresh-final-lock"),
              "relock": ("uv-before-relock", "uv-after-relock", "uv-fresh-final-lock")}[workflow]
    rows = []
    for label in labels:
        path = directory / "commands" / label / "command.json"
        if path.exists():
            value = load(path)
            rows.append({"label": label, "exit": value["exit"], "seconds": value.get("seconds"), **witness(path)})
    unfinished = [label for label in labels if (directory / "commands" / label).exists() and not (directory / "commands" / label / "command.json").exists()]
    return {"commands": rows, "commands_without_completion_record": unfinished,
            "all_actual_operations_exit_zero": len(rows) == len(labels) and all(r["exit"] == 0 for r in rows)}


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--original", required=True, type=Path)
    p.add_argument("--continuation", required=True, type=Path)
    p.add_argument("--readonly", required=True, type=Path)
    p.add_argument("--saved-review", required=True, type=Path)
    p.add_argument("--out", required=True, type=Path)
    args = p.parse_args()
    original, continuation, readonly, out = (x.resolve() for x in (args.original, args.continuation, args.readonly, args.out))
    assert (continuation / "summary.json").exists(), "Final continuation required"
    assert not out.exists(), "New ledger directory required"
    cases = load(original / "cases.json")
    proof = load(readonly)
    protocol = load(continuation / "protocol.json")
    dispatch = {r["row"]["canonical_name"]: r for r in load(continuation / "cases.json")["recovery_cases"]}
    rows = []
    for root in cases["roots"]:
        name = root["canonical_name"]
        for wf in ("update", "extras", "relock"):
            oldpath = original / "cases" / name / wf / "results.json"
            newpath = continuation / "cases" / name / wf / "results.json"
            old = load(oldpath) if oldpath.exists() else {"status": "explicitly_interrupted_or_not_started_original_workflow"}
            new = load(newpath) if newpath.exists() else {}
            ro = proof if (proof["name"], proof["workflow"]) == (name, wf) else {}
            if completed(old) or "candidate" in old["status"]:
                effective, evidence_class, directory = old, "original_actual_chain", oldpath.parent
                assert not newpath.exists(), "Completed/candidate original was reexecuted"
            elif ro:
                effective, evidence_class, directory = ro, "original_actual_chain_plus_additional_readonly_validation", oldpath.parent
                assert not newpath.exists(), "Read-only-validated original chain was reexecuted"
            elif new:
                reuse_proof = continuation / "cases" / name / "artifacts/complete-world-reuse.json"
                # Physical completeness covers the archived manifest; a missing
                # extra variant can still require a new preparation capture.
                # Classify actual evidence from its reuse witness, never the
                # preregistration's coarse physical-readiness label alone.
                evidence_class = "method_repair_same_complete_official_world" if reuse_proof.exists() else "preparation_continuation_same_requests_new_snapshot"
                effective, directory = new, newpath.parent
            else:
                effective, evidence_class, directory = old, "original_unrecovered_coverage_outcome", oldpath.parent
            selected = root["workflow_selection"].get(wf, {})
            if wf == "extras" and (selected.get("status") != "selected" or name == "setuptools" and selected.get("extra") == "cover"):
                status = "unsupported_selected_extra_tooling_semantics" if name == "setuptools" else "unsupported_no_eligible_runtime_extra"
            else:
                status = effective["status"]
            row = {"name": name, "version": root["version"], "workflow": wf,
                   "request": root["request"], "target_python": root["target_python"],
                   "marker_environment": root["marker_environment"], "frozen_workflow_selection": selected,
                   "candidate_worlds": {"original_manifest": witness(original / "cases" / name / "artifacts/wheel-manifest.json"),
                                        "continuation_manifest": witness(continuation / "cases" / name / "artifacts/wheel-manifest.json"),
                                        "original_preparation": witness(original / "cases" / name / "artifacts/results.json"),
                                        "continuation_preparation": witness(continuation / "cases" / name / "artifacts/results.json"),
                                        "complete_world_reuse_proof": witness(continuation / "cases" / name / "artifacts/complete-world-reuse.json"),
                                        "preregistered_coarse_classification": dispatch[name]["recovery_evidence_class"]},
                   "original": {"result": witness(oldpath), "status": old["status"], "reason": old.get("reason"), "actual_operations": operations(oldpath.parent, wf)},
                   "readonly_supplement": {"result": witness(readonly), "status": ro["status"]} if ro else None,
                   "actual_continuation": {"result": witness(newpath), "status": new.get("status"), "reason": new.get("reason"), "actual_operations": operations(newpath.parent, wf)} if new else None,
                   "effective_status": status,
                   "effective_reason": ("Frozen selected cover extra activates pytest-cov tooling; retained as unsupported runtime-extra coverage without choosing another extra."
                                        if status == "unsupported_selected_extra_tooling_semantics" else
                                        "No eligible runtime extra selected by the frozen rule." if status == "unsupported_no_eligible_runtime_extra" else effective.get("reason")),
                   "effective_evidence_class": evidence_class,
                   "completed_actual_chain": completed(effective), "actual_operations": operations(directory, wf),
                   "actual_delta": delta(directory, name, wf), "confirmed_defect": False,
                   "candidate_requires_independent_review": "candidate" in status or any(s.get("candidate") for s in effective.get("stages", []))}
            rows.append(row)
    baseline = ROOT / "work/fp-fixes-20261110/revalidation-final/summary.json"
    core = load(baseline)["implementation_sha256"]
    assert len(core) == 29
    checks = {path: {"expected": sha, "actual": digest(ROOT / path)} for path, sha in core.items()}
    assert all(c["expected"] == c["actual"] for c in checks.values())
    assert len(rows) == 57 and len({(r["name"], r["workflow"]) for r in rows}) == 57
    saved_review = load(args.saved_review.resolve())
    saved_paths = {str((ROOT / r["inventory"]["path"]).resolve()): r["inventory"]["sha256"] for r in saved_review["rows"]}
    for source in (original, continuation):
        for path in (source / "cases").glob("*/*/stages/*/installed.json"):
            assert saved_paths.get(str(path.resolve())) == digest(path), "Final saved-state sweep is stale or incomplete"
    for path in (original / "target-lock-original-complete-prefixes.json", continuation / "target-lock-complete-prefixes.json"):
        reviewed = load(path)
        assert reviewed["all_reviewed_inputs_unchanged"] and reviewed["core_unchanged"]
    done = [r for r in rows if r["completed_actual_chain"]]
    counts = {"eligible_roots": len(cases["roots"]), "logical_root_workflow_slots": len(rows),
              "effective_status": dict(Counter(r["effective_status"] for r in rows)),
              "completed_chains": len(done), "completed_by_evidence_class": dict(Counter(r["effective_evidence_class"] for r in done)),
              "completed_by_workflow": dict(Counter(r["workflow"] for r in done)),
              "nondegenerate_update_both_installers": sum(r["workflow"] == "update" and all(r["actual_delta"].get(t, {}).get("root_version_actually_changed") for t in ("pip", "uv")) for r in done),
              "extras_added_distributions": sum(len(r["actual_delta"].get("base_to_extra", {}).get("added", {})) for r in done if r["workflow"] == "extras"),
              "extras_removed_distributions": sum(len(r["actual_delta"].get("extra_to_base", {}).get("removed", {})) for r in done if r["workflow"] == "extras"),
              "extras_actual_name_version_delta": sum(r["actual_delta"].get("base_to_extra", {}).get("name_version_map_changed", False) for r in done if r["workflow"] == "extras"),
              "relock_actual_name_version_delta": sum(r["actual_delta"].get("before_to_after_relock", {}).get("name_version_map_changed", False) for r in done if r["workflow"] == "relock"),
              "relock_no_name_version_delta": sum(not r["actual_delta"].get("before_to_after_relock", {}).get("name_version_map_changed", False) for r in done if r["workflow"] == "relock"),
              "candidate_workflows": sum(r["candidate_requires_independent_review"] for r in rows),
              "saved_metadata_stage_candidates": sum(r["status"].startswith("candidate") for r in saved_review["rows"]),
              "saved_metadata_stage_unknowns": sum(r["status"].startswith("unknown") for r in saved_review["rows"]),
              "confirmed_new_defects": 0}
    unused = []
    for name in ("foundational-relock-recovery", "foundational-methods-recovery", "foundational-methods-recovery-v2"):
        directory = original.parent / name
        if directory.exists():
            assert not (directory / "run-started.json").exists()
            assert not (directory / "summary.json").exists()
            unused.append({"directory": str(directory.relative_to(ROOT)), "protocol": witness(directory / "protocol.json"), "executed": False})
    value = {"schema": "foundational-stateful-effective-ledger-v1", "created_at_utc": now(), "counts": counts,
             "original_protocol": witness(original / "protocol.json"), "continuation_protocol": witness(continuation / "protocol.json"),
             "classification_clarification": witness(continuation / "classification-clarification.json"),
             "unused_preexecution_registrations": unused,
             "independent_post_reviews": {"all_saved_metadata_states": witness(args.saved_review.resolve()),
                                          "original_complete_strict_stage_prefixes": witness(original / "target-lock-original-complete-prefixes.json"),
                                          "continuation_complete_strict_stage_prefixes": witness(continuation / "target-lock-complete-prefixes.json")},
             "interruption_record": witness(Path(protocol["parent_out"]).parent / "review/foundational-original-interruption.json"),
             "rows": rows, "excluded_coverage_slots": cases.get("excluded_coverage_slots", []),
             "core29": {"baseline": witness(baseline), "files": checks, "all_unchanged": True},
             "limits": ["Each logical root/workflow occurs once. Original outcomes, additional read-only proof and actual continuation remain distinct.",
                        "No-change relock is a real command chain but provides no observed graph/version-change sensitivity.",
                        "Official native-wheel restricted worlds and controlled package-root manifests do not replay original repository commands or the complete public index.",
                        "Original .data payload comparisons and any partial historical verification remain bounded separately; installed RECORD evidence does not erase that boundary.",
                        "No precision, recall, prevalence, cross-platform or application-behavior claim follows from these negative controlled workflows."]}
    out.mkdir(parents=True)
    dump(out / "effective-ledger.json", value)
    lines = ["| Root | Update actual root delta (pip / uv) | Extra add/remove distributions | Relock installed plan | Evidence (A/C/R) |", "|---|---|---|---|---|"]
    for root in cases["roots"]:
        selected = {r["workflow"]: r for r in rows if r["name"] == root["canonical_name"]}
        a, c, r = (selected[wf] for wf in ("update", "extras", "relock"))
        if a["completed_actual_chain"]:
            astr = " / ".join(d["root_before"] + "→" + d["root_after"] for d in (a["actual_delta"]["pip"], a["actual_delta"]["uv"]))
        else: astr = a["effective_status"]
        cstr = (str(len(c["actual_delta"]["base_to_extra"]["added"])) + "/" + str(len(c["actual_delta"]["extra_to_base"]["removed"]))) if c["completed_actual_chain"] else c["effective_status"]
        rstr = ("changed" if r["actual_delta"]["before_to_after_relock"]["name_version_map_changed"] else "no name/version delta") if r["completed_actual_chain"] else r["effective_status"]
        labels = "/".join({"original_actual_chain": "original", "original_actual_chain_plus_additional_readonly_validation": "original+RO", "method_repair_same_complete_official_world": "method", "preparation_continuation_same_requests_new_snapshot": "prep"}.get(x["effective_evidence_class"], "coverage") for x in (a, c, r))
        lines.append(f"| {root['canonical_name']} | {astr} | {cstr} | {rstr} | {labels} |")
    (out / "actual-deltas.md").write_text("\n".join(lines) + "\n")
    print(json.dumps({"counts": counts, "ledger_sha256": digest(out / "effective-ledger.json"), "table_sha256": digest(out / "actual-deltas.md")}, indent=2))


if __name__ == "__main__":
    main()
