"""Post-sweep quiescence and independent source-set delivery seal; no installs."""
from collections import Counter
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path

from attest_published_closure_1111 import process_snapshot

ROOT = Path(__file__).resolve().parents[3]
BASE = ROOT / "work/stateful-workflows-20261111/published"
REVIEW = ROOT / "work/stateful-workflows-20261111/review"


def digest(path): return hashlib.sha256(Path(path).read_bytes()).hexdigest()
def load(path): return json.loads(Path(path).read_bytes())
def ev(path):
    path = Path(path).resolve()
    return {"path": str(path.relative_to(ROOT)), "sha256": digest(path)}


attpath = BASE / "closure-attestation.json"
sweeppath = REVIEW / "published-saved-inventory-sweep-v3/final/results.json"
assert digest(attpath) == "57f75e12d076e4f19266df92df85be842f9b9b554553f04d631617261ce6d4b3"
assert digest(sweeppath) == "71cb8f5245a321e99bbfb1d72cac64e6030b58ef23982137723abf1df62d2a6f"
att, sweep = load(attpath), load(sweeppath)
assert sweep["is_final"] and sweep["final_gate_passed"]
assert sweep["final_closure_attestation"]["attestation"] == ev(attpath)
assert sweep["core29_unchanged"] and sweep["registered_inputs_unchanged"] and sweep["source_files_before_after_sha_unchanged"]
assert not sweep["source_changes"] and not sweep["scan_budget_exhausted"]
assert not sweep["later_inventories_excluded"] and not sweep["new_inventory_paths_after_selection"]
assert sweep["all_selected_inventory_paths_accounted_for"]
assert sweep["counts"]["saved_inventory_observations"] == 141 and sweep["counts"]["unaggregated_inventories"] == 23
assert sweep["counts"]["candidate_rows"] == sweep["counts"]["rows_with_unknowns"] == 0
assert sweep["counts"]["new_actual_installations_performed_by_this_review"] == 0
assert len(sweep["readonly_composite_proofs"]) == 3 and all(row["new_actual_installations"] == 0 for row in sweep["readonly_composite_proofs"])
sources = [ROOT / source["directory"] for source in sweep["registered_sources"]]
actual = {str(path.relative_to(ROOT)) for source in sources for path in (source / "cases").glob("*/*/stages/*/installed.json")}
reviewed = {row["inventory"]["path"] for row in sweep["rows"]}
assert len(actual) == len(reviewed) == 141 and actual == reviewed
selected = load(ROOT / sweep["frozen_selection"]["path"])
assert {row["inventory"]["path"] for row in selected["eligible_inventories"]} == actual
assert not selected["later_inventories_excluded"]
reg = load(ROOT / sweep["registration"]["path"])
assert digest(ROOT / sweep["registration"]["path"]) == sweep["registration"]["sha256"]
for key in ("script", "fixed_point_checker", "core29_baseline"):
    assert ev(ROOT / reg[key]["path"]) == reg[key]
for source in reg["sources"]:
    for key in ("cases", "protocol"): assert ev(ROOT / source[key]["path"]) == source[key]
assert all(digest(ROOT / path) == expected for path, expected in reg["core29_expected"].items())
for key in ("producer_handoff", "effective_ledger", "staged_summary", "staged_protocol", "producer_no_active_actual_workers", "attestation_tool"):
    assert ev(ROOT / att[key]["path"]) == att[key]
observed_roots = sorted({row["root"] for row in sweep["rows"]})
assert len(observed_roots) == 15
snapshot = process_snapshot(sources)
assert snapshot["active_actual_workers"] == 0 and not snapshot["processes"] and not snapshot["unreadable_owned_processes"]
post = BASE / "independent-final-no-active-workers-after-sweep.json"
assert not post.exists()
post.write_text(json.dumps(snapshot, indent=2) + "\n")
result = {
    "schema": "published-final-saved-inventory-delivery-v1", "sealed_at_utc": datetime.now(timezone.utc).isoformat(),
    "is_final": True, "status": "independent_final_saved_metadata_sweep_accepted_with_coverage_limits",
    "closure_attestation": ev(attpath), "final_sweep": ev(sweeppath), "frozen_sweep_registration": sweep["registration"],
    "independent_no_active_workers_before_sweep": att["independent_no_active_actual_workers"],
    "independent_no_active_workers_after_sweep": ev(post),
    "effective_ledger": att["effective_ledger"], "staged_summary": att["staged_summary"],
    "counts": {"published_registered_roots": 33, "logical_root_workflow_slots": 99, "semantic_applicable_slots": 84, "completed_workflows": 33, "closed_coverage_gaps": 51, "not_applicable_slots": 15, "saved_inventory_observations": 141, "unaggregated_inventory_observations": 23, "successful_pip_current_request_observations": 34, "successful_strict_sync_observations": 107, "candidate_saved_metadata_contract_violations": 0, "unknown_saved_stage_reviews": 0, "observed_installed_canonical_roots": 15, "readonly_composite_proofs": 3, "new_actual_installations_performed_by_review": 0},
    "saved_inventory_observations_by_layer": dict(Counter(row["source_layer"] for row in sweep["rows"])),
    "independently_checked_before_after_source_paths": len({path for row in sweep["rows"] + sweep["coverage_layer_rows"] for path in row.get("bound_paths", [])}),
    "observed_installed_root_names": observed_roots,
    "all_source_saved_inventory_paths_exactly_equal_reviewed_paths": True,
    "registered_inputs_and_core29_still_unchanged": True,
    "final_gate_passed": True,
    "scope": "All saved inventories in the three frozen published layers, including partial/unaggregated stages, full frozen native targets, successful actual operation/collection records, original METADATA field consistency, active current-root/extra fixed points for pip and strict sync, and strict all-installed-base closure. Read-only composite proofs bind existing logical chains without new installs.",
    "limits": ["Zero saved-metadata contradictions does not certify51 coverage gaps, all33 roots installed, package-wide health, artifact/source identity, file integrity, model inference or ecosystem novelty.", "Wheel/payload/RECORD and target-lock/source prefix reviews remain separate evidence. M2 shared-file failure can coexist with satisfied metadata closure and remains independently confirmed.", "141 observations and23 unaggregated observations are saved stages across historical layers, not141 independent logical workflows or projects.", "The pre-sweep closure attestation does not reference this seal or the later sweep; this post-sweep delivery binds both without a hash cycle."],
    "seal_tool": ev(Path(__file__).resolve()),
}
target = BASE / "final-saved-inventory-delivery.json"
assert not target.exists()
target.write_text(json.dumps(result, indent=2) + "\n")
assert ev(attpath) == result["closure_attestation"] and ev(sweeppath) == result["final_sweep"]
print(json.dumps({"delivery": ev(target), "after_process_check": ev(post), "counts": result["counts"], "bound_source_paths": result["independently_checked_before_after_source_paths"]}, indent=2))
