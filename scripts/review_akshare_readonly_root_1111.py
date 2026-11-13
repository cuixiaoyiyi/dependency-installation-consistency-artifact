"""Independent accounting gate for a completed install chain plus later audit."""
from concurrent.futures import ThreadPoolExecutor
import hashlib
import importlib.util
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BASE = ROOT / "work/stateful-workflows-20261111"
REVIEW = BASE / "published/akshare-completed-operations-readonly1"
OUT = BASE / "review/akshare-readonly-root-gate.json"


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


result_path = REVIEW / "akshare/update/results.json"
result = json.loads(result_path.read_bytes())
protocol = json.loads((REVIEW / "protocol.json").read_bytes())
assert sha(result_path) == "3076245ed2623d6eb1cb22ee5cafecfc601130203fa6139e5b45eed8e3e36c1a"
assert sha(ROOT / "scripts/review_completed_published_readonly_1111.py") == protocol["script_sha256"]
assert sha(REVIEW / "protocol.json") == result["protocol_sha256"]
assert result["status"] == "actual_operation_chain_completed_with_additional_readonly_validation"
assert result["original_actual_operations"] == 5 and result["earlier_stage_full_audits_reused"] == 4
assert result["original_metadata_record_unchanged"] and not result["related_processes_after"]
assert result["core_unchanged"] and result["seconds"] <= protocol["per_review_seconds"]
assert not result["final_file_audit"]["violations"]
assert result["final_target_graph"]["status"] == "verified"
assert all(command["exit"] == 0 for command in result["additional_readonly_checks"])
items = list(result["parent_input_hashes"].items())
with ThreadPoolExecutor(max_workers=4) as pool:
    actual = list(pool.map(lambda item: sha(item[0]), items))
assert all(value == item[1] for item, value in zip(items, actual)), "Parent evidence changed"
source = Path(protocol["source_out"])
workflow = source / "cases/akshare/update"
assert json.loads((workflow / "results.json").read_bytes())["status"] == result["parent_outcome_preserved"]
labels = ("pip-old", "pip-updated", "uv-old", "uv-updated", "uv-fresh-final-lock")
assert all(json.loads((workflow / "commands" / label / "command.json").read_bytes())["exit"] == 0 for label in labels)
inventory = json.loads((workflow / "stages/uv-fresh-final-lock/installed.json").read_bytes())
spec = importlib.util.spec_from_file_location("independent_saved_metadata_gate", BASE / "review/review_saved_partial_stages.py")
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
installed = {m.canonicalize_name(d["name"]): d for d in inventory["installed"]}
case = next(row for row in json.loads((source / "cases.json").read_bytes())["roots"] if row["canonical_name"] == "akshare")
assert inventory["environment"] == case["marker_environment"]
root = m.check([case["request"]], installed, inventory["environment"])
all_base = m.check([d["name"] + "==" + d["version"] for d in inventory["installed"]] + [case["request"]], installed, inventory["environment"])
assert not root["violations"] and not all_base["violations"]
assert not OUT.exists()
report = {"status": "accepted_as_one_composite_workflow", "scope": "Five original actual installations plus one separately registered final read-only audit. Original900 result remains unknown; no new installs and no new defect/project are counted.",
          "result_sha256": sha(result_path), "protocol_sha256": result["protocol_sha256"], "checked_parent_evidence_hashes": len(items),
          "root_closure": root, "all_installed_base_closure": all_base, "distributions": len(installed),
          "file_violations": 0, "original_path_transform_unknowns": len(result["final_file_audit"]["unknown"]),
          "code_review": "Root reviewed the full parent read-only audit and the exact published extension diff; it only adds missing final read-only checkers/inspect and stronger parent-input bindings. Every earlier state still requires its actual original full audit.",
          "script_sha256": sha(__file__)}
OUT.write_text(json.dumps(report, indent=2) + "\n")
print(json.dumps({k: report[k] for k in ("status", "checked_parent_evidence_hashes", "distributions", "original_path_transform_unknowns")}))
