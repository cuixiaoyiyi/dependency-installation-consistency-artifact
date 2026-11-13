"""Root verification of the real official-artifact source transition and controls."""
import hashlib
import importlib.util
import json
from pathlib import Path
from urllib.parse import unquote

ROOT = Path(__file__).resolve().parents[1]
BASE = ROOT / "work/stateful-workflows-20261111"
SOURCE = BASE / "source-switch/native-intel-url-normalized"
RUN = SOURCE / "transport-continuation"
spec = importlib.util.spec_from_file_location("independent_active_metadata_checker", BASE / "review/review_saved_partial_stages.py")
checker = importlib.util.module_from_spec(spec)
spec.loader.exec_module(checker)


def load(path):
    return json.loads(Path(path).read_bytes())


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


result = load(RUN / "results.json")
assert result["status"] == "completed_actual_sequence_no_admitted_defect"
assert result["controls_good"] and result["same_final_inputs"]
preflight = load(ROOT / "work/stateful-validation-20261111/source-switch/preflight-results.json")
expected = {row["source"]: row["candidates"][0]["metadata_sha256"] for row in preflight["results"] if row["package"] == "vllm" and row["source"] in ("cpu", "pypi")}
initial = SOURCE / "runs/vllm/02-cpu-install"
folders = [initial] + [RUN / step["stage"] for step in result["steps"]]
rows, signatures = [], []
for index, folder in enumerate(folders):
    inventory = load(folder / "installed.json")
    installed = {checker.canonicalize_name(d["name"]): d for d in inventory["installed"]}
    assert inventory["environment"]["python_full_version"] == "3.11.16"
    assert inventory["environment"]["sys_platform"] == "linux" and inventory["environment"]["platform_machine"] == "x86_64"
    assert sha(folder / "vllm.METADATA") == expected["cpu" if index == 0 else "pypi"]
    for label in ("pip-check", "uv-check", "pip-inspect"):
        command = load(folder / (label + ".command.json"))
        assert command["returncode"] == 0 and not command["timeout"]
    graph = checker.check(["vllm==0.33.0"], installed, inventory["environment"])
    all_graph = checker.check([d["name"] + "==" + d["version"] for d in inventory["installed"]] + ["vllm==0.33.0"], installed, inventory["environment"])
    assert not graph["violations"] and not all_graph["violations"]
    for entry in graph["source_unknowns"] + all_graph["source_unknowns"]:
        req = checker.Requirement(entry["requirement"])
        direct = installed[checker.canonicalize_name(req.name)]["direct_url"]
        assert direct and unquote(direct["url"].split("#", 1)[0]) == unquote(req.url.split("#", 1)[0])
    signatures.append(sorted((name, d["version"], hashlib.sha256(d["metadata"].encode()).hexdigest()) for name, d in installed.items()))
    rows.append({"stage": str(folder.relative_to(ROOT)), "inventory_sha256": sha(folder / "installed.json"), "installed_count": len(installed), "root_version": installed["vllm"]["version"], "official_source_metadata_match": True, "root_closure": graph, "all_installed_base_closure": all_graph, "direct_url_metadata_unknowns_independently_matched": len(graph["source_unknowns"]) + len(all_graph["source_unknowns"])})
assert signatures[1] == signatures[2] == signatures[3]
assert len({sha(folder / "pyproject.toml") for folder in folders[1:]}) == 1
assert len({sha(folder / "uv.lock") for folder in folders[1:]}) == 1
assert all(step["command"]["returncode"] == 0 and not step["command"]["timeout"] for step in result["steps"])
starting = load(RUN / "starting-record-integrity.json")
assert not starting["errors"] and starting["inventory_unchanged"]
out = RUN / "root-final-review.json"
assert not out.exists()
report = {"status": "one_completed_real_source_transition_no_installed_contract_violation", "confirmed_new_defects": 0, "confirmed_affected_roots": [],
          "source_result_sha256": sha(RUN / "results.json"), "rows": rows, "final_three_full_metadata_inventories_equal": True, "same_final_manifest_and_lock": True,
          "starting_record_payloads_checked": starting["checked_payloads"],
          "scope": "Official CPU consumer configuration with explicit original backend requirements, Triton authorization and native Intel-wheel URL workaround, then complete PyPI backend configuration. Full real dependencies installed. Original transport timeout remains unknown; parent healthy CPU plus one bounded continuation constitute one composite source workflow. Same shared verified content cache, distinct fresh environment, no GPU inference. Final whole CUDA payloads were not independently byte-hashed here; root METADATA/source identity and every installed active dependency were checked.",
          "script_sha256": sha(__file__)}
out.write_text(json.dumps(report, indent=2) + "\n")
print(json.dumps({"status": report["status"], "counts": [row["installed_count"] for row in rows], "full_metadata_inventories_equal": True}))
