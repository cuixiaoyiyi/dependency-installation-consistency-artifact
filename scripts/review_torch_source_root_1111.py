"""Independent metadata gate for the preregistered real Torch source control."""
import hashlib
import importlib.util
import json
from pathlib import Path
import tomllib

ROOT = Path(__file__).resolve().parents[1]
BASE = ROOT / "work/stateful-workflows-20261111"
RUN = BASE / "source-switch/torch-adaptive-control"
spec = importlib.util.spec_from_file_location("torch_source_active_contract_review", BASE / "review/review_saved_partial_stages.py")
checker = importlib.util.module_from_spec(spec)
spec.loader.exec_module(checker)
load = lambda path: json.loads(Path(path).read_bytes())
sha = lambda path: hashlib.sha256(Path(path).read_bytes()).hexdigest()
result = load(RUN / "results.json")
protocol = load(RUN / "protocol.json")
assert result["status"] == "completed_real_source_transition_negative"
assert result["reproduction_controls"] == "not_required_by_preregistered_negative_rule"
assert sha(ROOT / "scripts/torch_source_transition_control_1111.py") == protocol["script_sha256"]
rows, manifests = [], []
for step in result["steps"]:
    assert step["command"]["returncode"] == 0 and not step["command"]["timeout"]
    if "installed" not in step:
        continue
    folder = RUN / step["stage"]
    inventory = load(folder / "installed.json")
    installed = {checker.canonicalize_name(d["name"]): d for d in inventory["installed"]}
    target = inventory["environment"]
    assert target["python_full_version"] == "3.11.16" and target["sys_platform"] == "linux" and target["platform_machine"] == "x86_64"
    source = "cpu" if step["cpu"] else "pypi"
    assert sha(folder / "torch.METADATA") == protocol["expected_official_root_metadata_sha256"][source]
    assert step["actual_root_matches_locked_full_version"] and step["root_metadata_matches_official_source"]
    assert all(step["installed"][key]["returncode"] == 0 for key in ("pip_check", "uv_check", "inspect"))
    root = checker.check(["torch==2.15.0"], installed, target)
    all_base = checker.check([d["name"] + "==" + d["version"] for d in inventory["installed"]] + ["torch==2.15.0"], installed, target)
    assert not root["violations"] and not all_base["violations"]
    assert not root["source_unknowns"] and not all_base["source_unknowns"]
    manifest = tomllib.loads((folder / "pyproject.toml").read_text())
    manifests.append(manifest)
    rows.append({"stage": step["stage"], "source": source, "installed_count": len(installed), "root_version": installed["torch"]["version"], "official_metadata_matches": True, "root_closure": root, "all_installed_base_closure": all_base, "inventory_sha256": sha(folder / "installed.json")})
assert len(rows) == 2
assert manifests[0]["project"] == manifests[1]["project"]
assert manifests[0]["project"]["dependencies"] == ["torch==2.15.0"]
out = RUN / "root-final-review.json"
assert not out.exists()
out.write_text(json.dumps({"status": "one_completed_real_torch_source_transition_no_installed_contract_violation", "rows": rows, "source_result_sha256": sha(RUN / "results.json"), "protocol_sha256": sha(RUN / "protocol.json"), "reproduction_controls": "Skipped under the negative rule registered before this root ran. No fresh/reinstall equivalence is claimed.", "scope": "Full unmodified official CPU and PyPI artifact dependencies were actually installed; independent installed metadata/checker/source identity review only, no GPU inference or independent whole-payload hashing in this gate.", "confirmed_new_defects": 0, "script_sha256": sha(__file__)}, indent=2) + "\n")
print(json.dumps({"status": "accepted_negative_source_control", "installed_counts": [row["installed_count"] for row in rows]}))
