"""Independent read-only admission for the fixed official Ultralytics workflow."""
import csv
from datetime import datetime, timezone
from email.parser import BytesParser
import hashlib
import json
from pathlib import Path
import tomllib
from urllib.parse import unquote, urlsplit
import zipfile

from packaging.utils import canonicalize_name
from review_saved_partial_stages import check

ROOT = Path(__file__).resolve().parents[3]
REVIEW = ROOT / "work/stateful-workflows-20261111/review"
RUN = REVIEW / "ultralytics-extra-actual-01"
SECOND = REVIEW / "ultralytics-extra-independent-root-01"


def load(path):
    return json.loads(path.read_bytes())


def digest(path):
    h = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(4 * 1024**2), b""):
            h.update(block)
    return h.hexdigest()


def evidence(path):
    return {"path": str(path.relative_to(ROOT)), "sha256": digest(path)}


def command(label, expected_exit=0):
    folder = RUN / "commands" / label
    data = load(folder / "command.json")
    assert not data["timeout"] and data["exit"] == expected_exit, label
    assert digest(folder / "stdout") == data["stdout_sha256"]
    assert digest(folder / "stderr") == data["stderr_sha256"]
    return {**evidence(folder / "command.json"), "argv": data["argv"], "exit": data["exit"], "seconds": data["seconds"]}


result_path = RUN / "results.json"
assert result_path.exists(), "Wait for the actual bounded driver"
actual = load(result_path)
assert actual["status"] == "actual_workflow_complete_independent_admission_pending", actual["status"]
assert actual["helper_hashes_unchanged"]
labels = ["base", "extra", "base-restored", "fresh-final", "forced-reinstall-final", "pip-base", "pip-extra", "pip-base-request-again"]
assert [item["label"] for item in actual["stages"]] == labels
protocol_path = RUN / "protocol.json"
protocol = load(protocol_path)
assert digest(REVIEW / "ultralytics_extra_actual.py") == protocol["script_sha256"]
assert all(digest(ROOT / path) == sha for path, sha in protocol["helper_sha256"].items())
assert digest(ROOT / "work/runtime-linux/bin/uv") == protocol["uv_sha256"]
assert digest(ROOT / "work/stateful-validation-20261111/cohort.json") == protocol["cohort_sha256"]

artifacts = {}
preparations = []
worlds = {}
for label in ["base", "extra", "base-restored"]:
    path = RUN / "preparation" / (label + ".json")
    preparations.append(evidence(path))
    rows = load(path)["wheels"]
    assert sum(row["bytes"] for row in rows) <= protocol["max_compressed_bytes_each_state"]
    budget = load(RUN / "budgets" / (label + ".json"))
    assert {(r["name"], r["version"], r["url"], r["sha256"]) for r in budget["candidates"]} == {(r["name"], r["version"], r["url"], r["sha256"]) for r in rows}
    worlds[label] = {(r["name"], r["version"]): r for r in rows}
    raw_lock = tomllib.loads((RUN / "stages" / label / "uv.lock").read_text())
    for row in rows:
        nodes = [node for node in raw_lock["package"] if canonicalize_name(node["name"]) == row["name"] and node.get("version") == row["version"]]
        assert len(nodes) == 1
        assert any(wheel.get("url", nodes[0]["source"].get("url")) == row["url"] and wheel.get("hash") == "sha256:" + row["sha256"] for wheel in nodes[0].get("wheels", []))
        key = row["name"], row["version"]
        if key in artifacts:
            assert artifacts[key]["sha256"] == row["sha256"]
            continue
        archive = Path(row["archive_path"])
        assert archive.stat().st_size == row["bytes"] and digest(archive) == row["sha256"]
        source = ROOT / row["official_provenance"]["path"]
        assert digest(source) == row["official_provenance"]["sha256"]
        if row["official_provenance"]["kind"] == "official_pypi_release":
            matches = [file for file in load(source)["urls"] if file["url"] == row["url"] and file["filename"] == row["filename"]]
            assert len(matches) == 1 and matches[0]["digests"]["sha256"] == row["sha256"] and matches[0]["size"] == row["bytes"]
        else:
            assert row["official_provenance"]["kind"] == "official_pytorch_cpu_simple"
            anchor = row["official_provenance"]["anchor"]["href"]
            assert unquote(urlsplit(anchor).path.rsplit("/", 1)[-1]) == row["filename"]
            assert urlsplit(anchor).fragment == "sha256=" + row["sha256"]
            assert row["sha256"] in source.read_text()
        with zipfile.ZipFile(archive) as wheel:
            # Vendored libraries may carry their own nested dist-info copies.
            metas = [name for name in wheel.namelist() if name.count("/") == 1 and name.endswith(".dist-info/METADATA")]
            assert len(metas) == 1
            raw = wheel.read(metas[0])
        assert hashlib.sha256(raw).hexdigest() == row["metadata_sha256"]
        meta = BytesParser().parsebytes(raw)
        assert canonicalize_name(meta["Name"]) == row["name"] and meta["Version"] == row["version"]
        artifacts[key] = row

assert len(artifacts) == 66

stages = []
by_label = {}
for item in actual["stages"]:
    label = item["label"]
    stage = RUN / "stages" / label
    saved = load(stage / "results.json")
    assert saved == item
    inventory = load(stage / "installed.json")
    assert inventory["environment"]["python_full_version"] == "3.11.16"
    assert inventory["environment"]["sys_platform"] == "linux" and inventory["environment"]["platform_machine"] == "x86_64"
    installed = {canonicalize_name(dist["name"]): dist for dist in inventory["installed"]}
    assert len(installed) == len(inventory["installed"])
    for name, dist in installed.items():
        raw = (stage / "metadata" / name / "METADATA").read_bytes()
        meta = BytesParser().parsebytes(raw)
        assert canonicalize_name(meta["Name"]) == name and meta["Version"] == dist["version"]
        assert meta.get_all("Requires-Dist", []) == dist["requires_dist"]
        assert hashlib.sha256(raw).hexdigest() == artifacts[name, dist["version"]]["metadata_sha256"]
    roots = item["requests"]
    root_graph = check(roots, installed, inventory["environment"])
    all_graph = check([name + "==" + dist["version"] for name, dist in installed.items()] + roots, installed, inventory["environment"])
    assert not root_graph["violations"] and not root_graph["source_unknowns"]
    assert not all_graph["violations"] and not all_graph["source_unknowns"]
    actual_command = command(label + ("-install" if label.startswith("pip-") else "-sync"))
    assert "--no-deps" not in actual_command["argv"]
    if not label.startswith("pip-"):
        assert "--locked" in actual_command["argv"]
        assert tomllib.loads((stage / "pyproject.toml").read_text())["project"]["dependencies"] == roots
        world_label = label if label in worlds else "base-restored"
        assert {(name, dist["version"]) for name, dist in installed.items()} == set(worlds[world_label])
    checks = {name: command(label + "-" + name) for name in ["pip-check", "uv-check", "pip-inspect"]}
    smoke_command = command(label + "-cv2-smoke", item["cv2_smoke_exit"])
    audit = load(stage / "file-audit.json")
    assert audit["violations"] == item["file_violations"]
    audited = {canonicalize_name(dist["name"]): dist for dist in audit["distributions"]}
    assert set(audited) == set(installed)
    for name, dist in installed.items():
        record = list(csv.reader((stage / "metadata" / name / "RECORD").read_text().splitlines()))
        assert audited[name]["record_hashes_checked"] == sum(bool(row[1]) for row in record if len(row) >= 3)
        assert audited[name]["wheel_sha256"] == artifacts[name, dist["version"]]["sha256"]
    row = {
        "label": label, "installed_distributions": len(installed), "actual_command": actual_command,
        "inventory": evidence(stage / "installed.json"), "saved_result": evidence(stage / "results.json"),
        "file_audit": evidence(stage / "file-audit.json"),
        "metadata_matches_own_exact_original_wheel": len(installed),
        "independent_root_closure": root_graph, "independent_all_base_closure": all_graph,
        "check_and_inspect_commands": checks,
        "all_original_payload_checks": sum(dist["original_files_checked"] for dist in audit["distributions"]),
        "all_installed_record_hash_checks": sum(dist["record_hashes_checked"] for dist in audit["distributions"]),
        "original_auditor_unknown_count_retained": len(audit["unknown"]),
        "file_violation_entries": len(audit["violations"]),
        "unique_file_paths_violating": len({violation["path"] for violation in audit["violations"]}),
        "normal_cv2_missing": item["normal_opencv_cv2_missing"],
        "normal_cv2_mismatches": item["normal_opencv_cv2_mismatches"],
        "cv2_smoke_exit": item["cv2_smoke_exit"],
        "cv2_smoke_command": smoke_command,
        "manifest_sha256": item["manifest_sha256"], "lock_sha256": item["lock_sha256"],
        "headless_installed": "opencv-python-headless" in installed,
    }
    stages.append(row)
    by_label[label] = row

same_final = {(by_label[label]["manifest_sha256"], by_label[label]["lock_sha256"]) for label in ["base-restored", "fresh-final", "forced-reinstall-final"]}
assert len(same_final) == 1
for label in ["base", "fresh-final", "forced-reinstall-final", "pip-base"]:
    assert by_label[label]["file_violation_entries"] == 0 and by_label[label]["cv2_smoke_exit"] == 0
    assert not by_label[label]["normal_cv2_missing"] and not by_label[label]["normal_cv2_mismatches"]
assert len(by_label["base-restored"]["normal_cv2_missing"]) == 39 and by_label["base-restored"]["cv2_smoke_exit"] == 1
assert by_label["base-restored"]["unique_file_paths_violating"] == 39
assert by_label["extra"]["headless_installed"] and not by_label["base-restored"]["headless_installed"]
assert by_label["pip-extra"]["headless_installed"] and by_label["pip-base-request-again"]["headless_installed"]
assert by_label["pip-base-request-again"]["cv2_smoke_exit"] == 0

second = load(SECOND / "results.json")
assert second["same_final_inputs"]
second_stages = {item["label"]: item for item in second["stages"]}
assert set(second_stages) == {"base", "extra", "base-restored", "repair-opencv-only"}
for label in second_stages:
    entry = second_stages[label]
    assert not entry["root_closure"]["violations"] and not entry["all_base_closure"]["violations"]
    assert entry["pip_check_exit"] == 0 and entry["uv_check_exit"] == 0
assert second_stages["base-restored"]["normal_cv2_missing"] == 39
assert second_stages["base-restored"]["cv2_smoke_exit"] == 1 and second_stages["base-restored"]["yolo_import_exit"] == 1
for label in ["base", "extra", "repair-opencv-only"]:
    assert second_stages[label]["cv2_smoke_exit"] == 0 and second_stages[label]["yolo_import_exit"] == 0
assert second_stages["repair-opencv-only"]["normal_cv2_missing"] == 0
assert second_stages["base-restored"]["manifest_sha256"] == by_label["base-restored"]["manifest_sha256"]
assert second_stages["base-restored"]["lock_sha256"] == by_label["base-restored"]["lock_sha256"]
yolo = load(RUN / "supplemental-yolo-class-imports/results.json")
assert {item["stage"]: item["exit"] for item in yolo["observations"]} == {"base-restored": 1, "fresh-final": 0, "forced-reinstall-final": 0}
assert all(not item["timeout"] and item["status"] == "quiescent_actual_yolo_class_import_observed" for item in yolo["observations"])
data_addendum = load(RUN / "original-data-path-addendum.json")
assert data_addendum["counts"]["unresolved_original_data_path_entries"] == 0
upstream = load(REVIEW / "ultralytics-extra-upstream/final-review.json")
assert upstream["assessment"]["new_uv_mechanism_claim_supported"] is False

report = {
    "schema": "ultralytics-extra-manual-actual-admission-v1",
    "reviewed_at_utc": datetime.now(timezone.utc).isoformat(),
    "admission_tool": evidence(Path(__file__).resolve()),
    "independent_fixed_point_checker": evidence(REVIEW / "review_saved_partial_stages.py"),
    "status": "confirmed_real_project_incompatible_provider_declaration_and_extra_removal_failure",
    "canonical_root": "ultralytics", "repo": "ultralytics/ultralytics", "tested_version": "8.4.208", "runtime_extra": "extra",
    "native_target": "CPython3.11.16 Linux x86_64",
    "failure_mode": "Metadata/version closure is valid, but jointly required mutually exclusive distributions overwrite shared original payloads; removing the extra deletes files still required by the retained base provider.",
    "selection_provenance": {"supplemental_targeted_extra": True, "replaces_original_min_extra_sample": False, "risk_candidate": evidence(REVIEW / "namespace-exclusivity-addendum/candidate-ultralytics-extra.json")},
    "attribution": "Ultralytics base requires opencv-python while its published extra selects Albumentations2.0.8 requiring opencv-python-headless. The two publishers' cv2 payloads conflict. Removing extra deletes retained base provider files. This is a real upstream dependency-declaration/workflow instance of a known shared-file ownership limitation, not a new uv resolver mechanism.",
    "actual_request_scope": protocol["consumer_input"], "pure_pypi_difference": protocol["pure_pypi_difference"],
    "protocol": evidence(protocol_path), "actual_result": evidence(result_path), "actual_driver": evidence(REVIEW / "ultralytics_extra_actual.py"),
    "official_artifact_proof": {"complete_original_archives_rehashed_again_at_admission": len(artifacts), "compressed_union_bytes": sum(row["bytes"] for row in artifacts.values()), "metadata_own_wheel_verified": len(artifacts), "preparations": preparations},
    "stages": stages,
    "same_final_manifest_and_lock": {"verified": True, "manifest_sha256": next(iter(same_final))[0], "lock_sha256": next(iter(same_final))[1]},
    "cold_fresh_control": "Separate empty native environment and distinct initially empty cache; complete locked request, not a no-deps import check.",
    "independent_actual_repetition": {"result": evidence(SECOND / "results.json"), "protocol": evidence(SECOND / "protocol.json"), "different_empty_environment": True, "cold_cache": False, "scope": "Second actual full base -> extra -> remove transition, shared previously verified cache, exact official namespace payload and all installed METADATA/checkers. Own targeted opencv-python reinstall restores the same final input. Other dependency payloads are not represented as a second full rehash."},
    "yolo_import_controls": evidence(RUN / "supplemental-yolo-class-imports/results.json"),
    "original_data_mapping_addendum": evidence(RUN / "original-data-path-addendum.json"),
    "resource_footprint_observation": evidence(RUN / "resource-footprint-observation.json"),
    "namespace_overlap": evidence(RUN / "namespace-provider-overlap.json"),
    "upstream_review": evidence(REVIEW / "ultralytics-extra-upstream/final-review.json"),
    "interpretation": {"pip_base_request_retains_extra_dependencies": "Expected ordinary pip incremental behavior; not a pip defect or second trigger.", "metadata_checkers_all_pass_while_cv2_is_broken": True, "bare_import_cv2": "Succeeds as an empty namespace after removal. The minimal cvtColor call and from ultralytics import YOLO fail; do not claim ModuleNotFoundError.", "file_error_count": "78 audit entries are two checks of39 unique missing paths, not78 defects.", "novelty": "uv #19412 already reports the shared-provider removal mechanism. Ultralytics #16939 already has uv/cv2.imshow failure and reinstall recovery symptoms. The exact official extra -> Alb2.0.8 entry is supplementary bounded evidence; ecosystem-wide novelty and first discovery are not claimed."},
    "counts": {"independent_real_trigger_repetitions": 2, "new_real_affected_canonical_root_projects": 1, "dependency_chain_nodes_counted_as_additional_roots": 0, "locally_confirmed_failure_families_in_this_case": 1, "new_upstream_uv_mechanisms": 0, "novel_upstream_issues_established": 0, "public_messages_sent": 0},
    "issue_admission": {"local_issue_description_ready": True, "correct_target": "ultralytics/ultralytics", "role": "Confirmed declaration/workflow supplement for a known incompatibility family; linked prior project reports and uv issue required.", "do_not_duplicate_issue01": True, "public_submission_authorized_or_done": False},
    "limits": ["Only the exact8.4.208 nativeCPU consumer configuration was actually installed;8.4.210/currentHEAD were checked statically only.", "The targeted extra was separately preregistered after a risk screen; it does not replace the original fixed min-extra sample or turn missing static transitive metadata into negative results.", "No model instantiation, weights download, inference, GPU or multi-platform execution is claimed.", "The complete pip comparison is a controlled identical official-wheel union, not a new full-public-candidate-universe comparison.", "Original automatic raw confirmed counters remain0/admissionpending; this separate manually reviewed certificate is the counting authority for this case.", "Other unobserved extras, package versions, applications and all ecosystem reports remain outside this result."],
}
target = REVIEW / "ultralytics-extra-final-admission.json"
assert not target.exists()
target.write_text(json.dumps(report, indent=2) + "\n")
print(json.dumps({"output": evidence(target), "counts": report["counts"], "stages": len(stages)}))
