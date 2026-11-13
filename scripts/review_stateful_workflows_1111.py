"""Read-only target-lock/installed-file reconciliation for stateful controls."""
from __future__ import annotations

import argparse
from collections import Counter
from copy import deepcopy
import json
from pathlib import Path
import sys
import tomllib

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from packaging.utils import canonicalize_name
from drc.model import Context
from drc.resolvers.lock_projection import project_uv_lock
from scripts.run_expanded_validation import digest, dump, now


def review(out, destination):
    if destination.exists():
        raise FileExistsError(destination)
    cases = json.loads((out / "cases.json").read_text())
    protocol = json.loads((out / "protocol.json").read_text())
    rows, inputs = [], {}
    for case in cases["roots"]:
        root = out / "cases" / case["canonical_name"]
        world_path = root / "artifacts/wheel-manifest.json"
        if not world_path.exists():
            rows.append({"name": case["canonical_name"], "status": "unknown_artifacts_not_prepared"})
            continue
        world = json.loads(world_path.read_text())
        inputs[str(world_path)] = digest(world_path)
        world_by_file = {w["filename"]: w for w in world}
        for workflow in protocol.get("workflows", (("relock",) if protocol.get("source_out") else ("update", "extras", "relock"))):
            result_path = root / workflow / "results.json"
            if not result_path.exists():
                rows.append({"name": case["canonical_name"], "workflow": workflow, "status": "unknown_workflow_not_finished"})
                continue
            inputs[str(result_path)] = digest(result_path)
            result = json.loads(result_path.read_text())
            for entry in result.get("stages", []):
                if not entry["strict_uv_sync"]:
                    continue
                stage = root / workflow / "stages" / entry["stage"]
                lock_path, manifest_path = stage / "uv.lock", stage / "pyproject.toml"
                inventory_path, files_path = stage / "installed.json", stage / "file-audit.json"
                row = {"name": case["canonical_name"], "workflow": workflow, "stage": entry["stage"],
                       "request": entry["request"], "status": "unknown", "source_unknowns": [], "source_mismatches": []}
                try:
                    for p in (lock_path, manifest_path, inventory_path, files_path):
                        inputs[str(p)] = digest(p)
                    original = tomllib.loads(lock_path.read_text())
                    manifest = tomllib.loads(manifest_path.read_text())
                    inventory = json.loads(inventory_path.read_text())
                    files = json.loads(files_path.read_text())
                    assert manifest["project"]["dependencies"] == [entry["request"]]
                    assert inventory["environment"] == case["marker_environment"]
                    virtual = [p for p in original["package"] if p.get("source") == {"virtual": "."}]
                    assert len(virtual) == 1 and virtual[0]["name"] == manifest["project"]["name"]
                    # The existing projection adapter recognizes its own virtual
                    # probe root. Alias only our synthetic control-project name
                    # in memory; upstream nodes, dependencies and saved lock bytes
                    # remain untouched.
                    data = deepcopy(original)
                    next(p for p in data["package"] if p.get("source") == {"virtual": "."})["name"] = "drc-probe"
                    context = Context("stateful-post-review", "uv", [entry["request"]],
                                      python_version=case["target_python"], platform="linux-x86_64",
                                      marker_environment=case["marker_environment"], project_extras=[])
                    projected, certificate = project_uv_lock(data, context, case["marker_environment"])
                    row["projection"] = certificate
                    row["original_virtual_project_name"] = virtual[0]["name"]
                    row["virtual_root_alias_in_memory_only"] = True
                    actual = {canonicalize_name(d["name"]): d["version"] for d in inventory["installed"]}
                    expected = {name: artifact.version for name, artifact in projected.items()}
                    row["actual_versions"], row["active_lock_versions"] = actual, expected
                    row["installed_but_not_active_lock"] = sorted(set(actual) - set(expected))
                    row["active_lock_but_not_installed"] = sorted(set(expected) - set(actual))
                    row["version_mismatches"] = [{"name": name, "installed": actual[name], "locked": expected[name]}
                                                 for name in sorted(set(actual) & set(expected)) if actual[name] != expected[name]]
                    audited = {canonicalize_name(d["name"]): d for d in files["distributions"]}
                    for selected in certificate["selected"]:
                        name, version, source = selected["name"], selected["version"], selected["source"]
                        nodes = [p for p in original["package"] if canonicalize_name(p["name"]) == name and p.get("version") == version and p.get("source") == source]
                        if len(nodes) != 1 or source != {"registry": str(root / "artifacts/wheelhouse")}:
                            row["source_unknowns"].append({"name": name, "reason": "lock identity/source does not uniquely match prepared local world"})
                            continue
                        permitted = set()
                        for wheel in nodes[0].get("wheels", []):
                            path = Path(wheel.get("path", ""))
                            if not path.is_absolute() or not path.resolve().is_relative_to((root / "artifacts/wheelhouse").resolve()):
                                row["source_unknowns"].append({"name": name, "reason": "nonlocal or unsupported wheel locator"})
                                continue
                            official = world_by_file.get(path.name)
                            if official is None or digest(path) != official["sha256"]:
                                row["source_mismatches"].append({"name": name, "reason": "locked local wheel bytes differ from official artifact manifest"})
                            else:
                                permitted.add(official["sha256"])
                        chosen = audited.get(name)
                        if not permitted or chosen is None:
                            row["source_unknowns"].append({"name": name, "reason": "no verified locked candidate or no installed-file witness"})
                        elif chosen["wheel_sha256"] not in permitted:
                            row["source_mismatches"].append({"name": name, "installed_wheel_sha256": chosen["wheel_sha256"], "permitted": sorted(permitted)})
                    if certificate["status"] != "verified":
                        row["status"] = "unknown_target_lock_projection"
                    elif row["installed_but_not_active_lock"] or row["active_lock_but_not_installed"] or row["version_mismatches"] or row["source_mismatches"]:
                        row["status"] = "candidate_strict_sync_lock_membership_or_source_mismatch"
                    elif row["source_unknowns"]:
                        row["status"] = "unknown_locked_artifact_source"
                    else:
                        row["status"] = "active_lock_membership_versions_and_official_artifact_sources_match"
                    assert digest(lock_path) == inputs[str(lock_path)]
                except Exception as exc:
                    row.update(status="unknown_review_boundary", reason=str(exc))
                rows.append(row)
    result = {"schema": "stateful-target-lock-installed-review-v1", "reviewed_at_utc": now(),
              "execution_out": str(out), "execution_protocol_sha256": digest(out / "protocol.json"),
              "script_sha256": digest(Path(__file__)), "rows": rows, "counts": dict(Counter(r["status"] for r in rows)),
              "input_sha256": inputs, "all_reviewed_inputs_unchanged": all(digest(Path(p)) == s for p, s in inputs.items()),
              "core_unchanged": all(digest(ROOT / p) == s for p, s in protocol["core_hashes"].items()), "confirmed_defects": 0,
              "limits": ["No installed applications or package behavior are executed by this review.", "Saved lock bytes are unchanged; only the synthetic control-project root name is aliased in memory for the existing target projection adapter.",
                         "Membership uses target marker/extras reachability, never all nodes from a universal lock.", "Artifact source means the hash-verified official wheel prepared in the restricted local world, not live public-index resolver coverage.",
                         "Potential mismatches remain candidates for independent reproduction, not automatic new issues."]}
    assert result["all_reviewed_inputs_unchanged"] and result["core_unchanged"]
    dump(destination, result)
    print(json.dumps({"counts": result["counts"], "sha256": digest(destination)}, indent=2))


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", required=True, type=Path)
    parser.add_argument("--write", type=Path)
    args = parser.parse_args()
    out = args.out.resolve()
    review(out, args.write.resolve() if args.write else out / "target-lock-installed-review.json")
