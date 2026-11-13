"""Offline graph and stored-body review of the completed 1111 recovery pass."""
from __future__ import annotations

from collections import defaultdict
import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from packaging.requirements import Requirement
from packaging.utils import canonicalize_name
from scripts.run_expanded_validation import digest, dump, now

OUT = ROOT / "work/expanded-validation-20261111/recovery"


def active(req, environment, extras):
    return req.marker is None or any(req.marker.evaluate({**environment, "extra": extra}) for extra in {"", *extras})


def check_metadata(requirements, constraints, artifacts, environment):
    extras = defaultdict(set)
    reached, edges, failures = set(), set(), []
    roots = []
    for raw in requirements:
        req = Requirement(raw)
        if active(req, environment, set()):
            roots.append(("<request>", raw, req))
            reached.add(canonicalize_name(req.name))
            extras[canonicalize_name(req.name)].update(canonicalize_name(e) for e in req.extras)
    changed = True
    while changed:
        changed = False
        for parent in sorted(reached):
            if parent not in artifacts:
                continue
            for raw in artifacts[parent].get("requires_dist", []):
                req = Requirement(raw)
                if not active(req, environment, extras[parent]):
                    continue
                child = canonicalize_name(req.name)
                edges.add((parent, raw, child))
                old_extras = extras[child].copy()
                extras[child].update(canonicalize_name(e) for e in req.extras)
                if child not in reached or old_extras != extras[child]:
                    changed = True
                reached.add(child)
    checks = roots + [(parent, raw, Requirement(raw)) for parent, raw, child in sorted(edges)]
    checks += [("<constraint>", raw, Requirement(raw)) for raw in constraints
               if active(Requirement(raw), environment, set()) and canonicalize_name(Requirement(raw).name) in reached]
    for parent, raw, req in checks:
        child = canonicalize_name(req.name)
        artifact = artifacts.get(child)
        if artifact is None:
            failures.append({"parent": parent, "requirement": raw, "reason": "active node missing"})
        elif req.url:
            failures.append({"parent": parent, "requirement": raw, "reason": "URL identity needs independent review"})
        elif req.specifier and not req.specifier.contains(artifact["version"], prereleases=True):
            failures.append({"parent": parent, "requirement": raw, "version": artifact["version"], "reason": "version outside specifier"})
    return {"active_root_checks": len(roots), "active_metadata_edges": len(edges),
            "reached_nodes": len(reached), "selected_nodes": len(artifacts),
            "selected_but_not_reached": sorted(set(artifacts) - reached), "constraint_conflicts": failures}


def main():
    cases = json.loads((OUT / "cases.json").read_text())["cases"]
    protocol = json.loads((OUT / "protocol.json").read_text())
    reviews, body_errors, body_count, total_bytes = [], [], 0, 0
    parent_checks = []
    for case in cases:
        destination = OUT / "results" / case["case_id"]
        summary = json.loads((destination / "summary.json").read_text())
        row = {"case_id": case["case_id"], "status": summary["status"], "confirmed_defects": 0}
        if summary["status"] == "completed_1111_sealed_pair":
            pip = json.loads((destination / "runs/replay-pip/resolution.json").read_text())
            uv = json.loads((destination / "runs/replay-uv/resolution.json").read_text())
            contexts = json.loads((destination / "contexts.json").read_text())
            left = {canonicalize_name(k): v for k, v in pip["artifacts"].items()}
            right = {canonicalize_name(k): v for k, v in uv["artifacts"].items()}
            row.update({"pip_nodes": len(left), "uv_nodes": len(right),
                        "pip_only": sorted(set(left) - set(right)), "uv_only": sorted(set(right) - set(left)),
                        "version_differences": [{"name": k, "pip": left[k]["version"], "uv": right[k]["version"]}
                                                for k in sorted(set(left) & set(right)) if left[k]["version"] != right[k]["version"]],
                        "pip_graph_status": pip["graph_projection"]["status"], "uv_graph_status": uv["graph_projection"]["status"],
                        "pip_selected_files_verified": sum(v.get("selected_artifact_verified", False) for v in left.values()),
                        "uv_selected_files_verified": sum(v.get("selected_artifact_verified", False) for v in right.values()),
                        "normal_oracle": summary["pair"]["summary"]})
            row["pip_metadata_constraints"] = check_metadata(contexts["pip"]["requirements"], contexts["pip"]["constraints"],
                                                              left, summary["runtime"]["environment"])
            # Apply the same selected pip wheel's metadata to the uv graph separately;
            # this checks matching version plans, not unobserved uv wheel metadata identity.
            right_with_metadata = {k: {**v, "requires_dist": left.get(k, {}).get("requires_dist", [])} for k, v in right.items()}
            row["uv_graph_against_pip_metadata"] = check_metadata(contexts["uv"]["requirements"], contexts["uv"]["constraints"],
                                                                  right_with_metadata, summary["runtime"]["environment"])
        for manifest in destination.glob("cache/snapshots/*/manifest.json"):
            before = digest(manifest)
            for key, entry in json.loads(manifest.read_text())["entries"].items():
                kind, key_hash = key.split(":", 1)
                body = manifest.parent / kind / (key_hash + ".bin")
                data = body.read_bytes()
                body_count += 1
                total_bytes += len(data)
                if len(data) != entry["bytes"] or hashlib.sha256(data).hexdigest() != entry["sha256"]:
                    body_errors.append(str(body))
            assert digest(manifest) == before
        for parent in case["parents"]:
            parent_checks.append({"manifest": parent["manifest"], "expected_sha256": parent["sha256"],
                                  "unchanged": digest(Path(parent["manifest"])) == parent["sha256"]})
        reviews.append(row)
    core_checks = {path: digest(ROOT / path) == sha for path, sha in protocol["source_hashes"].items()}
    result = {"schema": "1111-recovery-offline-review-v1", "reviewed_at_utc": now(), "cases": reviews,
              "snapshot_body_count": body_count, "snapshot_body_bytes": total_bytes, "snapshot_body_errors": body_errors,
              "parent_manifests": parent_checks, "core_hash_checks": core_checks,
              "all_integrity_checks_passed": not body_errors and all(x["unchanged"] for x in parent_checks) and all(core_checks.values()),
              "limitations": ["Review uses recorded plans, pip-selected wheel metadata, and exact native marker environments.",
                              "uv chosen wheel bytes, actual installations, and projected repository installation semantics remain unverified.",
                              "No observed graph conflict does not establish that the package or resolver is defect-free."],
              "confirmed_defects": 0}
    target = OUT / "offline-review.json"
    if target.exists():
        raise FileExistsError(target)
    dump(target, result)
    print(json.dumps({"cases": len(reviews), "snapshot_bodies": body_count,
                      "integrity_passed": result["all_integrity_checks_passed"]}, indent=2))


if __name__ == "__main__":
    main()
