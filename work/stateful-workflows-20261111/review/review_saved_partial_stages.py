"""Read-only fixed-point audit of saved inventories, including unaggregated stages."""
from collections import defaultdict
from datetime import datetime, timezone
from email.parser import Parser
import hashlib
import json
from pathlib import Path
import tomllib

from packaging.requirements import Requirement
from packaging.utils import canonicalize_name

ROOT = Path(__file__).resolve().parents[3]
REVIEW = Path(__file__).resolve().parent


def identity(path):
    raw = path.read_bytes()
    return {"path": str(path.relative_to(ROOT)), "sha256": hashlib.sha256(raw).hexdigest()}


def check(roots, installed, environment):
    extras, reached, edges, unsupported = defaultdict(set), set(), set(), []
    active_roots = []
    def active(req, values):
        return req.marker is None or any(req.marker.evaluate({**environment, "extra": extra}) for extra in {"", *values})
    def include(req):
        name = canonicalize_name(req.name)
        before = (name in reached, len(extras[name]))
        reached.add(name)
        extras[name].update(canonicalize_name(extra) for extra in req.extras)
        return before != (True, len(extras[name]))
    for raw in roots:
        req = Requirement(raw)
        if active(req, set()):
            active_roots.append(("<request>", raw, req))
            include(req)
    changed = True
    while changed:
        changed = False
        for name in sorted(reached):
            if name not in installed:
                continue
            for raw in installed[name]["requires_dist"]:
                req = Requirement(raw)
                if active(req, extras[name]):
                    edges.add((name, raw))
                    changed = include(req) or changed
    checks = active_roots + [(name, raw, Requirement(raw)) for name, raw in sorted(edges)]
    violations = []
    for name, raw, req in checks:
        child = installed.get(canonicalize_name(req.name))
        if child is None:
            violations.append({"parent": name, "requirement": raw, "reason": "active dependency missing"})
        elif req.specifier and not req.specifier.contains(child["version"], prereleases=True):
            violations.append({"parent": name, "requirement": raw, "installed": child["version"], "reason": "version outside active specifier"})
        elif req.url:
            unsupported.append({"parent": name, "requirement": raw, "reason": "direct URL identity needs artifact review"})
    return {"active_roots": len(active_roots), "reachable_nodes": len(reached), "active_edges": len(edges), "violations": violations, "source_unknowns": unsupported}


def main():
    sources = [ROOT / "work/stateful-workflows-20261111/foundational", ROOT / "work/stateful-workflows-20261111/published/run1"]
    rows = []
    for source in sources:
        for path in sorted((source / "cases").glob("*/*/stages/*/installed.json")):
            row = {"inventory": identity(path)}
            try:
                stage = path.parent
                workflow = path.parents[2]
                inventory = json.loads(path.read_bytes())
                result_path = workflow / "results.json"
                aggregate = json.loads(result_path.read_bytes()) if result_path.exists() else {}
                entries = aggregate.get("stages", [])
                row.update(workflow=workflow.name, root=workflow.parent.name, stage=stage.name, present_in_aggregate=any(item["stage"] == stage.name for item in entries))
                command_path = workflow / "commands" / stage.name / "command.json"
                if not command_path.exists():
                    raise ValueError("Missing actual install command record")
                command = json.loads(command_path.read_bytes())
                row["command"] = identity(command_path)
                assert command["exit"] == 0
                strict = "sync" in command["argv"] and "--locked" in command["argv"]
                row["strict_uv_sync"] = strict
                manifest_path = stage / "pyproject.toml"
                if strict:
                    assert manifest_path.exists()
                    requests = tomllib.loads(manifest_path.read_text())["project"]["dependencies"]
                    row["manifest"] = identity(manifest_path)
                    row["lock"] = identity(stage / "uv.lock")
                else:
                    assert "install" in command["argv"]
                    requests = [command["argv"][-1]]
                row["requests"] = requests
                installed = {canonicalize_name(item["name"]): item for item in inventory["installed"]}
                assert len(installed) == len(inventory["installed"])
                for name, item in installed.items():
                    meta = Parser().parsestr(item["metadata"])
                    assert canonicalize_name(meta["Name"]) == name and meta["Version"] == item["version"]
                    assert meta.get_all("Requires-Dist", []) == item["requires_dist"]
                row["root_closure"] = check(requests, installed, inventory["environment"])
                row["all_installed_base_closure"] = check([item["name"] + "==" + item["version"] for item in inventory["installed"]] + requests, installed, inventory["environment"])
                candidate = bool(strict and (row["root_closure"]["violations"] or row["all_installed_base_closure"]["violations"]))
                row["status"] = "candidate_active_installed_contract_violation" if candidate else "saved_metadata_has_no_active_conflict" if strict else "pip_incremental_observation_only"
                assert identity(path) == row["inventory"], "Inventory changed during read-only review"
            except Exception as exc:
                row.update(status="unknown_saved_stage_review", reason=str(exc))
            rows.append(row)
    out = REVIEW / "saved-partial-stage-initial-review.json"
    assert not out.exists()
    report = {"schema": "stateful-saved-partial-stage-review-v1", "reviewed_at_utc": datetime.now(timezone.utc).isoformat(), "scope": "Initial saved native inventories in original passes, including stages absent from aggregate results. Read-only active installed METADATA review; not a second execution or complete artifact/lock/source certificate.", "counts": {"saved_inventories": len(rows), "unaggregated_inventories": sum(not row.get("present_in_aggregate", True) for row in rows), "strict_uv_candidates": sum(row["status"].startswith("candidate") for row in rows), "unknowns": sum(row["status"].startswith("unknown") for row in rows)}, "rows": rows, "limits": ["The original passes are still running. Future/unfinished stages are outside this frozen review.", "Ordinary pip incremental conflicts are observations and require current-request attribution before issue admission.", "No contradiction in a captured inventory certifies package-wide behavior or correct artifact identity.", "Each candidate requires independent actual reproduction and same-input controls before counting."]}
    out.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({"output": identity(out), "counts": report["counts"], "candidates": [row for row in rows if row["status"].startswith("candidate")]}))


if __name__ == "__main__":
    main()
