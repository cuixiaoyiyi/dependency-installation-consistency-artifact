"""Re-evaluate captured resolver evidence and regenerate source contexts read-only.

The lock projection and oracle are the same entry points used by normal analysis.
Saved resolver outputs retain their original unverified request provenance. A newly
generated source context never certifies a different historical execution.
"""
from __future__ import annotations

import argparse
from collections import Counter
from dataclasses import fields
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import sys
import tomllib

os.environ.setdefault("DRC_SKIP_VERSION_PROBE", "1")
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from packaging.markers import default_environment
from drc.cli import _validate_output
from drc.contexts import generate_rtos
from drc.frontend import parse_project
from drc.model import Context, Resolution
from drc.oracle import diff_resolutions, INSUFFICIENT_EVIDENCE, SAME, SAME_FILE_MIRROR
from drc.report.reliability import assess_case
from drc.resolvers import project_pip_report, project_uv_lock


def read(path, default=None):
    return json.loads(path.read_text(encoding="utf-8-sig")) if path.exists() else default


def _context(record):
    names = {field.name for field in fields(Context)}
    return Context(**{key: value for key, value in record.items() if key in names})


def _captured_environment(run, ctx):
    report = read(run / "pip-report.json", {}) if run else {}
    environment = report.get("environment", {})
    if environment:
        return environment, "paired-pip-report.environment"
    environment = default_environment()
    if environment["python_version"] == ctx.python_version:
        return environment, "current-native-interpreter for explicit target re-evaluation"
    return dict(ctx.marker_environment), "saved partial target; missing facts remain unknown"


def _read_resolution(run, ctx, environment):
    if not run:
        return Resolution(ctx.id, ctx.resolver, False, {}, 0.0, "", "saved run not found")
    saved = read(run / "resolution.json", {})
    if not saved.get("ok"):
        return Resolution(ctx.id, ctx.resolver, False, {}, 0.0, "", "original resolver failed")
    if ctx.resolver == "pip":
        report = read(run / "pip-report.json")
        if report is None:
            return Resolution(ctx.id, "pip", False, {}, 0.0, "", "original pip report missing")
        artifacts, projection = project_pip_report(report, ctx)
        result = Resolution(ctx.id, "pip", True, artifacts, 0.0, "saved pip report re-evaluation",
                            graph_projection=projection)
    else:
        lock = run / "uv.lock"
        if not lock.exists():
            return Resolution(ctx.id, "uv", False, {}, 0.0, "", "original uv lock missing")
        with lock.open("rb") as stream:
            artifacts, projection = project_uv_lock(tomllib.load(stream), ctx, environment)
        result = Resolution(ctx.id, "uv", True, artifacts, 0.0, "saved uv lock target re-evaluation",
                            graph_projection=projection)
    result.snapshot = saved.get("snapshot", {})
    result.resolver_version = saved.get("resolver_version", "")
    return result


def _context_changes(old, current):
    keys = ("requirements", "constraints", "index_url", "extra_index_urls", "find_links",
            "sources", "named_indexes", "no_deps", "project_extras", "platform",
            "python_version", "lock_mode")
    if current is None:
        return {"mapping": "original context no longer generated"}
    changes = {}
    for key in keys:
        old_value = old.get(key)
        new_value = current.get(key)
        if old_value != new_value:
            changes[key] = {"recorded": old_value, "regenerated": new_value}
    return changes


def _regenerated_context(old, current, request_origin, old_paths):
    if old["id"] in current:
        return current[old["id"]], "same context identifier; compare semantic inputs separately"
    identifiers = []
    if old.get("derived_from", "").startswith("install-path:"):
        identifiers.append(old["derived_from"].split(":", 1)[1])
    identifiers.extend(origin.split(":", 1)[1] for origin in request_origin.split(" | ")
                       if origin.startswith("install-path:"))
    locations = {(old_paths[identifier]["file"], old_paths[identifier]["line"])
                 for identifier in identifiers if identifier in old_paths}
    candidates = [context for context in current.values()
                  if context.get("resolver") == old.get("resolver")
                  and context.get("derived_from", "").startswith("install-path:")
                  and (context.get("origin", {}).get("file"), context.get("origin", {}).get("line")) in locations]
    if len(candidates) == 1:
        return candidates[0], "original file and line; this regeneration does not certify the saved execution"
    return None, "source invocation has no unique regenerated mapping"


def revalidate_project(project, source, output, submitted_ids):
    old_rtos = read(project / "rtos.json", [])
    old_contexts = {c["id"]: c for rto in old_rtos for c in rto.get("contexts", [])}
    request_origins = {c["id"]: rto.get("reqset", {}).get("origin", "")
                       for rto in old_rtos for c in rto.get("contexts", [])}
    old_paths = {path["id"]: path for path in read(project / "ir.json", {}).get("install_paths", [])}
    cases = read(project / "cases_triaged.json", read(project / "findings.json", []))
    cases = [case for case in cases if not case.get("consequential_of")]
    runs = {read(path, {}).get("context_id"): path.parent
            for path in (project / "runs").glob("*/resolution.json")}
    ir = parse_project(source, project.name)
    regenerated = generate_rtos(ir, source, budget_contexts=10000)
    current = {c.id: c.to_dict() for rto in regenerated for c in rto.contexts}
    output.mkdir(parents=True, exist_ok=False)
    (output / "ir.json").write_text(json.dumps(ir.to_dict(), indent=2), encoding="utf-8")
    (output / "rtos.json").write_text(json.dumps([r.to_dict() for r in regenerated], indent=2), encoding="utf-8")
    rows = []
    cache = {}
    input_hashes = {}
    for case in cases:
        old = {side: old_contexts[case[side]["context"]] for side in ("a", "b")}
        contexts = {side: _context(old[side]) for side in ("a", "b")}
        pip_run = next((runs.get(contexts[side].id) for side in ("a", "b")
                        if contexts[side].resolver == "pip"), None)
        environment, environment_source = _captured_environment(pip_run, contexts["a"])
        resolutions = {}
        for side in ("a", "b"):
            ctx = contexts[side]
            key = (ctx.id, json.dumps(environment, sort_keys=True))
            if key not in cache:
                cache[key] = _read_resolution(runs.get(ctx.id), ctx, environment)
            if ctx.id not in input_hashes:
                directory = runs.get(ctx.id)
                input_hashes[ctx.id] = {name: hashlib.sha256((directory / name).read_bytes()).hexdigest()
                                        for name in ("resolution.json", "pip-report.json", "uv.lock")
                                        if directory and (directory / name).is_file()}
            resolutions[side] = cache[key]
        left, right = resolutions["a"], resolutions["b"]
        if left.ok and right.ok:
            diffs = {diff.package: diff for diff in diff_resolutions(left, right, contexts["a"], contexts["b"])}
            difference = diffs.get(case["package"])
            if (case["package"] not in left.artifacts and case["package"] not in right.artifacts
                    and all(res.graph_projection.get("status") == "verified" for res in (left, right))):
                status = "absent_from_both_target_graphs"
            elif difference is None or difference.cls == INSUFFICIENT_EVIDENCE:
                status = "insufficient_evidence"
            elif difference.cls in (SAME, SAME_FILE_MIRROR) or difference.benign:
                status = "difference_not_reproduced_or_explained"
            else:
                status = "graph_or_selection_difference_retained"
        else:
            difference = None
            status = "saved_evidence_incomplete"
        checked = dict(case)
        if status == "absent_from_both_target_graphs":
            checked["cls"] = SAME
        elif status in ("insufficient_evidence", "saved_evidence_incomplete"):
            checked["cls"] = INSUFFICIENT_EVIDENCE
        if difference is not None:
            checked["cls"] = difference.cls
            for side in ("a", "b"):
                checked[side] = dict(case[side], artifact=(resolutions[side].artifacts[case["package"]].to_dict()
                                      if case["package"] in resolutions[side].artifacts else None))
        # Preserve the original request provenance. Regeneration alone cannot
        # upgrade a saved execution to a different, newly generated request.
        assessment = assess_case(checked, old_contexts)
        matched = {side: _regenerated_context(old[side], current,
                                              request_origins.get(contexts[side].id, ""), old_paths)
                   for side in ("a", "b")}
        row = {"project": project.name, "case_id": case["case_id"], "package": case["package"],
               "submitted": (project.name, case["case_id"]) in submitted_ids,
               "historical_class": case["cls"], "historical_label": case.get("type"),
               "reevaluation_status": status, "revised_difference": difference.to_dict() if difference else None,
               "target_environment": environment, "target_environment_source": environment_source,
               "developer_ready": assessment["developer_ready"], "assessment": assessment,
               "contexts": {side: {"recorded": old[side], "regenerated": matched[side][0],
                                      "regeneration_mapping": matched[side][1],
                                      "input_changes": _context_changes(old[side], matched[side][0]),
                                      "graph_projection": resolutions[side].graph_projection,
                                      "evidence_run": str(runs.get(contexts[side].id, "")),
                                      "recorded_input_sha256": input_hashes[contexts[side].id],
                                      "read_error": resolutions[side].error}
                            for side in ("a", "b")}}
        rows.append(row)
    (output / "case-revalidation.json").write_text(json.dumps(rows, indent=2), encoding="utf-8")
    summary = {"project": project.name, "cases": len(rows), "submitted": sum(r["submitted"] for r in rows),
               "outcomes": dict(Counter(r["reevaluation_status"] for r in rows)),
               "developer_ready": sum(r["developer_ready"] for r in rows),
               "regenerated_contexts": len(current),
               "verified_original_contexts": sum(c.get("faithfulness") == "verified" for c in current.values()),
               "parse_notes": ir.notes}
    (output / "summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    return summary, rows


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--all-existing", action="store_true")
    args = parser.parse_args(argv)
    out = _validate_output(args.out)
    out.mkdir(parents=True, exist_ok=False)
    code_files = sorted((ROOT / "drc").rglob("*.py")) + [Path(__file__).resolve()]
    implementation = {str(path.relative_to(ROOT)): hashlib.sha256(path.read_bytes()).hexdigest() for path in code_files}
    submitted = read(ROOT / "work/issue-audit-20261110/submitted-cases.json", [])
    submitted_ids = {(r["project"], r["case_id"]) for r in submitted}
    submitted_projects = {r["project"] for r in submitted}
    summaries, rows, errors = [], [], []
    for project in sorted((ROOT / "results/projects").iterdir()):
        if not project.is_dir() or not (project / "rtos.json").exists():
            continue
        if not args.all_existing and project.name not in submitted_projects:
            continue
        if not (project / "cases_triaged.json").exists() and not (project / "findings.json").exists():
            continue
        try:
            summary, records = revalidate_project(project, ROOT / "corpus/repos" / project.name,
                                                  out / project.name, submitted_ids)
            summaries.append(summary)
            rows.extend(records)
            print(json.dumps(summary), flush=True)
        except Exception as error:
            failure = {"project": project.name, "error": f"{type(error).__name__}: {error}"}
            errors.append(failure)
            print(json.dumps(failure), flush=True)
    inspected = [r for r in rows if r["submitted"]]
    after = {str(path.relative_to(ROOT)): hashlib.sha256(path.read_bytes()).hexdigest() for path in code_files}
    if implementation != after:
        errors.append({"error": "implementation changed during revalidation; rerun with a fixed version"})
    result = {"schema": "drc-audited-case-revalidation-v1", "checked_at_utc": datetime.now(timezone.utc).isoformat(),
              "scope": "Captured plans re-evaluated with current native graph projection and oracle; current source contexts regenerated. Full historical project installations remain unobserved.",
              "projects": len(summaries), "cases": len(rows), "submitted_cases": len(inspected),
              "all_case_outcomes": dict(Counter(r["reevaluation_status"] for r in rows)),
              "submitted_case_outcomes": dict(Counter(r["reevaluation_status"] for r in inspected)),
              "developer_ready": sum(r["developer_ready"] for r in rows), "errors": errors,
              "implementation_sha256": implementation, "implementation_unchanged": implementation == after,
              "project_summaries": summaries}
    (out / "summary.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
    (out / "submitted-revalidation.json").write_text(json.dumps(inspected, indent=2), encoding="utf-8")
    print(json.dumps({k: v for k, v in result.items() if k not in ("project_summaries", "implementation_sha256")}), flush=True)
    return 1 if errors or len(inspected) != len(submitted) else 0


if __name__ == "__main__":
    raise SystemExit(main())
