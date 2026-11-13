"""Read-only audit of saved DRC cases; never rerun resolvers or rewrite evidence.

Usage: python scripts/audit_existing_results.py --output-dir work/reliability-audit
The output separates recorded differences, comparability, and verified violations.
Old C-IntentViolation labels are retained as historical labels, not confirmations.
"""
from __future__ import annotations
import argparse
import collections
import csv
import datetime
import json
import pathlib
import sys
import tomllib

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from drc.report.reliability import assess_case, context_label


def read_json(path, default):
    if not path.exists():
        return default
    return json.loads(path.read_text(encoding="utf-8"))


def manifest_warnings(case, contexts, repo_dir):
    """Identify evidence requiring review, without treating a heuristic as a bug."""
    path = pathlib.Path(repo_dir) / "pyproject.toml"
    if not path.is_file():
        return []
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError) as exc:
        return [f"Could not audit root pyproject.toml: {exc}"]
    from packaging.requirements import Requirement, InvalidRequirement
    from packaging.version import InvalidVersion
    from packaging.utils import canonicalize_name
    package = canonicalize_name(case.get("package", "unknown"))
    requirements = []
    for text in data.get("project", {}).get("dependencies", []) or []:
        try:
            request = Requirement(text)
        except InvalidRequirement:
            continue
        if canonicalize_name(request.name) == package:
            requirements.append(request)
    warnings = []
    for side in ("a", "b"):
        record = case.get(side, {})
        context = contexts.get(record.get("context"), {})
        version = (record.get("artifact") or {}).get("version")
        for request in requirements:
            if request.marker or not request.specifier or not version:
                continue
            try:
                mismatch = not request.specifier.contains(version, prereleases=True)
            except InvalidVersion:
                mismatch = False
            if mismatch:
                warnings.append(f"Side {side.upper()}: selected {version} does not satisfy root runtime declaration {request}; verify whether this was a standalone probe or a project install")
        sources = data.get("tool", {}).get("uv", {}).get("sources", {})
        entries = sources.get(case.get("package"), sources.get(package))
        entries = entries if isinstance(entries, list) else [entries] if entries else []
        conditional = any(isinstance(item, dict) and (item.get("marker") or item.get("extra")) for item in entries)
        if conditional and context.get("sources") and context.get("project_extras") is None:
            warnings.append(f"Side {side.upper()}: conditional source bindings exist in the manifest but active extras/conditions were not recorded; check for flattened bindings")
    return list(dict.fromkeys(warnings))


def audit_project(project_dir, corpus_dir):
    contexts = {c["id"]: c for r in read_json(project_dir / "rtos.json", []) for c in r.get("contexts", [])}
    ir = read_json(project_dir / "ir.json", {})
    paths = {item["id"]: item for item in ir.get("install_paths", [])}
    case_file = project_dir / "cases_triaged.json"
    if not case_file.exists():
        case_file = project_dir / "cases.json"
    cases = read_json(case_file, [])
    if not isinstance(cases, list):
        raise ValueError(f"Expected a case list: {case_file}")
    rows = []
    for case in cases:
        assessment = assess_case(case, contexts)
        warnings = manifest_warnings(case, contexts, corpus_dir / project_dir.name)
        rows.append({
            "project": project_dir.name,
            "case_id": case.get("case_id", "not recorded"),
            "package": case.get("package", "not recorded"),
            "difference_class": case.get("cls", "not recorded"),
            "original_oracle_label": case.get("type", "not recorded"),
            "original_triage_label": (case.get("triage") or {}).get("label", "not recorded"),
            "observed_difference": assessment["observed_difference"],
            "comparison_status": assessment["comparison_status"],
            "contract_status": assessment["contract_status"],
            "classification": assessment["classification"],
            "developer_ready": assessment["developer_ready"],
            "context_a": case.get("a", {}).get("context", "not recorded"),
            "context_b": case.get("b", {}).get("context", "not recorded"),
            "origin_a": context_label(case.get("a", {}), contexts, paths),
            "origin_b": context_label(case.get("b", {}), contexts, paths),
            "faithfulness_a": assessment["contexts"]["a"]["faithfulness"],
            "faithfulness_b": assessment["contexts"]["b"]["faithfulness"],
            "limitations": list(dict.fromkeys(assessment["reasons"] + assessment["contexts"]["a"]["reasons"] + assessment["contexts"]["b"]["reasons"])),
            "audit_warnings": warnings,
            "source_file": str(case_file.resolve()),
        })
    return rows


def audit_results(results_dir, corpus_dir):
    results_dir, corpus_dir = pathlib.Path(results_dir), pathlib.Path(corpus_dir)
    rows, errors = [], []
    for project in sorted(path for path in results_dir.iterdir() if path.is_dir()):
        if not ((project / "cases_triaged.json").exists() or (project / "cases.json").exists()):
            continue
        try:
            rows.extend(audit_project(project, corpus_dir))
        except (OSError, ValueError, TypeError, KeyError) as exc:
            errors.append({"project": project.name, "error": str(exc)})
    return {
        "schema_version": 1,
        "audited_at_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "results_directory": str(results_dir.resolve()),
        "method": "Read-only audit; no resolver execution. Legacy labels are not verification. Unknown metadata remains unverified.",
        "summary": {"projects": len({row["project"] for row in rows}), "cases": len(rows),
                    "classifications": dict(collections.Counter(row["classification"] for row in rows)),
                    "developer_ready": sum(row["developer_ready"] for row in rows),
                    "cases_with_audit_warnings": sum(bool(row["audit_warnings"]) for row in rows),
                    "errors": len(errors)},
        "errors": errors,
        "cases": rows,
    }


def write_audit(report, output_dir, protected=()):
    output_dir = pathlib.Path(output_dir).resolve()
    guarded = [ROOT / "0909ISSUEs", ROOT / "0910issues", ROOT / "results", ROOT / "reports"]
    guarded.extend(pathlib.Path(path) for path in protected)
    for path in guarded:
        path = path.resolve()
        if output_dir == path or path in output_dir.parents:
            raise ValueError(f"Audit output must be outside historical evidence: {path}")
    paths = [output_dir / f"audit.{suffix}" for suffix in ("json", "csv", "md")]
    if any(path.exists() for path in paths):
        raise FileExistsError("Choose a new audit output directory; existing audit files are preserved")
    output_dir.mkdir(parents=True, exist_ok=True)
    paths[0].write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    fields = ["project", "case_id", "package", "difference_class", "original_oracle_label", "original_triage_label",
              "observed_difference", "comparison_status", "contract_status", "classification", "developer_ready",
              "context_a", "context_b", "origin_a", "origin_b", "faithfulness_a", "faithfulness_b",
              "limitations", "audit_warnings", "source_file"]
    with paths[1].open("w", encoding="utf-8-sig", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=fields)
        writer.writeheader()
        for row in report["cases"]:
            writer.writerow({key: json.dumps(value, ensure_ascii=False) if isinstance(value, list) else value for key, value in row.items()})
    summary = report["summary"]
    lines = ["# Saved resolution evidence audit", "", report["method"], "",
             f"Cases: {summary['cases']}; projects: {summary['projects']}; verified developer-ready cases: {summary['developer_ready']}.", "",
             "A historical C-IntentViolation label is preserved in the CSV and JSON. It does not establish a verified contract breach.", "",
             "| Evidence classification | Cases |", "|---|---|"]
    lines.extend(f"| {label} | {count} |" for label, count in sorted(summary["classifications"].items()))
    lines.extend(["", f"Cases with manifest/context warnings: {summary['cases_with_audit_warnings']}. These warnings require review and do not independently prove defects.", "",
                  f"Unreadable projects: {summary['errors']}. See audit.json for errors and audit.csv for per-case origins, limits, and warnings."])
    paths[2].write_text("\n".join(lines) + "\n", encoding="utf-8")
    return paths


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--results-dir", type=pathlib.Path, default=ROOT / "results" / "projects")
    parser.add_argument("--corpus-dir", type=pathlib.Path, default=ROOT / "corpus" / "repos")
    parser.add_argument("--output-dir", type=pathlib.Path, default=ROOT / "work" / "reliability-audit")
    args = parser.parse_args()
    report = audit_results(args.results_dir, args.corpus_dir)
    paths = write_audit(report, args.output_dir, (args.results_dir, args.corpus_dir))
    print(json.dumps({"summary": report["summary"], "outputs": list(map(str, paths))}, ensure_ascii=False))
    if report["errors"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
