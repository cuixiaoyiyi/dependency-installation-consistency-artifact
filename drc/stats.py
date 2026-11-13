"""Aggregate measured results across results/projects/* into results/stats.json and results/STATS.md."""
from __future__ import annotations
import json, pathlib, statistics
from collections import Counter, defaultdict

def _load(p):
    try: return json.loads(p.read_text(encoding="utf-8"))
    except Exception: return None

def build_stats(root: pathlib.Path, write: bool = True) -> dict:
    proj_dir = root / "results" / "projects"
    summaries = []
    for sd in sorted(proj_dir.glob("*")):
        s = _load(sd / "summary.json")
        if s: s["_dir"] = sd.name; summaries.append(s)
    errors = sorted(p.parent.name for p in proj_dir.glob("*/error.txt") if not (p.parent / "summary.json").exists())
    st = {"projects_analyzed": len(summaries), "projects_errored": len(errors), "errored": errors}
    def med(xs): xs = [x for x in xs if isinstance(x, (int, float))]; return round(statistics.median(xs), 1) if xs else None
    def q(xs, p): xs = sorted(x for x in xs if isinstance(x, (int, float))); return round(xs[min(len(xs)-1, int(p*len(xs)))], 1) if xs else None
    st["per_project"] = {
        "dependencies_median": med([s["ir"]["dependencies"] for s in summaries]),
        "install_paths_median": med([s["ir"]["install_paths"] for s in summaries]),
        "install_paths_with_index_median": med([s["ir"]["install_paths_with_index"] for s in summaries]),
        "custom_indexes_median": med([len(s["ir"]["custom_indexes"]) for s in summaries]),
        "contexts_median": med([s["contexts"] for s in summaries]), "contexts_total": sum(s["contexts"] for s in summaries),
        "resolutions_ok_total": sum(s["resolutions_ok"] for s in summaries), "resolutions_failed_total": sum(s["resolutions_failed"] for s in summaries),
        "resolver_seconds_total": round(sum(s["resolver_seconds"] for s in summaries), 1),
        "total_seconds_median": med([s["total_s"] for s in summaries]), "total_seconds_p90": q([s["total_s"] for s in summaries], 0.9),
        "llm_calls": sum(1 for s in summaries if (s.get("evidence", {}).get("llm_stats") or {}).get("calls")),
        "llm_cost_usd_total": round(sum((s.get("evidence", {}).get("llm_stats") or {}).get("cost_usd") or 0 for s in summaries), 2),
        "llm_evidence_total": sum(s.get("evidence", {}).get("llm", 0) for s in summaries),
        "parser_evidence_total": sum(s.get("evidence", {}).get("parser", 0) for s in summaries),
    }
    st["projects_with_any_case"] = sum(1 for s in summaries if s.get("cases", 0) > 0)
    st["projects_with_root_case"] = sum(1 for s in summaries if s.get("root_cases", 0) > 0)
    st["projects_with_intent_violation"] = sum(1 for s in summaries if (s.get("root_cases_by_type") or s.get("cases_by_type") or {}).get("C-IntentViolation", 0) > 0)
    st["cases_total"] = sum(s.get("cases", 0) for s in summaries)
    st["root_cases_total"] = sum(s.get("root_cases", 0) for s in summaries)
    by_type = Counter(); by_class = Counter(); by_family = Counter(); by_derivation = Counter(); by_direct = Counter()
    tri = Counter(); tri_by_class = defaultdict(Counter); tri_by_type = defaultdict(Counter)
    for s in summaries:
        for k, v in (s.get("root_cases_by_type") or {}).items(): by_type[k] += v
        for k, v in (s.get("root_cases_by_class") or {}).items(): by_class[k] += v
        cases = _load(proj_dir / s["_dir"] / "findings.json") or []
        for c in cases:
            if c.get("consequential_of"): continue
            regs = tuple(sorted({(c[x]["artifact"] or {}).get("registry", "-").split(":")[0] for x in ("a", "b")}))
            by_family[" vs ".join(regs)] += 1
            by_derivation[" | ".join(sorted({c["a"]["derived_from"].split(":")[0], c["b"]["derived_from"].split(":")[0]}))] += 1
            by_direct["direct" if c.get("direct") else "transitive"] += 1
        tcases = _load(proj_dir / s["_dir"] / "cases_triaged.json") or []
        for c in tcases:
            lab = (c.get("triage") or {}).get("label") or "UNTRIAGED"
            tri[lab] += 1; tri_by_class[c["cls"]][lab] += 1; tri_by_type[c["type"]][lab] += 1
    st["root_cases_by_type"] = dict(by_type); st["root_cases_by_class"] = dict(by_class); st["root_cases_by_registry_family_pair"] = dict(by_family.most_common())
    st["root_cases_by_context_derivation"] = dict(by_derivation.most_common()); st["root_cases_direct_vs_transitive"] = dict(by_direct)
    st["triage_labels"] = dict(tri); st["triage_by_class"] = {k: dict(v) for k, v in tri_by_class.items()}; st["triage_by_type"] = {k: dict(v) for k, v in tri_by_type.items()}
    st["projects"] = [{"repo": s["repo"], "stars": s.get("stars"), "custom_indexes": s["ir"]["custom_indexes"], "tools": s["ir"]["tools"], "install_paths_with_index": s["ir"]["install_paths_with_index"],
                       "contexts": s["contexts"], "ok": s["resolutions_ok"], "failed": s["resolutions_failed"], "root_cases": s.get("root_cases"), "cases": s.get("cases"), "types": s.get("root_cases_by_type"), "seconds": s["total_s"]} for s in summaries]
    if write:
        (root / "results" / "stats.json").write_text(json.dumps(st, indent=1, default=str), encoding="utf-8")
        (root / "results" / "STATS.md").write_text(render_md(st), encoding="utf-8")
    return st

def render_md(st: dict) -> str:
    L = ["# DRC corpus run — measured statistics", "", f"Projects analyzed: {st['projects_analyzed']} (errored: {st['projects_errored']})", ""]
    pp = st["per_project"]
    L += ["## Per-project medians", "", "| metric | value |", "|---|---|"] + [f"| {k} | {v} |" for k, v in pp.items()] + [""]
    L += ["## Cases", "", f"- projects with ≥1 root case: {st['projects_with_root_case']} / {st['projects_analyzed']}", f"- projects with ≥1 intent violation: {st['projects_with_intent_violation']}",
          f"- root cases (deduplicated, non-consequential): {st['root_cases_total']}; all cases incl. consequential: {st['cases_total']}", ""]
    for key, title in (("root_cases_by_type", "Root cases by type"), ("root_cases_by_class", "Root cases by oracle class"), ("root_cases_by_registry_family_pair", "Root cases by registry-family pair"),
                       ("root_cases_by_context_derivation", "Root cases by context derivation"), ("root_cases_direct_vs_transitive", "Root cases direct vs transitive"), ("triage_labels", "Triage labels (triaged root cases)")):
        L += [f"### {title}", "", "| key | count |", "|---|---|"] + [f"| {k} | {v} |" for k, v in sorted(st[key].items(), key=lambda kv: -kv[1])] + [""]
    L += ["### Triage by oracle class", "", "| class | " + " | ".join(sorted({l for v in st['triage_by_class'].values() for l in v})) + " |", "|---|" + "---|" * len({l for v in st['triage_by_class'].values() for l in v})]
    labels = sorted({l for v in st['triage_by_class'].values() for l in v})
    for k, v in st["triage_by_class"].items(): L.append(f"| {k} | " + " | ".join(str(v.get(l, 0)) for l in labels) + " |")
    L += ["", "## Projects", "", "| repo | stars | custom indexes | tools | IP w/ index | contexts | ok | failed | root cases | types | s |", "|---|---|---|---|---|---|---|---|---|---|---|"]
    for p in sorted(st["projects"], key=lambda x: -(x["root_cases"] or 0)):
        L.append(f"| {p['repo']} | {p['stars']} | {', '.join(p['custom_indexes'])[:60]} | {', '.join(p['tools'])} | {p['install_paths_with_index']} | {p['contexts']} | {p['ok']} | {p['failed']} | {p['root_cases']} | {json.dumps(p['types'])} | {p['seconds']} |")
    return "\n".join(L)
