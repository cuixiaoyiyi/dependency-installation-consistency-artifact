"""Failure minimisation: ddmin over the requirement set, then single-factor isolation between the two contexts."""
from __future__ import annotations
import pathlib, copy, re
from ..model import Context
from ..resolvers import run as run_resolver
from ..oracle import compare_artifacts, SAME, SAME_FILE_MIRROR, INSUFFICIENT_EVIDENCE

def _still_differs(ca: Context, cb: Context, reqs: list, pkg: str, wd: pathlib.Path, counter: dict) -> bool:
    ca2 = copy.deepcopy(ca); cb2 = copy.deepcopy(cb)
    ca2.requirements = list(reqs); cb2.requirements = list(reqs)
    ca2.id = ca.id + f"|min{counter['n']}"; cb2.id = cb.id + f"|min{counter['n']}"
    ra = run_resolver(ca2, wd / f"a{counter['n']}"); rb = run_resolver(cb2, wd / f"b{counter['n']}")
    counter["n"] += 2
    if not (ra.ok and rb.ok): return False
    d = compare_artifacts(ra.artifacts.get(pkg), rb.artifacts.get(pkg))
    return d.cls not in (SAME, SAME_FILE_MIRROR, INSUFFICIENT_EVIDENCE) and not d.benign

def ddmin_requirements(ca: Context, cb: Context, pkg: str, wd: pathlib.Path, max_probes: int = 16) -> dict:
    reqs = list(ca.requirements)
    counter = {"n": 0}
    # fast path: does the package alone reproduce?
    direct = [r for r in reqs if re.split(r"[\[<>=!~; ]", r, 1)[0].lower().replace("_", "-") == pkg]
    if direct and _still_differs(ca, cb, direct, pkg, wd, counter):
        return {"requirements": direct, "n_requirements": len(direct), "probes": counter["n"], "method": "direct-only"}
    if len(reqs) == 1:
        return {"requirements": reqs, "n_requirements": 1, "probes": counter["n"], "method": "single"}
    n = 2
    cur = reqs
    while len(cur) >= 2 and counter["n"] < max_probes:
        chunk = max(1, len(cur) // n); progressed = False
        for i in range(0, len(cur), chunk):
            cand = cur[:i] + cur[i + chunk:]
            if not cand: continue
            if _still_differs(ca, cb, cand, pkg, wd, counter):
                cur = cand; n = max(n - 1, 2); progressed = True; break
            if counter["n"] >= max_probes: break
        if not progressed:
            if n >= len(cur): break
            n = min(len(cur), n * 2)
    return {"requirements": cur, "n_requirements": len(cur), "probes": counter["n"], "method": "ddmin" + ("-budget" if counter["n"] >= max_probes else "")}

def factor_diff(ca: Context, cb: Context) -> dict:
    out = {}
    for k in ("resolver", "index_url", "extra_index_urls", "index_strategy", "sources", "pre", "find_links", "platform", "python_version"):
        va, vb = getattr(ca, k), getattr(cb, k)
        if va != vb: out[k] = {"a": va, "b": vb}
    return out

def minimize_case(case: dict, contexts: dict[str, Context], out_dir: pathlib.Path, max_probes: int = 16) -> dict:
    if (case.get("contract_violation") or {}).get("verified"):
        return {"status": "not-run", "reason": "A verified defect requires a contract-preserving reduction predicate; difference-only reduction is insufficient."}
    ca = contexts[case["a"]["context"]]; cb = contexts[case["b"]["context"]]
    wd = out_dir / "minimize" / case["case_id"]
    res = ddmin_requirements(ca, cb, case["package"], wd, max_probes=max_probes)
    res["factor_diff"] = factor_diff(ca, cb)
    res["command_a"] = _cmd(ca, res["requirements"]); res["command_b"] = _cmd(cb, res["requirements"])
    res["claim"] = "Reduced exploratory difference only; not a verified reproducer of the original project or contract violation."
    return res

def _cmd(c: Context, reqs: list) -> str:
    q = " ".join(f'"{r}"' for r in reqs)
    if c.resolver == "pip":
        s = "pip install --dry-run --report report.json " + q
        if c.index_url: s += f" --index-url {c.index_url}"
        for u in c.extra_index_urls: s += f" --extra-index-url {u}"
        if c.pre: s += " --pre"
        return s + "   # target: linux x86_64, cp312 (add --platform/--python-version/--only-binary=:all: for cross-platform)"
    s = "uv pip compile --emit-index-annotation " + ("-" if False else "requirements.txt") + f"  # requirements.txt = {q}"
    if c.index_url: s += f" --index-url {c.index_url}"
    for u in c.extra_index_urls: s += f" --extra-index-url {u}"
    if c.index_strategy: s += f" --index-strategy {c.index_strategy}"
    if c.sources: s += f"   # with tool.uv.sources: {c.sources}"
    return s
