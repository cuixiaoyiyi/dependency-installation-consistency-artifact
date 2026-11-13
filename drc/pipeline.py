"""End-to-end analysis of one project: parse -> evidence -> RTOs -> execute -> diff -> classify -> (minimize) -> report."""
from __future__ import annotations
import json, pathlib, time, re, itertools, hashlib, traceback
import uuid
from dataclasses import asdict
from datetime import datetime, timezone
from typing import Optional
from packaging.utils import canonicalize_name

from .model import ProjectIR, Context, Resolution, registry_id, registry_family, PYPI
from .frontend import parse_project
from .intent import structured_evidence, build_intents, Evidence
from .contexts import generate_rtos, RTO
from .resolvers import run as run_resolver
from .oracle import diff_resolutions, summarize, Diff, SAME, SAME_FILE_MIRROR, INSUFFICIENT_EVIDENCE
from .contracts import assess_contracts, comparison_eligibility

TYPE_STABLE = "A-Stable"
TYPE_AMBIGUITY = "B-ResolutionAmbiguity"
TYPE_VIOLATION = "C-IntentViolation"
TYPE_LATENT = "B'-LatentExposure"

def _now(): return datetime.now(timezone.utc).isoformat(timespec="seconds")

def _dump(path: pathlib.Path, obj):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=1, default=str), encoding="utf-8")

class ProjectRun:
    def __init__(self, repo: str, root: pathlib.Path, out: pathlib.Path, llm: bool = True, max_contexts: int = 14, max_rtos: int = 6, resolver_filter: Optional[set] = None,
                 snapshot_id=None, snapshot_mode="record", strict_reproducibility=True, latent_checks=False):
        self.repo = repo; self.root = pathlib.Path(root); self.out = pathlib.Path(out); self.llm = llm
        self.max_contexts = max_contexts; self.max_rtos = max_rtos; self.resolver_filter = resolver_filter
        self.log = []
        self.timing = {}
        self.snapshot_id = snapshot_id or "run-" + uuid.uuid4().hex
        self.snapshot_mode = snapshot_mode
        self.strict_reproducibility = strict_reproducibility
        self.latent_checks = latent_checks

    def _log(self, msg):
        line = f"{_now()} {msg}"
        self.log.append(line)
        try:
            with open(self.out / "log.txt", "a", encoding="utf-8") as f: f.write(line + "\n")
        except OSError:
            pass

    def run(self) -> dict:
        t_all = time.time()
        if (self.out / "summary.json").exists() or (self.out / "rtos.json").exists():
            raise FileExistsError(f"Existing experiment preserved; select a new output directory: {self.out}")
        self.out.mkdir(parents=True, exist_ok=True)
        (self.out / "log.txt").write_text("", encoding="utf-8")
        # ---------------- Phase 1
        t = time.time(); ir = parse_project(self.root, self.repo); self.timing["parse_s"] = round(time.time() - t, 2)
        _dump(self.out / "ir.json", ir.to_dict())
        # ---------------- Phase 2/3 evidence
        t = time.time(); ev = structured_evidence(ir)
        llm_ev = []
        llm_stats = {}
        if self.llm:
            try:
                from .intent.llm_miner import mine_llm_evidence
                llm_ev, llm_stats = mine_llm_evidence(ir, self.root, self.out)
            except Exception as e:
                self._log(f"llm-miner failed: {e}"); llm_stats = {"error": str(e)}
        self.timing["evidence_s"] = round(time.time() - t, 2)
        all_ev = ev + llm_ev
        dep_names = sorted({d.cname for d in ir.dependencies})
        intents = build_intents(all_ev, dep_names)
        _dump(self.out / "evidence.json", {"parser": [e.to_dict() for e in ev], "llm": [e.to_dict() for e in llm_ev], "llm_stats": llm_stats})
        _dump(self.out / "intents.json", {k: v.to_dict() for k, v in intents.items()})
        # ---------------- Phase 4/5 RTOs
        t = time.time(); rtos = generate_rtos(ir, self.root, budget_contexts=self.max_contexts)
        rtos = _prioritize(rtos, ir)[: self.max_rtos]
        if self.resolver_filter:
            for r in rtos: r.contexts = [c for c in r.contexts if c.resolver in self.resolver_filter]
        for r in rtos:
            for c in r.contexts:
                c.snapshot_id = self.snapshot_id
                c.snapshot_mode = self.snapshot_mode
                c.strict_reproducibility = self.strict_reproducibility
        self.timing["rto_s"] = round(time.time() - t, 2)
        _dump(self.out / "rtos.json", [r.to_dict() for r in rtos])
        file_hashes = {}
        for rel in ir.files:
            try: file_hashes[rel] = hashlib.sha256((self.root / rel).read_bytes()).hexdigest()
            except OSError: file_hashes[rel] = None
        _dump(self.out / "experiment_manifest.json", {"schema": "drc-reliability-v2", "snapshot_id": self.snapshot_id,
              "snapshot_mode": self.snapshot_mode, "strict_reproducibility": self.strict_reproducibility,
              "source_files_sha256": file_hashes, "llm_role": "supporting evidence; not a verified contract or test-generation component",
              "claim": "exploratory resolution contrasts plus separately verified scoped contracts"})
        # ---------------- Phase 6 execution
        t = time.time()
        resolutions: dict[str, Resolution] = {}
        n_exec = 0
        budget_s = float(__import__("os").environ.get("DRC_PROJECT_BUDGET_S", "2400"))
        for r in rtos:
            for c in r.contexts:
                wd = self.out / "runs" / _safe(c.id)
                if time.time() - t_all > budget_s:
                    res = Resolution(c.id, c.resolver, False, {}, 0.0, "", "skipped: project time budget exhausted")
                else:
                    res = run_resolver(c, wd)
                policy = (res.snapshot or {}).get("candidate_policy") or {}
                if policy.get("drop_sdists_without_static_metadata") and c.only_binary != ":all:":
                    limitation = "metadata-only candidate universe excludes some sdists; original unrestricted selection is not certified"
                    if limitation not in c.limitations: c.limitations.append(limitation)
                    c.faithfulness = "projected"
                resolutions[c.id] = res; n_exec += 1
                _dump(wd / "resolution.json", res.to_dict())
                self._log(f"resolve {c.id}: {'ok' if res.ok else 'FAIL'} {res.seconds:.1f}s n={len(res.artifacts)} {res.fallback} {res.error[:120] if not res.ok else ''}")
        self.timing["execute_s"] = round(time.time() - t, 2); self.timing["n_resolutions"] = n_exec
        _dump(self.out / "rtos.json", [r.to_dict() for r in rtos])
        # ---------------- Phase 7/8 differential oracle + classification
        t = time.time()
        findings = []
        pair_stats = []
        assessments = {c.id: assess_contracts(ir, intents, c, resolutions[c.id]) for r in rtos for c in r.contexts}
        _dump(self.out / "contracts.json", {cid: value.to_dict() for cid, value in assessments.items()})
        for r in rtos:
            ok_ctxs = [c for c in r.contexts if resolutions[c.id].ok]
            requested = {canonicalize_name(re.split(r"[\[<>=!~; ]", x, 1)[0]) for x in r.reqset.requirements if re.split(r"[\[<>=!~; ]", x, 1)[0]}
            for ca, cb in itertools.combinations(ok_ctxs, 2):
                diffs = diff_resolutions(resolutions[ca.id], resolutions[cb.id], ca, cb)
                s = summarize(diffs)
                eligible = comparison_eligibility(ca, cb, resolutions[ca.id], resolutions[cb.id]).to_dict()
                pair_stats.append({"rto": r.id, "a": ca.id, "b": cb.id, "comparison": eligible, **s})
                changed = {d.package for d in diffs if d.cls not in (SAME, SAME_FILE_MIRROR, INSUFFICIENT_EVIDENCE) and not d.benign}
                parents = _parent_map(resolutions[ca.id], resolutions[cb.id])
                for d in diffs:
                    if d.cls in (SAME, SAME_FILE_MIRROR, INSUFFICIENT_EVIDENCE) or d.benign: continue
                    f = _classify(d, ca, cb, intents, ir, r, assessments=assessments, comparability=eligible)
                    # consequential: transitive package whose difference is explained by a changed parent
                    if d.package not in requested:
                        ps = parents.get(d.package, set()) & changed
                        if ps: f["consequential_of"] = sorted(ps)
                    findings.append(f)
            # Absolute conformance is checked even when every context agrees.
            # A pairwise differential alone can miss a consistently wrong result.
            for ctx in ok_ctxs:
                for check in assessments[ctx.id].violations:
                    pkg = check["dependency"]
                    art = resolutions[ctx.id].artifacts.get(pkg)
                    if art is None: continue
                    diff = Diff(pkg, "EXPLICIT_CONTRACT_VIOLATION", art.to_dict(), art.to_dict(), check["reason"], severity=3)
                    findings.append(_classify(diff, ctx, ctx, intents, ir, r, assessments=assessments))
        self.timing["oracle_s"] = round(time.time() - t, 2)
        cases = _dedup_findings(findings)
        # ---------------- latent exposure: packages served by a custom index whose name is NOT registered on PyPI
        t = time.time()
        latent = _latent_exposure(resolutions, rtos, intents, ir) if self.latent_checks and not self.strict_reproducibility else []
        for i, c in enumerate(latent, 1): c["case_id"] = f"latent-{_safe(c['package'])[:20]}-{i:03d}"
        cases += latent
        self.timing["latent_s"] = round(time.time() - t, 2)
        _dump(self.out / "pairs.json", pair_stats)
        _dump(self.out / "findings.json", cases)
        summary = {
            "schema": "drc-reliability-v2", "snapshot_id": self.snapshot_id,
            "verified_contract_contexts": sum(a.status == "violation" for a in assessments.values()),
            "comparable_pairs": sum(p["comparison"]["eligible"] for p in pair_stats),
            "insufficient_artifact_comparisons": sum(p.get("insufficient_evidence", 0) for p in pair_stats),
            "repo": self.repo, "timestamp": _now(), "timing": self.timing, "total_s": round(time.time() - t_all, 1),
            "ir": {"files": len(ir.files), "dependencies": len(ir.dependencies), "indexes": len(ir.indexes), "custom_indexes": sorted({ix.rid for ix in ir.indexes if ix.rid != PYPI and ix.url.startswith("http")}),
                   "bindings": len(ir.bindings), "install_paths": len(ir.install_paths), "install_paths_with_index": sum(1 for ip in ir.install_paths if ip.index_url or ip.extra_index_urls),
                   "locks": [l.kind for l in ir.locks], "tools": ir.tools, "notes": len(ir.notes)},
            "evidence": {"parser": len(ev), "llm": len(llm_ev), "llm_stats": llm_stats, "intents_with_tier<=2": sum(1 for i in intents.values() if i.tier <= 2)},
            "rtos": len(rtos), "contexts": sum(len(r.contexts) for r in rtos), "resolutions_ok": sum(1 for x in resolutions.values() if x.ok),
            "resolutions_failed": sum(1 for x in resolutions.values() if not x.ok), "resolver_seconds": round(sum(x.seconds for x in resolutions.values()), 1),
            "pairs": len(pair_stats), "pairs_with_ambiguity": sum(1 for p in pair_stats if p["ambiguous"] > 0),
            "findings_raw": len(findings), "cases": len(cases), "root_cases": sum(1 for c in cases if not c.get("consequential_of")),
            "consequential_cases": sum(1 for c in cases if c.get("consequential_of")),
            "cases_by_type": _count(cases, "type"), "cases_by_class": _count(cases, "cls"),
            "root_cases_by_type": _count([c for c in cases if not c.get("consequential_of")], "type"),
            "root_cases_by_class": _count([c for c in cases if not c.get("consequential_of")], "cls"),
        }
        _dump(self.out / "summary.json", summary)
        (self.out / "log.txt").write_text("\n".join(self.log), encoding="utf-8")
        return summary

_PYPI_EXISTS: dict[str, Optional[bool]] = {}

def pypi_exists(name: str) -> Optional[bool]:
    """True/False whether a project name is registered on PyPI (None on network error). Cached per process + on disk."""
    import urllib.request, urllib.error, os
    if name in _PYPI_EXISTS: return _PYPI_EXISTS[name]
    cache = pathlib.Path(__file__).resolve().parents[1] / "results" / "_cache" / "pypi_exists.json"
    disk = {}
    if cache.exists():
        try: disk = json.loads(cache.read_text(encoding="utf-8"))
        except json.JSONDecodeError: disk = {}
    if name in disk: _PYPI_EXISTS[name] = disk[name]; return disk[name]
    try:
        req = urllib.request.Request(f"https://pypi.org/simple/{name}/", method="HEAD", headers={"User-Agent": "drc-research/0.1", "Accept": "application/vnd.pypi.simple.v1+json"})
        with urllib.request.urlopen(req, timeout=30) as r: val = r.status == 200
    except urllib.error.HTTPError as e:
        val = False if e.code == 404 else None
    except Exception:
        val = None
    _PYPI_EXISTS[name] = val
    if val is not None:
        disk[name] = val
        try: cache.write_text(json.dumps(disk), encoding="utf-8")
        except OSError: pass
    return val

def _latent_exposure(resolutions: dict, rtos: list, intents: dict, ir: ProjectIR) -> list[dict]:
    """Names that the project obtains from a non-PyPI registry and that are unregistered on PyPI: a pre-condition for
    classic dependency confusion. Also names that are registered on PyPI but never selected from it in any context
    (present-day shadowing risk is then reported by the differential oracle, not here)."""
    served: dict[str, dict] = {}
    for cid, res in resolutions.items():
        if not res.ok: continue
        for cname, a in res.artifacts.items():
            if a.registry != PYPI and a.registry not in ("git", "direct-url", "local", "?"):
                served.setdefault(cname, {"registries": set(), "contexts": set(), "versions": set()})
                served[cname]["registries"].add(a.registry); served[cname]["contexts"].add(cid); served[cname]["versions"].add(a.version)
    # only names whose PyPI namesake could plausibly shadow: any custom-served package
    out = []
    direct = {d.cname for d in ir.dependencies}
    for cname, info in sorted(served.items()):
        ex = pypi_exists(cname)
        if ex is False:
            it = intents.get(cname)
            out.append({"package": cname, "cls": "UNREGISTERED_ON_PYPI", "severity": 2, "type": TYPE_LATENT,
                        "explanation": f"`{cname}` is served only by {sorted(info['registries'])} and the name is not registered on PyPI; any install path that also consults PyPI (pip --extra-index-url, uv unsafe-* strategies) can be hijacked by registering the name.",
                        "a": {"context": sorted(info["contexts"])[0], "derived_from": "observed", "factors": {}, "artifact": {"name": cname, "version": sorted(info["versions"])[0], "registry": sorted(info["registries"])[0], "url": "", "filename": "", "kind": "", "sha256": None}},
                        "b": {"context": "pypi", "derived_from": "namespace-check", "factors": {}, "artifact": None},
                        "intent": {"tier": it.tier if it else 5, "allowed": it.allowed_registries if it else [], "strong": [], "n_evidence": len(it.evidence) if it else 0, "conflicting": False, "note": ""},
                        "violated_in": [], "direct": cname in direct, "rto": "-", "reqset_origin": "-", "occurrences": len(info["contexts"]), "registries": sorted(info["registries"])})
    return out

def _parent_map(ra: Resolution, rb: Resolution) -> dict:
    """child cname -> set of parent cnames (union over both resolutions)."""
    out: dict[str, set] = {}
    for res in (ra, rb):
        for parent, art in res.artifacts.items():
            for req in art.requires_dist or []:
                if not isinstance(req, str) or req.startswith("__fork__"): continue
                name = re.split(r"[\[<>=!~; (]", req.strip(), 1)[0]
                if name: out.setdefault(canonicalize_name(name), set()).add(parent)
    return out

def _safe(s: str) -> str:
    h = hashlib.sha1(s.encode()).hexdigest()[:6]
    return re.sub(r"[^A-Za-z0-9._-]+", "_", s)[:60] + "_" + h

def _count(items, key):
    from collections import Counter
    return dict(Counter(i[key] for i in items))

def _prioritize(rtos: list[RTO], ir: ProjectIR) -> list[RTO]:
    """Prefer requirement sets tied to install paths with custom indexes and to bound packages; smaller sets first on ties."""
    def score(r: RTO):
        bound = {b.dep for b in ir.bindings if str(pathlib.PurePosixPath(b.file).parent) == r.reqset.scope}
        s = 0
        if r.reqset.origin.startswith("pyproject:runtime"): s -= 5
        if "install-path" in r.reqset.origin: s -= 3
        if any(c.derived_from.startswith("install-path") for c in r.contexts): s -= 4
        s -= 2 * len(bound & set(r.focus))
        s += len(r.reqset.requirements) / 100.0
        observed = any(c.derived_from.startswith("install-path:") for c in r.contexts)
        return (not observed, s)
    return sorted(rtos, key=score)

def _classify(d: Diff, ca: Context, cb: Context, intents: dict, ir: ProjectIR, rto: RTO, assessments=None, comparability=None) -> dict:
    pkg = d.package
    requested = {canonicalize_name(re.split(r"[\[<>=!~; ]", requirement, 1)[0])
                 for requirement in rto.reqset.requirements}
    it = intents.get(pkg)
    regs = {x["registry"] for x in (d.a, d.b) if x}
    intent_regs = set(it.allowed_registries) if it else set()
    tier = it.tier if it else 5
    ftype = TYPE_AMBIGUITY
    violated_in = []
    strong_regs = set()
    contract = {"verified": False, "evidence": []}
    for side, ctx in (("a", ca), ("b", cb)):
        assessment = (assessments or {}).get(ctx.id)
        breaches = [c for c in (assessment.violations if assessment else []) if c["dependency"] == pkg]
        if breaches:
            ftype = TYPE_VIOLATION
            violated_in.append({"context": ctx.id, "side": side, "checks": breaches})
            contract = {"verified": True, "kind": "single-context", "side": side, "context": ctx.id,
                        "contract": "The selected artifact must satisfy the explicit scoped source/lock contract.", "evidence": breaches}
    return {"package": pkg, "cls": d.cls, "severity": d.severity, "type": ftype, "explanation": d.explanation,
            "a": {"context": ca.id, "derived_from": ca.derived_from, "factors": ca.factors, "artifact": d.a, "origin": ca.origin},
            "b": {"context": cb.id, "derived_from": cb.derived_from, "factors": cb.factors, "artifact": d.b, "origin": cb.origin},
            "comparability": {**(comparability or {"eligible": False, "reasons": ["comparison-not-assessed"]}),
                              "verified": False, "evidence": [], "note": "Input equality is not a proof of an irrelevant transformation."},
            "contract_violation": contract,
            "intent": {"tier": tier, "allowed": sorted(intent_regs), "strong": sorted(strong_regs), "n_evidence": len(it.evidence) if it else 0, "conflicting": it.conflicting if it else False, "note": it.note if it else "",
                       "basis": ("tier1-config" if it and any(e.get("tier", 5) <= 1 and e.get("registry") for e in it.evidence) else "multi-install-path" if strong_regs else "none"),
                       "evidence_files": sorted({e.get("file") for e in (it.evidence if it else []) if e.get("registry")})[:8]},
            "violated_in": violated_in, "direct": pkg in requested, "rto": rto.id, "reqset_origin": rto.reqset.origin}

def _dedup_findings(findings: list[dict]) -> list[dict]:
    """One case per (package, diff class, registry pair, version pair); keep the pair with the most 'realistic' contexts."""
    cases = {}
    def realism(f):
        r = 0
        for side in ("a", "b"):
            df = f[side]["derived_from"]
            r += 3 if df.startswith("install-path") else 2 if df == "declared" else 1
        return r
    for f in findings:
        ra = f["a"]["artifact"]["registry"] if f["a"]["artifact"] else "-"; rb = f["b"]["artifact"]["registry"] if f["b"]["artifact"] else "-"
        va = f["a"]["artifact"]["version"] if f["a"]["artifact"] else "-"; vb = f["b"]["artifact"]["version"] if f["b"]["artifact"] else "-"
        if f.get("contract_violation", {}).get("verified"):
            checks = f["contract_violation"]["evidence"]
            key = ("contract", f["package"], json.dumps([{k: c.get(k) for k in ("kind", "reason", "expected", "actual", "evidence")} for c in checks], sort_keys=True))
        else:
            key = (f["package"], f["cls"], tuple(sorted([(ra, va), (rb, vb)])))
        if key not in cases or realism(f) > realism(cases[key]) or (realism(f) == realism(cases[key]) and f["type"] > cases[key]["type"]):
            f = dict(f); f["occurrences"] = cases[key]["occurrences"] + 1 if key in cases else 1
            cases[key] = f
        else:
            cases[key]["occurrences"] += 1
    out = sorted(cases.values(), key=lambda f: (-f["severity"], f["type"], f["package"]))
    for i, c in enumerate(out, 1): c["case_id"] = f"{_safe(c['package'])[:20]}-{i:03d}"
    return out
