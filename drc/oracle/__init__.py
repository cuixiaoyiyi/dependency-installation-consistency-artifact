"""Artifact identity normalisation + differential oracle + benign-variation filter."""
from __future__ import annotations
import re
from dataclasses import dataclass, field, asdict
from typing import Optional
from packaging.version import Version, InvalidVersion
from packaging.utils import canonicalize_name
from ..model import Artifact, Resolution, registry_id, registry_family

# Difference classes (ordered by severity for reporting)
SAME = "SAME"
SAME_FILE_MIRROR = "SAME_FILE_MIRROR"                 # same filename+hash, different URL host (mirror)
LOCAL_VARIANT = "LOCAL_VARIANT"                       # same base version, different local label (+cu128) and/or registry
SAME_VERSION_DIFF_HASH_SAME_REGISTRY = "SAME_VERSION_DIFF_HASH_SAME_REGISTRY"  # e.g. different wheel tag chosen
SAME_VERSION_DIFF_REGISTRY = "SAME_VERSION_DIFF_REGISTRY"                    # same version, different registry (hash may differ)
DIFF_VERSION_SAME_REGISTRY = "DIFF_VERSION_SAME_REGISTRY"
DIFF_VERSION_DIFF_REGISTRY = "DIFF_VERSION_DIFF_REGISTRY"
WHEEL_VS_SDIST = "WHEEL_VS_SDIST"
ONLY_IN_A = "ONLY_IN_A"
ONLY_IN_B = "ONLY_IN_B"
INSUFFICIENT_EVIDENCE = "INSUFFICIENT_EVIDENCE"

SEVERITY = {SAME: 0, SAME_FILE_MIRROR: 0, LOCAL_VARIANT: 1, SAME_VERSION_DIFF_HASH_SAME_REGISTRY: 1, WHEEL_VS_SDIST: 1, DIFF_VERSION_SAME_REGISTRY: 2,
            ONLY_IN_A: 2, ONLY_IN_B: 2, SAME_VERSION_DIFF_REGISTRY: 3, DIFF_VERSION_DIFF_REGISTRY: 3}

@dataclass
class Diff:
    package: str
    cls: str
    a: Optional[dict]
    b: Optional[dict]
    explanation: str = ""
    benign: bool = False
    benign_reason: str = ""
    severity: int = 0
    def to_dict(self): return asdict(self)

def _base_version(v: str):
    try:
        pv = Version(v); return pv.base_version, pv.local, pv.is_prerelease
    except InvalidVersion:
        return v.split("+")[0], (v.split("+")[1] if "+" in v else None), False

def compare_artifacts(a: Optional[Artifact], b: Optional[Artifact]) -> Diff:
    if a is None and b is None:
        return Diff("?", INSUFFICIENT_EVIDENCE, None, None, "neither execution selected this package")
    name = (a or b).cname
    if a is None or b is None:
        artifact = a or b
        if not getattr(artifact, "selected_artifact_verified", False):
            return Diff(name, INSUFFICIENT_EVIDENCE, a.to_dict() if a else None, b.to_dict() if b else None,
                        "one side contains an unselected or legacy lock candidate; package presence is unverified")
        cls = ONLY_IN_A if a else ONLY_IN_B
        return Diff(name, cls, a.to_dict() if a else None, b.to_dict() if b else None,
                    "package selected only in context " + ("A" if a else "B"), severity=SEVERITY[cls])
    if any("fork-unverified" in getattr(x, "selection_evidence", "") for x in (a, b)):
        return Diff(name, INSUFFICIENT_EVIDENCE, a.to_dict(), b.to_dict(), "universal lock contains multiple active-version/source candidates; actual target selection was not observed")
    files_verified = all(getattr(x, "selected_artifact_verified", False) for x in (a, b))
    if not files_verified and a.version == b.version and a.registry == b.registry:
        return Diff(name, INSUFFICIENT_EVIDENCE, a.to_dict(), b.to_dict(), "matching version/source metadata does not establish which file was selected")
    if files_verified and a.sha256 and b.sha256 and a.sha256 == b.sha256:
        cls = SAME if a.url == b.url or a.registry == b.registry else SAME_FILE_MIRROR
        return Diff(name, cls, a.to_dict(), b.to_dict(), "identical file hash", benign=True, benign_reason="identical artifact hash", severity=0)
    if files_verified and a.url and a.url == b.url and not (a.sha256 and b.sha256 and a.sha256 != b.sha256):
        return Diff(name, INSUFFICIENT_EVIDENCE, a.to_dict(), b.to_dict(), "same URL without a common verified content hash; content identity not established")
    ba, la, _ = _base_version(a.version); bb, lb, _ = _base_version(b.version)
    same_reg = a.registry == b.registry
    if a.kind != b.kind and a.version == b.version and same_reg:
        return Diff(name, WHEEL_VS_SDIST, a.to_dict(), b.to_dict(), f"{a.kind} vs {b.kind} for same version/registry", severity=SEVERITY[WHEEL_VS_SDIST])
    if a.version == b.version:
        if same_reg:
            if a.filename == b.filename and (not a.sha256 or not b.sha256):
                return Diff(name, INSUFFICIENT_EVIDENCE, a.to_dict(), b.to_dict(), "same filename/registry without a common verified content hash; content identity not established")
            return Diff(name, SAME_VERSION_DIFF_HASH_SAME_REGISTRY, a.to_dict(), b.to_dict(), f"same version+registry, different file ({a.filename} vs {b.filename})", severity=SEVERITY[SAME_VERSION_DIFF_HASH_SAME_REGISTRY])
        return Diff(name, SAME_VERSION_DIFF_REGISTRY, a.to_dict(), b.to_dict(), f"same version {a.version} served by different registries: {a.registry} vs {b.registry}" + (" (identical filename, different hash)" if a.filename == b.filename and a.sha256 and b.sha256 else ""), severity=SEVERITY[SAME_VERSION_DIFF_REGISTRY])
    if ba == bb and (la or lb):
        return Diff(name, LOCAL_VARIANT, a.to_dict(), b.to_dict(), f"same base version {ba}, local variants {la or '-'} vs {lb or '-'} ({a.registry} vs {b.registry})", severity=SEVERITY[LOCAL_VARIANT])
    cls = DIFF_VERSION_SAME_REGISTRY if same_reg else DIFF_VERSION_DIFF_REGISTRY
    direction = _direction(a.version, b.version)
    return Diff(name, cls, a.to_dict(), b.to_dict(), f"version {a.version} ({a.registry}) vs {b.version} ({b.registry}); {direction}", severity=SEVERITY[cls])

def _direction(va, vb):
    try:
        A, B = Version(va), Version(vb)
        if A == B: return "equal"
        return "A newer" if A > B else "B newer"
    except InvalidVersion:
        return "incomparable"

def diff_resolutions(ra: Resolution, rb: Resolution, ctx_a=None, ctx_b=None, bindings=None) -> list[Diff]:
    """Compare two successful resolutions package-wise and apply benign filter."""
    names = set(ra.artifacts) | set(rb.artifacts)
    out = []
    for n in sorted(names):
        a, b = ra.artifacts.get(n), rb.artifacts.get(n)
        d = compare_artifacts(a, b)
        if (a is None) != (b is None):
            present, absent = (ra, rb) if a else (rb, ra)
            artifact = a or b
            present_graph = getattr(present, "graph_projection", {}) or {}
            absent_graph = getattr(absent, "graph_projection", {}) or {}
            present_nodes = {node.get("name") for node in present_graph.get("selected", [])}
            absent_nodes = {node.get("name") for node in absent_graph.get("selected", [])}
            target_environments = [{key: value for key, value in graph.get("environment", {}).items()
                                    if key not in {"extra", "extras", "dependency_groups"}}
                                   for graph in (present_graph, absent_graph)]
            same_target = bool(target_environments[0]) and target_environments[0] == target_environments[1]
            presence_known = (getattr(artifact, "selected_artifact_verified", False) or
                              (present_graph.get("status") == "verified" and n in present_nodes))
            absence_known = absent_graph.get("status") == "verified" and n not in absent_nodes
            if present.ok and absent.ok and same_target and presence_known and absence_known:
                cls = ONLY_IN_A if a else ONLY_IN_B
                d = Diff(n, cls, a.to_dict() if a else None, b.to_dict() if b else None,
                         "package belongs only to verified target dependency graph " + ("A" if a else "B") +
                         "; this does not claim a lock candidate was installed", severity=SEVERITY[cls])
            else:
                d = Diff(n, INSUFFICIENT_EVIDENCE, a.to_dict() if a else None, b.to_dict() if b else None,
                         "target package presence/absence is not certified on both sides")
        apply_benign_filter(d, ctx_a, ctx_b, bindings or {})
        out.append(d)
    return out

def apply_benign_filter(d: Diff, ctx_a, ctx_b, bindings: dict):
    """Mark differences that are explained by the contexts themselves (not by resolver ambiguity)."""
    if d.benign: return
    if ctx_a is not None and ctx_b is not None:
        if ctx_a.platform != ctx_b.platform or ctx_a.python_version != ctx_b.python_version:
            if d.cls in (SAME_VERSION_DIFF_HASH_SAME_REGISTRY, WHEEL_VS_SDIST):
                d.benign = True; d.benign_reason = "different target platform/python in contexts"; return
        # explicit variant selection: if both contexts bind this package to different explicit indexes (e.g. cu118 vs cu128), a LOCAL_VARIANT is expected
        if d.cls == LOCAL_VARIANT:
            fa = ctx_a.factors.get("variant") if ctx_a else None; fb = ctx_b.factors.get("variant") if ctx_b else None
            if fa and fb and fa != fb: d.benign = True; d.benign_reason = "contexts intentionally select different hardware variants"; return
    if d.cls in (ONLY_IN_A, ONLY_IN_B):
        # extras/markers differences produce presence differences; treat as benign only if contexts differ in requirement set
        if ctx_a is not None and ctx_b is not None and set(ctx_a.requirements) != set(ctx_b.requirements):
            d.benign = True; d.benign_reason = "contexts install different requirement sets"; return

def summarize(diffs: list[Diff]) -> dict:
    from collections import Counter
    c = Counter(d.cls for d in diffs); nb = sum(1 for d in diffs if d.benign)
    return {"packages": len(diffs), "stable": sum(1 for d in diffs if d.cls in (SAME, SAME_FILE_MIRROR)), "benign_filtered": nb,
            "ambiguous": sum(1 for d in diffs if not d.benign and d.cls not in (SAME, SAME_FILE_MIRROR, INSUFFICIENT_EVIDENCE)),
            "insufficient_evidence": sum(d.cls == INSUFFICIENT_EVIDENCE for d in diffs), "by_class": dict(c),
            "max_severity": max([d.severity for d in diffs if not d.benign] or [0])}
