"""Combine parser + LLM evidence into per-dependency intent hypotheses with tiers."""
from __future__ import annotations
from collections import defaultdict
from dataclasses import dataclass, field, asdict
from typing import Optional
from .structured_evidence import Evidence, E1, E2, E3, E4, E5, E6
from packaging.utils import canonicalize_name
import json

@dataclass
class Intent:
    dep: str
    allowed_registries: list          # registry ids considered intended (ordered by strength)
    tier: int                          # best tier of supporting evidence (1 strongest, 4 weakest, 5 none)
    evidence: list                     # Evidence dicts
    conflicting: bool = False          # evidence points to different registries
    note: str = ""
    contracts: list = field(default_factory=list)
    def to_dict(self): return asdict(self)

def build_intents(evidence: list[Evidence], deps: list[str]) -> dict[str, Intent]:
    by_dep = defaultdict(list)
    for e in evidence: by_dep[e.dep if e.dep == "*" else canonicalize_name(e.dep)].append(e)
    project_wide = by_dep.get("*", [])
    out = {}
    for dep in sorted({canonicalize_name(d) for d in deps} | {d for d in by_dep if d != "*"}):
        evs = by_dep.get(dep, [])
        # registry votes weighted by tier
        regs = defaultdict(lambda: 5)
        for e in evs:
            if e.registry: regs[e.registry] = min(regs[e.registry], e.tier)
        tier = min([e.tier for e in evs if e.registry] or [5])
        allowed = sorted(regs, key=lambda r: (regs[r], r))
        # Different channels are different sources.  Mutually conditional source
        # alternatives are not one global allow-list, nor necessarily a conflict.
        contract_groups = defaultdict(set)
        contracts = [e.to_dict() for e in evs if e.enforceable]
        for e in evs:
            if e.enforceable and e.registry:
                key = (e.contract_kind, e.tool, e.scope, json.dumps(e.conditions, sort_keys=True, default=str))
                contract_groups[key].add(e.registry)
        conflicting = any(len(values) > 1 for values in contract_groups.values())
        note = ""
        if not evs and project_wide:
            # fall back: project-wide configured indexes (weak)
            pw = defaultdict(lambda: 5)
            for e in project_wide:
                if e.registry: pw[e.registry] = min(pw[e.registry], e.tier)
            allowed = sorted(pw, key=lambda r: (pw[r], r)); tier = 5; note = "no dependency-specific evidence; project-wide indexes only"
            evs = project_wide
        out[dep] = Intent(dep, allowed, tier, [e.to_dict() for e in evs], conflicting, note, contracts)
    return out
