"""Evidence derived deterministically from the ProjectIR (no LLM)."""
from __future__ import annotations
from dataclasses import dataclass, field, asdict
from typing import Optional
import pathlib
import tomllib
from packaging.utils import canonicalize_name
from ..model import ProjectIR, registry_id

# Evidence classes (plan section 10)
E1 = "E1-explicit-source-binding"
E2 = "E2-url-hash-lock-binding"
E3 = "E3-build-ci-context"
E4 = "E4-documentation"
E5 = "E5-historical-resolution"
E6 = "E6-ownership-publisher"
TIER = {E1: 1, E2: 1, E3: 2, E5: 3, E4: 4, E6: 4}

@dataclass
class Evidence:
    dep: str                       # canonical name or '*' (project-wide)
    cls: str
    tier: int
    registry: Optional[str]        # allowed/intended registry id (None if unknown)
    registry_url: Optional[str]
    file: str
    line: int
    quote: str
    source: str = "parser"         # parser | llm
    confidence: str = "high"
    note: str = ""
    # Evidence is descriptive unless an explicit, scoped contract is recoverable.
    # These fields are intentionally independent of the strength/tier of a quote.
    contract_kind: str = ""
    enforceable: bool = False
    tool: str = ""
    scope: str = "."
    conditions: dict = field(default_factory=dict)
    expected: dict = field(default_factory=dict)
    def to_dict(self): return asdict(self)


def _scope(file: str) -> str:
    return str(pathlib.PurePosixPath(file.replace("\\", "/")).parent)


def _binding_conditions(ir, binding):
    """Keep source predicates, recovering old lossy uv records from the TOML.

    A legacy SourceBinding did not preserve uv's ``extra``.  In its absence a
    marker-only detail string is not evidence of an unconditional binding.
    """
    conditions = dict(getattr(binding, "conditions", {}) or {})
    for key in ("marker", "extra", "group"):
        value = getattr(binding, key, None)
        if value is not None:
            conditions[key] = value
    known = bool(getattr(binding, "conditions_known", False))
    if known:
        return [(conditions, True)]
    if binding.tool == "uv":
        try:
            data = tomllib.loads((pathlib.Path(ir.root) / binding.file).read_text(encoding="utf-8"))
            sources = ((data.get("tool") or {}).get("uv") or {}).get("sources") or {}
            source = next((v for k, v in sources.items() if canonicalize_name(k) == canonicalize_name(binding.dep)), None)
            matches = []
            for item in source if isinstance(source, list) else [source]:
                if not isinstance(item, dict) or item.get("index") != binding.index_name:
                    continue
                matches.append(({k: item[k] for k in ("marker", "extra", "group") if k in item}, True))
            if matches:
                return matches
        except (OSError, ValueError, TypeError):
            pass
    if binding.detail.startswith("marker="):
        conditions.setdefault("marker", binding.detail[len("marker="):])
    return [(conditions, False)]

def structured_evidence(ir: ProjectIR) -> list[Evidence]:
    ev: list[Evidence] = []
    # E1: explicit source bindings (uv sources / poetry source / pdm include_packages / pipenv index / CLI --index-url with explicit package)
    for b in ir.bindings:
        if not b.index_url or not b.index_url.startswith("http"): continue
        # configuration-level bindings (uv/poetry/pdm/pipenv) are Tier 1; a CLI `pip install X --index-url Y` in one install path is Tier 2 (strong contextual)
        # An index participating in one command is not a per-package source pin.
        for conditions, known in _binding_conditions(ir, b):
            conditions = dict(conditions)
            conditions["conditions_known"] = known
            conditions["project_file"] = b.file
            ev.append(Evidence(canonicalize_name(b.dep), E1 if b.tool != "cli" else E3, 1 if b.tool != "cli" else 2,
                               registry_id(b.index_url), b.index_url, b.file, b.line,
                               (b.detail or f"{b.tool} binding -> {b.index_name or b.index_url}")[:200],
                               confidence="high" if b.tool != "cli" else "medium", note=f"tool={b.tool}",
                               contract_kind="source-binding" if b.tool != "cli" else "index-participation",
                               enforceable=b.tool != "cli" and not b.detail.startswith("direct:"), tool=b.tool,
                               scope=getattr(b, "scope", None) if getattr(b, "scope", ".") != "." else _scope(b.file),
                               conditions=conditions, expected={"registry": registry_id(b.index_url)}))
    # E2: lockfile attribution of registry per package (identity binding: hash + registry)
    for lk in ir.locks:
        for dep, info in lk.packages.items():
            reg = info.get("registry")
            if reg and reg not in ("git", "url", "path", "editable", "virtual", "directory", "?", "local") and (info.get("hashes") or info.get("urls") or lk.kind == "poetry.lock"):
                ev.append(Evidence(canonicalize_name(dep), E2, 1, reg, info.get("registry_url"), lk.file, 0,
                                   f"{lk.kind}: {dep}=={info.get('version')} from {reg}", confidence="high",
                                   note="applies only when this exact lockfile is enforced for its scope",
                                   contract_kind="lock", enforceable=True, scope=_scope(lk.file),
                                   conditions={"lock_file": lk.file, "lock_kind": lk.kind}, expected=dict(info)))
    # E3: CI / Dockerfile install contexts declare indexes for the install of requirement files / project
    for ip in ir.install_paths:
        if ip.kind not in ("ci", "dockerfile", "script", "makefile", "tox", "conda-env", "noxfile"): continue
        idxs = ([ip.index_url] if ip.index_url else []) + list(ip.extra_index_urls)
        idxs = [u for u in idxs if u and u.startswith("http")]
        if not idxs: continue
        for pkg in ip.packages:
            import re
            m = re.match(r"^([A-Za-z0-9][A-Za-z0-9._-]*)", pkg)
            if not m: continue
            for u in idxs:
                ev.append(Evidence(canonicalize_name(m.group(1)), E3, 2, registry_id(u), u, ip.file, ip.line, ip.command[:200], confidence="medium",
                                   note=("primary" if u == ip.index_url else "extra") + f" index in {ip.kind} install path {ip.id}"))
        if ip.req_files or ip.editable_local or ip.uv_sync:
            for u in idxs:
                ev.append(Evidence("*", E3, 2, registry_id(u), u, ip.file, ip.line, ip.command[:200], confidence="medium",
                                   note=("primary" if u == ip.index_url else "extra") + f" index for whole-project install in {ip.kind} path {ip.id}"))
    # E5: historical: project-level configured indexes (pip.conf / pyproject) indicate which registries are *expected* to participate
    for ix in ir.indexes:
        if ix.scope != "project" and not ix.scope.startswith("reqfile:"): continue
        ev.append(Evidence("*", E5, 3, ix.rid, ix.url, ix.file, ix.line, f"{ix.kind}{'(' + ix.name + ')' if ix.name else ''} = {ix.url}", confidence="medium",
                           note=f"configured index kind={ix.kind} explicit={ix.explicit} default={ix.default} priority={ix.priority}"))
    # The legacy frontend could collapse source alternatives at the same line.
    # Recovery above expands them again; remove only genuinely identical evidence.
    import json
    unique = {}
    for item in ev:
        unique.setdefault(json.dumps(item.to_dict(), sort_keys=True, default=str), item)
    return list(unique.values())
