"""Phase 4/5: Resolution Test Obligations -> concrete resolver contexts.

Contexts are grounded in *observed install paths* of the project (README/CI/Dockerfile/scripts) plus the
declared configuration; synthetic perturbations (index visibility, strategy, primary/extra swap, binding bypass)
are derived from the factors present in the project. Each context records which install path / factor produced it.
"""
from __future__ import annotations
import re, pathlib, hashlib
import json, posixpath
from dataclasses import dataclass, field, asdict
from typing import Optional
from packaging.requirements import Requirement, InvalidRequirement
from packaging.utils import canonicalize_name
from packaging.markers import Marker, default_environment
from ..model import ProjectIR, Context, InstallPath, registry_id, registry_family, PYPI
from ..frontend import requirements as req_mod

DEFAULT_PLATFORM = "linux-x86_64"
DEFAULT_PY = "3.12"
MAX_REQS_PER_SET = 120

@dataclass
class ReqSet:
    """A concrete set of requirement strings the project installs somewhere."""
    id: str
    requirements: list
    origin: str                    # e.g. 'pyproject:runtime', 'reqfile:requirements.txt', 'install-path:<id>'
    constraints: list = field(default_factory=list)
    scope: str = "."
    project_file: str = ""
    project_extras: list = field(default_factory=list)
    indexes: list = field(default_factory=list)
    flags: dict = field(default_factory=dict)
    limitations: list = field(default_factory=list)
    request_complete: bool = True
    def key(self):
        payload = [sorted(self.requirements), sorted(self.constraints), self.origin, self.scope, self.project_extras]
        return hashlib.sha1(json.dumps(payload, sort_keys=True).encode()).hexdigest()[:10]

@dataclass
class RTO:
    """Resolution Test Obligation: which requirement set, which factor(s), which contexts, which packages are of interest."""
    id: str
    reqset: ReqSet
    factor: str
    contexts: list                 # [Context]
    focus: list = field(default_factory=list)   # packages of interest (canonical names)
    evidence_refs: list = field(default_factory=list)
    def to_dict(self):
        return {"id": self.id, "reqset": {**asdict(self.reqset), "n": len(self.reqset.requirements)},
                "factor": self.factor, "contexts": [c.to_dict() for c in self.contexts], "focus": self.focus, "evidence_refs": self.evidence_refs}

# ----------------------------------------------------------------------------- requirement sets
def _clean_req(s: str) -> Optional[str]:
    s = s.strip()
    if not s or s.startswith(("-", "#")): return None
    if re.match(r"^(https?://|git\+|file:|\.|/|[A-Za-z]:\\)", s): return None
    if "$" in s or "__SUBST__" in s: return None
    s = s.split(" --hash")[0].split(" \\")[0].strip()
    try:
        r = Requirement(s)
        if r.url: return None
        return str(r)
    except InvalidRequirement:
        return None

def requirement_sets(ir: ProjectIR, root: pathlib.Path, project_name: Optional[str] = None) -> list[ReqSet]:
    sets: dict[str, ReqSet] = {}
    def add(rs: ReqSet):
        if not rs.requirements and not rs.origin.startswith("install-path:"): return
        # Budget whole contexts, never silently remove requirements from a request.
        rs.requirements = sorted(set(rs.requirements))
        k = rs.key()
        if k not in sets: sets[k] = rs
        else: sets[k].origin += " | " + rs.origin
    # declared runtime deps (pyproject / setup / Pipfile)
    metadata_files = sorted({d.file for d in ir.dependencies if d.tool in ("pep621", "poetry", "pipenv", "setup.cfg", "setup.py", "pdm")})
    for metadata_file in metadata_files:
        scoped = [d for d in ir.dependencies if d.file == metadata_file]
        runtime_deps = [d for d in scoped if d.group == "runtime"]
        runtime = [_clean_req(d.spec) for d in runtime_deps]
        dropped = [d.spec for d, r in zip(runtime_deps, runtime) if not r]
        runtime = [r for r in runtime if r]
        scope = str(pathlib.PurePosixPath(metadata_file).parent)
        suffix = "" if scope == "." else "-" + hashlib.sha1(metadata_file.encode()).hexdigest()[:7]
        limits = [f"unsupported project dependency: {r}" for r in dropped]
        if metadata_file.endswith("setup.py"): limits.append("dynamic setup.py metadata is not replayed")
        if runtime:
            add(ReqSet("declared-runtime" + suffix, runtime, "pyproject:runtime:" + metadata_file,
                       scope=scope, project_file=metadata_file, limitations=limits, request_complete=not dropped))
        for grp in sorted({d.group for d in scoped if d.group.startswith("optional:")}):
            extra = grp.split(":", 1)[1]
            raw = [d.spec for d in scoped if d.group == grp]
            parsed = [_clean_req(r) for r in raw]
            extra_limits = limits + [f"unsupported extra dependency: {r}" for r, p in zip(raw, parsed) if not p]
            if parsed:
                add(ReqSet(f"declared-extra-{extra}{suffix}", runtime + [p for p in parsed if p],
                           f"pyproject:optional:{extra}:{metadata_file}", scope=scope, project_file=metadata_file,
                           project_extras=[extra], limitations=extra_limits, request_complete=not extra_limits))
    # runtime + each optional extra group (only for extras referenced by install paths / all if few)
    # Development/build groups require their original tool's group semantics.
    # They are not silently combined with runtime or with another subproject.
    # each requirements file (recursively expanded)
    for f in ir.files:
        name = f.rsplit("/", 1)[-1].lower()
        if re.match(r"^(requirements|reqs?|constraints?)([-_.a-z0-9]*)\.(txt|in|pip)$", name) or (f.lower().startswith("requirements/") and name.endswith((".txt", ".in"))):
            p = root / f
            if not p.is_file(): continue
            r = req_mod.parse_requirements_file(p, root)
            lst = [_clean_req(d.spec) for d in r["deps"] if not d.url and not d.editable]; lst = [x for x in lst if x]
            limits = list(r.get("limitations", []))
            if len(lst) != len(r["deps"]): limits.append("some requirement entries could not be represented")
            if any(d.hashes for d in r["deps"]): limits.append("hash requirements require original-file replay")
            parsed_constraints = [_clean_req(x) for x in r.get("constraints", [])]
            if any(x is None for x in parsed_constraints): limits.append("some constraints could not be represented")
            if lst and "constraint" not in name:
                add(ReqSet(f"reqfile-{re.sub(r'[^A-Za-z0-9]+', '-', f)}", lst, f"reqfile:{f}",
                           constraints=[c for c in parsed_constraints if c],
                           scope=str(pathlib.PurePosixPath(f).parent), indexes=r["indexes"], flags=r["flags"],
                           limitations=limits, request_complete=not limits))
    # A single invocation is a single request. Splitting literal arguments,
    # -r files, and a local project creates requests the project never made.
    for ip in ir.install_paths:
        add(_install_request(ip, ir, root))
    return list(sets.values())


def _install_request(ip: InstallPath, ir: ProjectIR, root: pathlib.Path) -> ReqSet:
    """Preserve the full static request and identify every unrepresented part."""
    flags = {key: getattr(ip, key) for key in ("no_index", "pre", "no_deps", "require_hashes", "only_binary")}
    rs = ReqSet(f"ip-{re.sub(r'[^A-Za-z0-9]+', '-', ip.id)}", [], f"install-path:{ip.id}",
                scope=ip.working_directory or ".", project_extras=sorted(set(ip.extras_of_project)), flags=flags)
    if ip.working_directory is None:
        rs.limitations.append("invocation working directory is unknown")

    def append_requirements(raw, destination, label):
        for spec in raw:
            parsed = _clean_req(spec)
            if parsed:
                destination.append(parsed)
            else:
                rs.limitations.append(f"unsupported {label}: {spec}")

    append_requirements(ip.packages, rs.requirements, "explicit requirement")
    for constraint, references in ((False, ip.req_files), (True, ip.constraint_files)):
        for ref in references:
            if ip.working_directory is None or not ref or "$" in ref or re.match(r"^https?://", ref):
                rs.limitations.append(f"unresolved request file: {ref}")
                continue
            parsed = req_mod.parse_requirements_file(root / ip.working_directory / ref, root)
            target = rs.constraints if constraint else rs.requirements
            append_requirements([dep.spec for dep in parsed["deps"]], target, "file requirement")
            append_requirements(parsed.get("constraints", []), rs.constraints, "constraint")
            rs.indexes.extend(parsed["indexes"])
            rs.limitations.extend(parsed.get("limitations", []))
            if any(dep.url or dep.editable or dep.hashes for dep in parsed["deps"]):
                rs.limitations.append(f"direct, editable, or hashed entries require original-file replay: {ref}")
            for key, value in parsed.get("flags", {}).items():
                if value:
                    rs.flags[key] = value

    if ip.editable_local or ip.uv_sync:
        _append_project_request(rs, ip, ir, root)
    file_primaries = {index.url for index in rs.indexes if index.kind == "index-url"}
    if ip.index_url and any(url != ip.index_url for url in file_primaries):
        rs.limitations.append("command and requirement-file primary indexes require original ordered replay")
    rs.requirements = sorted(set(rs.requirements))
    rs.constraints = sorted(set(rs.constraints))
    rs.limitations = list(dict.fromkeys(rs.limitations))
    rs.request_complete = not rs.limitations
    return rs


def _append_project_request(rs: ReqSet, ip: InstallPath, ir: ProjectIR, root: pathlib.Path):
    metadata = [name for name in ir.files if pathlib.PurePosixPath(name).name in ("pyproject.toml", "setup.cfg", "setup.py")
                and str(pathlib.PurePosixPath(name).parent) == rs.scope]
    metadata.sort(key=lambda name: (0 if name.endswith("pyproject.toml") else 1 if name.endswith("setup.cfg") else 2, name))
    if not metadata:
        rs.limitations.append("local project metadata could not be identified")
        return
    rs.project_file = metadata[0]
    deps = [dep for dep in ir.dependencies if dep.file == rs.project_file]
    extras = {dep.group.split(":", 1)[1] for dep in deps if dep.group.startswith("optional:")}
    if rs.project_file.endswith("pyproject.toml"):
        import tomllib
        try:
            data = tomllib.loads((root / rs.project_file).read_text(encoding="utf-8"))
            extras.update((data.get("project", {}).get("optional-dependencies") or {}).keys())
            if data.get("project", {}).get("dynamic"):
                rs.limitations.append("dynamic project metadata requires original-project replay")
            uv = data.get("tool", {}).get("uv", {})
            if ip.uv_sync:
                for key in ("override-dependencies", "workspace", "default-groups", "dev-dependencies", "environments", "required-environments"):
                    if uv.get(key):
                        rs.limitations.append(f"uv {key} requires original-project replay: {uv[key]}")
                if "dependency-groups" in data and "--no-dev" not in ip.group_flags:
                    rs.limitations.append("project dependency groups require original-project replay")
        except (OSError, ValueError):
            rs.limitations.append("project metadata could not be read")
    if "--all-extras" in ip.group_flags:
        rs.project_extras = sorted(extras)
    missing = set(rs.project_extras) - extras
    if missing:
        rs.limitations.append("unknown requested project extras: " + ", ".join(sorted(missing)))
    groups = {"runtime"} | {"optional:" + extra for extra in rs.project_extras}
    for dep in deps:
        if dep.group not in groups and not (ip.tool == "uv" and dep.group == "constraint"):
            continue
        parsed = _clean_req(dep.spec)
        if not parsed or dep.url or dep.editable:
            rs.limitations.append(f"unsupported project requirement: {dep.spec}")
        elif dep.group == "constraint":
            rs.constraints.append(parsed)
        else:
            rs.requirements.append(parsed)
    if rs.project_file.endswith("setup.py"):
        rs.limitations.append("dynamic setup.py metadata is not replayed")

# ----------------------------------------------------------------------------- index configuration of the project
def project_index_config(ir: ProjectIR, scope=".", reqset=None, marker_environment=None, tool="uv") -> dict:
    """Summarise project-level index configuration (pyproject/uv.toml/pip.conf/requirements option lines)."""
    primary = None; extras = []; find_links = []; named = []; explicit = {}; limitations = []
    active_indexes = list(getattr(reqset, "indexes", []))
    for ix in ir.indexes:
        if str(pathlib.PurePosixPath(ix.file).parent) != scope: continue
        if ix.scope.startswith(("install-path:", "reqfile:")): continue
        if tool == "pip": continue  # pip does not automatically load repository-local pip.conf or tool.uv configuration
        if pathlib.PurePosixPath(ix.file).name not in ("pyproject.toml", "uv.toml"): continue
        if ix.kind == "poetry-source" or ix.kind == "pdm-source": continue
        active_indexes.append(ix)
    for ix in active_indexes:
        if not ix.url.startswith("http"):
            limitations.append(f"unsupported index location: {ix.url}")
            continue
        if ix.scope.startswith("install-path:"): continue
        if ix.kind in ("index-url", "uv-default-index") or (ix.kind == "uv-index" and ix.default) or (ix.kind == "poetry-source" and ix.priority in ("default", "primary") and ix.rid != PYPI and primary is None):
            if primary is None: primary = ix.url
            elif ix.url != primary:
                limitations.append("multiple primary index options require ordered replay")
                primary = ix.url
        elif ix.kind in ("extra-index-url", "poetry-source", "pdm-source", "pipenv-source"):
            if ix.rid != PYPI: extras.append(ix.url)
        elif ix.kind == "find-links": find_links.append(ix.url)
        if ix.kind == "uv-index":
            named.append({"name": ix.name or ix.rid, "url": ix.url, "explicit": ix.explicit, "default": ix.default})
        if ix.explicit and ix.name: explicit[ix.name] = ix.url
    extras = list(dict.fromkeys(u for u in extras if u != primary))
    sources = {}; ambiguous_sources = set()
    for b in ir.bindings:
        if tool != "uv" or b.tool != "uv" or str(pathlib.PurePosixPath(b.file).parent) != scope: continue
        if not b.conditions_known:
            limitations.append(f"unknown source conditions: {b.dep} ({b.file}:{b.line})"); continue
        if b.extra and b.extra not in (getattr(reqset, "project_extras", None) or []): continue
        if b.group:
            limitations.append(f"dependency-group source not modeled: {b.dep}"); continue
        if b.marker:
            if not marker_environment:
                limitations.append(f"unknown marker environment: {b.dep}"); continue
            from ..contracts import _marker_applies
            applies, reason = _marker_applies(b.marker, {"marker_environment": marker_environment,
                            "project_extras": getattr(reqset, "project_extras", None),
                            "python_version": marker_environment.get("python_version", "")})
            if applies is None:
                limitations.append(f"unresolved source marker: {b.dep}: {reason}"); continue
            if applies is False: continue
        if not b.index_url or not b.index_url.startswith("http") or b.detail.startswith("direct:"):
            limitations.append(f"unsupported source binding: {b.dep}"); continue
        if b.dep in ambiguous_sources:
            continue
        if b.dep in sources and sources[b.dep] != b.index_url:
            limitations.append(f"multiple active sources for {b.dep}"); sources.pop(b.dep, None)
            ambiguous_sources.add(b.dep)
            continue
        sources[b.dep] = b.index_url
    strategy = None
    if tool == "uv":
        import tomllib
        for filename in ("pyproject.toml", "uv.toml"):
            path = pathlib.Path(ir.root) / scope / filename
            if not path.is_file():
                continue
            try:
                data = tomllib.loads(path.read_text(encoding="utf-8"))
                config = data if filename == "uv.toml" else data.get("tool", {}).get("uv", {})
                strategy = config.get("index-strategy", strategy)
            except (OSError, ValueError):
                limitations.append(f"unreadable scoped uv configuration: {path.name}")
    return {"primary": primary, "extras": extras, "find_links": find_links, "named": named, "sources": sources, "explicit": explicit, "uv_strategy": strategy, "limitations": limitations}

# ----------------------------------------------------------------------------- context generation
def _ctx(id_, resolver, reqs, *, index_url=None, extras=(), find_links=(), strategy=None, sources=None, named=None, pre=False, derived="synthetic", factors=None, desc="", constraints=(), **metadata):
    named_list = []
    seen_names = set(); seen_urls = set()
    for n in (named or []):
        nm = n["name"] or "idx"; base = nm; k = 2
        if n["url"] in seen_urls: continue
        while nm in seen_names: nm = f"{base}-{k}"; k += 1
        seen_names.add(nm); seen_urls.add(n["url"])
        named_list.append({"name": nm, "url": n["url"], "explicit": n.get("explicit", False), "default": n.get("default", False)})
    src = {}
    if sources:
        # map source urls to names in named_list (create entries if needed)
        for dep, url in sources.items():
            nm = next((n["name"] for n in named_list if n["url"] == url), None)
            if nm is None:
                nm = "src-" + re.sub(r"[^A-Za-z0-9]+", "-", registry_id(url))[:30]
                named_list.append({"name": nm, "url": url, "explicit": True, "default": False})
            src[dep] = nm
    return Context(id=id_, resolver=resolver, requirements=list(reqs), index_url=index_url, extra_index_urls=list(extras), find_links=list(find_links),
                   pre=pre, index_strategy=strategy, sources=src, named_indexes=named_list, constraints=list(constraints), platform=DEFAULT_PLATFORM,
                   python_version=DEFAULT_PY, derived_from=derived, factors=factors or {}, description=desc, **metadata)

def choose_python(ir: ProjectIR) -> str:
    """Target CPython for resolution: prefer 3.11 (widest wheel coverage 2023-2026), honour requires-python, else 3.12 / 3.10."""
    from packaging.specifiers import SpecifierSet, InvalidSpecifier
    from packaging.version import Version
    spec = None
    if ir.requires_python:
        try: spec = SpecifierSet(ir.requires_python.replace("~=", ">=") if ir.requires_python.startswith("~=") else ir.requires_python)
        except InvalidSpecifier: spec = None
    for v in ("3.11", "3.12", "3.10"):
        if spec is None or Version(v + ".0") in spec or spec.contains(v + ".9", prereleases=True): return v
    return "3.11"

def target_environment(python_version: str, platform: str = DEFAULT_PLATFORM) -> dict:
    """Known target facts only; never inherit the machine running the parser."""
    windows = platform.startswith("windows")
    macos = platform.startswith("macos")
    return {"python_version": python_version, "implementation_name": "cpython",
            "platform_python_implementation": "CPython", "sys_platform": "win32" if windows else "darwin" if macos else "linux",
            "os_name": "nt" if windows else "posix", "platform_system": "Windows" if windows else "Darwin" if macos else "Linux",
            "platform_machine": "AMD64" if windows else "arm64" if platform.endswith("arm64") else "aarch64" if platform.endswith("aarch64") else "x86_64",
            "extra": ""}

def generate_rtos(ir: ProjectIR, root: pathlib.Path, budget_contexts: int = 14, include_plain_declared: bool = False) -> list[RTO]:
    python_version = choose_python(ir)
    marker_env = target_environment(python_version)
    reqsets = requirement_sets(ir, root)
    rtos: list[RTO] = []
    ip_index_ctxs = []
    # ---- install-path-derived contexts: every install path with indexes, applied to the requirement set it installs
    for ip in ir.install_paths:
        idx = ip.index_url if ip.index_url and ip.index_url.startswith("http") else None
        ex = [u for u in ip.extra_index_urls if u.startswith("http")]
        targets = [rs for rs in reqsets if rs.origin == f"install-path:{ip.id}"]
        for rs in targets:
            ip_index_ctxs.append((ip, rs, idx, ex))
    # ---- for each requirement set build the context family
    for rs in reqsets:
        cfg = project_index_config(ir, rs.scope, rs, marker_env, tool="uv")
        pip_cfg = project_index_config(ir, rs.scope, rs, marker_env, tool="pip")
        custom = [u for u in ([cfg["primary"]] if cfg["primary"] and registry_id(cfg["primary"]) != PYPI else []) + cfg["extras"] + [n["url"] for n in cfg["named"]] if u]
        rs_ips = [(ip, idx, ex) for (ip, r2, idx, ex) in ip_index_ctxs if r2.id == rs.id]
        # custom indexes relevant to this requirement set: project-level + those used by install paths that install it
        custom_rs = list(dict.fromkeys(custom + [u for (_, idx, ex) in rs_ips for u in ([idx] if idx else []) + list(ex) if registry_id(u) != PYPI]))
        has_custom = bool(custom_rs) or bool(cfg["sources"])
        if not has_custom and not rs_ips and not include_plain_declared:
            continue
        n = 0
        fam: list[tuple[str, Context]] = []
        # C0 declared (as the project configures it) — pip semantics and uv semantics
        decl_primary = cfg["primary"]; decl_extras = cfg["extras"]
        fam.append(("F0-declared", _ctx(f"{rs.id}|pip|declared", "pip", rs.requirements, index_url=pip_cfg["primary"], extras=pip_cfg["extras"], find_links=pip_cfg["find_links"], derived="declared",
                                        factors={"resolver": "pip", "indexes": "declared"}, desc="pip projection of scoped dependency configuration; no original pip invocation asserted", constraints=rs.constraints)))
        fam.append(("F0-declared", _ctx(f"{rs.id}|uv|declared", "uv", rs.requirements, index_url=decl_primary, extras=decl_extras, find_links=cfg["find_links"], strategy=cfg["uv_strategy"],
                                        sources=cfg["sources"], named=cfg["named"], derived="declared", factors={"resolver": "uv", "indexes": "declared", "sources": "on"},
                                        desc="uv projection of scoped dependency configuration; no original uv invocation asserted", constraints=rs.constraints)))
        # F1 index visibility: PyPI-only  /  custom-only  (for every custom index)
        fam.append(("F1-visibility", _ctx(f"{rs.id}|pip|pypi-only", "pip", rs.requirements, derived="synthetic:F1", factors={"resolver": "pip", "indexes": "pypi-only"}, desc="pip, PyPI only (custom indexes not visible)", constraints=rs.constraints)))
        for u in custom_rs[:3]:
            rid = registry_id(u)
            # NOTE: a "custom index only" context is deliberately NOT generated: custom indexes (PyTorch, NVIDIA, ...) do not
            # host general-purpose packages, so such a context fails for any non-trivial requirement set and is not a realistic
            # install path. Custom-only resolution appears only when an observed install path uses `--index-url <custom>` alone.
            # F2 priority: custom as primary + PyPI extra  vs  PyPI primary + custom extra  (pip: version priority => identical sets, but tie-breaking differs)
            fam.append(("F2-priority", _ctx(f"{rs.id}|pip|primary-{_slug(rid)}+pypi", "pip", rs.requirements, index_url=u, extras=["https://pypi.org/simple"], derived="synthetic:F2", factors={"resolver": "pip", "indexes": f"primary:{rid}+pypi"}, desc=f"pip, {rid} primary + PyPI extra", constraints=rs.constraints)))
            fam.append(("F2-priority", _ctx(f"{rs.id}|pip|pypi+extra-{_slug(rid)}", "pip", rs.requirements, extras=[u], derived="synthetic:F2", factors={"resolver": "pip", "indexes": f"pypi+extra:{rid}"}, desc=f"pip, PyPI primary + {rid} extra", constraints=rs.constraints)))
            # F3 resolver strategy (uv): first-index vs unsafe-best-match with the same two indexes
            fam.append(("F3-strategy", _ctx(f"{rs.id}|uv|first-index-{_slug(rid)}", "uv", rs.requirements, extras=[u], strategy="first-index", derived="synthetic:F3", factors={"resolver": "uv", "indexes": f"pypi+extra:{rid}", "strategy": "first-index"}, desc=f"uv first-index, {rid} + PyPI", constraints=rs.constraints)))
            fam.append(("F3-strategy", _ctx(f"{rs.id}|uv|best-match-{_slug(rid)}", "uv", rs.requirements, extras=[u], strategy="unsafe-best-match", derived="synthetic:F3", factors={"resolver": "uv", "indexes": f"pypi+extra:{rid}", "strategy": "unsafe-best-match"}, desc=f"uv unsafe-best-match, {rid} + PyPI", constraints=rs.constraints)))
        # F4 binding bypass: uv declared but without tool.uv.sources (e.g. `uv pip install -r requirements.txt` ignores pyproject sources)
        if cfg["sources"]:
            fam.append(("F4-binding-bypass", _ctx(f"{rs.id}|uv|no-sources", "uv", rs.requirements, index_url=decl_primary, extras=decl_extras + [u for u in dict.fromkeys(cfg["sources"].values()) if u not in decl_extras and u != decl_primary],
                                                  strategy=cfg["uv_strategy"], named=cfg["named"], derived="synthetic:F4", factors={"resolver": "uv", "indexes": "declared", "sources": "off"},
                                                  desc="uv with the same indexes but tool.uv.sources bindings bypassed (indexes all visible as extras)", constraints=rs.constraints)))
            fam.append(("F4-binding-bypass", _ctx(f"{rs.id}|pip|sources-as-extra", "pip", rs.requirements, index_url=decl_primary, extras=decl_extras + [u for u in dict.fromkeys(cfg["sources"].values()) if u not in decl_extras and u != decl_primary],
                                                  derived="synthetic:F4", factors={"resolver": "pip", "indexes": "declared+source-indexes", "sources": "n/a"},
                                                  desc="pip cannot express per-package source bindings: same indexes as extras", constraints=rs.constraints)))
        # install-path-derived contexts
        for (ip, idx, ex) in rs_ips:
            if ip.tool not in ("pip", "uv", "uv-pip"): continue
            resolver = "uv" if ip.tool in ("uv", "uv-pip") else "pip"
            path_cfg = cfg if resolver == "uv" else pip_cfg
            fam.append((f"IP-{ip.kind}", _ctx(f"{rs.id}|{resolver}|ip-{_slug(ip.id)}", resolver, rs.requirements, index_url=idx, extras=ex, strategy=ip.index_strategy if resolver == "uv" else None, pre=ip.pre,
                                              sources=path_cfg["sources"] if ip.uv_sync else None, named=path_cfg["named"] if resolver == "uv" else None,
                                              derived=f"install-path:{ip.id}", factors={"resolver": resolver, "indexes": "install-path", "path": ip.id}, desc=f"observed {ip.kind} command at {ip.file}:{ip.line}: {ip.command[:120]}", constraints=rs.constraints)))
            c = fam[-1][1]
            c.index_url = ip.default_index or idx or path_cfg["primary"]
            c.index_strategy = (ip.index_strategy or path_cfg["uv_strategy"]) if resolver == "uv" else None
            c.extra_index_urls = list(dict.fromkeys(ex + path_cfg["extras"]))
            if resolver == "uv" and ip.named_index:
                cli_indexes = []
                for index in ip.named_index:
                    if not index:
                        continue
                    name, url = index.split("=", 1) if "=" in index else ("cli-index", index)
                    if url.startswith("http"):
                        cli_indexes.append({"name": name, "url": url, "explicit": False, "default": False})
                c.named_indexes = cli_indexes + c.named_indexes
            c.find_links = list(dict.fromkeys(ip.find_links + path_cfg["find_links"]))
            c.no_index = ip.no_index or bool(rs.flags.get("no_index"))
            c.no_deps = ip.no_deps or bool(rs.flags.get("no_deps"))
            c.require_hashes = ip.require_hashes or bool(rs.flags.get("require_hashes"))
            c.only_binary = ip.only_binary or rs.flags.get("only_binary")
            c.pre = ip.pre or bool(rs.flags.get("pre"))
            c.lock_mode = ip.lock_mode
            c.limitations = list(ip.limitations)
            unsupported_groups = [flag for flag in ip.group_flags if not flag.startswith("--extra=") and flag != "--all-extras"]
            if unsupported_groups: c.limitations.append("project dependency-group flags require original-project replay: " + ", ".join(unsupported_groups))
            if ip.uv_sync or ip.editable_local: c.limitations.append("project metadata is projected; original project/lock execution is not certified")
            if resolver == "uv": c.limitations.append("uv lock projection is not certified equivalent to the original uv invocation")
            if ip.lock_mode in ("locked", "frozen"):
                lock = next((info for info in ir.locks if info.kind == "uv.lock" and str(pathlib.PurePosixPath(info.file).parent) == rs.scope), None)
                c.lock_file = lock.file if lock else ""
                if not lock: c.limitations.append("requested project lock is missing")
            c.origin = {"kind": "install-path", "id": ip.id, "file": ip.file, "line": ip.line, "command": ip.command,
                        "working_directory": ip.working_directory, "request_origin": rs.origin,
                        "command_kind": ip.command_kind, "packages": list(ip.packages), "requirement_files": list(ip.req_files),
                        "constraint_files": list(ip.constraint_files), "project_request": ip.editable_local or ip.uv_sync,
                        "environment": dict(ip.env)}
        # dedupe identical contexts, apply budget
        seen = set(); uniq = []
        for f, c in fam:
            c.python_version = python_version
            c.no_index = c.no_index or bool(rs.flags.get("no_index"))
            c.no_deps = c.no_deps or bool(rs.flags.get("no_deps"))
            c.require_hashes = c.require_hashes or bool(rs.flags.get("require_hashes"))
            c.only_binary = c.only_binary or rs.flags.get("only_binary")
            c.pre = c.pre or bool(rs.flags.get("pre"))
            c.scope = rs.scope; c.project_file = rs.project_file; c.project_extras = list(rs.project_extras)
            c.marker_environment = dict(marker_env)
            c.source_bindings_enabled = c.resolver == "uv" and bool(c.sources)
            c.limitations += list(rs.limitations) + (cfg["limitations"] if c.resolver == "uv" else pip_cfg["limitations"])
            selected_cfg = cfg if c.resolver == "uv" else pip_cfg
            request_errors = ("unresolved", "missing value", "unsupported install option", "unparsed requirement", "unparsed install")
            c.request_complete = rs.request_complete and not selected_cfg["limitations"] and not any(
                error in limitation.lower() for error in request_errors for limitation in c.limitations)
            if not c.origin:
                c.origin = {"kind": "configuration-projection" if c.derived_from == "declared" else "synthetic",
                            "request_origin": rs.origin, "project_file": rs.project_file, "scope": rs.scope}
            if c.derived_from == "declared":
                c.no_index = bool(rs.flags.get("no_index")); c.no_deps = bool(rs.flags.get("no_deps"))
                c.require_hashes = bool(rs.flags.get("require_hashes")); c.only_binary = rs.flags.get("only_binary")
                c.pre = bool(rs.flags.get("pre"))
                if rs.project_file:
                    c.limitations.append("configuration projection does not certify an original installation path")
                    chosen_cfg = cfg if c.resolver == "uv" else pip_cfg
                    c.request_complete = rs.request_complete and not chosen_cfg["limitations"] and not rs.limitations
            c.faithfulness = "verified" if c.derived_from.startswith("install-path:") and c.request_complete and not c.limitations else "projected" if c.request_complete else "unverified"
            c.limitations = list(dict.fromkeys(c.limitations))
            k = (c.resolver, c.index_url, tuple(c.extra_index_urls), c.index_strategy, tuple(sorted(c.sources.items())), c.pre,
                 c.derived_from, c.no_index, c.no_deps, c.require_hashes, c.only_binary, tuple(c.constraints))
            if k in seen: continue
            seen.add(k); uniq.append((f, c))
        uniq.sort(key=lambda item: not item[1].derived_from.startswith("install-path:"))
        uniq = uniq[:budget_contexts]
        focus = sorted({b.dep for b in ir.bindings} | {canonicalize_name(re.split(r"[\[<>=!~; ]", r, 1)[0]) for r in rs.requirements if re.split(r"[\[<>=!~; ]", r, 1)[0]})
        rtos.append(RTO(id=f"rto-{rs.id}", reqset=rs, factor=",".join(sorted({f for f, _ in uniq})), contexts=[c for _, c in uniq], focus=focus[:200]))
    return rtos

def _slug(s: str) -> str:
    return re.sub(r"[^A-Za-z0-9]+", "-", s).strip("-")[:40]
