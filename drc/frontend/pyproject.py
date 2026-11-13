"""pyproject.toml parser: PEP 621 / PEP 735, tool.uv, tool.poetry, tool.pdm."""
from __future__ import annotations
import re, tomllib, pathlib
from typing import Optional
from ..model import Dependency, IndexSpec, SourceBinding

def _line_of(text: str, pattern: str, default: int = 0) -> int:
    for i, l in enumerate(text.splitlines(), 1):
        if re.search(pattern, l): return i
    return default

def poetry_spec_to_pep508(name: str, spec) -> str:
    """Convert a Poetry dependency spec (string or table) into a PEP 508 string."""
    extras = ""; markers = ""; version = ""
    if isinstance(spec, dict):
        version = spec.get("version", "") or ""
        if spec.get("extras"): extras = "[" + ",".join(spec["extras"]) + "]"
        mk = []
        if spec.get("markers"): mk.append(spec["markers"])
        if spec.get("python"): mk.append(_python_constraint_to_marker(spec["python"]))
        if spec.get("platform"): mk.append(f'sys_platform == "{spec["platform"]}"')
        markers = " and ".join(m for m in mk if m)
        if spec.get("git") or spec.get("url") or spec.get("path"):
            return f"{name}{extras}"  # non-registry dependency; caller handles
    elif isinstance(spec, str):
        version = spec
    ver = _poetry_version_to_pep440(version)
    s = f"{name}{extras}{ver}"
    if markers: s += f" ; {markers}"
    return s

def _python_constraint_to_marker(c: str) -> str:
    parts = [p.strip() for p in c.split(",") if p.strip()]
    out = []
    for p in parts:
        conv = _poetry_version_to_pep440(p)
        for spec in [x for x in conv.split(",") if x]:
            m = re.match(r"^(==|!=|<=|>=|<|>|~=)(.+)$", spec)
            if m: out.append(f'python_version {m.group(1)} "{m.group(2).replace(".*", "")}"')
    return " and ".join(out)

def _poetry_version_to_pep440(v: str) -> str:
    v = (v or "").strip()
    if not v or v == "*": return ""
    out = []
    for part in [p.strip() for p in v.split(",") if p.strip()]:
        if part.startswith("^"):
            base = part[1:]; nums = [int(x) if x.isdigit() else 0 for x in re.sub(r"[^0-9.]", "", base).split(".") if x != ""]
            while len(nums) < 3: nums.append(0)
            if nums[0] != 0: up = f"{nums[0]+1}.0.0"
            elif nums[1] != 0: up = f"0.{nums[1]+1}.0"
            else: up = f"0.0.{nums[2]+1}"
            out.append(f">={base},<{up}")
        elif part.startswith("~") and not part.startswith("~="):
            base = part[1:]; nums = base.split(".")
            if len(nums) == 1: up = f"{int(nums[0])+1}"
            else: up = f"{nums[0]}.{int(re.sub(r'[^0-9]', '', nums[1]) or 0)+1}"
            out.append(f">={base},<{up}")
        elif re.match(r"^[0-9][0-9.]*\*$", part) or re.match(r"^[0-9][0-9.]*\.\*$", part):
            out.append(f"=={part}")
        elif re.match(r"^[0-9]", part):
            out.append(f"=={part}")
        else:
            out.append(part.replace(" ", ""))
    return ",".join(out)

def parse_pyproject(path: pathlib.Path, root: pathlib.Path):
    rel = str(path.relative_to(root)).replace("\\", "/")
    text = path.read_text(encoding="utf-8", errors="replace")
    try:
        data = tomllib.loads(text)
    except tomllib.TOMLDecodeError as e:
        return {"error": f"toml: {e}", "deps": [], "indexes": [], "bindings": [], "tools": [], "file": rel}
    deps, indexes, bindings, tools = [], [], [], []
    uv_strategy = None; requires_python = None; poetry_python = None
    proj = data.get("project", {}) or {}
    if proj:
        tools.append("pep621")
        requires_python = proj.get("requires-python")
        for d in proj.get("dependencies", []) or []:
            deps.append(_pep508(d, rel, text, "runtime", "pep621"))
        for extra, lst in (proj.get("optional-dependencies", {}) or {}).items():
            for d in lst or []: deps.append(_pep508(d, rel, text, f"optional:{extra}", "pep621"))
    for grp, lst in (data.get("dependency-groups", {}) or {}).items():
        for d in lst or []:
            if isinstance(d, str): deps.append(_pep508(d, rel, text, f"group:{grp}", "pep735"))
    for d in (data.get("build-system", {}) or {}).get("requires", []) or []:
        deps.append(_pep508(d, rel, text, "build", "build-system"))
    tool = data.get("tool", {}) or {}
    # ---------------- uv
    uv = tool.get("uv")
    if uv is not None:
        tools.append("uv")
        uv_strategy = uv.get("index-strategy")
        if uv.get("index-url"): indexes.append(IndexSpec(url=uv["index-url"], kind="index-url", name="uv:index-url", file=rel, line=_line_of(text, r"^\s*index-url\s*=")))
        for u in _aslist(uv.get("extra-index-url")): indexes.append(IndexSpec(url=u, kind="extra-index-url", file=rel, line=_line_of(text, r"^\s*extra-index-url\s*=")))
        for u in _aslist(uv.get("find-links")): indexes.append(IndexSpec(url=u, kind="find-links", file=rel, line=_line_of(text, r"^\s*find-links\s*=")))
        named = {}
        for idx in uv.get("index", []) or []:
            if not isinstance(idx, dict) or not idx.get("url"): continue
            spec = IndexSpec(url=idx["url"], kind="uv-index", name=idx.get("name"), explicit=bool(idx.get("explicit")), default=bool(idx.get("default")),
                             file=rel, line=_line_of(text, re.escape(idx["url"])))
            indexes.append(spec)
            if idx.get("name"): named[idx["name"]] = idx["url"]
        for dep, src in (uv.get("sources", {}) or {}).items():
            for s in (src if isinstance(src, list) else [src]):
                if not isinstance(s, dict): continue
                if "index" in s:
                    bindings.append(SourceBinding(dep=_canon(dep), index_url=named.get(s["index"]), index_name=s["index"], tool="uv", file=rel,
                                                  line=_line_of(text, rf"^\s*\"?{re.escape(dep)}\"?\s*="), detail=("marker=" + s["marker"]) if s.get("marker") else "",
                                                  marker=s.get("marker"), extra=s.get("extra"), group=s.get("group"),
                                                  scope=str(pathlib.PurePosixPath(rel).parent), conditions_known=True))
                elif "url" in s or "git" in s or "path" in s or "workspace" in s:
                    bindings.append(SourceBinding(dep=_canon(dep), index_url=s.get("url") or s.get("git"), index_name=None, tool="uv", file=rel,
                                                  line=_line_of(text, rf"^\s*\"?{re.escape(dep)}\"?\s*="), detail="direct:" + ("url" if "url" in s else "git" if "git" in s else "path" if "path" in s else "workspace"),
                                                  marker=s.get("marker"), extra=s.get("extra"), group=s.get("group"),
                                                  scope=str(pathlib.PurePosixPath(rel).parent), conditions_known=True))
        for d in uv.get("dev-dependencies", []) or []: deps.append(_pep508(d, rel, text, "dev", "uv"))
        for d in uv.get("constraint-dependencies", []) or []: deps.append(_pep508(d, rel, text, "constraint", "uv"))
    # ---------------- poetry
    po = tool.get("poetry")
    if po is not None:
        tools.append("poetry")
        srcs = {}
        for s in po.get("source", []) or []:
            if not isinstance(s, dict) or not s.get("url"):
                if isinstance(s, dict) and s.get("name", "").lower() in ("pypi",): srcs[s["name"]] = "https://pypi.org/simple"
                continue
            pr = s.get("priority") or ("default" if s.get("default") else "secondary" if s.get("secondary") else "primary")
            indexes.append(IndexSpec(url=s["url"], kind="poetry-source", name=s.get("name"), explicit=(pr == "explicit"), default=(pr in ("default", "primary")),
                                     priority=pr, file=rel, line=_line_of(text, re.escape(s["url"]))))
            srcs[s.get("name")] = s["url"]
        def _po_deps(table, group):
            for name, spec in (table or {}).items():
                if name.lower() == "python":
                    nonlocal poetry_python; poetry_python = spec if isinstance(spec, str) else None; continue
                for sp in (spec if isinstance(spec, list) else [spec]):
                    pep = poetry_spec_to_pep508(name, sp)
                    url = None
                    if isinstance(sp, dict):
                        url = sp.get("git") or sp.get("url") or sp.get("path")
                        if sp.get("source"):
                            bindings.append(SourceBinding(dep=_canon(name), index_url=srcs.get(sp["source"]), index_name=sp["source"], tool="poetry", file=rel,
                                                          line=_line_of(text, rf"^\s*\"?{re.escape(name)}\"?\s*=")))
                    deps.append(Dependency(name=name, spec=pep, file=rel, line=_line_of(text, rf"^\s*\"?{re.escape(name)}\"?\s*="), group=group, url=url, tool="poetry"))
        _po_deps(po.get("dependencies"), "runtime")
        _po_deps(po.get("dev-dependencies"), "dev")
        for g, gd in (po.get("group", {}) or {}).items(): _po_deps((gd or {}).get("dependencies"), f"group:{g}")
    # ---------------- pdm
    pdm = tool.get("pdm")
    if pdm is not None:
        tools.append("pdm")
        for s in pdm.get("source", []) or []:
            if not isinstance(s, dict) or not s.get("url"): continue
            indexes.append(IndexSpec(url=s["url"], kind="pdm-source", name=s.get("name"), file=rel, line=_line_of(text, re.escape(s["url"])), priority=s.get("type")))
            for pkg in s.get("include_packages", []) or []:
                bindings.append(SourceBinding(dep=_canon(pkg), index_url=s["url"], index_name=s.get("name"), tool="pdm", file=rel, line=_line_of(text, re.escape(s["url"])), detail="include_packages"))
        for g, lst in (pdm.get("dev-dependencies", {}) or {}).items():
            for d in lst or []: deps.append(_pep508(d, rel, text, f"dev:{g}", "pdm"))
    if tool.get("pixi"): tools.append("pixi")
    if tool.get("hatch"): tools.append("hatch")
    return {"deps": [d for d in deps if d], "indexes": indexes, "bindings": bindings, "tools": tools, "uv_index_strategy": uv_strategy,
            "requires_python": requires_python or (poetry_python and _poetry_version_to_pep440(poetry_python)), "file": rel,
            "uv_environments": (uv or {}).get("environments") if uv else None}

def _aslist(v):
    if v is None: return []
    return v if isinstance(v, list) else [v]

def _canon(n: str) -> str:
    from packaging.utils import canonicalize_name
    return canonicalize_name(re.split(r"[\[<>=!~;@ ]", n, 1)[0])

def _pep508(d: str, rel: str, text: str, group: str, tool: str) -> Optional[Dependency]:
    if not isinstance(d, str): return None
    from packaging.requirements import Requirement, InvalidRequirement
    try:
        r = Requirement(d); name = r.name; url = r.url
    except InvalidRequirement:
        m = re.match(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)", d)
        if not m: return None
        name = m.group(1); url = None
    return Dependency(name=name, spec=d, file=rel, line=_line_of(text, re.escape(d.split(";")[0].strip()[:40])), group=group, url=url, tool=tool)
