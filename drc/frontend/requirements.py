"""requirements.txt parser (pip requirement file format)."""
from __future__ import annotations
import re, shlex, pathlib
from typing import Optional
from packaging.requirements import Requirement, InvalidRequirement

from ..model import Dependency, IndexSpec

_OPT_WITH_VALUE = {"-r", "--requirement", "-c", "--constraint", "-i", "--index-url", "--extra-index-url",
                   "-f", "--find-links", "--only-binary", "--no-binary", "--prefer-binary", "--trusted-host",
                   "--use-feature", "--hash", "-e", "--editable", "--config-settings", "--global-option"}
_FLAGS = {"--no-index", "--pre", "--require-hashes", "--no-deps", "--prefer-binary", "--no-build-isolation",
          "--use-pep517", "--no-cache-dir", "--upgrade", "-U", "--user", "--quiet", "-q"}

def _logical_lines(text: str):
    """Yield (first_line_no, logical_line) joining backslash continuations, stripping comments."""
    buf = []; start = None
    for i, raw in enumerate(text.splitlines(), 1):
        line = raw.rstrip("\r")
        if start is None: start = i
        if line.rstrip().endswith("\\"):
            buf.append(line.rstrip()[:-1]); continue
        buf.append(line)
        logical = " ".join(buf).strip(); buf = []; s = start; start = None
        # strip comments: ' #' or leading '#' (keep #egg= / #sha256= fragments in URLs)
        logical = re.sub(r"(^|\s)#.*$", "", logical).strip()
        if logical: yield s, logical
    if buf:
        logical = re.sub(r"(^|\s)#.*$", "", " ".join(buf)).strip()
        if logical: yield start, logical

def _split_req_and_opts(logical: str):
    """Split 'pkg>=1 --hash=sha256:...' into (req, {opts})."""
    # Requirement markers contain significant quoting. Only tokenize trailing
    # pip options; shlex over the entire line silently removes marker quotes.
    parts = re.split(r"\s+(?=--[A-Za-z])", logical, maxsplit=1)
    requirement = parts[0].strip()
    try:
        toks = shlex.split(parts[1], posix=True) if len(parts) > 1 else []
    except ValueError:
        toks = parts[1].split() if len(parts) > 1 else []
    req_parts, hashes, opts = [], [], {}
    i = 0
    while i < len(toks):
        t = toks[i]
        if t.startswith("--hash"):
            v = t.split("=", 1)[1] if "=" in t else (toks[i+1] if i+1 < len(toks) else ""); hashes.append(v); i += 2 if "=" not in t else 1; continue
        if t.startswith("--"):
            if "=" in t or t in _FLAGS: opts[t.split("=")[0]] = t.split("=", 1)[1] if "=" in t else True; i += 1; continue
            opts[t] = toks[i+1] if i+1 < len(toks) else True; i += 2; continue
        req_parts.append(t); i += 1
    return requirement, hashes, opts

_NAME_RE = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)")

def parse_requirements_text(text: str, file: str, group: str = "runtime", tool: str = "requirements"):
    """Return dict(deps=[Dependency], indexes=[IndexSpec], find_links=[], refs=[(kind,path)], flags={})."""
    deps, indexes, find_links, refs = [], [], [], []
    flags = {"no_index": False, "pre": False, "require_hashes": False, "no_deps": False, "only_binary": None}
    limitations = []
    for ln, logical in _logical_lines(text):
        s = logical.strip()
        if s.startswith("-"):
            # option lines (may combine e.g. "--extra-index-url X --trusted-host Y")
            try: toks = shlex.split(s, posix=True)
            except ValueError: toks = s.split()
            i = 0
            while i < len(toks):
                t = toks[i]; val = None
                if "=" in t and t.startswith("--"): t, val = t.split("=", 1)
                elif t in _OPT_WITH_VALUE and i + 1 < len(toks): val = toks[i+1]; i += 1
                elif re.match(r"^-[ricfe]\S+$", t): t, val = t[:2], t[2:].lstrip("=")
                if t in _OPT_WITH_VALUE and val is None:
                    limitations.append(f"missing value for requirement-file option {t} at {file}:{ln}")
                if t in ("-r", "--requirement"): refs.append(("requirement", val))
                elif t in ("-c", "--constraint"): refs.append(("constraint", val))
                elif t in ("-i", "--index-url"):
                    if val: indexes.append(IndexSpec(url=val, kind="index-url", file=file, line=ln))
                elif t == "--extra-index-url":
                    if val: indexes.append(IndexSpec(url=val, kind="extra-index-url", file=file, line=ln))
                elif t in ("-f", "--find-links"):
                    if val: find_links.append(val); indexes.append(IndexSpec(url=val, kind="find-links", file=file, line=ln))
                elif t == "--no-index": flags["no_index"] = True
                elif t == "--pre": flags["pre"] = True
                elif t == "--require-hashes": flags["require_hashes"] = True
                elif t == "--no-deps": flags["no_deps"] = True
                elif t == "--only-binary": flags["only_binary"] = val
                elif t in ("-e", "--editable"):
                    if val: deps.append(Dependency(name=_guess_name(val) or val, spec=val, file=file, line=ln, group=group, editable=True, url=val, tool=tool))
                elif t.startswith("-") and t not in ("--trusted-host",):
                    limitations.append(f"unsupported requirement-file option {t} at {file}:{ln}")
                i += 1
            continue
        req_str, hashes, opts = _split_req_and_opts(s)
        if not req_str: continue
        d = _make_dep(req_str, file, ln, group, tool)
        if d:
            d.hashes = hashes; deps.append(d)
            if opts: limitations.append(f"per-requirement options require original-file replay at {file}:{ln}")
        else:
            limitations.append(f"unparsed requirement at {file}:{ln}: {req_str}")
    return {"deps": deps, "indexes": indexes, "find_links": find_links, "refs": refs, "flags": flags, "limitations": limitations}

def _guess_name(s: str) -> Optional[str]:
    m = re.search(r"[#&]egg=([A-Za-z0-9._-]+)", s)
    if m: return m.group(1)
    m = re.search(r"/([A-Za-z0-9._-]+?)(?:-[0-9][^/]*)?\.(?:whl|tar\.gz|zip)$", s)
    if m: return m.group(1)
    return None

def _make_dep(req_str: str, file: str, ln: int, group: str, tool: str) -> Optional[Dependency]:
    req_str = req_str.strip()
    if not req_str: return None
    # env var interpolation ${VAR} -> keep literal; packaging fails -> raw
    if re.match(r"^(https?|git\+|ssh|file:|\.|/|[A-Za-z]:\\)", req_str) or req_str.startswith("-"):
        name = _guess_name(req_str)
        return Dependency(name=name or req_str, spec=req_str, file=file, line=ln, group=group, url=req_str, tool=tool) if name else None
    try:
        r = Requirement(req_str)
        return Dependency(name=r.name, spec=req_str, file=file, line=ln, group=group, url=r.url, tool=tool)
    except InvalidRequirement:
        m = _NAME_RE.match(req_str)
        if m: return Dependency(name=m.group(1), spec=req_str, file=file, line=ln, group=group, tool=tool)
        return None

def parse_requirements_file(path: pathlib.Path, root: pathlib.Path, group: str = "runtime", seen=None):
    """Parse a requirements file recursively following -r / -c (within repo)."""
    seen = seen if seen is not None else set()
    root = pathlib.Path(root).resolve(); path = pathlib.Path(path).resolve()
    try:
        rel = str(path.relative_to(root)).replace("\\", "/")
    except ValueError:
        return {"deps": [], "indexes": [], "find_links": [], "refs": [], "flags": {}, "constraints": [], "limitations": ["requirement reference outside project root"]}
    if rel in seen: return {"deps": [], "indexes": [], "find_links": [], "refs": [], "flags": {}, "constraints": [], "limitations": [f"cyclic requirement reference: {rel}"]}
    seen = set(seen)
    seen.add(rel)
    try: text = path.read_text(encoding="utf-8", errors="replace")
    except OSError: return {"deps": [], "indexes": [], "find_links": [], "refs": [], "flags": {}, "constraints": [], "limitations": [f"missing requirement file: {rel}"]}
    res = parse_requirements_text("", rel, group=group)
    res["constraints"] = []
    # Expand references at their original position. In particular, uv index
    # priority depends on the order of --extra-index-url across included files.
    for line, logical in _logical_lines(text):
        entry = parse_requirements_text(logical, rel, group=group)
        for item in entry["deps"] + entry["indexes"]:
            item.line = line
        res["deps"] += entry["deps"]
        res["indexes"] += entry["indexes"]
        res["find_links"] += entry["find_links"]
        res["refs"] += entry["refs"]
        res["limitations"] += entry["limitations"]
        for key, value in entry["flags"].items():
            if value: res["flags"][key] = value
        for kind, ref in entry["refs"]:
            if not ref or "$" in ref or re.match(r"^https?://", ref):
                res["limitations"].append(f"unresolved requirement reference: {ref}"); continue
            sub = (path.parent / ref).resolve()
            try: sub.relative_to(root)
            except ValueError:
                res["limitations"].append(f"requirement reference outside project root: {ref}"); continue
            child = parse_requirements_file(sub, root, group=group, seen=seen)
            if kind == "requirement":
                res["deps"] += child["deps"]
            else:
                res["constraints"] += [dep.spec for dep in child["deps"]]
                if child["indexes"] or any(child.get("flags", {}).values()):
                    res["limitations"].append(f"constraint-file options require original ordered replay: {ref}")
            res["indexes"] += child["indexes"]
            res["find_links"] += child["find_links"]
            res["constraints"] += child.get("constraints", [])
            res["limitations"] += child.get("limitations", [])
            for key, value in child.get("flags", {}).items():
                if value: res["flags"][key] = value
    primaries = {ix.url for ix in res["indexes"] if ix.kind == "index-url"}
    if len(primaries) > 1:
        res["limitations"].append("multiple primary index options require original ordered replay")
    return res
