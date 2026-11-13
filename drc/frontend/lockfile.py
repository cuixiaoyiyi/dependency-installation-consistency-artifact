"""Lockfile parsers: uv.lock, poetry.lock, pylock.toml, Pipfile.lock (+ Pipfile sources)."""
from __future__ import annotations
import json, tomllib, pathlib, re
from packaging.utils import canonicalize_name
from ..model import LockInfo, IndexSpec, SourceBinding, registry_id

def _read(p):
    try: return p.read_text(encoding="utf-8", errors="replace")
    except OSError: return ""

def uv_lock(path: pathlib.Path, rel: str) -> LockInfo:
    li = LockInfo(kind="uv.lock", file=rel)
    try: d = tomllib.loads(_read(path))
    except tomllib.TOMLDecodeError: return li
    for p in d.get("package", []) or []:
        src = p.get("source", {}) or {}
        reg = src.get("registry")
        kind = "registry" if reg else next((k for k in ("git", "url", "path", "editable", "virtual", "directory") if k in src), "?")
        entry = {"version": p.get("version"), "registry": registry_id(reg) if reg else kind, "registry_url": reg,
                 "urls": [w.get("url") for w in p.get("wheels", []) or [] if w.get("url")],
                 "hashes": [w.get("hash") for w in p.get("wheels", []) or [] if w.get("hash")]}
        if p.get("sdist", {}).get("url"): entry["urls"].append(p["sdist"]["url"]); entry["hashes"].append(p["sdist"].get("hash"))
        li.packages[canonicalize_name(p.get("name", ""))] = entry
    return li

def poetry_lock(path: pathlib.Path, rel: str) -> LockInfo:
    li = LockInfo(kind="poetry.lock", file=rel)
    try: d = tomllib.loads(_read(path))
    except tomllib.TOMLDecodeError: return li
    for p in d.get("package", []) or []:
        src = p.get("source", {}) or {}
        url = src.get("url") if src.get("type") in ("legacy", None) and src.get("url") else None
        reg = registry_id(url) if url else ("pypi" if not src else src.get("type", "?"))
        files = p.get("files", []) or []
        li.packages[canonicalize_name(p.get("name", ""))] = {"version": p.get("version"), "registry": reg, "registry_url": url,
                                                             "files": [f.get("file") for f in files], "hashes": [f.get("hash") for f in files]}
    return li

def pylock(path: pathlib.Path, rel: str) -> LockInfo:
    li = LockInfo(kind="pylock.toml", file=rel)
    try: d = tomllib.loads(_read(path))
    except tomllib.TOMLDecodeError: return li
    for p in d.get("packages", []) or []:
        # Keep each URL aligned with its own hash, including an allowed sdist.
        archives = [w for w in p.get("wheels", []) or [] if w.get("url")]
        sdist = p.get("sdist") or {}
        if sdist.get("url"): archives.append(sdist)
        urls = [archive["url"] for archive in archives]
        idx = p.get("index")
        li.packages[canonicalize_name(p.get("name", ""))] = {"version": p.get("version"), "registry": registry_id(idx) if idx else (registry_id(urls[0]) if urls else "?"),
                                                             "registry_url": idx, "urls": urls,
                                                             "hashes": [(archive.get("hashes") or {}).get("sha256") for archive in archives]}
    return li

def pipfile_lock(path: pathlib.Path, rel: str) -> tuple[LockInfo, list, list]:
    li = LockInfo(kind="Pipfile.lock", file=rel)
    indexes, bindings = [], []
    try: d = json.loads(_read(path))
    except json.JSONDecodeError: return li, indexes, bindings
    srcs = {s.get("name"): s.get("url") for s in (d.get("_meta", {}).get("sources") or []) if isinstance(s, dict)}
    for name, url in srcs.items():
        if url: indexes.append(IndexSpec(url=url, kind="pipenv-source", name=name, file=rel, line=0))
    for sec in ("default", "develop"):
        for name, spec in (d.get(sec) or {}).items():
            if not isinstance(spec, dict): continue
            idx = spec.get("index")
            url = srcs.get(idx)
            li.packages[canonicalize_name(name)] = {"version": (spec.get("version") or "").lstrip("="), "registry": registry_id(url) if url else "pypi",
                                                    "registry_url": url, "hashes": spec.get("hashes", [])}
            if idx and url:
                bindings.append(SourceBinding(dep=canonicalize_name(name), index_url=url, index_name=idx, tool="pipenv", file=rel, line=0))
    return li, indexes, bindings

def pipfile(path: pathlib.Path, rel: str):
    """Pipfile: [[source]] + per-package index= bindings."""
    text = _read(path)
    indexes, bindings, deps = [], [], []
    try: d = tomllib.loads(text)
    except tomllib.TOMLDecodeError: return indexes, bindings, deps
    srcs = {}
    for s in d.get("source", []) or []:
        if isinstance(s, dict) and s.get("url"):
            srcs[s.get("name")] = s["url"]
            indexes.append(IndexSpec(url=s["url"], kind="pipenv-source", name=s.get("name"), file=rel, line=_line(text, s["url"])))
    from ..model import Dependency
    for sec, grp in (("packages", "runtime"), ("dev-packages", "dev")):
        for name, spec in (d.get(sec) or {}).items():
            ver = spec if isinstance(spec, str) else (spec.get("version", "") if isinstance(spec, dict) else "")
            ver = "" if ver == "*" else ver
            deps.append(Dependency(name=name, spec=f"{name}{ver}", file=rel, line=_line(text, name), group=grp, tool="pipenv"))
            if isinstance(spec, dict) and spec.get("index"):
                bindings.append(SourceBinding(dep=canonicalize_name(name), index_url=srcs.get(spec["index"]), index_name=spec["index"], tool="pipenv", file=rel, line=_line(text, name)))
    return indexes, bindings, deps

def _line(text, needle):
    for i, l in enumerate(text.splitlines(), 1):
        if needle in l: return i
    return 0
