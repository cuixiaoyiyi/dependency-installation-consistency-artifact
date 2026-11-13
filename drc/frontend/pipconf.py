"""pip.conf / pip.ini / uv.toml / poetry.toml / .pdm.toml / setup.cfg(install_requires) / setup.py(best effort)."""
from __future__ import annotations
import configparser, tomllib, pathlib, re, ast
from ..model import IndexSpec, Dependency

def _read(p):
    try: return p.read_text(encoding="utf-8", errors="replace")
    except OSError: return ""

def pip_conf(path: pathlib.Path, rel: str) -> list[IndexSpec]:
    text = _read(path); out = []
    cp = configparser.ConfigParser(interpolation=None, strict=False)
    try: cp.read_string(text)
    except configparser.Error: return out
    for sec in cp.sections():
        for key, kind in (("index-url", "index-url"), ("index_url", "index-url"), ("extra-index-url", "extra-index-url"), ("extra_index_url", "extra-index-url"), ("find-links", "find-links")):
            if cp.has_option(sec, key):
                for u in cp.get(sec, key).split():
                    out.append(IndexSpec(url=u, kind=kind, name=f"pip.conf[{sec}]", file=rel, line=_line(text, u)))
    return out

def uv_toml(path: pathlib.Path, rel: str):
    text = _read(path); out = []; strategy = None
    try: d = tomllib.loads(text)
    except tomllib.TOMLDecodeError: return out, strategy
    strategy = d.get("index-strategy")
    if d.get("index-url"): out.append(IndexSpec(url=d["index-url"], kind="index-url", name="uv.toml", file=rel, line=_line(text, d["index-url"])))
    for u in (d.get("extra-index-url") if isinstance(d.get("extra-index-url"), list) else [d.get("extra-index-url")] if d.get("extra-index-url") else []):
        out.append(IndexSpec(url=u, kind="extra-index-url", file=rel, line=_line(text, u)))
    for idx in d.get("index", []) or []:
        if isinstance(idx, dict) and idx.get("url"):
            out.append(IndexSpec(url=idx["url"], kind="uv-index", name=idx.get("name"), explicit=bool(idx.get("explicit")), default=bool(idx.get("default")), file=rel, line=_line(text, idx["url"])))
    return out, strategy

def poetry_toml(path: pathlib.Path, rel: str) -> list[IndexSpec]:
    text = _read(path); out = []
    try: d = tomllib.loads(text)
    except tomllib.TOMLDecodeError: return out
    for name, r in (d.get("repositories") or {}).items():
        if isinstance(r, dict) and r.get("url"): out.append(IndexSpec(url=r["url"], kind="poetry-source", name=name, file=rel, line=_line(text, r["url"])))
    return out

def pdm_toml(path: pathlib.Path, rel: str) -> list[IndexSpec]:
    text = _read(path); out = []
    try: d = tomllib.loads(text)
    except tomllib.TOMLDecodeError: return out
    if (d.get("pypi") or {}).get("url"): out.append(IndexSpec(url=d["pypi"]["url"], kind="index-url", name="pdm:pypi", file=rel, line=_line(text, d["pypi"]["url"])))
    for name, r in (d.get("pypi") or {}).items():
        if isinstance(r, dict) and r.get("url"): out.append(IndexSpec(url=r["url"], kind="pdm-source", name=name, file=rel, line=_line(text, r["url"])))
    return out

def setup_cfg(path: pathlib.Path, rel: str) -> list[Dependency]:
    text = _read(path); out = []
    cp = configparser.ConfigParser(interpolation=None, strict=False)
    try: cp.read_string(text)
    except configparser.Error: return out
    if cp.has_option("options", "install_requires"):
        for l in cp.get("options", "install_requires").splitlines():
            l = l.strip()
            if l and not l.startswith("#"):
                m = re.match(r"^([A-Za-z0-9][A-Za-z0-9._-]*)", l)
                if m: out.append(Dependency(name=m.group(1), spec=l, file=rel, line=_line(text, l), tool="setup.cfg"))
    if cp.has_section("options.extras_require"):
        for extra, val in cp.items("options.extras_require"):
            for l in val.splitlines():
                l = l.strip(); m = re.match(r"^([A-Za-z0-9][A-Za-z0-9._-]*)", l) if l and not l.startswith("#") else None
                if m: out.append(Dependency(name=m.group(1), spec=l, file=rel, line=_line(text, l), group=f"optional:{extra}", tool="setup.cfg"))
    return out

def setup_py(path: pathlib.Path, rel: str) -> list[Dependency]:
    """Best-effort: literal install_requires=[...] lists only."""
    text = _read(path); out = []
    try: tree = ast.parse(text)
    except SyntaxError: return out
    for node in ast.walk(tree):
        if isinstance(node, ast.keyword) and node.arg in ("install_requires", "setup_requires") and isinstance(node.value, (ast.List, ast.Tuple)):
            for elt in node.value.elts:
                if isinstance(elt, ast.Constant) and isinstance(elt.value, str):
                    m = re.match(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)", elt.value)
                    if m: out.append(Dependency(name=m.group(1), spec=elt.value, file=rel, line=elt.lineno, group="runtime" if node.arg == "install_requires" else "build", tool="setup.py"))
        if isinstance(node, ast.keyword) and node.arg == "extras_require" and isinstance(node.value, ast.Dict):
            for k, v in zip(node.value.keys, node.value.values):
                if isinstance(k, ast.Constant) and isinstance(v, (ast.List, ast.Tuple)):
                    for elt in v.elts:
                        if isinstance(elt, ast.Constant) and isinstance(elt.value, str):
                            m = re.match(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)", elt.value)
                            if m: out.append(Dependency(name=m.group(1), spec=elt.value, file=rel, line=elt.lineno, group=f"optional:{k.value}", tool="setup.py"))
    return out

def _line(text, needle):
    for i, l in enumerate(text.splitlines(), 1):
        if needle in l: return i
    return 0
