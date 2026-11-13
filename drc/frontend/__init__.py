"""Phase 1: structured dependency-configuration parsing -> ProjectIR."""
from __future__ import annotations
import pathlib, re
from packaging.utils import canonicalize_name
from ..model import ProjectIR, IndexSpec, SourceBinding, Dependency
from . import requirements as req_mod, pyproject as pyp_mod, ci as ci_mod, lockfile as lock_mod, pipconf as conf_mod

SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "env", "__pycache__", ".tox", ".nox", "site-packages", "dist", "build", ".mypy_cache", ".pytest_cache", "third_party", "3rdparty", "vendor", "vendored", ".eggs"}
MAX_FILES = 6000
MAX_DEPTH = 6

def iter_files(root: pathlib.Path):
    n = 0
    for p in sorted(root.rglob("*")):
        if not p.is_file(): continue
        parts = p.relative_to(root).parts
        if any(x in SKIP_DIRS for x in parts[:-1]) or len(parts) > MAX_DEPTH: continue
        n += 1
        if n > MAX_FILES: break
        yield p

def parse_project(root: str | pathlib.Path, repo: str = "") -> ProjectIR:
    root = pathlib.Path(root)
    ir = ProjectIR(repo=repo or root.name, root=str(root))
    tools = set()
    for p in iter_files(root):
        rel = str(p.relative_to(root)).replace("\\", "/")
        name = p.name.lower()
        low = rel.lower()
        try:
            if name == "pyproject.toml":
                ir.files.append(rel)
                r = pyp_mod.parse_pyproject(p, root)
                ir.dependencies += r["deps"]; ir.indexes += r["indexes"]; ir.bindings += r["bindings"]; tools.update(r["tools"])
                if r.get("uv_index_strategy"): ir.uv_index_strategy = r["uv_index_strategy"]
                if r.get("requires_python") and rel == "pyproject.toml": ir.requires_python = r["requires_python"]
                if r.get("error"): ir.notes.append(f"{rel}: {r['error']}")
                ir.install_paths += ci_mod.script_file(p, rel, kind="pyproject-scripts") if "[tool.hatch" in p.read_text(encoding="utf-8", errors="replace") else []
            elif re.match(r"^(requirements|reqs?|deps?|constraints?)([-_.a-z0-9]*)\.(txt|in|pip)$", name) or (low.startswith("requirements/") and name.endswith((".txt", ".in"))) or name == "requirements.txt":
                ir.files.append(rel); tools.add("pip")
                grp = "runtime" if re.match(r"^requirements(\.txt|\.in)$", name) else f"reqfile:{re.sub(r'^(requirements|reqs?)[-_.]?', '', name).rsplit('.', 1)[0] or 'base'}"
                r = req_mod.parse_requirements_text(p.read_text(encoding="utf-8", errors="replace"), rel, group=grp)
                ir.dependencies += r["deps"]
                for ix in r["indexes"]: ix.scope = f"reqfile:{rel}"
                ir.indexes += r["indexes"]
                if r["flags"].get("require_hashes") or any(d.hashes for d in r["deps"]):
                    from ..model import LockInfo
                    ir.locks.append(LockInfo(kind="requirements-hashes", file=rel, packages={d.cname: {"version": d.spec, "hashes": d.hashes} for d in r["deps"] if d.hashes}))
            elif name in ("pip.conf", "pip.ini") or low.endswith(".pip/pip.conf"):
                ir.files.append(rel); tools.add("pip"); ir.indexes += conf_mod.pip_conf(p, rel)
            elif name == "uv.toml":
                ir.files.append(rel); tools.add("uv"); ix, st = conf_mod.uv_toml(p, rel); ir.indexes += ix
                if st: ir.uv_index_strategy = st
            elif name == "poetry.toml":
                ir.files.append(rel); tools.add("poetry"); ir.indexes += conf_mod.poetry_toml(p, rel)
            elif name == ".pdm.toml" or name == "pdm.toml":
                ir.files.append(rel); tools.add("pdm"); ir.indexes += conf_mod.pdm_toml(p, rel)
            elif name == "uv.lock":
                ir.files.append(rel); tools.add("uv"); ir.locks.append(lock_mod.uv_lock(p, rel))
            elif name == "poetry.lock":
                ir.files.append(rel); tools.add("poetry"); ir.locks.append(lock_mod.poetry_lock(p, rel))
            elif name == "pylock.toml" or re.match(r"^pylock\.[^.]+\.toml$", name):
                ir.files.append(rel); ir.locks.append(lock_mod.pylock(p, rel))
            elif name == "pipfile.lock":
                ir.files.append(rel); tools.add("pipenv"); li, ix, b = lock_mod.pipfile_lock(p, rel); ir.locks.append(li); ir.indexes += ix; ir.bindings += b
            elif name == "pipfile":
                ir.files.append(rel); tools.add("pipenv"); ix, b, d = lock_mod.pipfile(p, rel); ir.indexes += ix; ir.bindings += b; ir.dependencies += d
            elif name == "setup.cfg":
                ir.files.append(rel); ir.dependencies += conf_mod.setup_cfg(p, rel)
            elif name == "setup.py":
                ir.files.append(rel); ir.dependencies += conf_mod.setup_py(p, rel)
            elif low.startswith(".github/workflows/") and name.endswith((".yml", ".yaml")):
                ir.files.append(rel); ir.install_paths += ci_mod.github_workflow(p, rel)
            elif name == ".gitlab-ci.yml" or (low.startswith(".gitlab/") and name.endswith(".yml")):
                ir.files.append(rel); ir.install_paths += ci_mod.gitlab_ci(p, rel)
            elif name in ("azure-pipelines.yml", ".travis.yml", "appveyor.yml", ".appveyor.yml", "bitbucket-pipelines.yml", "cloudbuild.yaml", "buildspec.yml", ".drone.yml", "jenkinsfile") or low.startswith((".circleci/", ".buildkite/", ".azure/", ".woodpecker")):
                ir.files.append(rel); ir.install_paths += ci_mod.generic_yaml_ci(p, rel)
            elif name.startswith("dockerfile") or name.endswith(".dockerfile") or (name == "containerfile"):
                ir.files.append(rel); ir.install_paths += ci_mod.dockerfile(p, rel)
            elif name in ("readme.md", "readme.rst", "readme.txt", "readme", "install.md", "installation.md", "install.rst", "installation.rst", "getting_started.md", "getting-started.md", "quickstart.md", "setup.md", "contributing.md", "development.md", "developing.md") or (low.startswith(("docs/", "doc/", "documentation/")) and name.endswith((".md", ".rst")) and re.search(r"install|setup|getting|quick|start|develop|contrib|build|environment|requirement|depend", low)):
                ir.files.append(rel); ir.install_paths += ci_mod.markdown_doc(p, rel, kind="readme" if name.startswith("readme") else "docs")
            elif name.endswith((".sh", ".bash", ".zsh", ".bat", ".cmd", ".ps1")):
                if p.stat().st_size < 400_000:
                    ir.files.append(rel); ir.install_paths += ci_mod.script_file(p, rel)
            elif name in ("makefile", "justfile", "taskfile.yml", "taskfile.yaml") or name.endswith(".mk"):
                ir.files.append(rel); ir.install_paths += ci_mod.makefile(p, rel)
            elif name == "tox.ini":
                ir.files.append(rel); ir.install_paths += ci_mod.tox_ini(p, rel)
            elif name in ("noxfile.py",):
                ir.files.append(rel); ir.install_paths += ci_mod.script_file(p, rel, kind="noxfile")
            elif name in ("environment.yml", "environment.yaml") or re.match(r"^environment[-_.].*\.ya?ml$", name) or name.startswith("conda") and name.endswith((".yml", ".yaml")):
                ir.files.append(rel); ir.install_paths += ci_mod.conda_env_yaml(p, rel)
            elif name in ("docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml") or name == "devcontainer.json" or name == "setup.cfg":
                ir.files.append(rel); ir.install_paths += ci_mod.generic_yaml_ci(p, rel)
        except Exception as e:  # keep going; record parser failure
            ir.notes.append(f"parse-error {rel}: {type(e).__name__}: {e}")
    ir.tools = sorted(tools | {ip.tool for ip in ir.install_paths})
    _derive_cli_bindings(ir)
    _dedup(ir)
    return ir

def _derive_cli_bindings(ir: ProjectIR):
    """`pip install torch --index-url X` (explicit packages + explicit index) is an explicit CLI-level source binding."""
    for ip in ir.install_paths:
        if ip.index_url and ip.packages and not ip.req_files:
            for pkg in ip.packages:
                m = re.match(r"^([A-Za-z0-9][A-Za-z0-9._-]*)", pkg)
                if m:
                    ir.bindings.append(SourceBinding(dep=canonicalize_name(m.group(1)), index_url=ip.index_url, index_name=None, tool="cli", file=ip.file, line=ip.line,
                                                     detail=f"install-path {ip.id}: {ip.command[:120]}"))
        # uv `--index name=url` / `--default-index`
        for ni in getattr(ip, "named_index", []) or []:
            if ni and "=" in ni: nm, url = ni.split("=", 1)
            else: nm, url = None, ni
            if url and url.startswith("http"):
                ir.indexes.append(IndexSpec(url=url, kind="uv-index", name=nm, file=ip.file, line=ip.line, scope=f"install-path:{ip.id}"))
        if getattr(ip, "default_index", None):
            ir.indexes.append(IndexSpec(url=ip.default_index, kind="uv-default-index", file=ip.file, line=ip.line, scope=f"install-path:{ip.id}"))
        if ip.index_url:
            ir.indexes.append(IndexSpec(url=ip.index_url, kind="index-url", file=ip.file, line=ip.line, scope=f"install-path:{ip.id}"))
        for u in ip.extra_index_urls:
            ir.indexes.append(IndexSpec(url=u, kind="extra-index-url", file=ip.file, line=ip.line, scope=f"install-path:{ip.id}"))
        for u in ip.find_links:
            if u and u.startswith("http"): ir.indexes.append(IndexSpec(url=u, kind="find-links", file=ip.file, line=ip.line, scope=f"install-path:{ip.id}"))

def _dedup(ir: ProjectIR):
    seen = set(); out = []
    for ix in ir.indexes:
        if ix.url: ix.url = ix.url.strip().strip("\"'`,;)").rstrip("\\")
        if not ix.url or "$" in ix.url and not ix.url.startswith("http"):
            if ix.url and "$" in ix.url: ir.notes.append(f"unresolved index variable: {ix.url} ({ix.file}:{ix.line})")
            continue
        if re.search(r"[<>{}]|example\.com|your[-_]|__SUBST__|localhost|127\.0\.0\.1", ix.url):
            ir.notes.append(f"placeholder/local index skipped: {ix.url} ({ix.file}:{ix.line})"); continue
        if "$" in ix.url:
            ir.notes.append(f"unresolved index variable: {ix.url} ({ix.file}:{ix.line})"); continue
        key = (ix.url.rstrip("/"), ix.kind, ix.file, ix.line, ix.scope)
        if key in seen: continue
        seen.add(key); out.append(ix)
    ir.indexes = out
    seen = set(); outb = []
    for b in ir.bindings:
        key = (b.dep, b.index_url, b.tool, b.file, b.line, b.marker, b.extra, b.group, b.scope)
        if key in seen: continue
        seen.add(key); outb.append(b)
    ir.bindings = outb
