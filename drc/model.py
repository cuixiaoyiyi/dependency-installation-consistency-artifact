"""Core data model (Dependency Configuration IR, contexts, artifacts, findings)."""
from __future__ import annotations
from dataclasses import dataclass, field, asdict
from typing import Optional
import re
from urllib.parse import urlsplit

from packaging.utils import canonicalize_name

# ----------------------------------------------------------------------------- registries
PYPI = "pypi"

def registry_id(url: str) -> str:
    """Map an index/file URL to a stable registry identifier.

    files.pythonhosted.org / pypi.org -> 'pypi'
    download.pytorch.org/whl/cu128/... -> 'pytorch:cu128'
    download.pytorch.org/whl/nightly/cu128 -> 'pytorch:nightly/cu128'
    other hosts -> host[/first path segments] normalised.
    """
    if not url:
        return "?"
    u = urlsplit(url.strip().rstrip("/"))
    host = (u.hostname or "").lower()
    path = u.path or ""
    if host in ("files.pythonhosted.org", "pypi.org", "pypi.python.org", "test.pypi.org" if False else "pypi.org"):
        return PYPI
    if host == "test.pypi.org":
        return "testpypi"
    if host in ("download.pytorch.org", "download-r2.pytorch.org"):
        m = re.match(r"^/whl/(nightly/|test/)?([A-Za-z0-9_.+-]+)?", path)
        chan = ""
        if m:
            chan = (m.group(1) or "") + (m.group(2) or "")
            # strip package dir like /whl/cu128/torch/ or file names
            chan = chan.strip("/")
            parts = chan.split("/")
            keep = []
            for p in parts:
                if p in ("nightly", "test") or re.match(r"^(cu\d+|cpu|rocm[\d.]+|xpu|cpu-cxx11-abi|cpu\.cxx11\.abi)$", p):
                    keep.append(p)
                else:
                    break
            chan = "/".join(keep)
        return "pytorch:" + (chan or "default")
    if host.endswith("nvidia.com"):
        return "nvidia:" + host
    if host == "storage.googleapis.com" and "jax-releases" in path:
        return "jax-releases"
    if host == "pypi.anaconda.org":
        seg = path.strip("/").split("/")
        return "anaconda:" + (seg[0] if seg and seg[0] else "?")
    if host in ("data.pyg.org",):
        return "pyg:" + path.strip("/").replace("/simple", "")
    if host == "data.dgl.ai":
        return "dgl:" + path.strip("/").split("/")[-1]
    if host == "repo.radeon.com":
        return "rocm:" + host
    # generic: host + up to two leading path segments that are not 'simple'
    seg = [s for s in path.strip("/").split("/") if s and s != "simple"]
    seg = [s for s in seg if not s.endswith((".whl", ".tar.gz", ".zip"))]
    return host + ("/" + "/".join(seg[:2]) if seg else "")

def registry_family(rid: str) -> str:
    return rid.split(":")[0].split("/")[0]

# ----------------------------------------------------------------------------- IR
@dataclass
class IndexSpec:
    url: str
    kind: str            # index-url | extra-index-url | find-links | uv-index | uv-default-index | poetry-source | pdm-source | env
    name: Optional[str] = None
    explicit: bool = False       # uv explicit=true / poetry priority=explicit
    default: bool = False        # uv default=true / poetry primary(default)
    priority: Optional[str] = None  # poetry: primary|supplemental|explicit ; uv: position
    file: str = ""
    line: int = 0
    scope: str = "project"       # project | install-path:<id>
    @property
    def rid(self) -> str: return registry_id(self.url)

@dataclass
class Dependency:
    name: str
    spec: str                 # full PEP 508 string (may include extras/markers)
    file: str
    line: int
    group: str = "runtime"    # runtime | optional:<extra> | dev | build | group:<name>
    direct: bool = True
    hashes: list = field(default_factory=list)
    url: Optional[str] = None       # direct URL / VCS
    editable: bool = False
    tool: str = "pep621"            # pep621 | requirements | poetry | uv | pdm | setup.py
    @property
    def cname(self) -> str: return canonicalize_name(self.name)

@dataclass
class SourceBinding:
    dep: str                  # canonical name
    index_url: Optional[str]  # resolved URL when possible
    index_name: Optional[str]
    tool: str                 # uv | poetry | pdm | cli
    file: str
    line: int
    detail: str = ""
    marker: Optional[str] = None
    extra: Optional[str] = None
    group: Optional[str] = None
    scope: str = "."
    conditions_known: bool = False
    @property
    def rid(self) -> Optional[str]: return registry_id(self.index_url) if self.index_url else None

@dataclass
class InstallPath:
    id: str
    kind: str                 # readme | docs | ci | dockerfile | script | makefile | compose | other
    file: str
    line: int
    tool: str                 # pip | uv | uv-pip | poetry | pdm | pipenv | conda | pipx
    command: str
    packages: list = field(default_factory=list)      # explicit requirement strings
    req_files: list = field(default_factory=list)     # -r files
    constraint_files: list = field(default_factory=list)
    index_url: Optional[str] = None
    extra_index_urls: list = field(default_factory=list)
    find_links: list = field(default_factory=list)
    no_index: bool = False
    pre: bool = False
    no_deps: bool = False
    require_hashes: bool = False
    only_binary: Optional[str] = None
    index_strategy: Optional[str] = None
    env: dict = field(default_factory=dict)           # PIP_*/UV_* env visible at this point
    uv_sync: bool = False                             # uv sync/lock (uses pyproject + lock)
    editable_local: bool = False                      # installs '.' / '-e .'
    extras_of_project: list = field(default_factory=list)
    working_directory: Optional[str] = None
    limitations: list = field(default_factory=list)
    command_kind: str = ""
    group_flags: list = field(default_factory=list)
    named_index: list = field(default_factory=list)
    default_index: Optional[str] = None
    source: Optional[str] = None
    lock_mode: str = "unknown"

@dataclass
class LockInfo:
    kind: str       # uv.lock | poetry.lock | pylock.toml | requirements-hashes | Pipfile.lock
    file: str
    packages: dict = field(default_factory=dict)   # cname -> {version, registry, urls, hashes}

@dataclass
class ProjectIR:
    repo: str
    root: str
    files: list = field(default_factory=list)
    dependencies: list = field(default_factory=list)      # Dependency
    indexes: list = field(default_factory=list)           # IndexSpec
    bindings: list = field(default_factory=list)          # SourceBinding
    install_paths: list = field(default_factory=list)     # InstallPath
    locks: list = field(default_factory=list)             # LockInfo
    tools: list = field(default_factory=list)             # detected package managers
    requires_python: Optional[str] = None
    uv_index_strategy: Optional[str] = None
    notes: list = field(default_factory=list)

    def to_dict(self): return asdict(self)

# ----------------------------------------------------------------------------- resolution
@dataclass
class Context:
    id: str
    resolver: str                       # pip | uv
    requirements: list                  # PEP 508 strings
    index_url: Optional[str] = None     # primary (None => resolver default = PyPI)
    extra_index_urls: list = field(default_factory=list)
    find_links: list = field(default_factory=list)
    no_index: bool = False
    pre: bool = False
    index_strategy: Optional[str] = None       # uv: first-index | unsafe-first-match | unsafe-best-match
    sources: dict = field(default_factory=dict)  # uv: cname -> index name  (tool.uv.sources)
    named_indexes: list = field(default_factory=list)  # uv: [{name,url,explicit,default}]
    constraints: list = field(default_factory=list)
    platform: str = "linux-x86_64"
    python_version: str = "3.12"
    derived_from: str = "synthetic"     # install-path id | declared | synthetic:<factor>
    factors: dict = field(default_factory=dict)  # factor -> value
    description: str = ""
    origin: dict = field(default_factory=dict)
    faithfulness: str = "unverified"
    limitations: list = field(default_factory=list)
    request_complete: bool = False
    project_file: str = ""
    scope: str = "."
    project_extras: Optional[list] = None
    marker_environment: dict = field(default_factory=dict)
    source_bindings_enabled: Optional[bool] = None
    lock_mode: str = "unknown"
    lock_file: str = ""
    no_deps: bool = False
    require_hashes: bool = False
    only_binary: Optional[str] = None
    snapshot_id: Optional[str] = None
    snapshot_mode: str = "record"
    strict_reproducibility: bool = False
    def to_dict(self): return asdict(self)

@dataclass
class Artifact:
    name: str
    version: str
    url: str
    filename: str
    kind: str                 # wheel | sdist | unknown
    sha256: Optional[str]
    registry: str
    requested: bool = False
    requires_dist: list = field(default_factory=list)
    selection_evidence: str = "legacy-unverified"
    selected_artifact_verified: bool = False
    candidate_artifacts: list = field(default_factory=list)
    registry_verified: bool = False
    registry_evidence: str = "legacy-unverified"
    @property
    def cname(self): return canonicalize_name(self.name)
    def to_dict(self): d = asdict(self); d["cname"] = self.cname; return d

@dataclass
class Resolution:
    context_id: str
    resolver: str
    ok: bool
    artifacts: dict               # cname -> Artifact
    seconds: float
    command: str
    error: str = ""
    resolver_version: str = ""
    timestamp: str = ""
    fallback: str = ""            # e.g. 'host-platform' if cross-platform failed
    snapshot: dict = field(default_factory=dict)
    graph_projection: dict = field(default_factory=dict)
    def to_dict(self):
        return {"context_id": self.context_id, "resolver": self.resolver, "ok": self.ok, "seconds": self.seconds,
                "command": self.command, "error": self.error[-4000:], "resolver_version": self.resolver_version,
                "timestamp": self.timestamp, "fallback": self.fallback, "snapshot": self.snapshot,
                "graph_projection": self.graph_projection,
                "artifacts": {k: v.to_dict() for k, v in self.artifacts.items()}}
