"""Real package-manager execution adapters (pip, uv). Each returns a Resolution with concrete artifacts."""
from __future__ import annotations
import json, os, re, subprocess, sys, tempfile, time, pathlib, hashlib, shutil, platform, urllib.request
from datetime import datetime, timezone
from typing import Optional
from packaging.utils import canonicalize_name, parse_wheel_filename, parse_sdist_filename, InvalidWheelFilename, InvalidSdistFilename
from packaging.tags import Tag
from packaging.markers import default_environment
from ..model import Context, Artifact, Resolution, registry_id
from .lock_projection import project_uv_lock, target_environment_reasons

PY = sys.executable
CACHE_ROOT = pathlib.Path(os.environ.get("DRC_CACHE", pathlib.Path(__file__).resolve().parents[2] / "work" / "resolver-reliability-cache"))
PIP_TIMEOUT = int(os.environ.get("DRC_PIP_TIMEOUT", "600"))
UV_TIMEOUT = int(os.environ.get("DRC_UV_TIMEOUT", "420"))

# Execution backend: "host" (Windows python/uv with cross-platform flags) or "wsl" (real Linux: markers evaluated natively).
EXEC = os.environ.get("DRC_EXEC", "wsl")
WSL_DISTRO = os.environ.get("DRC_WSL_DISTRO", "Ubuntu")
WSL_PY = os.environ.get("DRC_WSL_PY", "/home/clm/drc-venv/bin/python")   # default (3.12)
WSL_PY_BY_VERSION = {"3.10": "/home/clm/drc-venv310/bin/python", "3.11": "/home/clm/drc-venv311/bin/python", "3.12": "/home/clm/drc-venv312/bin/python"}
WSL_UV = os.environ.get("DRC_WSL_UV", "/home/clm/.local/bin/uv")
WSL_CACHE = os.environ.get("DRC_WSL_CACHE", "/home/clm/drc-cache")

def to_wsl_path(p) -> str:
    s = str(pathlib.Path(p).resolve()).replace("\\", "/")
    m = re.match(r"^([A-Za-z]):/(.*)$", s)
    return f"/mnt/{m.group(1).lower()}/{m.group(2)}" if m else s

def _run(cmd: list, cwd: pathlib.Path, env: dict, timeout: int, tool: str, pyver: str = "3.12"):
    """Run a resolver command either on the host or inside WSL (paths translated)."""
    if EXEC != "wsl":
        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, env=env, cwd=str(cwd), encoding="utf-8", errors="replace", stdin=subprocess.DEVNULL), " ".join(cmd)
    wsl_py = WSL_PY_BY_VERSION.get(_python_minor(pyver), WSL_PY)
    # translate: interpreter + arguments that are host paths
    tcmd = []
    for i, c in enumerate(cmd):
        if i == 0: continue  # drop host python
        if c == "-m" and i == 1: continue
        if i == 2 and c in ("pip", "uv"): tcmd.append(f"{wsl_py} -m pip" if c == "pip" else WSL_UV); continue
        if re.match(r"^[A-Za-z]:[\\/]", c): tcmd.append(to_wsl_path(c))
        elif re.match(r"^(--[a-z-]+=)([A-Za-z]:[\\/].*)$", c): m = re.match(r"^(--[a-z-]+=)([A-Za-z]:[\\/].*)$", c); tcmd.append(m.group(1) + to_wsl_path(m.group(2)))
        else: tcmd.append(c)
    # swap cache dir to WSL-native FS (much faster than /mnt/d)
    for j, c in enumerate(tcmd):
        if c == "--cache-dir" and j + 1 < len(tcmd):
            sid = env.get("DRC_SNAPSHOT_ID")
            tcmd[j + 1] = f"{WSL_CACHE}/snapshots/{sid}/{tool}" if sid else f"{WSL_CACHE}/{tool}"
    exports = " ".join(f"export {k}={_shq(v)};" for k, v in env.items() if k.startswith(("PIP_", "UV_", "XDG_", "HOME_", "CI")) and k not in ("PIP_CONFIG_FILE",))
    if tool == "pip": exports += " export PIP_CONFIG_FILE=/dev/null;"
    else: exports += f" export XDG_CONFIG_HOME={WSL_CACHE}/empty-xdg;"
    line = f"mkdir -p {WSL_CACHE}/{tool} {WSL_CACHE}/empty-xdg; cd {_shq(to_wsl_path(cwd))} && {exports} " + " ".join(_shq(x) if not x.endswith(" -m pip") else x for x in tcmd)
    full = ["wsl", "-d", WSL_DISTRO, "--", "bash", "-c", line]
    for attempt in range(3):
        p = subprocess.run(full, capture_output=True, text=True, timeout=timeout, encoding="utf-8", errors="replace", stdin=subprocess.DEVNULL)
        # WSL returns UTF-16-ish NULs on some consoles; strip
        p.stdout = (p.stdout or "").replace("\x00", ""); p.stderr = (p.stderr or "").replace("\x00", "")
        transient = re.search(r"dns error|Name or service not known|Connection reset|Temporary failure in name resolution|Read timed out|Max retries exceeded|error sending request|502 Bad Gateway|503 Service", (p.stderr or "") + (p.stdout or ""))
        if p.returncode == 0 or not transient: break
        time.sleep(5 * (attempt + 1))
    return p, line

def _shq(s: str) -> str:
    if re.match(r"^[A-Za-z0-9_./:=+-]+$", s): return s
    return "'" + s.replace("'", "'\"'\"'") + "'"

PLATFORMS = {
    # key: (pip --platform list, pip abi/impl, uv --python-platform)
    "linux-x86_64": (["manylinux_2_28_x86_64", "manylinux_2_17_x86_64", "manylinux2014_x86_64", "manylinux_2_5_x86_64", "manylinux1_x86_64", "linux_x86_64"], "x86_64-manylinux_2_28"),
    "linux-aarch64": (["manylinux_2_28_aarch64", "manylinux_2_17_aarch64", "manylinux2014_aarch64", "linux_aarch64"], "aarch64-manylinux_2_28"),
    "macos-arm64": (["macosx_14_0_arm64", "macosx_13_0_arm64", "macosx_12_0_arm64", "macosx_11_0_arm64"], "aarch64-apple-darwin"),
    "windows-x86_64": (["win_amd64"], "x86_64-pc-windows-msvc"),
}

def _now(): return datetime.now(timezone.utc).isoformat(timespec="seconds")

def _version(cmd):
    try: return subprocess.run(cmd, capture_output=True, text=True, timeout=60).stdout.strip().splitlines()[0]
    except Exception as e: return f"? ({e})"

def _versions():
    if EXEC == "wsl":
        try:
            p = subprocess.run(["wsl", "-d", WSL_DISTRO, "--", "bash", "-c", f"{WSL_PY} -m pip --version; {WSL_UV} --version"], capture_output=True, text=True, timeout=120, encoding="utf-8", errors="replace", stdin=subprocess.DEVNULL)
            lines = [l for l in p.stdout.replace("\x00", "").splitlines() if l.strip()]
            return (lines[0] if lines else "?") + " [wsl]", (lines[1] if len(lines) > 1 else "?") + " [wsl]"
        except Exception as e:
            return f"? ({e})", f"? ({e})"
    return _version([PY, "-m", "pip", "--version"]), _version([PY, "-m", "uv", "--version"])

PIP_VERSION, UV_VERSION = "not probed", "not probed"

def _resolver_version(tool):
    """Importing an adapter must not start WSL or perform filesystem/network work."""
    global PIP_VERSION, UV_VERSION
    if PIP_VERSION == "not probed" and os.environ.get("DRC_SKIP_VERSION_PROBE") != "1":
        PIP_VERSION, UV_VERSION = _versions()
    return PIP_VERSION if tool == "pip" else UV_VERSION

def artifact_from_url(name: str, version: str, url: str, sha256: Optional[str], requested=False, requires_dist=None) -> Artifact:
    from urllib.parse import unquote
    fn = unquote(url.split("#")[0].rstrip("/").split("/")[-1])
    kind = "wheel" if fn.endswith(".whl") else "sdist" if re.search(r"\.(tar\.gz|zip|tar\.bz2|tgz)$", fn) else "unknown"
    if sha256 is None and "#sha256=" in url: sha256 = url.split("#sha256=")[1].split("&")[0]
    return Artifact(name=name, version=version, url=url.split("#")[0], filename=fn, kind=kind, sha256=sha256, registry=registry_id(url), requested=requested, requires_dist=requires_dist or [])


def project_pip_report(report: dict, ctx: Context):
    """Read selected report entries without attributing a download host to an index."""
    arts = {}
    entries = report.get("install")
    environment = report.get("environment") or {}
    reasons = target_environment_reasons(ctx, environment)
    if not isinstance(entries, list):
        entries = []
        reasons.append("pip-report-install-list-missing")
    for item in entries:
        metadata = item.get("metadata", {})
        download = item.get("download_info", {})
        url = unproxy_url(download.get("url", ""))
        digest = ((download.get("archive_info") or {}).get("hashes") or {}).get("sha256")
        artifact = artifact_from_url(metadata.get("name", "?"), metadata.get("version", "?"), url, digest,
                                     requested=bool(item.get("requested")), requires_dist=metadata.get("requires_dist", []))
        artifact.selection_evidence = "pip-report-selected"
        artifact.selected_artifact_verified = bool(url and artifact.kind in ("wheel", "sdist"))
        artifact.registry_verified = False
        artifact.registry_evidence = "artifact-url-origin; index attribution unverified"
        _normalize_registry(artifact, ctx)
        if artifact.cname in arts:
            reasons.append("duplicate-pip-report-identity:" + artifact.cname)
        arts[artifact.cname] = artifact
    evidence = {"schema": "pip-report-target-v1", "status": "verified" if not reasons else "unknown",
                "environment": environment, "environment_source": "pip-report", "reasons": reasons,
                "selected": [{"name": artifact.cname, "version": artifact.version,
                              "file_url": artifact.url, "sha256": artifact.sha256} for artifact in arts.values()]}
    return arts, evidence

# ----------------------------------------------------------------------------- pip
def run_pip(ctx: Context, workdir: pathlib.Path) -> Resolution:
    """pip install --dry-run --report with platform override (no files installed)."""
    error = _preflight(ctx, "pip")
    if error: return _failed(ctx, "pip", error)
    try: snapshot = _prepare_snapshot(ctx)
    except ReproducibilityError as exc: return _failed(ctx, "pip", str(exc))
    _resolver_version("pip")
    workdir = workdir.resolve()
    workdir.mkdir(parents=True, exist_ok=True)
    req_file = workdir / "requirements.txt"
    req_file.write_text("\n".join(ctx.requirements) + "\n", encoding="utf-8")
    report = workdir / "pip-report.json"
    if report.exists(): report.unlink()
    plats, _ = PLATFORMS[ctx.platform]
    pyver = ctx.python_version; abi = "cp" + _python_minor(pyver).replace(".", "")
    cmd = [PY, "-m", "pip", "install", "--dry-run", "--ignore-installed", "--report", str(report), "-r", str(req_file),
           "--cache-dir", str(_resolver_cache(ctx, "pip")), "--disable-pip-version-check", "--no-input", "--progress-bar", "off", "--retries", "2", "--timeout", "60"]
    # SAFETY: never build sdists (that would execute third-party setup.py during resolution).
    # With the metadata proxy, sdists lacking static metadata are removed from index pages, so pip cannot build anything;
    # without the proxy we must restrict to wheels.
    if not snapshot.get("proxy_verified"): cmd += ["--only-binary=:all:"]
    if getattr(ctx, "no_deps", False): cmd.append("--no-deps")
    if getattr(ctx, "require_hashes", False): cmd.append("--require-hashes")
    if getattr(ctx, "only_binary", None): cmd += ["--only-binary", ctx.only_binary]
    if EXEC != "wsl" and not _native_host_target(ctx):
        # host (Windows) execution: cross-platform dry-run needs tag overrides (markers still evaluated on host!)
        cmd += ["--python-version", pyver, "--implementation", "cp", "--abi", abi, "--abi", "abi3", "--abi", "none"]
        for p in plats: cmd += ["--platform", p]
    cmd += _pip_index_args(ctx, use_proxy=bool(snapshot.get("proxy_verified")))
    for c in ctx.constraints:
        cf = workdir / "constraints.txt"; cf.write_text("\n".join(ctx.constraints) + "\n", encoding="utf-8"); cmd += ["-c", str(cf)]; break
    env = dict(os.environ); env["PIP_CONFIG_FILE"] = os.devnull; env["PIP_NO_INPUT"] = "1"
    for k in list(env):
        if k.startswith(("PIP_INDEX", "PIP_EXTRA", "PIP_FIND", "PIP_NO_INDEX", "PIP_PRE", "UV_")): env.pop(k, None)
    _snapshot_env(env, ctx)
    t0 = time.time(); fallback = ""
    try:
        p, shown = _run(cmd, workdir, env, PIP_TIMEOUT, "pip", ctx.python_version)
    except subprocess.TimeoutExpired:
        return _finish_snapshot(Resolution(ctx.id, "pip", False, {}, time.time() - t0, " ".join(cmd), "timeout", PIP_VERSION, _now()), ctx, snapshot)
    err = (p.stderr or "") + (p.stdout or "")
    secs = time.time() - t0
    if p.returncode != 0 or not report.exists():
        if re.search(r"only-binary|No matching distribution|Could not find a version", err): fallback = "sdist-only-or-missing"
        return _finish_snapshot(Resolution(ctx.id, "pip", False, {}, secs, shown, err[-6000:], PIP_VERSION, _now(), fallback), ctx, snapshot)
    try:
        rep = json.loads(report.read_text(encoding="utf-8"))
    except json.JSONDecodeError as e:
        return _finish_snapshot(Resolution(ctx.id, "pip", False, {}, secs, " ".join(cmd), f"bad report: {e}", PIP_VERSION, _now(), fallback), ctx, snapshot)
    arts, projection = project_pip_report(rep, ctx)
    result = Resolution(ctx.id, "pip", True, arts, secs, shown, "", PIP_VERSION, _now(), fallback,
                        graph_projection=projection)
    return _finish_snapshot(result, ctx, snapshot)

def _normalize_registry(a: Artifact, ctx: Context):
    """pip reports file URLs, not the index that served them. Files under download.pytorch.org/whl/<file> (channel-less
    mirror copies) are attributed to the (single) PyTorch index configured in the context, matching uv's lock attribution."""
    if a.registry == "pytorch:default":
        pt = [u for u in ([ctx.index_url] if ctx.index_url else []) + list(ctx.extra_index_urls) if u and registry_id(u).startswith("pytorch:")]
        if len({registry_id(u) for u in pt}) == 1: a.registry = registry_id(pt[0])

PROXY_PORT = int(os.environ.get("DRC_PROXY_PORT", "8765"))
USE_PROXY = os.environ.get("DRC_PROXY", "1") == "1" and EXEC == "wsl"
PYPI_SIMPLE = "https://pypi.org/simple"
_proxy_ok = {"t": 0.0}

class ReproducibilityError(RuntimeError):
    pass

def _snapshot_config(ctx=None):
    sid = getattr(ctx, "snapshot_id", None) or os.environ.get("DRC_SNAPSHOT_ID")
    mode = getattr(ctx, "snapshot_mode", None) or os.environ.get("DRC_SNAPSHOT_MODE", "record")
    strict = bool(getattr(ctx, "strict_reproducibility", False)) or os.environ.get("DRC_STRICT_REPRODUCIBILITY") == "1"
    if sid and not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", sid):
        raise ReproducibilityError("invalid snapshot id")
    if mode not in ("record", "replay"):
        raise ReproducibilityError("snapshot mode must be record or replay")
    return sid, mode, strict

def _failed(ctx, tool, error):
    res = Resolution(ctx.id, tool, False, {}, 0.0, "", error, timestamp=_now())
    res.snapshot = {"proxy_verified": False, "complete": False, "error": error}
    return res

def _preflight(ctx, tool):
    if not getattr(ctx, "request_complete", True):
        return "incomplete resolution request: " + "; ".join(getattr(ctx, "limitations", []) or ["source request could not be preserved"])
    if ctx.platform not in PLATFORMS:
        return "unsupported target platform: " + ctx.platform
    if EXEC == "wsl" and ctx.platform != "linux-x86_64":
        return "WSL adapter cannot preserve markers for this non-native target: " + ctx.platform
    if EXEC == "wsl" and _python_minor(ctx.python_version) not in WSL_PY_BY_VERSION:
        return "WSL interpreter mapping is missing for Python " + ctx.python_version
    origin = getattr(ctx, "origin", {}) or {}
    if (ctx.lock_mode in ("frozen", "locked") or origin.get("project_request") or
            origin.get("command_kind") in ("uv sync", "uv lock", "uv run")):
        return "original project/lock replay is not implemented; an extracted request cannot replace this invocation"
    if tool == "pip" and EXEC != "wsl" and not _native_host_target(ctx):
        if not getattr(ctx, "no_deps", False) and getattr(ctx, "only_binary", None) != ":all:":
            return "cross-target pip requires explicit --only-binary=:all: or --no-deps; adapter will not add an undeclared policy"
        if any(";" in r for r in ctx.requirements + ctx.constraints):
            return "cross-target pip evaluates markers on the host; marker-bearing requests are refused"
    if tool == "uv" and getattr(ctx, "no_deps", False):
        return "uv lock adapter cannot preserve --no-deps; request refused"
    if tool == "uv" and getattr(ctx, "require_hashes", False):
        return "uv lock adapter cannot preserve pip --require-hashes enforcement; request refused"
    if tool == "uv" and getattr(ctx, "only_binary", None):
        return "uv lock adapter cannot prove --only-binary selection; request refused"
    if any(not isinstance(v, str) for v in ctx.sources.values()):
        return "conditional/multiple sources must be projected for the requested environment before execution"
    try:
        sid, mode, strict = _snapshot_config(ctx)
    except ReproducibilityError as exc:
        return str(exc)
    if strict and not sid:
        return "strict reproducibility requires an explicit per-run snapshot id"
    if mode == "replay" and not sid:
        return "snapshot replay requires an explicit snapshot id"
    if sid:
        if ctx.find_links:
            return "find-links inputs are not recorded by this snapshot adapter; request refused"
        if any(re.search(r"(?:@\s*(?:https?|git\+|file):|^(?:https?|git\+|file):)", r) for r in ctx.requirements + ctx.constraints):
            return "direct URL/VCS inputs are not recorded by this snapshot adapter; request refused"
    return ""

def _native_host_target(ctx):
    machine = platform.machine().lower()
    arch = "x86_64" if machine in ("amd64", "x86_64") else "aarch64" if machine in ("arm64", "aarch64") else machine
    native = "windows-x86_64" if sys.platform == "win32" and arch == "x86_64" else "macos-arm64" if sys.platform == "darwin" and arch == "aarch64" else "linux-" + arch if sys.platform.startswith("linux") else "unsupported"
    return ctx.platform == native and _python_minor(ctx.python_version) == f"{sys.version_info.major}.{sys.version_info.minor}"


def _python_minor(version):
    return ".".join(str(version).split(".")[:2])


def _target_marker_environment(ctx):
    """Observe the interpreter used by the adapter, retaining explicitly supplied targets."""
    supplied = dict(ctx.marker_environment or {})
    if EXEC != "wsl" and _native_host_target(ctx):
        observed = default_environment()
    elif EXEC == "wsl":
        interpreter = WSL_PY_BY_VERSION.get(_python_minor(ctx.python_version))
        probe = ("import json, os, platform, sys; "
                 "v=sys.implementation.version; "
                 "iv='.'.join(map(str,v[:3])) + ('' if v.releaselevel == 'final' else v.releaselevel[0] + str(v.serial)); "
                 "print(json.dumps(dict(implementation_name=sys.implementation.name, implementation_version=iv, "
                 "os_name=os.name, platform_machine=platform.machine(), platform_release=platform.release(), "
                 "platform_system=platform.system(), platform_version=platform.version(), "
                 "python_full_version=platform.python_version(), platform_python_implementation=platform.python_implementation(), "
                 "python_version='.'.join(map(str,sys.version_info[:2])), sys_platform=sys.platform)))")
        try:
            result = subprocess.run(["wsl", "-d", WSL_DISTRO, "--", interpreter, "-c", probe],
                                    capture_output=True, text=True, timeout=30, encoding="utf-8", errors="replace")
            observed = json.loads(result.stdout.replace("\x00", "")) if result.returncode == 0 else {}
        except (OSError, ValueError, subprocess.SubprocessError):
            observed = {}
    else:
        observed = {}
    # Explicit targets may be symbolic cross-target uv requests. They must not
    # be completed with this host's unrelated operating-system marker values.
    return {**observed, **supplied} if observed else supplied

def _resolver_cache(ctx, tool):
    sid, _, _ = _snapshot_config(ctx)
    return CACHE_ROOT / "snapshot-resolvers" / sid / tool if sid else CACHE_ROOT / tool

def _snapshot_env(env, ctx):
    sid, _, strict = _snapshot_config(ctx)
    if sid: env["DRC_SNAPSHOT_ID"] = sid
    if strict: env["UV_PYTHON_DOWNLOADS"] = "never"

def _proxy_health():
    try:
        url = f"http://127.0.0.1:{PROXY_PORT}/health"
        if EXEC == "wsl":
            p = subprocess.run(["wsl", "-d", WSL_DISTRO, "--", "curl", "-s", "--fail", "-m", "5", url],
                               capture_output=True, text=True, timeout=15, encoding="utf-8", errors="replace", stdin=subprocess.DEVNULL)
            if p.returncode != 0: return None
            return json.loads(p.stdout.replace("\x00", ""))
        with urllib.request.urlopen(url, timeout=5) as response:
            return json.loads(response.read())
    except (OSError, ValueError, subprocess.SubprocessError):
        return None

def _prepare_snapshot(ctx):
    sid, mode, strict = _snapshot_config(ctx)
    requested = bool(sid) or USE_PROXY
    if not requested:
        return {"id": None, "mode": "live", "proxy_verified": False, "complete": False}
    if not ensure_proxy(ctx):
        if sid or strict:
            raise ReproducibilityError("required snapshot proxy unavailable: " + _proxy_ok.get("error", "unknown error"))
        return {"id": None, "mode": "live", "proxy_verified": False, "complete": False, "error": _proxy_ok.get("error")}
    health = _proxy_health()
    if health is None:
        raise ReproducibilityError("proxy health could not be verified")
    actual = health.get("snapshot") or {}
    if sid and (actual.get("id") != sid or actual.get("mode") != mode):
        raise ReproducibilityError("snapshot proxy identity/mode mismatch")
    if mode == "replay" and not actual.get("frozen"):
        raise ReproducibilityError("replay snapshot is not sealed")
    return {"id": sid, "mode": mode if sid else "legacy-unfrozen", "proxy_verified": True,
            "complete": False, "sealed": False, "frozen": False, "integrity_verified": False,
            "health_before": actual, "strict": strict}

def _finish_snapshot(res, ctx, snapshot):
    evidence = dict(snapshot)
    sid = snapshot.get("id")
    if sid:
        health = _proxy_health()
        after = (health or {}).get("snapshot") or {}
        before = snapshot.get("health_before") or {}
        bad = ("missing_entries", "integrity_errors", "fetch_errors", "blocked_artifact_requests")
        problems = [k for k in bad if after.get(k, 0) > before.get(k, 0)]
        if after.get("id") != sid or after.get("mode") != snapshot.get("mode"):
            problems.append("snapshot identity/health unavailable")
        if not after.get("integrity_ok", False): problems.append("snapshot integrity failure")
        evidence["health_after"] = after
        evidence["complete"] = not problems
        evidence["integrity_verified"] = not problems
        evidence["sealed"] = bool(snapshot.get("mode") == "replay" and before.get("frozen") and after.get("frozen"))
        evidence["frozen"] = evidence["sealed"]
        evidence["manifest_sha256"] = after.get("manifest_sha256")
        evidence["candidate_policy"] = after.get("candidate_policy")
        if evidence["sealed"] and before.get("manifest_sha256") != after.get("manifest_sha256"):
            problems.append("sealed snapshot manifest changed during resolution")
            evidence["complete"] = evidence["integrity_verified"] = False
        evidence["problems"] = problems
        if problems:
            res.ok = False
            res.error = (res.error + "; " if res.error else "") + "snapshot verification failed: " + ", ".join(problems)
    res.snapshot = evidence
    return res

def _b64e(s: str) -> str:
    import base64
    return base64.urlsafe_b64encode(s.encode()).decode().rstrip("=")

def _b64d(s: str) -> str:
    import base64
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4)).decode()

def proxy_index(url: str, ctx=None) -> str:
    sid, _, _ = _snapshot_config(ctx)
    prefix = f"/s/{sid}" if sid else ""
    return f"http://127.0.0.1:{PROXY_PORT}{prefix}/idx/{_b64e(url.rstrip('/'))}/simple"

def unproxy_url(url: str) -> str:
    m = re.match(r"^http://127\.0\.0\.1:\d+/(?:s/[A-Za-z0-9._-]+/)?f/([A-Za-z0-9_-]+)/[^/#]+(#.*)?$", url or "")
    if not m: return url
    return _b64d(m.group(1)) + (m.group(2) or "")

def unproxy_index(url: str) -> str:
    m = re.match(r"^http://127\.0\.0\.1:\d+/(?:s/[A-Za-z0-9._-]+/)?idx/([A-Za-z0-9_-]+)/simple/?$", url or "")
    return _b64d(m.group(1)) if m else url

def ensure_proxy(ctx=None) -> bool:
    """Verify the requested proxy, never silently reuse a different snapshot."""
    sid, mode, strict = _snapshot_config(ctx)
    if not USE_PROXY and not sid: return False
    health = _proxy_health()
    try:
        if health is None:
            script = pathlib.Path(__file__).resolve().parents[1] / "proxy.py"
            args = ["--port", str(PROXY_PORT), "--cache", f"{WSL_CACHE}/reliability-proxy" if EXEC == "wsl" else str(CACHE_ROOT / "proxy")]
            if sid: args += ["--snapshot-id", sid, "--mode", mode]
            if EXEC == "wsl":
                cmd = [WSL_PY, to_wsl_path(script), *args]
                line = (f"mkdir -p {_shq(WSL_CACHE)}; nohup setsid " + " ".join(_shq(x) for x in cmd)
                        + f" > {_shq(WSL_CACHE + '/proxy-' + (sid or 'legacy') + '.log')} 2>&1 < /dev/null &")
                subprocess.run(["wsl", "-d", WSL_DISTRO, "--", "bash", "-c", line], capture_output=True,
                               timeout=15, stdin=subprocess.DEVNULL)
            else:
                kwargs = {"stdin": subprocess.DEVNULL, "stdout": subprocess.DEVNULL, "stderr": subprocess.DEVNULL}
                if os.name == "nt": kwargs["creationflags"] = subprocess.CREATE_NO_WINDOW
                subprocess.Popen([PY, str(script), *args], **kwargs)
            for _ in range(3):
                time.sleep(0.1)
                health = _proxy_health()
                if health is not None: break
        if not health or "pages" not in health:
            raise ReproducibilityError("proxy did not return a valid health record")
        actual = health.get("snapshot") or {}
        if sid and (actual.get("id") != sid or actual.get("mode") != mode):
            raise ReproducibilityError("another proxy/snapshot already uses this port; choose DRC_PROXY_PORT")
        if not sid and actual:
            raise ReproducibilityError("a snapshot proxy cannot serve an unspecified legacy request")
        _proxy_ok.update(t=time.time(), error="")
        return True
    except (OSError, ValueError, subprocess.SubprocessError, ReproducibilityError) as exc:
        _proxy_ok["error"] = str(exc)
        return False

def _pip_index_args(ctx: Context, use_proxy=None) -> list:
    args = []
    use = ensure_proxy(ctx) if use_proxy is None else use_proxy
    px = (lambda u: proxy_index(u, ctx)) if use else (lambda u: u)
    if ctx.no_index: args.append("--no-index")
    if ctx.index_url: args += ["--index-url", px(ctx.index_url)]
    elif use: args += ["--index-url", px(PYPI_SIMPLE)]
    for u in ctx.extra_index_urls: args += ["--extra-index-url", px(u)]
    for u in ctx.find_links: args += ["--find-links", u]
    if ctx.pre: args.append("--pre")
    return args

# ----------------------------------------------------------------------------- uv
def run_uv(ctx: Context, workdir: pathlib.Path) -> Resolution:
    """uv lock on a generated project (honours [[tool.uv.index]] / [tool.uv.sources] / index-strategy), restricted to one environment."""
    error = _preflight(ctx, "uv")
    if error: return _failed(ctx, "uv", error)
    try: snapshot = _prepare_snapshot(ctx)
    except ReproducibilityError as exc: return _failed(ctx, "uv", str(exc))
    _resolver_version("uv")
    workdir = workdir.resolve()
    workdir.mkdir(parents=True, exist_ok=True)
    pyver = ctx.python_version
    marker_environment = _target_marker_environment(ctx)
    full_python = marker_environment.get("python_full_version", "")
    exact_target = bool(full_python and _python_minor(full_python) == _python_minor(pyver))
    requires_python = "==" + (full_python if exact_target else pyver + ".*")
    py_marker = {"linux-x86_64": "sys_platform == 'linux' and platform_machine == 'x86_64'", "linux-aarch64": "sys_platform == 'linux' and platform_machine == 'aarch64'",
                 "macos-arm64": "sys_platform == 'darwin' and platform_machine == 'arm64'", "windows-x86_64": "sys_platform == 'win32'"}[ctx.platform]
    if marker_environment:
        py_marker = " and ".join(key + " == " + json.dumps(value) for key, value in sorted(marker_environment.items())
                                  if isinstance(value, str) and key not in ("extra", "extras", "dependency_groups"))
    deps = [_uv_dep_string(r) for r in ctx.requirements]
    lines = ["[project]", 'name = "drc-probe"', 'version = "0.0.0"', f'requires-python = "{requires_python}"', "dependencies = [", *[f"    {json.dumps(d)}," for d in deps if d], "]", "",
             "[tool.uv]", f'environments = [{json.dumps(py_marker)}]']
    if ctx.index_strategy: lines.append(f'index-strategy = "{ctx.index_strategy}"')
    if ctx.pre: lines.append('prerelease = "allow"')
    if ctx.constraints: lines.append("constraint-dependencies = [" + ", ".join(json.dumps(c) for c in ctx.constraints) + "]")
    if ctx.no_index: lines.append("no-index = true")
    if ctx.find_links: lines.append("find-links = [" + ", ".join(json.dumps(u) for u in ctx.find_links) + "]")
    # indexes: named indexes first (uv: earlier = higher priority), then primary/extra as tool.uv index entries
    named = list(ctx.named_indexes)
    if ctx.index_url and not any(n.get("url") == ctx.index_url for n in named):
        named.append({"name": "drc-primary", "url": ctx.index_url, "default": True})
    for i, u in enumerate(ctx.extra_index_urls):
        if not any(n.get("url") == u for n in named): named.insert(0 if False else len(named), {"name": f"drc-extra{i}", "url": u})
    # uv semantics: extra-index-url entries have higher priority than the default index (like pip --extra-index-url first-index behaviour)
    # We express this ordering: extras first, then default.
    ordered = [n for n in named if not n.get("default")] + [n for n in named if n.get("default")]
    # uv otherwise adds live PyPI implicitly. Make that default explicit through
    # the same proxy used by pip, including in legacy recording mode.
    if snapshot.get("proxy_verified") and not ctx.no_index and not any(n.get("default") for n in ordered):
        ordered.append({"name": "drc-pypi-default", "url": PYPI_SIMPLE, "default": True})
    for n in ordered:
        index_url = proxy_index(n["url"], ctx) if snapshot.get("proxy_verified") else n["url"]
        lines += ["", "[[tool.uv.index]]", f'name = {json.dumps(n["name"])}', f'url = {json.dumps(index_url)}']
        if n.get("explicit"): lines.append("explicit = true")
        if n.get("default"): lines.append("default = true")
    if ctx.sources:
        lines += ["", "[tool.uv.sources]"]
        for dep, idx in ctx.sources.items():
            lines.append(f'{json.dumps(dep)} = {{ index = {json.dumps(idx)} }}')
    (workdir / "pyproject.toml").write_text("\n".join(lines) + "\n", encoding="utf-8")
    lock = workdir / "uv.lock"
    if lock.exists(): lock.unlink()
    # SAFETY: --no-build -> never execute third-party build backends; wheels (or static sdist metadata) only.
    cmd = [PY, "-m", "uv", "lock", "--no-progress", "--color", "never", "--no-build", "--cache-dir", str(_resolver_cache(ctx, "uv")), "--python", pyver]
    # NOTE: do not set UV_NO_CONFIG -- it makes uv ignore [tool.uv] in the generated pyproject (indexes/sources/strategy).
    env = dict(os.environ); env["UV_PYTHON_PREFERENCE"] = "managed"; env["UV_NO_INPUT"] = "1"
    env["XDG_CONFIG_HOME"] = str(CACHE_ROOT / "empty-xdg"); env["APPDATA"] = str(CACHE_ROOT / "empty-appdata")  # isolate from user-level uv.toml
    (CACHE_ROOT / "empty-xdg").mkdir(parents=True, exist_ok=True); (CACHE_ROOT / "empty-appdata").mkdir(parents=True, exist_ok=True)
    for k in list(env):
        if k.startswith(("UV_INDEX", "UV_EXTRA", "UV_DEFAULT", "UV_FIND", "PIP_")): env.pop(k, None)
    _snapshot_env(env, ctx)
    t0 = time.time()
    try:
        p, shown = _run(cmd, workdir, env, UV_TIMEOUT, "uv", pyver)
    except subprocess.TimeoutExpired:
        return _finish_snapshot(Resolution(ctx.id, "uv", False, {}, time.time() - t0, " ".join(cmd), "timeout", UV_VERSION, _now()), ctx, snapshot)
    secs = time.time() - t0
    if p.returncode != 0 or not lock.exists():
        return _finish_snapshot(Resolution(ctx.id, "uv", False, {}, secs, shown, (p.stderr or "")[-6000:], UV_VERSION, _now()), ctx, snapshot)
    import tomllib
    try: d = tomllib.loads(lock.read_text(encoding="utf-8"))
    except tomllib.TOMLDecodeError as e:
        return _finish_snapshot(Resolution(ctx.id, "uv", False, {}, secs, " ".join(cmd), f"bad lock: {e}", UV_VERSION, _now()), ctx, snapshot)
    arts, projection = project_uv_lock(d, ctx, marker_environment)
    projection["environment_source"] = "adapter-interpreter-and-explicit-target"
    result = Resolution(ctx.id, "uv", True, arts, secs, shown, "", UV_VERSION, _now(), graph_projection=projection)
    return _finish_snapshot(result, ctx, snapshot)

def _uv_dep_string(r: str) -> str:
    return r.strip()

def run(ctx: Context, workdir: pathlib.Path) -> Resolution:
    return run_pip(ctx, workdir) if ctx.resolver == "pip" else run_uv(ctx, workdir)
