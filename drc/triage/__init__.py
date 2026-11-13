"""Triage of ambiguity cases: benign / needs-explanation / suspicious.

For each case we (1) download both artifacts when small enough and compare contents, (2) fetch PyPI metadata for
the PyPI side (upload time, uploader/author, project URLs, release count, attestations), (3) scan for install-time
code / obfuscation / network indicators in differing files, and (4) assign a label with an explicit reason.
Labels:
  BENIGN            identical content (metadata/RECORD-only differences), or explained variant (same project, hardware build), or mirror copy
  NEEDS_EXPLANATION content differs beyond metadata, version regression, unexpected registry, or artifacts too large to compare
  SUSPICIOUS        indicators of malicious substitution (unknown publisher squatting a name, install hooks with network/exec, obfuscated code)
"""
from __future__ import annotations
import io, json, os, re, zipfile, tarfile, hashlib, pathlib, time, urllib.request, urllib.error
from typing import Optional
from packaging.version import Version, InvalidVersion

MAX_DOWNLOAD = int(os.environ.get("DRC_TRIAGE_MAX_MB", "120")) * 1024 * 1024
CACHE = pathlib.Path(__file__).resolve().parents[2] / "results" / "_cache" / "artifacts"
CACHE.mkdir(parents=True, exist_ok=True)
UA = {"User-Agent": "drc-research-prototype/0.1 (dependency-resolution-consistency study)"}

SUSPICIOUS_CODE = re.compile(rb"(base64\.b64decode|exec\(|eval\(|subprocess\.(Popen|call|run)|os\.system|urllib\.request\.urlopen|requests\.(get|post)|socket\.socket|__import__\(|marshal\.loads|zlib\.decompress|compile\(|/etc/passwd|\.ssh/|AWS_SECRET|curl \| sh|wget .* \| sh|powershell -e)", re.I)

def _get(url: str, limit: Optional[int] = None) -> bytes:
    key = hashlib.sha256(url.encode()).hexdigest()
    cf = CACHE / key
    if cf.exists(): return cf.read_bytes()
    req = urllib.request.Request(url, headers=UA)
    with urllib.request.urlopen(req, timeout=120) as r:
        size = r.headers.get("Content-Length")
        if limit and size and int(size) > limit: raise ValueError(f"too large: {size}")
        data = r.read(limit + 1 if limit else None)
        if limit and len(data) > limit: raise ValueError("too large (stream)")
    cf.write_bytes(data)
    return data

def _head_size(url: str) -> Optional[int]:
    try:
        req = urllib.request.Request(url, method="HEAD", headers=UA)
        with urllib.request.urlopen(req, timeout=60) as r:
            cl = r.headers.get("Content-Length"); return int(cl) if cl else None
    except Exception:
        return None

def _members(data: bytes, filename: str) -> dict[str, bytes]:
    out = {}
    if filename.endswith(".whl") or filename.endswith(".zip"):
        with zipfile.ZipFile(io.BytesIO(data)) as z:
            for n in z.namelist():
                if n.endswith("/"): continue
                out[n] = z.read(n)
    elif re.search(r"\.(tar\.gz|tgz|tar\.bz2|tar)$", filename):
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:*") as t:
            for m in t.getmembers():
                if m.isfile():
                    f = t.extractfile(m)
                    if f: out["/".join(m.name.split("/")[1:]) or m.name] = f.read()
    return out

def _is_meta(path: str) -> bool:
    return bool(re.search(r"(\.dist-info/(RECORD|WHEEL|METADATA|direct_url\.json|INSTALLER|REQUESTED)|PKG-INFO|\.egg-info/|SOURCES\.txt|licenses?/|LICENSE|NOTICE)", path, re.I))

def _norm_metadata(b: bytes) -> bytes:
    # strip fields that legitimately differ between builds of the same source
    lines = [l for l in b.splitlines() if not l.startswith((b"Generator:", b"Tag:", b"Build:", b"Root-Is-Purelib:"))]
    return b"\n".join(lines)

def compare_contents(url_a: str, fn_a: str, url_b: str, fn_b: str) -> dict:
    res = {"compared": False}
    sizes = (_head_size(url_a), _head_size(url_b))
    res["sizes"] = sizes
    if any(s is None for s in sizes) or any(s > MAX_DOWNLOAD for s in sizes):
        res["reason"] = f"artifact too large or size unknown (limit {MAX_DOWNLOAD // 1024 // 1024} MB)"; return res
    try:
        A = _members(_get(url_a, MAX_DOWNLOAD), fn_a); B = _members(_get(url_b, MAX_DOWNLOAD), fn_b)
    except Exception as e:
        res["reason"] = f"download/extract failed: {type(e).__name__}: {str(e)[:120]}"; return res
    # normalise top-level dist-info dir name (version/tag in name) so that same files compare equal
    def norm(d):
        out = {}
        for k, v in d.items():
            k2 = re.sub(r"^[^/]+\.dist-info/", "DIST-INFO/", k); k2 = re.sub(r"^[^/]+\.egg-info/", "EGG-INFO/", k2)
            out[k2] = v
        return out
    A, B = norm(A), norm(B)
    same = only_a = only_b = differ = 0; differ_files = []; differ_code = []; meta_only = True
    for k in sorted(set(A) | set(B)):
        if k in A and k in B:
            va, vb = A[k], B[k]
            if k.endswith(("METADATA", "PKG-INFO", "WHEEL")): va, vb = _norm_metadata(va), _norm_metadata(vb)
            if va == vb: same += 1
            else:
                differ += 1; differ_files.append(k)
                if not _is_meta(k): meta_only = False; differ_code.append(k)
        elif k in A:
            only_a += 1
            if not _is_meta(k): meta_only = False; differ_code.append("A:" + k)
        else:
            only_b += 1
            if not _is_meta(k): meta_only = False; differ_code.append("B:" + k)
    sus = []
    for k in differ_code[:400]:
        side, _, name = k.partition(":") if k.startswith(("A:", "B:")) else ("", "", k)
        blob = (A if side == "A" else B if side == "B" else A).get(name) or (B.get(name) if not side else None) or b""
        if name.endswith((".py", ".sh", ".cfg", ".toml", ".pth")) and SUSPICIOUS_CODE.search(blob):
            sus.append({"file": k, "hits": sorted({m.group(0).decode("latin1")[:30] for m in SUSPICIOUS_CODE.finditer(blob)})[:6]})
    hooks = [k for k in (set(A) | set(B)) if re.search(r"(^|/)(setup\.py|__init__\.py)$", k) and k.count("/") <= 1] if fn_a.endswith((".tar.gz", ".zip")) or fn_b.endswith((".tar.gz", ".zip")) else []
    pth = [k for k in (set(A) | set(B)) if k.endswith(".pth")]
    res.update({"compared": True, "same": same, "only_a": only_a, "only_b": only_b, "differ": differ, "differ_files": differ_files[:50], "differ_code": differ_code[:50],
                "metadata_only": meta_only, "suspicious_hits": sus[:20], "pth_files": pth[:10], "sdist_hooks": hooks[:10], "n_files": (len(A), len(B))})
    return res

def pypi_meta(name: str, version: Optional[str] = None) -> dict:
    try:
        d = json.loads(_get(f"https://pypi.org/pypi/{name}/json").decode("utf-8"))
    except Exception as e:
        return {"error": f"{type(e).__name__}: {str(e)[:100]}"}
    info = d.get("info", {}); rel = d.get("releases", {})
    uploads = sorted((f.get("upload_time_iso_8601") or f.get("upload_time") or "" for files in rel.values() for f in files if f), reverse=False)
    vfiles = rel.get(version, []) if version else []
    out = {"name": info.get("name"), "author": info.get("author") or info.get("author_email"), "maintainer": info.get("maintainer") or info.get("maintainer_email"),
           "home_page": info.get("home_page") or (info.get("project_urls") or {}).get("Homepage") or (info.get("project_urls") or {}).get("Source"),
           "project_urls": info.get("project_urls"), "n_releases": len(rel), "first_upload": uploads[0] if uploads else None, "last_upload": uploads[-1] if uploads else None,
           "latest": info.get("version"), "summary": (info.get("summary") or "")[:160]}
    if vfiles:
        out["version_upload"] = sorted(f.get("upload_time_iso_8601", "") for f in vfiles)[0]
        out["version_has_attestation"] = any(f.get("provenance") for f in vfiles)
        out["version_yanked"] = any(f.get("yanked") for f in vfiles)
    return out

MIRROR_HOSTS = ("mirrors.cernet.edu.cn", "mirrors.tuna.tsinghua.edu.cn", "pypi.tuna.tsinghua.edu.cn", "mirrors.aliyun.com", "mirrors.huaweicloud.com", "repo.huaweicloud.com", "mirrors.ustc.edu.cn",
                "pypi.douban.com", "mirrors.cloud.tencent.com", "mirror.baidu.com", "pypi.mirrors.ustc.edu.cn", "aiinfra.pkgs.visualstudio.com", "files.pythonhosted.org")

def _is_pypi_mirror(reg: str) -> bool:
    return any(reg.startswith(h) for h in MIRROR_HOSTS)

def _version_on_pypi(name: str, version: str) -> Optional[dict]:
    """Return PyPI release info for (name, version) if it exists on PyPI right now (mirror freshness check)."""
    try:
        d = json.loads(_get(f"https://pypi.org/pypi/{name}/json").decode("utf-8"))
    except Exception:
        return None
    files = d.get("releases", {}).get(version)
    if not files: return {"exists": False}
    return {"exists": True, "upload": sorted(f.get("upload_time_iso_8601", "") for f in files)[0], "sha256s": sorted(f.get("digests", {}).get("sha256", "") for f in files)}

def triage_case(case: dict, do_content: bool = True) -> dict:
    a, b = case["a"]["artifact"], case["b"]["artifact"]
    cls = case["cls"]
    out = {"label": None, "reason": None, "notes": []}
    pypi_side = next((x for x in (a, b) if x and x["registry"] == "pypi"), None)
    custom_side = next((x for x in (a, b) if x and x["registry"] != "pypi"), None)
    if pypi_side:
        out["pypi_meta"] = pypi_meta(pypi_side["name"], pypi_side["version"])
    # --- PyPI mirrors: differences are explained by snapshot timing (our proxy freezes each index page at first fetch)
    if a and b and custom_side and _is_pypi_mirror(custom_side["registry"]):
        vp = _version_on_pypi(custom_side["name"], custom_side["version"])
        out["mirror_check"] = vp
        if vp and vp.get("exists") and (not custom_side.get("sha256") or custom_side["sha256"] in vp.get("sha256s", [])):
            out["label"] = "BENIGN"; out["reason"] = f"{custom_side['registry']} is a PyPI mirror; version {custom_side['version']} exists on PyPI with the same file hash -> difference is index snapshot timing / mirror lag, not a different artifact"; return out
        if vp and vp.get("exists"):
            out["notes"].append("mirror serves a file whose hash is not among PyPI's files for that version")
        elif vp and not vp.get("exists"):
            out["notes"].append("mirror serves a version that does not exist on PyPI")
    # --- same release on PyPI, different wheel file (tag / ABI choice by the resolver): both hashes belong to PyPI's file list
    if a and b and cls == "SAME_VERSION_DIFF_HASH_SAME_REGISTRY" and a["registry"] == "pypi" and b["registry"] == "pypi":
        vp = _version_on_pypi(a["name"], a["version"]); out["pypi_release_files"] = vp
        if vp and vp.get("exists") and a.get("sha256") in vp.get("sha256s", []) and b.get("sha256") in vp.get("sha256s", []):
            out["label"] = "BENIGN"; out["reason"] = f"both files are official PyPI files of release {a['version']} ({a['filename']} vs {b['filename']}): resolvers picked different wheel tags for the same release"; return out
    # --- TestPyPI is not a mirror: anyone can upload namesakes there
    if custom_side and custom_side["registry"].startswith(("testpypi", "test-files.pythonhosted.org")):
        out["testpypi"] = True
        try:
            d = json.loads(_get(f"https://test.pypi.org/pypi/{custom_side['name']}/json").decode("utf-8")); info = d.get("info", {})
            out["testpypi_meta"] = {"author": info.get("author") or info.get("author_email"), "home_page": info.get("home_page") or (info.get("project_urls") or {}).get("Homepage"), "n_releases": len(d.get("releases", {})), "summary": (info.get("summary") or "")[:120]}
        except Exception as e:
            out["testpypi_meta"] = {"error": str(e)[:80]}
    # presence-only differences
    if cls in ("ONLY_IN_A", "ONLY_IN_B"):
        out["label"] = "NEEDS_EXPLANATION"; out["reason"] = "package present in only one context (dependency-graph difference); requires reading both graphs"
        return out
    if a and b and do_content and cls in ("SAME_VERSION_DIFF_REGISTRY", "SAME_VERSION_DIFF_HASH_SAME_REGISTRY", "LOCAL_VARIANT", "DIFF_VERSION_DIFF_REGISTRY", "DIFF_VERSION_SAME_REGISTRY", "WHEEL_VS_SDIST"):
        cd = compare_contents(a["url"], a["filename"], b["url"], b["filename"])
        out["content_diff"] = cd
    cd = out.get("content_diff") or {}
    same_project = _same_project(a, b, out.get("pypi_meta"))
    # identical official file: the custom-side (name, version) exists on PyPI with the *same* sha256 -> only version shadowing, artifact is official
    if custom_side and custom_side.get("sha256"):
        vp2 = _version_on_pypi(custom_side["name"], custom_side["version"]); out["custom_version_on_pypi"] = vp2
        if vp2 and vp2.get("exists") and custom_side["sha256"] in vp2.get("sha256s", []):
            same_project = True
            if cls in ("DIFF_VERSION_DIFF_REGISTRY", "DIFF_VERSION_SAME_REGISTRY"):
                out["same_project_signal"] = True
                out["label"] = "NEEDS_EXPLANATION"; out["reason"] = f"version shadowing between registries, but the file served by {custom_side['registry']} ({custom_side['name']} {custom_side['version']}) is byte-identical to PyPI's official file of that version; " + _version_regression(a, b); return out
    out["same_project_signal"] = same_project
    # ---------------- labelling rules
    if cd.get("compared"):
        high = [h for h in cd.get("suspicious_hits", []) if any(x in json.dumps(h) for x in ("b64decode", "marshal.loads", "socket.socket", "/etc/passwd", ".ssh/", "AWS_SECRET", "curl | sh", "wget", "powershell -e", "zlib.decompress"))]
        squat = bool(pypi_side and out.get("pypi_meta") and _looks_squatted(out["pypi_meta"], custom_side))
        if not same_project and (squat or (high and cd.get("differ_code"))):
            out["label"] = "SUSPICIOUS"; out["reason"] = ("public namesake looks squatted; " if squat else "") + (f"differing code contains high-risk indicators: {high[:3]}" if high else ""); return out
        if cls in ("SAME_VERSION_DIFF_REGISTRY", "SAME_VERSION_DIFF_HASH_SAME_REGISTRY") and cd.get("metadata_only"):
            out["label"] = "BENIGN"; out["reason"] = "same version; file contents identical except packaging metadata (RECORD/WHEEL/METADATA) -> mirror/rebuild of the same release"; return out
        if cls in ("SAME_VERSION_DIFF_REGISTRY", "SAME_VERSION_DIFF_HASH_SAME_REGISTRY") and not cd.get("metadata_only"):
            out["label"] = "NEEDS_EXPLANATION"; out["reason"] = f"same version string but {len(cd.get('differ_code', []))} non-metadata files differ between registries ({', '.join(cd.get('differ_code', [])[:5])})"; return out
        if cls == "LOCAL_VARIANT":
            out["label"] = "BENIGN" if same_project else "NEEDS_EXPLANATION"
            out["reason"] = "hardware/local variant of the same project (+cuXXX/+cpu build); differs by design" if same_project else "local variant with no evidence both files are the same project"; return out
        if cls in ("DIFF_VERSION_DIFF_REGISTRY", "DIFF_VERSION_SAME_REGISTRY"):
            reg = _version_regression(a, b)
            if not same_project and pypi_side and out.get("pypi_meta") and _looks_squatted(out["pypi_meta"], custom_side):
                out["label"] = "SUSPICIOUS"; out["reason"] = f"public-registry package with same name has few releases / recent first upload / unrelated URLs: {json.dumps({k: out['pypi_meta'].get(k) for k in ('n_releases', 'first_upload', 'home_page', 'author')}, default=str)}"; return out
            out["label"] = "NEEDS_EXPLANATION"
            out["reason"] = ("version shadowing: " + reg) if reg else "different versions selected"
            if same_project: out["reason"] += " (same project on both registries; versions on the custom index lag/lead the public index)"
            return out
        if cls == "WHEEL_VS_SDIST":
            out["label"] = "BENIGN" if same_project else "NEEDS_EXPLANATION"; out["reason"] = "wheel vs sdist of the same release" if same_project else "wheel vs sdist, provenance unclear"; return out
    # no content comparison possible
    if cls in ("LOCAL_VARIANT",) and same_project:
        out["label"] = "BENIGN"; out["reason"] = "hardware/local variant of the same project (content not compared: " + str(cd.get("reason")) + ")"; return out
    if cls in ("DIFF_VERSION_DIFF_REGISTRY", "DIFF_VERSION_SAME_REGISTRY") and pypi_side and out.get("pypi_meta") and not same_project and _looks_squatted(out["pypi_meta"], custom_side):
        out["label"] = "SUSPICIOUS"; out["reason"] = "public-registry namesake looks unrelated to the custom-index package (few releases / recent / unrelated URLs)"; return out
    out["label"] = "NEEDS_EXPLANATION"
    out["reason"] = f"{cls}: " + (cd.get("reason") or "content not compared") + (f"; {_version_regression(a, b)}" if a and b and a['version'] != b['version'] else "")
    return out

def _version_regression(a, b) -> str:
    try:
        va, vb = Version(a["version"]), Version(b["version"])
    except (InvalidVersion, KeyError, TypeError):
        return ""
    newer, older = (a, b) if va > vb else (b, a)
    return f"{newer['registry']} serves newer {newer['version']} vs {older['registry']} {older['version']}"

def _same_project(a, b, pm) -> bool:
    """Heuristic: the two artifacts are builds of the same upstream project."""
    if not a or not b: return False
    regs = {a["registry"], b["registry"]}
    # PyTorch / NVIDIA / Intel / ROCm channels host official rebuilds & mirrors of PyPI projects
    fam = {r.split(":")[0] for r in regs}
    if fam <= {"pypi", "pytorch"} or fam <= {"pypi", "nvidia"} or fam <= {"pypi", "jax-releases"} or fam <= {"pypi", "anaconda"} or fam <= {"pypi", "pyg"} or fam <= {"pypi", "dgl"} or fam <= {"pypi", "rocm"}:
        return True
    if pm and not pm.get("error"):
        urls = " ".join([pm.get("home_page") or ""] + list((pm.get("project_urls") or {}).values()))
        # established PyPI project (many releases, old) with source URLs: a namesake elsewhere is far more likely a mirror/rebuild/test upload than a squat
        if (pm.get("n_releases") or 0) >= 10 and (pm.get("first_upload") or "9999") < "2023-01" and any(k in urls for k in ("github.com", "gitlab.com", "pypa.io", "readthedocs")):
            return True
    return False

def _looks_squatted(pm: dict, custom_side) -> bool:
    if not pm or pm.get("error"): return False
    n = pm.get("n_releases") or 0
    recent = (pm.get("first_upload") or "9999") > "2024-06"
    no_urls = not pm.get("home_page") and not pm.get("project_urls")
    return (n <= 3 and recent) or (n <= 2 and no_urls)
