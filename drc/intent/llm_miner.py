"""LLM-assisted intent-evidence mining (Phase 2).

Backend: the `claude` CLI in headless mode (`claude -p --output-format json`). The LLM only extracts
*evidence* (dependency -> intended registry/variant, with file + verbatim quote); every quote is verified
programmatically against the file content and unverifiable items are dropped. Results are cached by content hash.
"""
from __future__ import annotations
import json, os, re, subprocess, hashlib, pathlib, time
from typing import Optional
from packaging.utils import canonicalize_name
from ..model import ProjectIR, registry_id
from .structured_evidence import Evidence, E4, E1, E3

MODEL = os.environ.get("DRC_LLM_MODEL", "sonnet")
MAX_CHARS = int(os.environ.get("DRC_LLM_MAX_CHARS", "60000"))
TIMEOUT = int(os.environ.get("DRC_LLM_TIMEOUT", "300"))
CACHE = pathlib.Path(__file__).resolve().parents[2] / "results" / "_cache" / "llm"
CACHE.mkdir(parents=True, exist_ok=True)

_INDEX_HINT = re.compile(r"(index-url|extra-index-url|find-links|download\.pytorch\.org|pypi\.nvidia|nvidia\.com|jax-releases|whl/|wheel|CUDA|cu1[0-9]{2}|ROCm|rocm|cpu-only|CPU only|nightly|private (index|registry|repository|PyPI)|Artifactory|Nexus|devpi|package index|mirror|tsinghua|aliyun|official (wheel|build|package)|--index|--extra-index|uv add|uv pip|pip install|poetry source|tool\.uv\.sources|\[\[tool\.uv\.index\]\])", re.I)

PROMPT = """You are extracting *dependency source intent evidence* from a software project's files.

Goal: for Python dependencies of this project, find statements that indicate WHICH package index / registry / wheel source a dependency is intended to come from, or WHICH hardware variant (CUDA/CPU/ROCm/XPU) is intended, or that a dependency must be installed from a specific/official/private source. Also note wrapper scripts or docs that introduce an index that is not visible in the packaging configuration.

Rules:
- Only report what the text literally supports. Do NOT infer from general knowledge which index a package "usually" comes from.
- Every item must include the exact file path and a VERBATIM quote (<= 200 chars) copied from that file which supports it. The quote must appear in the file exactly.
- registry_url must be a URL that appears in the quote or elsewhere in the same file; if the text names a source without URL (e.g. "PyTorch nightly index", "our internal Artifactory"), put the name in registry_name and leave registry_url null.
- dependency: the package name as written (or "*" if the statement applies to the whole install / all dependencies).
- kind: one of "source_binding" (this dep must come from that index), "variant" (CUDA/CPU/ROCm build requirement), "install_instruction" (docs tell users to install from an index), "wrapper_index" (a script/CI/Docker introduces an index), "warning" (docs warn about wrong source/version), "other".
- confidence: "high" if the text explicitly binds the dependency to the source; "medium" if the instruction is for a whole install command that includes the dependency; "low" otherwise.
Return ONLY a JSON object: {"items": [{"dependency": str, "kind": str, "registry_url": str|null, "registry_name": str|null, "variant": str|null, "file": str, "quote": str, "confidence": str, "note": str}]}
If nothing is found return {"items": []}.

PROJECT: %s
FILES (path then content; long files are excerpted around index-related lines):
%s
"""

def _select_files(ir: ProjectIR, root: pathlib.Path) -> list[tuple[str, str]]:
    """Choose README/docs/CI/Docker/scripts/config excerpts most likely to carry source intent."""
    cands = []
    for rel in ir.files:
        p = root / rel
        low = rel.lower(); name = low.rsplit("/", 1)[-1]
        if not p.is_file(): continue
        pri = 9
        if name.startswith("readme"): pri = 0
        elif re.search(r"install|setup|getting|quick|start|build|environment|depend", low) and name.endswith((".md", ".rst")): pri = 1
        elif name == "pyproject.toml" or name.endswith((".txt", ".in")) and "req" in name: pri = 2
        elif low.startswith(".github/workflows/") or name.startswith("dockerfile") or name.endswith(".dockerfile"): pri = 3
        elif name.endswith((".sh", "makefile", "tox.ini", "noxfile.py", ".cfg", "pip.conf", "uv.toml", "environment.yml")): pri = 4
        elif name.endswith((".md", ".rst")): pri = 5
        else: continue
        try: text = p.read_text(encoding="utf-8", errors="replace")
        except OSError: continue
        if not _INDEX_HINT.search(text) and pri > 2: continue
        cands.append((pri, rel, text))
    cands.sort(key=lambda x: (x[0], x[1]))
    out = []; total = 0
    for pri, rel, text in cands:
        ex = _excerpt(text, 2500 if pri <= 1 else 1800)
        if total + len(ex) > MAX_CHARS: break
        out.append((rel, ex)); total += len(ex)
    return out

def _excerpt(text: str, limit: int) -> str:
    if len(text) <= limit: return text
    lines = text.splitlines()
    hits = [i for i, l in enumerate(lines) if _INDEX_HINT.search(l)]
    if not hits: return text[:limit]
    keep = set()
    for i in hits:
        for j in range(max(0, i - 6), min(len(lines), i + 7)): keep.add(j)
    out = []; last = -1; size = 0
    for j in sorted(keep):
        if j != last + 1: out.append("...")
        out.append(lines[j]); size += len(lines[j]) + 1; last = j
        if size > limit: break
    return "\n".join(out)

def _call_claude(prompt: str) -> tuple[Optional[dict], dict]:
    key = hashlib.sha256((MODEL + prompt).encode("utf-8")).hexdigest()
    cf = CACHE / f"{key}.json"
    if cf.exists():
        d = json.loads(cf.read_text(encoding="utf-8")); d["cached"] = True; return d.get("parsed"), d
    t0 = time.time()
    # disable agentic tools: we want a single extraction answer, not file reads / shell
    cmd = ["claude", "-p", "--output-format", "json", "--model", MODEL, "--max-turns", "3",
           "--disallowedTools", "Bash,Read,Edit,Write,MultiEdit,Glob,Grep,LS,WebFetch,WebSearch,Task,TodoWrite,NotebookEdit,NotebookRead,Agent"]
    try:
        p = subprocess.run(cmd, input=prompt, capture_output=True, text=True, timeout=TIMEOUT, encoding="utf-8", errors="replace", shell=(os.name == "nt"))
    except subprocess.TimeoutExpired:
        return None, {"error": "timeout", "seconds": time.time() - t0}
    meta = {"seconds": round(time.time() - t0, 1), "returncode": p.returncode, "prompt_chars": len(prompt), "model": MODEL}
    try:
        outer = json.loads(p.stdout)
        meta["cost_usd"] = outer.get("total_cost_usd"); meta["usage"] = outer.get("usage"); meta["model_usage"] = outer.get("modelUsage"); meta["num_turns"] = outer.get("num_turns")
        result = outer.get("result", "") or ""
    except json.JSONDecodeError:
        meta["error"] = "non-json stdout: " + p.stdout[:300] + " / " + p.stderr[:300]; return None, meta
    m = re.search(r"\{.*\}", result, re.S)
    parsed = None
    if m:
        try: parsed = json.loads(m.group(0))
        except json.JSONDecodeError as e: meta["error"] = f"bad json in result: {e}"
    else:
        meta["error"] = "empty or non-json result"
    meta["parsed"] = parsed; meta["raw"] = result[:20000]
    if parsed is not None:
        cf.write_text(json.dumps(meta), encoding="utf-8")   # cache only successful extractions
    return parsed, meta

def mine_llm_evidence(ir: ProjectIR, root: pathlib.Path, out_dir: pathlib.Path) -> tuple[list[Evidence], dict]:
    root = pathlib.Path(root)
    files = _select_files(ir, root)
    stats = {"files": len(files), "chars": sum(len(t) for _, t in files), "items": 0, "verified": 0, "dropped_unverified": 0, "calls": 0}
    if not files: return [], stats
    prompt = PROMPT % (ir.repo, "\n\n".join(f"=== {rel}\n{txt}" for rel, txt in files))
    (out_dir / "llm_prompt.txt").write_text(prompt, encoding="utf-8")
    parsed, meta = _call_claude(prompt)
    stats["calls"] = 1; stats["seconds"] = meta.get("seconds"); stats["cost_usd"] = meta.get("cost_usd"); stats["cached"] = meta.get("cached", False)
    if meta.get("error"): stats["error"] = meta["error"]
    (out_dir / "llm_raw.json").write_text(json.dumps(meta, indent=1, default=str), encoding="utf-8")
    ev = []
    if not parsed or not isinstance(parsed.get("items"), list): return ev, stats
    texts = {rel: (root / rel).read_text(encoding="utf-8", errors="replace") if (root / rel).is_file() else "" for rel, _ in files}
    for it in parsed["items"]:
        stats["items"] += 1
        f = it.get("file"); q = (it.get("quote") or "").strip()
        if not f or not q or f not in texts: stats["dropped_unverified"] += 1; continue
        text = texts[f]
        pos = text.find(q)
        if pos < 0:
            qn = re.sub(r"\s+", " ", q); tn = re.sub(r"\s+", " ", text)
            pos2 = tn.find(qn)
            if pos2 < 0: stats["dropped_unverified"] += 1; continue
            line = tn[:pos2].count("\n") + 1 if "\n" in tn else _approx_line(text, qn)
        else:
            line = text[:pos].count("\n") + 1
        stats["verified"] += 1
        dep = it.get("dependency") or "*"
        dep = "*" if dep.strip() in ("*", "all", "project") else canonicalize_name(re.split(r"[\[<>=!~; ]", dep.strip(), 1)[0]) if re.match(r"^[A-Za-z0-9]", dep.strip()) else "*"
        url = it.get("registry_url")
        reg = registry_id(url) if url and str(url).startswith("http") else None
        kind = it.get("kind") or "other"
        conf = it.get("confidence") or "low"
        # LLM evidence is E4 (tier 4) unless it merely restates an explicit binding/CI index (then still tier 4: it adds documentation support)
        ev.append(Evidence(dep, E4, 4, reg, url if reg else None, f, line, q[:200], source="llm", confidence=conf,
                           note=f"kind={kind}" + (f"; variant={it.get('variant')}" if it.get("variant") else "") + (f"; registry_name={it.get('registry_name')}" if it.get("registry_name") and not reg else "") + (f"; {it.get('note')}" if it.get("note") else "")))
    return ev, stats

def _approx_line(text: str, qn: str) -> int:
    first = qn.split(" ")[0]
    for i, l in enumerate(text.splitlines(), 1):
        if first and first in l: return i
    return 0
