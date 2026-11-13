"""Command line: analyze one project / run corpus / post-process (triage + issues) / stats."""
from __future__ import annotations
import argparse, json, pathlib, sys, time, os, traceback
import uuid
import socket
import shutil
import hashlib
from concurrent.futures import ThreadPoolExecutor, as_completed

ROOT = pathlib.Path(__file__).resolve().parents[1]

def _run_dir():
    return ROOT / "work" / "experiments" / (time.strftime("%Y%m%d-%H%M%S") + "-" + uuid.uuid4().hex[:8])

def _options(args):
    return {"snapshot_id": args.snapshot_id, "snapshot_mode": args.snapshot_mode,
            "strict_reproducibility": not args.exploratory_live}


def _validate_output(path, inputs=()):
    """Outputs must not modify a historical evidence tree or their own inputs."""
    path = pathlib.Path(path).resolve()
    protected = [ROOT / name for name in ("results", "reports", "0909ISSUEs", "0910issues")]
    protected.extend(pathlib.Path(value) for value in inputs)
    for item in protected:
        item = item.resolve()
        if path == item or item in path.parents:
            raise ValueError(f"Historical evidence is read-only; choose a new output directory outside {item}")
    return path

def _prepare_proxy_port():
    if "DRC_PROXY_PORT" not in os.environ:
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            os.environ["DRC_PROXY_PORT"] = str(sock.getsockname()[1])

def cmd_analyze(args):
    _prepare_proxy_port()
    from .pipeline import ProjectRun
    out = _validate_output(args.out if args.out else _run_dir() / pathlib.Path(args.path).name, (args.path,))
    s = ProjectRun(args.repo or pathlib.Path(args.path).name, args.path, out, llm=not args.no_llm, max_contexts=args.max_contexts, max_rtos=args.max_rtos, **_options(args)).run()
    print("Experiment output:", out)
    print(json.dumps({k: s[k] for k in ("repo", "total_s", "rtos", "contexts", "resolutions_ok", "resolutions_failed", "cases", "cases_by_type", "cases_by_class")}, indent=1))

def _one(repo: dict, args):
    from .pipeline import ProjectRun
    d = ROOT / repo["dir"]
    name = pathlib.Path(repo["dir"]).name
    out = pathlib.Path(args.out) / name
    if (out / "summary.json").exists() and not args.force:
        return name, "skip", json.loads((out / "summary.json").read_text(encoding="utf-8"))
    t0 = time.time()
    try:
        s = ProjectRun(repo["repo"], d, out, llm=not args.no_llm, max_contexts=args.max_contexts, max_rtos=args.max_rtos, **_options(args)).run()
        s["commit"] = repo.get("commit"); s["stars"] = repo.get("stars")
        (out / "summary.json").write_text(json.dumps(s, indent=1, default=str), encoding="utf-8")
        return name, "ok", s
    except FileExistsError as e:
        return name, "preserved", {"error": str(e), "seconds": time.time() - t0}
    except Exception as e:
        out.mkdir(parents=True, exist_ok=True)
        (out / "error.txt").write_text(traceback.format_exc(), encoding="utf-8")
        return name, "error", {"error": str(e), "seconds": time.time() - t0}

def cmd_corpus(args):
    _prepare_proxy_port()
    sel = json.loads((ROOT / "corpus" / "selected.json").read_text(encoding="utf-8"))["repos"]
    repos = [r for r in sel if (ROOT / r["dir"]).exists()]
    if args.limit: repos = repos[: args.limit]
    args.out = str(_validate_output(args.out or _run_dir()))
    # A corpus batch shares one recording ID and mode across worker contexts.
    args.snapshot_id = args.snapshot_id or "corpus-" + uuid.uuid4().hex
    pathlib.Path(args.out).mkdir(parents=True, exist_ok=True)
    log = open(pathlib.Path(args.out) / "corpus_run.log", "a", encoding="utf-8")
    log.write(f"\n=== run {time.strftime('%Y-%m-%d %H:%M:%S')} repos={len(repos)} workers={args.workers}\n"); log.flush()
    done = 0
    with ThreadPoolExecutor(max_workers=args.workers) as ex:
        futs = {ex.submit(_one, r, args): r for r in repos}
        for f in as_completed(futs):
            name, status, s = f.result(); done += 1
            msg = f"[{done}/{len(repos)}] {name} {status} " + (f"cases={s.get('cases')} ctx={s.get('contexts')} ok={s.get('resolutions_ok')} fail={s.get('resolutions_failed')} t={s.get('total_s')}s" if status != "error" else s.get("error", "")[:200])
            print(msg, flush=True); log.write(msg + "\n"); log.flush()

def cmd_post(args):
    """Triage + minimisation + issue drafts for all cases in results/projects/*."""
    from .triage import triage_case
    from . import triage as triage_module
    from .report import write_case_bundle
    from .minimize import minimize_case
    from .model import Context
    from .resolvers import PIP_VERSION, UV_VERSION
    selection = ROOT / "corpus" / "selected.json"
    selected = json.loads(selection.read_text(encoding="utf-8"))["repos"] if selection.exists() else []
    sel = {pathlib.Path(r["dir"]).name: r for r in selected}
    source = pathlib.Path(args.results_dir).resolve()
    output = _validate_output(args.out if args.out else _run_dir() / "post", (source,))
    projects = {path.parent: path for path in source.glob("*/cases_triaged.json")}
    projects.update({path.parent: path for path in source.glob("*/findings.json")})
    projects = [projects[key] for key in sorted(projects)]
    if args.project: projects = [p for p in projects if p.parent.name == args.project]
    n = 0
    for fp in projects:
        pdir = fp.parent
        cases = json.loads(fp.read_text(encoding="utf-8"))
        if not cases: continue
        rtos = json.loads((pdir / "rtos.json").read_text(encoding="utf-8"))
        ctxs = {c["id"]: c for r in rtos for c in r["contexts"]}
        ctx_objs = {cid: Context(**{k: v for k, v in c.items()}) for cid, c in ctxs.items()}
        res = {}
        for rd in (pdir / "runs").glob("*/resolution.json"):
            d = json.loads(rd.read_text(encoding="utf-8")); res[d["context_id"]] = d
        repo = sel.get(pdir.name, {}).get("repo", pdir.name); commit = sel.get(pdir.name, {}).get("commit", "?")
        out_cases = output / pdir.name
        out_cases.mkdir(parents=True, exist_ok=False)
        copied = {}
        for name in ("rtos.json", "ir.json", "experiment_manifest.json", "contracts.json", "intents.json", "evidence.json"):
            original = pdir / name
            if original.is_file():
                shutil.copyfile(original, out_cases / name)
                copied[name] = hashlib.sha256(original.read_bytes()).hexdigest()
        (out_cases / "source_evidence.json").write_text(json.dumps({"source_results_dir": str(pdir), "source_case_file": str(fp), "copied_files_sha256": copied}, indent=2), encoding="utf-8")
        triaged = []
        for c in cases:
            if args.max_per_project and len(triaged) >= args.max_per_project: break
            if c.get("consequential_of") and not args.include_consequential: continue
            tfile = out_cases / c["case_id"] / "triage.json"
            if tfile.exists() and not args.force:
                tri = json.loads(tfile.read_text(encoding="utf-8"))
            else:
                previous_cache = triage_module.CACHE
                triage_module.CACHE = output / "_cache" / "artifacts"
                triage_module.CACHE.mkdir(parents=True, exist_ok=True)
                try:
                    tri = triage_case(c, do_content=not args.no_content)
                except Exception as e:
                    tri = {"label": "NEEDS_EXPLANATION", "reason": f"triage error: {e}", "notes": [traceback.format_exc()[-500:]]}
                finally:
                    triage_module.CACHE = previous_cache
            minimal = None
            if args.minimize and c["type"] != "A-Stable":
                mfile = out_cases / c["case_id"] / "minimal.json"
                if mfile.exists() and not args.force: minimal = json.loads(mfile.read_text(encoding="utf-8"))
                else:
                    try: minimal = minimize_case(c, ctx_objs, out_cases, max_probes=args.max_probes)
                    except Exception as e: minimal = {"error": str(e)}
            write_case_bundle(out_cases, c, ctxs, res, repo, commit, tri, minimal, {"pip": PIP_VERSION, "uv": UV_VERSION})
            c2 = dict(c); c2["triage"] = {"label": tri.get("label"), "reason": tri.get("reason")}; c2["minimal"] = minimal; triaged.append(c2); n += 1
            print(f"{pdir.name} {c['case_id']} {c['type']} {c['cls']} -> {tri.get('label')}", flush=True)
        out_cases.mkdir(parents=True, exist_ok=True)
        (out_cases / "cases_triaged.json").write_text(json.dumps(triaged, indent=1, default=str), encoding="utf-8")
    print("triaged cases:", n)

def cmd_stats(args):
    from .stats import build_stats, render_md
    statistics = build_stats(ROOT, write=False)
    if getattr(args, "out", None):
        output = _validate_output(args.out)
        output.mkdir(parents=True, exist_ok=False)
        (output / "stats.json").write_text(json.dumps(statistics, indent=2, default=str), encoding="utf-8")
        (output / "STATS.md").write_text(render_md(statistics), encoding="utf-8")
        print("Statistics output:", output)
    else:
        print(json.dumps(statistics, indent=2, default=str))

def main(argv=None):
    ap = argparse.ArgumentParser(prog="drc")
    sub = ap.add_subparsers(dest="cmd", required=True)
    a = sub.add_parser("analyze"); a.add_argument("path"); a.add_argument("--repo"); a.add_argument("--out"); a.add_argument("--no-llm", action="store_true"); a.add_argument("--max-contexts", type=int, default=12); a.add_argument("--max-rtos", type=int, default=4); a.set_defaults(fn=cmd_analyze)
    c = sub.add_parser("corpus"); c.add_argument("--workers", type=int, default=3); c.add_argument("--limit", type=int, default=0); c.add_argument("--force", action="store_true"); c.add_argument("--no-llm", action="store_true"); c.add_argument("--max-contexts", type=int, default=12); c.add_argument("--max-rtos", type=int, default=4); c.set_defaults(fn=cmd_corpus)
    c.add_argument("--out")
    for parser in (a, c):
        parser.add_argument("--snapshot-id")
        parser.add_argument("--snapshot-mode", choices=("record", "replay"), default="record")
        parser.add_argument("--exploratory-live", action="store_true", help="Disable snapshot enforcement; results cannot support controlled stability claims")
    p = sub.add_parser("post"); p.add_argument("--project"); p.add_argument("--force", action="store_true"); p.add_argument("--no-content", action="store_true"); p.add_argument("--minimize", action="store_true"); p.add_argument("--max-probes", type=int, default=12); p.add_argument("--max-per-project", type=int, default=0); p.add_argument("--include-consequential", action="store_true"); p.set_defaults(fn=cmd_post)
    p.add_argument("--results-dir", default=str(ROOT / "results" / "projects")); p.add_argument("--out")
    s = sub.add_parser("stats"); s.add_argument("--out", help="Write statistics to a new directory; default prints without modifying saved evidence"); s.set_defaults(fn=cmd_stats)
    args = ap.parse_args(argv)
    args.fn(args)

if __name__ == "__main__":
    main()
