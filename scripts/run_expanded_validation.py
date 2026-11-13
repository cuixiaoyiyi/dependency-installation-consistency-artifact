"""Bounded native-Linux declared-request planning contrasts for the frozen sample."""
from __future__ import annotations

import argparse
from collections import Counter
from copy import deepcopy
from datetime import datetime, timezone
import hashlib
from http.server import ThreadingHTTPServer
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
from threading import Thread
import time
import traceback


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
EXPANDED = ROOT / "work/fp-fixes-20261110/expanded"
INPUT = EXPANDED / "analysis-input.json"
PROTOCOL = EXPANDED / "execution-protocol.json"
PER_RESOLVER_SECONDS = 60
PROJECT_SECONDS = 240
WORKERS = 4


def now():
    return datetime.now(timezone.utc).isoformat()


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def dump(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    os.replace(temporary, path)


def slug(row):
    return row["repo"].removeprefix("github.com/").replace("/", "__")


def protocol():
    from packaging.markers import default_environment
    return {
        "schema": "drc-expanded-execution-protocol-v1", "registered_at_utc": now(),
        "analysis_input_sha256": digest(INPUT),
        "selection_sha256": digest(EXPANDED / "selection.json"),
        "sample_size": 20, "script_sha256": digest(Path(__file__)),
        "source_hashes": {str(path.relative_to(ROOT)): digest(path) for path in (
            ROOT / "drc/contexts/__init__.py", ROOT / "drc/frontend/requirements.py",
            ROOT / "drc/frontend/pyproject.py", ROOT / "drc/resolvers/__init__.py",
            ROOT / "drc/resolvers/lock_projection.py", ROOT / "drc/proxy.py", ROOT / "drc/contracts.py",
            ROOT / "drc/oracle/__init__.py")},
        "native_python": sys.executable, "native_version": sys.version,
        "marker_environment": default_environment(),
        "request_selection": [
            "Generate normal ProjectIR, requirement sets and RTOs with include_plain_declared=True.",
            "Keep nonempty statically complete declaration/file ReqSets with no parsing limitations; installation-command ReqSets are not eligible for this projection experiment.",
            "Prefer scope '.' and origin pyproject:runtime, then root requirements files, then the first remaining declaration/file ReqSet by (origin, id).",
            "Choose at most one ReqSet per repository, independently of solver outcomes. Do not truncate requirements, strip pins, change extras, or select a second set after failure.",
            "Use the chosen RTO's F0 pip and uv contexts and the exact native target. If the selected metadata's requires-python excludes the native interpreter, retain unsupported coverage.",
        ],
        "context_claim": "Declared dependency-request projection for planning comparison. No observed install path, existing project lock replay, installed environment, or application behavior is certified.",
        "faithfulness": "projected", "lock_mode": "off for the declared-request experiment, with original project/lock metadata retained as provenance",
        "adapters": "Normal drc.resolvers.run_pip/run_uv, built-in target graph projection, normal differential oracle and assess_contracts.",
        "snapshot_sequence": ["pip record", "uv record", "seal shared snapshot", "pip replay", "uv replay"],
        "snapshot_policy": "A per-worker random-port metadata proxy records first observations. Replay is sealed, hash checked, and cannot fetch missing live entries.",
        "candidate_policy": "Normal metadata-only proxy policy. No payload installation, source builds, repository scripts, LLM calls, or registry writes. Candidate-policy restrictions remain limitations.",
        "resolver_timeout_seconds": PER_RESOLVER_SECONDS, "project_deadline_seconds": PROJECT_SECONDS,
        "max_parallel_project_processes": WORKERS, "max_tool_attempts_per_project": 4,
        "timeout_policy": "Supervisor terminates the entire isolated project process group at its deadline and records unknown coverage. No unbounded retry.",
        "support_policy": "Unsupported requests, Python constraints, adapter restrictions, network failures and timeouts remain in the selected-sample denominator.",
        "interpretation": "Version, policy or graph differences are observations. A zero confirmed-contract count under projected contexts does not establish absence of project defects.",
    }


def choose_rto(rtos):
    def eligible(rto):
        reqset = rto.reqset
        return bool(reqset.requirements and reqset.request_complete and not reqset.limitations
                    and reqset.origin.startswith(("pyproject:", "reqfile:")))

    def priority(rto):
        reqset = rto.reqset
        if reqset.scope == "." and reqset.origin.startswith("pyproject:runtime"):
            tier = 0
        elif reqset.scope == "." and reqset.origin.startswith("reqfile:"):
            tier = 1
        else:
            tier = 2
        return tier, reqset.origin, reqset.id

    candidates = sorted((rto for rto in rtos if eligible(rto)), key=priority)
    return candidates[0] if candidates else None


def python_constraint(ir, reqset, directory):
    if reqset.project_file.endswith("pyproject.toml"):
        from drc.frontend.pyproject import parse_pyproject
        return parse_pyproject(directory / reqset.project_file, directory).get("requires_python")
    if reqset.scope == "." and ir.requires_python:
        return ir.requires_python
    setup = directory / reqset.scope / "setup.cfg"
    if setup.is_file():
        from configparser import ConfigParser
        configuration = ConfigParser(interpolation=None)
        configuration.read(setup, encoding="utf-8")
        return configuration.get("options", "python_requires", fallback=None)
    return None


def worker(index, output):
    from packaging.markers import default_environment
    from packaging.specifiers import SpecifierSet
    from drc import proxy, resolvers
    from drc.contexts import generate_rtos
    from drc.contracts import assess_contracts, comparison_eligibility
    from drc.frontend import parse_project
    from drc.intent import build_intents, structured_evidence
    from drc.oracle import diff_resolutions, summarize

    started = time.monotonic()
    row = json.loads(INPUT.read_text(encoding="utf-8"))["repos"][index]
    directory = ROOT / row["dir"]
    destination = output / slug(row)
    destination.mkdir(parents=True, exist_ok=True)
    summary = {"repo": row["repo"], "commit": row["commit"], "started_at_utc": now(),
               "status": "unknown", "attempts": [], "projection": "declared-request", "confirmed_defects": 0}
    dump(destination / "progress.json", summary)
    actual = subprocess.check_output(["git", "-C", str(directory), "rev-parse", "HEAD"], text=True, timeout=15).strip()
    if actual != row["commit"]:
        raise RuntimeError("selected revision changed")
    ir = parse_project(directory, row["repo"])
    dump(destination / "ir.json", ir.to_dict())
    rtos = generate_rtos(ir, directory, include_plain_declared=True)
    dump(destination / "rtos.json", [rto.to_dict() for rto in rtos])
    summary["coverage"] = {"files": len(ir.files), "dependencies": len(ir.dependencies), "install_paths": len(ir.install_paths),
                           "rtos": len(rtos), "statically_complete_declaration_reqsets": sum(
                               bool(rto.reqset.requirements and rto.reqset.request_complete and not rto.reqset.limitations
                                    and rto.reqset.origin.startswith(("pyproject:", "reqfile:"))) for rto in rtos)}
    selected = choose_rto(rtos)
    if selected is None:
        summary.update(status="unsupported_no_complete_static_declaration", reason="No complete declaration/file request was available; command projections were not substituted.")
        dump(destination / "summary.json", summary)
        return
    dump(destination / "selected-rto.json", selected.to_dict())
    summary["selected_reqset"] = {"id": selected.reqset.id, "origin": selected.reqset.origin,
                                  "scope": selected.reqset.scope, "requirements": selected.reqset.requirements,
                                  "constraints": selected.reqset.constraints}
    environment = default_environment()
    constraint = python_constraint(ir, selected.reqset, directory)
    summary["requires_python"] = constraint
    if constraint:
        try:
            compatible = SpecifierSet(constraint).contains(environment["python_full_version"], prereleases=True)
        except ValueError:
            compatible = False
        if not compatible:
            summary.update(status="unsupported_native_python", reason="Selected declaration does not support the fixed native interpreter.")
            dump(destination / "summary.json", summary)
            return
    contexts = {}
    snapshot_id = "expanded-" + hashlib.sha256((row["repo"] + row["commit"] + selected.reqset.id).encode()).hexdigest()[:20]
    for tool in ("pip", "uv"):
        context = next((context for context in selected.contexts
                        if context.resolver == tool and context.derived_from == "declared"), None)
        if context is None:
            continue
        context = deepcopy(context)
        context.id = "expanded|" + selected.reqset.id + "|" + tool
        context.python_version = environment["python_full_version"]
        context.platform = "linux-x86_64"
        context.marker_environment = dict(environment)
        context.faithfulness = "projected"
        context.derived_from = "synthetic:expanded-declared-request"
        context.lock_mode = "off"
        context.lock_file = ""
        context.snapshot_id = snapshot_id
        context.strict_reproducibility = True
        context.origin = {"kind": "declared-request-projection", "request_origin": selected.reqset.origin,
                          "project_file": selected.reqset.project_file, "scope": selected.reqset.scope,
                          "repository_commit": row["commit"], "original_lock_files": [lock.file for lock in ir.locks]}
        context.limitations.append("metadata-only declared-request planning contrast; original installation and prior environment are not replayed")
        contexts[tool] = context
    dump(destination / "contexts.json", {tool: context.to_dict() for tool, context in contexts.items()})
    evidence = structured_evidence(ir)
    intents = build_intents(evidence, sorted({dependency.cname for dependency in ir.dependencies}))
    dump(destination / "intent-evidence.json", [item.to_dict() for item in evidence])
    cache = destination / "cache"
    store = proxy.configure_snapshot(cache, snapshot_id, "record")
    server = ThreadingHTTPServer(("127.0.0.1", 0), proxy.H)
    server.daemon_threads = True
    server.block_on_close = False
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    resolvers.EXEC = "host"
    resolvers.PY = sys.executable
    resolvers.CACHE_ROOT = cache / "resolvers"
    resolvers.PIP_TIMEOUT = PER_RESOLVER_SECONDS
    resolvers.UV_TIMEOUT = PER_RESOLVER_SECONDS
    resolvers.PROXY_PORT = server.server_port
    resolvers.USE_PROXY = True
    original_run = resolvers._run

    def log_run(command, cwd, env, timeout, tool, pyver="3.12"):
        try:
            process, shown = original_run(command, cwd, env, timeout, tool, pyver)
        except subprocess.TimeoutExpired as error:
            for filename, content in (("stdout.log", error.stdout), ("stderr.log", error.stderr)):
                value = content.decode("utf-8", "replace") if isinstance(content, bytes) else content or ""
                (cwd / filename).write_text(value, encoding="utf-8")
            raise
        (cwd / "stdout.log").write_text(process.stdout or "", encoding="utf-8")
        (cwd / "stderr.log").write_text(process.stderr or "", encoding="utf-8")
        return process, shown

    resolvers._run = log_run
    resolutions = {}
    try:
        for phase in ("record", "replay"):
            if phase == "replay":
                store.freeze()
                dump(destination / "sealed-snapshot-health.json", store.health())
                store = proxy.configure_snapshot(cache, snapshot_id, "replay")
            for tool, context in contexts.items():
                if time.monotonic() - started >= PROJECT_SECONDS - 3:
                    summary["status"] = "unknown_project_budget"
                    break
                context.snapshot_mode = phase
                workdir = destination / "runs" / (phase + "-" + tool)
                result = resolvers.run_pip(context, workdir) if tool == "pip" else resolvers.run_uv(context, workdir)
                resolutions[(phase, tool)] = result
                dump(workdir / "resolution.json", result.to_dict())
                dump(workdir / "graph-projection.json", result.graph_projection)
                assessment = assess_contracts(ir, intents, context, result).to_dict()
                dump(workdir / "contracts.json", assessment)
                attempt = {"phase": phase, "resolver": tool, "ok": result.ok, "seconds": round(result.seconds, 2),
                           "artifact_count": len(result.artifacts), "graph_status": result.graph_projection.get("status", "unknown"),
                           "contract_status": assessment["status"], "verified_contract_violations": len(assessment["violations"]),
                           "error": result.error, "snapshot_complete": result.snapshot.get("complete", False),
                           "snapshot_sealed": result.snapshot.get("sealed", False)}
                summary["attempts"].append(attempt)
                dump(destination / "progress.json", summary)
                print(json.dumps({"repo": row["repo"], **attempt}), flush=True)
        pair_results = []
        for label, left_key, right_key in (
            ("replay-pip-versus-uv", ("replay", "pip"), ("replay", "uv")),
            ("pip-record-versus-replay", ("record", "pip"), ("replay", "pip")),
            ("uv-record-versus-replay", ("record", "uv"), ("replay", "uv")),
        ):
            left, right = resolutions.get(left_key), resolutions.get(right_key)
            if left is None or right is None or not left.ok or not right.ok:
                pair_results.append({"pair": label, "status": "unknown", "reason": "both successful results were not available"})
                continue
            left_context = deepcopy(contexts[left_key[1]])
            right_context = deepcopy(contexts[right_key[1]])
            left_context.snapshot_mode = left_key[0]
            right_context.snapshot_mode = right_key[0]
            differences = diff_resolutions(left, right, left_context, right_context)
            pair_results.append({"pair": label, "status": "observed", "summary": summarize(differences),
                                 "comparison_eligibility": comparison_eligibility(left_context, right_context, left, right).to_dict(),
                                 "differences": [difference.to_dict() for difference in differences]})
        dump(destination / "pairs.json", pair_results)
        summary["pairs"] = [{key: value for key, value in pair.items() if key != "differences"} for pair in pair_results]
        summary["status"] = "completed_bounded_projection" if len(summary["attempts"]) == 4 else "unknown_incomplete_attempts"
        summary["successful_attempts"] = sum(attempt["ok"] for attempt in summary["attempts"])
        summary["interpretation"] = "Observed planning differences and coverage limitations; actual project installation defects remain unestablished by these projected requests."
        dump(destination / "final-snapshot-health.json", store.health())
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)
    summary["finished_at_utc"] = now()
    summary["total_seconds"] = round(time.monotonic() - started, 2)
    dump(destination / "summary.json", summary)


def supervise(output):
    data = json.loads(INPUT.read_text(encoding="utf-8"))
    rows = data["repos"]
    pending = list(enumerate(rows))
    running, finished = {}, []
    environment = {**os.environ, "DRC_EXEC": "host", "DRC_PROXY": "1", "DRC_PROXY_KEEP_SDISTS": "0",
                   "UV_PYTHON_DOWNLOADS": "never", "PYTHONUNBUFFERED": "1"}
    while pending or running:
        while pending and len(running) < WORKERS:
            index, row = pending.pop(0)
            directory = output / slug(row)
            directory.mkdir(parents=True, exist_ok=True)
            log = (directory / "worker.log").open("w", encoding="utf-8")
            process = subprocess.Popen([sys.executable, str(Path(__file__)), "--worker", str(index), "--output", str(output)],
                                       cwd=ROOT, env=environment, stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
            running[index] = (process, log, time.monotonic(), row, directory)
        for index, (process, log, started, row, directory) in list(running.items()):
            timed_out = time.monotonic() - started >= PROJECT_SECONDS
            if timed_out and process.poll() is None:
                os.killpg(process.pid, signal.SIGTERM)
                try:
                    process.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    os.killpg(process.pid, signal.SIGKILL)
                    process.wait(timeout=3)
            if process.poll() is None:
                continue
            log.close()
            summary_path = directory / "summary.json"
            if summary_path.exists():
                summary = json.loads(summary_path.read_text(encoding="utf-8"))
            else:
                progress_path = directory / "progress.json"
                summary = json.loads(progress_path.read_text(encoding="utf-8")) if progress_path.exists() else {"repo": row["repo"], "attempts": []}
                summary.update(status="unknown_project_deadline" if timed_out else "unknown_worker_failure",
                               reason="Project process deadline" if timed_out else "Inspect worker.log for the preserved failure",
                               worker_returncode=process.returncode, confirmed_defects=0)
                dump(summary_path, summary)
            finished.append(summary)
            del running[index]
            print(json.dumps({"finished": len(finished), "total": len(rows), "repo": row["repo"], "status": summary["status"],
                              "attempts": len(summary.get("attempts", []))}), flush=True)
            dump(output / "progress.json", {"finished": len(finished), "total": len(rows), "results": finished})
        if running:
            time.sleep(0.25)
    attempts = [attempt for summary in finished for attempt in summary.get("attempts", [])]
    result = {"schema": "drc-expanded-validation-summary-v1", "finished_at_utc": now(), "protocol_sha256": digest(PROTOCOL),
              "selection_sha256": digest(EXPANDED / "selection.json"), "repositories": len(rows),
              "status_counts": dict(Counter(summary["status"] for summary in finished)),
              "resolver_attempts": len(attempts), "successful_attempts": sum(attempt["ok"] for attempt in attempts),
              "sealed_successful_replay_attempts": sum(attempt["ok"] and attempt["phase"] == "replay" and attempt["snapshot_sealed"] for attempt in attempts),
              "verified_contract_violations": sum(attempt.get("verified_contract_violations", 0) for attempt in attempts),
              "interpretation": "Coverage and bounded declared-request planning observations. Zero verified violations here does not establish absence of project bugs.",
              "results": sorted(finished, key=lambda summary: summary["repo"])}
    dump(output / "summary.json", result)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--prepare", action="store_true")
    parser.add_argument("--worker", type=int)
    parser.add_argument("--output", type=Path, default=EXPANDED / "drc")
    args = parser.parse_args()
    if sys.platform != "linux":
        parser.error("Use the fixed native Linux interpreter.")
    if sys.version_info[:3] != (3, 11, 16):
        parser.error("The registered experiment requires CPython 3.11.16.")
    output = args.output.resolve()
    if EXPANDED not in output.parents:
        parser.error("The output must be a fresh directory below the expanded experiment.")
    if args.worker is not None:
        try:
            worker(args.worker, output)
        except Exception:
            traceback.print_exc()
            raise
        return
    if args.prepare:
        if PROTOCOL.exists():
            raise SystemExit("The execution protocol is already registered.")
        dump(PROTOCOL, protocol())
        print("REGISTERED", digest(PROTOCOL), flush=True)
        return
    registered = json.loads(PROTOCOL.read_text(encoding="utf-8"))
    if registered["analysis_input_sha256"] != digest(INPUT) or registered["script_sha256"] != digest(Path(__file__)):
        raise SystemExit("Frozen protocol input or script integrity check failed.")
    for relative, expected in registered["source_hashes"].items():
        if digest(ROOT / relative) != expected:
            raise SystemExit("Method source changed after protocol registration: " + relative)
    output.mkdir(parents=True, exist_ok=False)
    supervise(output)


if __name__ == "__main__":
    main()
