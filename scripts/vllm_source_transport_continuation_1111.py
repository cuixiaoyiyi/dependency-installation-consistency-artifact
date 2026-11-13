"""One bounded continuation of an interrupted official vLLM source workflow."""
import base64
import csv
import hashlib
import importlib.util
import os
from pathlib import Path
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from scripts.stateful_fast_file_audit_1111 import StableEnvironmentPaths
HELPER = ROOT / "scripts/real_source_switch_workflows_1111.py"
spec = importlib.util.spec_from_file_location("frozen_source_transport_helpers", HELPER)
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
OLD = m.BASE / "runs/vllm"
OUT = m.BASE / "transport-continuation"
PROJECT = OLD / "project"


def main():
    OUT.mkdir(exist_ok=True)
    protocol = OUT / "protocol.json"
    if not protocol.exists():
        m.dump(protocol, {
            "registered_at_utc": m.now(), "script_sha256": m.sha(__file__),
            "helper_sha256": m.sha(HELPER), "original_result_sha256": m.sha(OLD / "results.json"),
            "fast_path_helper_sha256": m.sha(ROOT / "scripts/stateful_fast_file_audit_1111.py"),
            "pre_execution_revision": "Unexecuted v1 protocol/code retained. Use the already independently equivalence-checked StableEnvironmentPaths to avoid repeating known slow path resolution; all payload digests still checked in quiescent starting state.",
            "reason": "Original warm sync exhausted its registered 1800 seconds while preparing official CUDA payloads; exit -9, no successful transition. Preserve original unknown. One same-input transport continuation reuses only the official content cache and the independently verified intact CPU environment.",
            "preconditions": "All saved installed distribution METADATA identical between initial CPU and interrupted state; current inventory identical again; every current RECORD payload digest and size valid; same final manifest and lock as original PyPI stage; CPU checker and active closure clean. If any precondition fails, stop unknown without restarting or repairing the witness.",
            "sequence": ["verify intact starting CPU environment", "retry identical warm PyPI sync once", "same final input fresh PyPI sync", "same final input forced vLLM root reinstall"],
            "limits": {"each_sync_seconds": 1800, "native_closure_bytes": m.MAX_CLOSURE, "minimum_free_bytes": m.MIN_FREE},
            "counting": "Same one cohort root and source transition. Failed original and continuation are separate evidence layers, never two successes/projects. Candidate requires concrete active dependency violation, clean initial/fresh/repair controls, identical final inputs and independent reproduction. No defect inferred from source/local-version differences or transport failures.",
        })
    p = m.load(protocol)
    assert p["script_sha256"] == m.sha(__file__) and p["helper_sha256"] == m.sha(HELPER)
    assert p["fast_path_helper_sha256"] == m.sha(ROOT / "scripts/stateful_fast_file_audit_1111.py")
    if "--prepare" in sys.argv:
        return
    result = {"started_at_utc": m.now(), "protocol_sha256": m.sha(protocol), "steps": [], "status": "unknown", "confirmed_defects": 0}
    env = {k: v for k, v in os.environ.items() if not k.startswith(("PIP_", "UV_")) and k not in ("PYTHONPATH", "PYTHONHOME", "VIRTUAL_ENV", "CONDA_PREFIX")}
    env.update(HOME=str(OUT / "home"), XDG_CONFIG_HOME=str(OUT / "config"), UV_CACHE_DIR=str(m.SOURCE_BASE / "artifact-cache"), UV_PYTHON_DOWNLOADS="never", UV_NO_INPUT="1", UV_LINK_MODE="copy", PIP_CONFIG_FILE=os.devnull, PIP_DISABLE_PIP_VERSION_CHECK="1", PYTHONDONTWRITEBYTECODE="1")
    auditor = m.get_auditor()
    shared = OLD / "environments/shared"

    def clean(row):
        return not row["audit"]["violations"] and row["pip_check"]["returncode"] == row["uv_check"]["returncode"] == 0

    def stage(label, target, force=False):
        folder = OUT / label
        folder.mkdir()
        envdir = shared if target == "shared" else OUT / "environments" / target
        active = {**env, "UV_PROJECT_ENVIRONMENT": str(envdir)}
        assert shutil.disk_usage(OUT).free > m.MIN_FREE
        args = [m.UV, "--no-config", "sync", "--project", PROJECT, "--python", m.NATIVE, "--no-python-downloads", "--no-build", "--locked", "--no-install-project", "--no-default-groups", "--verbose"]
        if force:
            args += ["--reinstall-package", "vllm"]
        execution = m.command(args, folder, "uv", active, 1800)
        row = {"stage": label, "command": execution, "environment_path": str(envdir)}
        for filename in ("pyproject.toml", "uv.lock"):
            shutil.copyfile(PROJECT / filename, folder / filename)
            row[filename + "_sha256"] = m.sha(PROJECT / filename)
        if (envdir / "bin/python").exists():
            row["installed"] = m.inventory_check("vllm", "0.33.0", envdir, folder, active, auditor)
        m.dump(folder / "step.json", row)
        result["steps"].append(row)
        m.dump(OUT / "progress.json", result)
        print(m.json.dumps({"stage": label, "exit": execution["returncode"], "violations": row.get("installed", {}).get("audit", {}).get("violations")}), flush=True)
        if execution["returncode"]:
            raise RuntimeError("One registered source continuation failed; retain unknown")
        return row

    try:
        prior = m.load(OLD / "02-cpu-install/installed.json")
        interrupted = m.load(OLD / "04-warm-pypi-sync/installed.json")
        current = m.json.loads(subprocess.check_output([str(shared / "bin/python"), "-I", "-c", auditor.COLLECT], env=env, text=True))
        stable = lambda inv: sorted((d["name"], d["version"], d["metadata"], m.json.dumps(d.get("direct_url"), sort_keys=True)) for d in inv["installed"])
        assert stable(prior) == stable(interrupted) == stable(current), "Installed starting state changed"
        for filename in ("pyproject.toml", "uv.lock"):
            assert m.sha(PROJECT / filename) == m.sha(OLD / "03-switch-to-pypi-relock" / filename)
        checked = 0
        errors = []
        resolver = StableEnvironmentPaths(shared)
        for dist in current["installed"]:
            record = Path(dist["dist_info"]) / "RECORD"
            for rel, digest, size in csv.reader(record.open(newline="")):
                file = resolver.resolve(record.parent.parent / rel)
                assert file.is_relative_to(resolver.environment), "RECORD escaped target environment"
                if not digest:
                    continue
                if not file.is_file():
                    errors.append({"path": str(file), "error": "missing"})
                    continue
                algorithm, encoded = digest.split("=", 1)
                actual = hashlib.new(algorithm)
                with file.open("rb") as stream:
                    for block in iter(lambda: stream.read(8 * 1024**2), b""):
                        actual.update(block)
                if base64.urlsafe_b64encode(actual.digest()).rstrip(b"=").decode() != encoded or (size and int(size) != file.stat().st_size):
                    errors.append({"path": str(file), "error": "record mismatch"})
                checked += 1
        m.dump(OUT / "starting-record-integrity.json", {"at_utc": m.now(), "checked_payloads": checked, "errors": errors, "inventory_unchanged": True})
        assert not errors
        start_folder = OUT / "00-starting-control"
        start_folder.mkdir()
        initial = m.inventory_check("vllm", "0.33.0", shared, start_folder, env, auditor)
        assert clean(initial)
        warm = stage("04-warm-pypi-sync-retry", "shared")
        fresh = stage("05-fresh-pypi-sync", "fresh")
        repair = stage("06-forced-root-reinstall", "shared", True)
        equal = len({s["pyproject.toml_sha256"] for s in (warm, fresh, repair)}) == len({s["uv.lock_sha256"] for s in (warm, fresh, repair)}) == 1
        controls = all(clean(s["installed"]) for s in (fresh, repair))
        candidate = controls and equal and bool(warm["installed"]["audit"]["violations"])
        result.update(status="candidate_needs_independent_review" if candidate else "completed_actual_sequence_no_admitted_defect", controls_good=controls, same_final_inputs=equal)
    except Exception as exc:
        result.update(status="unknown_execution_or_coverage", error=repr(exc))
    result["finished_at_utc"] = m.now()
    m.dump(OUT / "results.json", result)


if __name__ == "__main__":
    main()
