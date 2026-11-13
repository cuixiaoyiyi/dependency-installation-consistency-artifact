"""Official Torch CPU-to-PyPI flow; extra controls are conditional on a candidate."""
from copy import deepcopy
import importlib.util
import json
import os
from pathlib import Path
import shutil
import sys
import tomllib

ROOT = Path(__file__).resolve().parents[1]
HELPER = ROOT / "scripts/real_source_switch_workflows_1111.py"
spec = importlib.util.spec_from_file_location("frozen_source_flow_helpers", HELPER)
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
OUT = ROOT / "work/stateful-workflows-20261111/source-switch/torch-adaptive-control"
m.BASE = OUT
NAME, VERSION = "torch", "2.15.0"


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    protocol = OUT / "protocol.json"
    preflight = m.load(m.PREFLIGHT / "preflight-results.json")
    expected = {row["source"]: row["candidates"][0]["metadata_sha256"] for row in preflight["results"] if row["package"] == NAME and row.get("candidates") and row["source"] in ("cpu", "pypi")}
    if not protocol.exists():
        m.dump(protocol, {"schema": "official-torch-source-control-v1", "registered_at_utc": m.now(), "script_sha256": m.sha(__file__), "source_helper_sha256": m.sha(HELPER), "cohort_sha256": m.sha(m.COHORT), "request": NAME + "==" + VERSION,
            "sequence": ["CPU source lock and full install", "change only Torch binding to PyPI and relock", "warm exact sync"],
            "adaptive_rule": "When initial/warm active contracts and both checkers pass, and actual root METADATA exactly matches the selected official source, conclude this source transition negative. Fresh and forced-root-reinstall are required only if a concrete violation, checker failure or root metadata/locked-version mismatch is observed. This rule is frozen before this root executes; the VLLM full-six-step protocol is unchanged.",
            "expected_official_root_metadata_sha256": expected, "limits": {"native_closure_bytes": m.MAX_CLOSURE, "minimum_free_bytes": m.MIN_FREE, "lock_timeout_seconds": 900, "sync_timeout_seconds": 1800},
            "counting": "One existing real cohort root. Different local versions alone are not defects. A negative transition has no reproduction controls and cannot be advertised as a fresh/reinstall equivalence experiment. Positive results need independent review/reproduction before counting.",
            "artifacts": "Original official CPU/PyPI only; shared source artifact cache, copy links, no package metadata edits, no-deps, GPU inference or synthetic index."})
    assert m.load(protocol)["script_sha256"] == m.sha(__file__)
    assert m.load(protocol)["source_helper_sha256"] == m.sha(HELPER)
    if "--prepare" in sys.argv:
        return
    project = OUT / "project"
    project.mkdir(exist_ok=False)
    environment = {k: v for k, v in os.environ.items() if not k.startswith(("PIP_", "UV_")) and k not in ("PYTHONPATH", "PYTHONHOME", "VIRTUAL_ENV", "CONDA_PREFIX")}
    environment.update(HOME=str(OUT / "home"), XDG_CONFIG_HOME=str(OUT / "config"), UV_CACHE_DIR=str(m.SOURCE_BASE / "artifact-cache"), UV_PYTHON_DOWNLOADS="never", UV_NO_INPUT="1", UV_LINK_MODE="copy", PIP_CONFIG_FILE=os.devnull, PIP_DISABLE_PIP_VERSION_CHECK="1", PYTHONDONTWRITEBYTECODE="1")
    auditor = m.get_auditor()
    result = {"root": NAME, "version": VERSION, "protocol_sha256": m.sha(protocol), "started_at_utc": m.now(), "steps": [], "status": "unknown", "confirmed_defects": 0, "affected_projects": []}

    def stage(label, cpu, lock=False, target="shared", force=False):
        folder = OUT / label
        folder.mkdir()
        if lock:
            (project / "pyproject.toml").write_text(m.manifest(NAME, VERSION, cpu), encoding="utf-8")
        envdir = OUT / "environments" / target
        env = {**environment, "UV_PROJECT_ENVIRONMENT": str(envdir)}
        if not lock and shutil.disk_usage(OUT).free < m.MIN_FREE:
            raise RuntimeError("Registered free disk bound reached")
        args = [m.UV, "--no-config", "lock" if lock else "sync", "--project", project, "--python", m.NATIVE, "--no-python-downloads", "--no-build"]
        if not lock:
            args += ["--locked", "--no-install-project", "--no-default-groups", "--verbose"]
        if force:
            args += ["--reinstall-package", NAME]
        execution = m.command(args, folder, "uv", env, 900 if lock else 1800)
        row = {"stage": label, "cpu": cpu, "command": execution, "environment_path": str(envdir)}
        for filename in ("pyproject.toml", "uv.lock"):
            path = project / filename
            if path.exists():
                shutil.copyfile(path, folder / filename)
                row[filename + "_sha256"] = m.sha(path)
        if execution["returncode"] == 0 and lock:
            row["budget"] = m.lock_budget(project / "uv.lock")
        if (envdir / "bin/python").exists() and not lock:
            row["installed"] = m.inventory_check(NAME, VERSION, envdir, folder, env, auditor)
            node = next(p for p in tomllib.loads((project / "uv.lock").read_text(encoding="utf-8"))["package"] if p["name"] == NAME)
            actual = row["installed"]["root"]
            row["locked_root_full_version"] = node["version"]
            row["actual_root_matches_locked_full_version"] = bool(actual and actual["version"] == node["version"])
            row["root_metadata_matches_official_source"] = bool(actual and actual["saved_metadata_sha256"] == expected["cpu" if cpu else "pypi"])
        m.dump(folder / "step.json", row)
        result["steps"].append(row)
        m.dump(OUT / "progress.json", result)
        print(json.dumps({"stage": label, "exit": execution["returncode"], "violations": row.get("installed", {}).get("audit", {}).get("violations"), "official_root_metadata_matches": row.get("root_metadata_matches_official_source")}), flush=True)
        if execution["returncode"] or (lock and not row["budget"]["eligible"]):
            raise RuntimeError("Command, artifact or budget coverage limitation")
        return row

    def clean(row):
        actual = row["installed"]
        return not actual["audit"]["violations"] and actual["pip_check"]["returncode"] == actual["uv_check"]["returncode"] == 0 and row["actual_root_matches_locked_full_version"] and row["root_metadata_matches_official_source"]

    try:
        stage("01-cpu-lock", True, lock=True)
        initial = stage("02-cpu-install", True)
        if not clean(initial):
            raise RuntimeError("Initial CPU environment is not a clean control")
        stage("03-pypi-lock", False, lock=True)
        warm = stage("04-warm-pypi-sync", False)
        if clean(warm):
            result.update(status="completed_real_source_transition_negative", reproduction_controls="not_required_by_preregistered_negative_rule")
        else:
            fresh = stage("05-fresh-pypi-sync", False, target="fresh")
            repair = stage("06-forced-root-reinstall", False, force=True)
            result.update(status="candidate_needs_independent_review", fresh_clean=clean(fresh), repair_clean=clean(repair), same_final_inputs=len({s["uv.lock_sha256"] for s in (warm, fresh, repair)}) == len({s["pyproject.toml_sha256"] for s in (warm, fresh, repair)}) == 1)
    except Exception as exc:
        result.update(status="unknown_execution_or_coverage", error=str(exc))
    result["finished_at_utc"] = m.now()
    m.dump(OUT / "results.json", result)


if __name__ == "__main__":
    main()
