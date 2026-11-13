"""Actual official CPU-to-PyPI source workflows; never modify upstream wheels."""
from __future__ import annotations

import argparse
from copy import deepcopy
from datetime import datetime, timezone
from email.parser import BytesParser
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import time
import tomllib
import urllib.request
import zipfile

from packaging.markers import default_environment
from packaging.requirements import Requirement
from packaging.specifiers import SpecifierSet
from packaging.tags import sys_tags
from packaging.utils import canonicalize_name, parse_wheel_filename
from packaging.version import Version

ROOT = Path(__file__).resolve().parents[1]
SOURCE_BASE = ROOT / "work/stateful-workflows-20261111/source-switch"
BASE = SOURCE_BASE / "native-intel-url-normalized"
PREFLIGHT = ROOT / "work/stateful-validation-20261111/source-switch"
COHORT = ROOT / "work/stateful-validation-20261111/cohort.json"
UV = ROOT / "work/runtime-linux/bin/uv"
NATIVE = ROOT / "work/runtime-linux/bin/python"
MAX_CLOSURE = 16 * 1024**3
MIN_FREE = 60 * 1024**3
CPU_TRITON = "https://github.com/triton-lang/triton-cpu/releases/download/v3.8.0/triton-3.8.0+cpu-cp311-cp311-manylinux_2_27_x86_64.manylinux_2_28_x86_64.whl"
CPU_INTEL_WHEEL = "https://files.pythonhosted.org/packages/78/2d/64570ae938a8ee2337ed8ba28ae1d85d3555ee6e5faadabea9e8b43a900d/intel_openmp-2024.2.1-py2.py3-none-manylinux1_x86_64.whl"
CPU_INTEL_SHA256 = "21892ea07a9c6e164707d2b44e6f396f9f2ab6cc7e108755011fad59b596182a"


def sha(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for block in iter(lambda: stream.read(8 * 1024**2), b""):
            digest.update(block)
    return digest.hexdigest()


def dump(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_suffix(path.suffix + ".tmp")
    temp.write_text(json.dumps(value, ensure_ascii=False, indent=2), encoding="utf-8")
    temp.replace(path)


def load(path):
    return json.loads(Path(path).read_text(encoding="utf-8-sig"))


def now():
    return datetime.now(timezone.utc).isoformat()


def capture(url, path, maximum=5 * 1024**2):
    request = urllib.request.Request(url, headers={"User-Agent": "dependency-stateful-official-workflow/1111"})
    with urllib.request.urlopen(request, timeout=90) as response:
        if int(response.headers.get("Content-Length", 0)) > maximum:
            raise RuntimeError("Published response exceeds registered byte limit")
        body = response.read(maximum + 1)
        if len(body) > maximum:
            raise RuntimeError("Response exceeds registered byte limit")
        record = {"url": url, "final_url": response.url, "status": response.status, "headers": dict(response.headers), "at_utc": now(), "bytes": len(body), "sha256": hashlib.sha256(body).hexdigest()}
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    Path(path).write_bytes(body)
    dump(str(path) + ".capture.json", record)
    return body


def document():
    urls = {
        "vllm-cpu": "https://raw.githubusercontent.com/vllm-project/vllm/v0.33.0/docs/getting_started/installation/cpu.md",
        "vllm-cpu-x86": "https://raw.githubusercontent.com/vllm-project/vllm/v0.33.0/docs/getting_started/installation/cpu.x86.inc.md",
        "vllm-gpu": "https://raw.githubusercontent.com/vllm-project/vllm/v0.33.0/docs/getting_started/installation/gpu.md",
        "uv-torch": "https://raw.githubusercontent.com/astral-sh/uv/0.13.7/docs/guides/integration/pytorch.md",
        "uv-indexes": "https://raw.githubusercontent.com/astral-sh/uv/0.13.7/docs/concepts/indexes.md",
        "uv-sync": "https://raw.githubusercontent.com/astral-sh/uv/0.13.7/docs/concepts/projects/sync.md",
    }
    records = []
    for name, url in urls.items():
        path = BASE / "official-docs" / (name + ".md")
        try:
            body = capture(url, path)
            records.append({"name": name, "url": url, "sha256": sha(path), "path": str(path.relative_to(ROOT)), "status": "captured", "source_lines": [line for line in body.decode("utf-8").splitlines() if "index" in line.lower() or "reinstall" in line.lower()][:50]})
        except Exception as exc:
            records.append({"name": name, "url": url, "status": "unknown_document_unavailable", "error": str(exc)})
    dump(BASE / "official-documents.json", records)


def command(argv, folder, label, environment, timeout):
    folder.mkdir(parents=True, exist_ok=True)
    started = time.monotonic()
    with (folder / (label + ".stdout")).open("wb") as out, (folder / (label + ".stderr")).open("wb") as err:
        process = subprocess.Popen(list(map(str, argv)), cwd=folder, env=environment, stdout=out, stderr=err, start_new_session=True)
        timed_out = False
        try:
            code = process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL)
            code = process.wait()
            timed_out = True
    result = {"command": list(map(str, argv)), "returncode": code, "timeout": timed_out, "seconds": round(time.monotonic() - started, 3), "stdout_sha256": sha(folder / (label + ".stdout")), "stderr_sha256": sha(folder / (label + ".stderr"))}
    dump(folder / (label + ".command.json"), result)
    return result


def manifest(name, version, cpu):
    sources = {name: "vllm-cpu" if name == "vllm" and cpu else "pytorch-cpu" if cpu else "pypi"}
    if name == "vllm":
        sources.update({n: "pytorch-cpu" if cpu else "pypi" for n in ("torch", "torchvision", "torchaudio")})
    dependencies = [name + "==" + version]
    if name == "vllm" and cpu:
        # Explicitly authorize the exact transitive CPU URL already declared by
        # the authentic vLLM CPU wheel, as required by uv's URL trust policy.
        dependencies.append("triton @ " + CPU_TRITON)
        cpu_metadata = next(r["candidates"][0] for r in load(PREFLIGHT / "preflight-results.json")["results"] if r["package"] == "vllm" and r["source"] == "cpu")
        explicit_backend = []
        for raw in cpu_metadata["requires_dist"]:
            requirement = Requirement(raw)
            if canonicalize_name(requirement.name) in ("torch", "torchvision", "torchaudio", "intel-openmp") and (not requirement.marker or requirement.marker.evaluate(default_environment())):
                explicit_backend.append(raw)
        assert len(explicit_backend) == 4
        dependencies.extend(explicit_backend)
    text = ('[project]\nname="official-source-workflow"\nversion="0.0.0"\nrequires-python="==3.11.16"\ndependencies=' + json.dumps(dependencies) + '\n\n'
            '[tool.uv]\npackage=false\nenvironments=[\'sys_platform == "linux" and platform_machine == "x86_64" and python_full_version == "3.11.16"\']\n\n'
            '[tool.uv.sources]\n')
    for package, source in sources.items():
        text += package + '={index="' + source + '"}\n'
    if name == "vllm" and cpu:
        text += 'intel-openmp={url=' + json.dumps(CPU_INTEL_WHEEL) + '}\n'
    for label, url, is_default in (("vllm-cpu", "https://wheels.vllm.ai/0.33.0/cpu", False), ("pytorch-cpu", "https://download.pytorch.org/whl/cpu", False), ("pypi", "https://pypi.org/simple", True)):
        text += '\n[[tool.uv.index]]\nname="' + label + '"\nurl="' + url + '"\n' + ('default=true\n' if is_default else 'explicit=true\n')
    return text


def lock_budget(lock_path):
    lock = tomllib.loads(lock_path.read_text(encoding="utf-8"))
    tags = {tag: i for i, tag in enumerate(sys_tags())}
    candidates, unknown = [], []
    for package in lock["package"]:
        if package.get("source", {}).get("virtual") is not None:
            continue
        choices = []
        for file in package.get("wheels", []):
            url = file.get("url") or package.get("source", {}).get("url")
            if not url:
                continue
            filename = urllib.parse.unquote(urllib.parse.urlsplit(url).path.rsplit("/", 1)[-1])
            try:
                _, _, _, wheel_tags = parse_wheel_filename(filename)
                priority = min((tags[t] for t in wheel_tags if t in tags), default=None)
            except ValueError:
                priority = None
            if priority is not None:
                choices.append((priority, url, file))
        if not choices:
            unknown.append({"name": package["name"], "version": package["version"], "reason": "no native wheel; no-build source workflow is not covered"})
            continue
        _, url, chosen = min(choices, key=lambda item: (item[0], item[1]))
        if package["name"] == "intel-openmp" and package.get("source", {}).get("url", "").split("#", 1)[0] == CPU_INTEL_WHEEL:
            assert chosen.get("hash") == "sha256:" + CPU_INTEL_SHA256
        size = chosen.get("size")
        if size is None:
            try:
                with urllib.request.urlopen(urllib.request.Request(url, method="HEAD", headers={"User-Agent": "dependency-stateful-official-workflow/1111"}), timeout=60) as response:
                    size = int(response.headers["Content-Length"])
            except Exception as exc:
                unknown.append({"name": package["name"], "url": url, "reason": "size unavailable", "error": str(exc)})
        candidates.append({"name": package["name"], "version": package["version"], "url": url, "size": size, "hash": chosen.get("hash"), "source": package["source"]})
    total = sum(r["size"] or 0 for r in candidates)
    return {"lock_sha256": sha(lock_path), "native_candidate_size_sum": total, "limit": MAX_CLOSURE, "unknown": unknown, "candidates": candidates, "eligible": not unknown and total <= MAX_CLOSURE and shutil.disk_usage(BASE).free > MIN_FREE,
            "interpretation": "Size uses best native tag candidate per lock node as a preflight bound; actual installer file choice is separately observed. No dependencies omitted to meet budget."}


def get_auditor():
    path = ROOT / "scripts/validate_foundational_installs_1111.py"
    spec = importlib.util.spec_from_file_location("installed_auditor_source_workflow", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def inventory_check(name, version, envdir, folder, env, auditor):
    python = envdir / "bin/python"
    inventory = json.loads(subprocess.check_output([str(python), "-I", "-c", auditor.COLLECT], text=True, env=env))
    dump(folder / "installed.json", inventory)
    audit = auditor.closure(inventory, name, version)
    actual = next((r for r in inventory["installed"] if canonicalize_name(r["name"]) == name), None)
    # PEP440 ==public permits local versions. Keep exact lock identity as a separate observation.
    audit["violations"] = [r for r in audit["violations"] if r["kind"] != "root_pin"]
    if not actual or not SpecifierSet("==" + version).contains(actual["version"], prereleases=True):
        audit["violations"].append({"kind": "requested_root_specifier_not_satisfied", "request": name + "==" + version, "installed_version": actual["version"] if actual else None})
    check = command([NATIVE, "-m", "pip", "--python", python, "check"], folder, "pip-check", env, 120)
    uvcheck = command([UV, "--no-config", "pip", "check", "--python", python], folder, "uv-check", env, 120)
    inspect = command([NATIVE, "-m", "pip", "--python", python, "inspect", "--local"], folder, "pip-inspect", env, 120)
    # Persist the actual root metadata instead of allowing reinstall to erase the witness.
    if actual:
        info = Path(actual["dist_info"])
        for filename in ("METADATA", "WHEEL", "RECORD", "INSTALLER", "direct_url.json"):
            source = info / filename
            if source.is_file():
                shutil.copyfile(source, folder / (name + "." + filename))
        actual = {**actual, "saved_metadata_sha256": sha(folder / (name + ".METADATA"))}
    dump(folder / "constraint-audit.json", audit)
    return {"installed_count": len(inventory["installed"]), "root": actual, "target": inventory["environment"], "audit": audit, "pip_check": check, "uv_check": uvcheck, "inspect": inspect}


def execute_root(name, version):
    destination = BASE / "runs" / name
    destination.mkdir(parents=True, exist_ok=False)
    project = destination / "project"
    project.mkdir()
    env = {k: v for k, v in os.environ.items() if not k.startswith(("PIP_", "UV_")) and k not in ("PYTHONPATH", "PYTHONHOME", "VIRTUAL_ENV", "CONDA_PREFIX")}
    env.update(HOME=str(destination / "home"), XDG_CONFIG_HOME=str(destination / "config"), UV_CACHE_DIR=str(SOURCE_BASE / "artifact-cache"), UV_PYTHON_DOWNLOADS="never", UV_NO_INPUT="1", UV_LINK_MODE="copy", PIP_CONFIG_FILE=os.devnull, PIP_DISABLE_PIP_VERSION_CHECK="1", PYTHONDONTWRITEBYTECODE="1")
    auditor = get_auditor()
    result = {"name": name, "version": version, "started_at_utc": now(), "steps": [], "status": "unknown", "confirmed_mechanisms": [], "confirmed_affected_projects": []}
    def stage(label, cpu, lock_only=False, target="shared", reinstall=False):
        folder = destination / label
        folder.mkdir()
        if lock_only:
            (project / "pyproject.toml").write_text(manifest(name, version, cpu), encoding="utf-8")
        envdir = destination / "environments" / target
        active_env = {**env, "UV_PROJECT_ENVIRONMENT": str(envdir)}
        if not lock_only and shutil.disk_usage(BASE).free <= MIN_FREE:
            raise RuntimeError("Registered minimum free disk budget reached before installation")
        argv = [UV, "--no-config", "lock" if lock_only else "sync", "--project", project, "--python", NATIVE, "--no-python-downloads", "--no-build"]
        if not lock_only:
            argv += ["--locked", "--no-install-project", "--no-default-groups", "--verbose"]
            if reinstall:
                argv += ["--reinstall-package", name]
        execution = command(argv, folder, "uv", active_env, 900 if lock_only else 1800)
        row = {"stage": label, "source_state": "official-cpu" if cpu else "official-pypi", "command": execution, "environment_path": str(envdir), "cache_path": active_env["UV_CACHE_DIR"]}
        for filename in ("pyproject.toml", "uv.lock"):
            path = project / filename
            if path.exists():
                shutil.copyfile(path, folder / filename)
                row[filename + "_sha256"] = sha(path)
        if execution["returncode"] == 0 and lock_only:
            budget = lock_budget(project / "uv.lock")
            dump(folder / "installation-budget.json", budget)
            row["budget"] = budget
        if (envdir / "bin/python").exists() and not lock_only:
            row["installed"] = inventory_check(name, version, envdir, folder, active_env, auditor)
        dump(folder / "step.json", row)
        result["steps"].append(row)
        dump(destination / "progress.json", result)
        print(json.dumps({"root": name, "stage": label, "exit": execution["returncode"], "budget_bytes": row.get("budget", {}).get("native_candidate_size_sum"), "violations": row.get("installed", {}).get("audit", {}).get("violations"), "pip_check_exit": row.get("installed", {}).get("pip_check", {}).get("returncode")}), flush=True)
        if execution["returncode"]:
            raise RuntimeError("Registered command failed; no package defect inferred")
        if lock_only and not row["budget"]["eligible"]:
            raise RuntimeError("Native artifact or registered byte/disk budget coverage restriction")
        return row
    try:
        stage("01-cpu-lock", True, True)
        initial = stage("02-cpu-install", True)
        if initial["installed"]["audit"]["violations"] or initial["installed"]["pip_check"]["returncode"]:
            raise RuntimeError("Initial official CPU environment is not a valid control; retain unknown")
        stage("03-switch-to-pypi-relock", False, True)
        warm = stage("04-warm-pypi-sync", False)
        fresh = stage("05-fresh-pypi-sync", False, target="fresh")
        repaired = stage("06-forced-root-reinstall", False, reinstall=True)
        controls_good = all(not s["installed"]["audit"]["violations"] and s["installed"]["pip_check"]["returncode"] == s["installed"]["uv_check"]["returncode"] == 0 for s in (initial, fresh, repaired))
        input_equal = len({s["pyproject.toml_sha256"] for s in (warm, fresh, repaired)}) == len({s["uv.lock_sha256"] for s in (warm, fresh, repaired)}) == 1
        result.update(status="candidate_actual_closure_violation" if controls_good and input_equal and warm["installed"]["audit"]["violations"] else "completed_actual_sequence_no_admitted_defect", controls_good=controls_good, same_final_inputs=input_equal)
    except Exception as exc:
        result.update(status="unknown_execution_or_coverage", error=str(exc))
    result["finished_at_utc"] = now()
    dump(destination / "results.json", result)
    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", choices=("vllm", "torch"), required=True)
    parser.add_argument("--prepare", action="store_true")
    args = parser.parse_args()
    BASE.mkdir(parents=True, exist_ok=True)
    protocol = BASE / "execution-protocol.json"
    if not protocol.exists():
        dump(protocol, {"schema": "official-real-source-workflow-v1", "registered_at_utc": now(), "cohort_sha256": sha(COHORT), "preflight_sha256": sha(PREFLIGHT / "preflight-results.json"), "script_sha256": sha(__file__),
            "preparation_protocol_sha256": sha(SOURCE_BASE / "protocol.json"),
            "parent_execution_protocol_sha256": sha(SOURCE_BASE / "native-intel-wheel-recovery/execution-protocol.json"),
            "parent_result_sha256": sha(SOURCE_BASE / "native-intel-wheel-recovery/runs/vllm/results.json"),
            "native_intel_expected_original_sha256": CPU_INTEL_SHA256,
            "url_normalization": "Prior direct URL was refused before any installation because tool.uv.sources disallows hash fragments. HTTP resource remains identical; remove non-transmitted fragment and verify the exact original publisher SHA against the resolved wheel in lock_budget before installation. Prior API-format failure preserved; no defect inferred.",
            "intel_independent_review_sha256": sha(ROOT / "work/stateful-workflows-20261111/review/intel-openmp-2024.2.1/review.json"),
            "pre_execution_revision": "Prior full CPU install exposed a separate documented universal metadata-consistency limitation (Intel i686 metadata differs from native x86_64); it is not admitted as a new uv bug. Preserve that failed initial control. This independently registered workaround repeats the CPU wheel's already-active IntelOpenMP requirement as direct and pins its exact original SHA-verified official native wheel URL, making actual native metadata available without editing metadata or manually adding the missing child. GPU removes this CPU-only direct/URL input as part of the full backend configuration change. The original baseline is not declared successful. Only after this new CPU control checks clean can a source-reuse candidate be assessed.",
            "roots": [{"name": "vllm", "pin": "0.33.0"}, {"name": "torch", "pin": "2.15.0"}],
            "target": default_environment(), "native_python": str(NATIVE), "uv_sha256": sha(UV),
            "sequence": ["official CPU source lock", "complete old install", "switch actual source bindings to official PyPI and relock", "warm exact sync", "same-input fresh exact sync", "same-input forced root reinstall"],
            "source_edits": "VLLM CPU directly repeats its actual active torch/vision/audio and IntelOpenMP Requires-Dist statements, exact Triton URL authorization, and original native Intel wheel URL; officialCPU named indexes handle the root/backend. GPU removes all CPU-only direct/URL inputs and switches four root/backend bindings to PyPI. Torch control switches only its own binding. Main cohort pins and target are unchanged; this is a consumer workflow with an explicit documented-assumption workaround, not a verbatim upstream installation recipe.",
            "source_authenticity": "Only original official stable-release wheels/indices. No repackaging, edited METADATA, synthetic local registry, no-deps or application/GPU execution. Some officialCPU files lack publisher digests; actual lock SHA plus native metadata retained and independently reviewed.",
            "max_native_wheel_closure_bytes_each_state": MAX_CLOSURE, "minimum_free_bytes_before_install": MIN_FREE,
            "limits": "Full GPU dependency closure may be installed even without GPU execution. Missing native wheel/source builds/budget/timeouts remain unknown, never a package defect. Shared content cache reduces repeated real payload downloads; old/new official URLs remain distinct. Copy linking, separate fresh environment and durable per-stage META/RECORD snapshots protect witnesses.",
            "admission": "Successful warm command + actual active Requires-Dist violation + clean initial/fresh/forced controls + identical final inputs is a candidate only. Cases agent independently reruns before counting. Local suffix/backend/source differences alone do not prove violation. Artificial probes do not count as real project impact. Existing reuse mechanism extends01, not02."})
    assert load(protocol)["script_sha256"] == sha(__file__)
    if args.prepare:
        document()
        return
    selected = next(r for r in load(COHORT)["roots"] if r["canonical_name"] == args.root)
    version = "0.33.0" if args.root == "vllm" else "2.15.0"
    assert Version(selected["version"]) == Version(version)
    execute_root(args.root, version)


if __name__ == "__main__":
    main()
