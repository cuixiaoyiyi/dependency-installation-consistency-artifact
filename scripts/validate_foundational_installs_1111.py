"""Frozen foundational-library controls with real, hash-audited wheel installs."""
from __future__ import annotations

import argparse
import ast
import base64
from collections import Counter, deque
from concurrent.futures import ThreadPoolExecutor, as_completed
import csv
from datetime import datetime, timezone
from email.parser import BytesParser
import hashlib
import io
import json
import os
from pathlib import Path
import platform
import signal
import subprocess
import sys
from threading import Lock
import time
import urllib.error
import urllib.request
import zipfile

from packaging.requirements import Requirement
from packaging.specifiers import SpecifierSet
from packaging.utils import canonicalize_name, parse_wheel_filename
from packaging.version import Version

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "work/expanded-validation-20261111/foundational-installs"
FETCH_LOCK = Lock()
SAMPLE = [
    ("http", "requests", "psf/requests"), ("http", "httpx", "encode/httpx"),
    ("http", "aiohttp", "aio-libs/aiohttp"), ("http", "urllib3", "urllib3/urllib3"),
    ("web", "django", "django/django"), ("web", "flask", "pallets/flask"),
    ("web", "fastapi", "fastapi/fastapi"), ("web", "starlette", "encode/starlette"),
    ("data", "numpy", "numpy/numpy"), ("data", "scipy", "scipy/scipy"),
    ("data", "pillow", "python-pillow/Pillow"), ("data", "pyarrow", "apache/arrow"),
    ("packaging", "pip", "pypa/pip"), ("packaging", "setuptools", "pypa/setuptools"),
    ("packaging", "build", "pypa/build"), ("packaging", "virtualenv", "pypa/virtualenv"),
    ("infrastructure", "pytest", "pytest-dev/pytest"),
    ("infrastructure", "cryptography", "pyca/cryptography"),
    ("infrastructure", "sqlalchemy", "sqlalchemy/sqlalchemy"),
    ("infrastructure", "boto3", "boto/boto3"),
]


def now():
    return datetime.now(timezone.utc).isoformat()


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def dump(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_suffix(path.suffix + ".tmp")
    temp.write_text(json.dumps(value, ensure_ascii=False, indent=2), encoding="utf-8")
    temp.replace(path)


def load(path):
    return json.loads(Path(path).read_text(encoding="utf-8-sig"))


def fetch(url, path):
    with FETCH_LOCK:
        return fetch_serial(url, path)


def fetch_serial(url, path):
    path = Path(path)
    if path.exists():
        return load(path)
    error = None
    for attempt in range(3):
        try:
            request = urllib.request.Request(url, headers={"User-Agent": "Dependency-Consistency-Research/1111", "Accept": "application/json"})
            with urllib.request.urlopen(request, timeout=40) as response:
                body = response.read()
                value = json.loads(body)
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(body)
            dump(path.with_suffix(".capture.json"), {"url": url, "retrieved_at_utc": now(), "sha256": sha(path), "bytes": len(body)})
            return value
        except Exception as exc:
            error = str(exc)
            time.sleep(attempt + 1)
    raise RuntimeError(f"Cannot capture {url}: {error}")


def select():
    protocol = OUT / "selection-protocol.json"
    if not protocol.exists():
        dump(protocol, {"registered_at_utc": now(), "sample": SAMPLE, "size": 20,
            "design": "Purposive stratified foundational-library controls: five predeclared domains, four fixed package roots in each; not a popularity ranking or random prevalence sample.",
            "importance_check": "Registered official public/nonfork/nonarchived repository with at least 1000 current stars and pushed since 2025-11-11; mixed source languages permitted for Python distributions.",
            "version_rule": "Latest stable PyPI release at capture; retain every named root including unavailable, incompatible or source-only roots; no result-driven substitutions.",
            "implementation_sha256": sha(__file__), "followup": "Actual installations against a per-root wheelhouse resolved by pip; this is an artifact/constraint control and does not compare public-registry resolver candidate universes."})
    if (OUT / "selection.json").exists():
        raise RuntimeError("Selection is already frozen")
    rows = []
    for category, name, repo in SAMPLE:
        row = {"category": category, "canonical_name": name, "registered_repo": repo, "status": "unknown"}
        try:
            source = OUT / "sources" / f"{name}.json"
            package = fetch(f"https://pypi.org/pypi/{name}/json", source)
            version = Version(package["info"]["version"])
            if version.is_prerelease or version.is_devrelease:
                version = max(Version(v) for v, files in package["releases"].items() if files and not Version(v).is_prerelease and not Version(v).is_devrelease)
                source = OUT / "sources" / f"{name}-{version}.json"
                package = fetch(f"https://pypi.org/pypi/{name}/{version}/json", source)
            gh_path = OUT / "sources" / f"{name}-github.json"
            gh = fetch(f"https://api.github.com/repos/{repo}", gh_path)
            links = list((package["info"].get("project_urls") or {}).values()) + [package["info"].get("home_page") or ""]
            aliases = {repo.lower(), gh["full_name"].lower()}
            correspondence = any(any(("github.com/" + alias) in value.lower().rstrip("/").removesuffix(".git") for alias in aliases) for value in links)
            importance = not any(gh.get(k) for k in ("private", "fork", "archived")) and gh.get("stargazers_count", 0) >= 1000 and gh.get("pushed_at", "") >= "2025-11-11T00:00:00Z"
            row.update(status="registered", version=str(version), request=f"{name}=={version}",
                requires_python=package["info"].get("requires_python") or "", official_repository=gh["full_name"],
                importance_verified=importance, correspondence_verified=correspondence,
                stars=gh.get("stargazers_count"), pushed_at=gh.get("pushed_at"),
                pypi_json=str(source.relative_to(ROOT)), pypi_sha256=sha(source), github_json=str(gh_path.relative_to(ROOT)), github_sha256=sha(gh_path))
        except Exception as exc:
            row.update(status="selection_source_unavailable", error=str(exc))
        rows.append(row)
        print(json.dumps({"selected": len(rows), "name": name, "status": row["status"], "request": row.get("request")}), flush=True)
    dump(OUT / "selection.json", {"frozen_at_utc": now(), "protocol_sha256": sha(protocol), "projects": rows})


def run(command, directory, label, timeout=600, env=None):
    directory.mkdir(parents=True, exist_ok=True)
    stdout, stderr = directory / f"{label}.stdout", directory / f"{label}.stderr"
    started = time.monotonic()
    timed_out = False
    with stdout.open("wb") as out, stderr.open("wb") as err:
        process = subprocess.Popen([str(v) for v in command], cwd=directory, stdout=out, stderr=err, env=env, start_new_session=True)
        try:
            code = process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL)
            code = process.wait()
            timed_out = True
    result = {"command": [str(v) for v in command], "exit": code, "timeout": timed_out,
              "seconds": round(time.monotonic() - started, 3), "stdout_sha256": sha(stdout), "stderr_sha256": sha(stderr)}
    dump(directory / f"{label}.command.json", result)
    return result


COLLECT = r'''
import importlib.metadata as md, json, os, platform, sys
from pathlib import Path
env={"implementation_name":sys.implementation.name,"implementation_version":platform.python_version(),"os_name":os.name,"platform_machine":platform.machine(),"platform_release":platform.release(),"platform_system":platform.system(),"platform_version":platform.version(),"python_full_version":platform.python_version(),"platform_python_implementation":platform.python_implementation(),"python_version":".".join(platform.python_version_tuple()[:2]),"sys_platform":sys.platform}
rows=[]
for dist in md.distributions():
 path=Path(dist._path)
 rows.append({"name":dist.metadata["Name"],"version":dist.version,"requires_dist":dist.metadata.get_all("Requires-Dist",[]),"dist_info":str(path),"metadata":(path/"METADATA").read_text(encoding="utf-8"),"direct_url":json.loads((path/"direct_url.json").read_text()) if (path/"direct_url.json").exists() else None})
print(json.dumps({"executable":sys.executable,"environment":env,"installed":rows}))
'''


def closure(inventory, root_name, root_version):
    installed = {canonicalize_name(r["name"]): r for r in inventory["installed"]}
    violations, edges, unknown = [], [], []
    root = installed.get(root_name)
    if root is None or Version(root["version"]) != Version(root_version):
        violations.append({"kind": "root_pin", "expected": f"{root_name}=={root_version}", "actual": root})
    extras = {root_name: set()}
    queue = deque([root_name])
    visited = {}
    while queue:
        name = queue.popleft()
        active = extras[name]
        state = frozenset(active)
        if visited.get(name) == state:
            continue
        visited[name] = state
        parent = installed.get(name)
        if parent is None:
            continue
        for value in parent["requires_dist"]:
            try:
                requirement = Requirement(value)
                if requirement.marker and not any(requirement.marker.evaluate({**inventory["environment"], "extra": extra}) for extra in ["", *sorted(active)]):
                    continue
                target = canonicalize_name(requirement.name)
                actual = installed.get(target)
                edge = {"parent": name, "requirement": value, "target": target, "installed_version": actual["version"] if actual else None}
                if edge not in edges:
                    edges.append(edge)
                if actual is None:
                    violations.append({"kind": "missing_required_distribution", **edge})
                elif not requirement.specifier.contains(actual["version"], prereleases=True):
                    violations.append({"kind": "requires_dist_version", **edge})
                if requirement.url:
                    unknown.append({"kind": "direct_url_constraint", **edge})
                old = extras.get(target)
                union = (old or set()) | set(requirement.extras)
                if old is None or union != old:
                    extras[target] = union
                    queue.append(target)
            except Exception as exc:
                unknown.append({"kind": "metadata_parse_or_marker", "parent": name, "value": value, "error": str(exc)})
    return {"reachable_names": sorted(visited), "active_edges": edges, "violations": violations, "unknown": unknown}


def audit_wheels(wheelhouse):
    rows = []
    for path in sorted(wheelhouse.glob("*.whl")):
        name, version, _, _ = parse_wheel_filename(path.name)
        with zipfile.ZipFile(path) as archive:
            metadata_path = next(v for v in archive.namelist() if v.endswith(".dist-info/METADATA"))
            metadata = archive.read(metadata_path)
        release_path = OUT / "dependency-release-metadata" / f"{name}-{version}.json"
        release = fetch(f"https://pypi.org/pypi/{name}/{version}/json", release_path)
        matches = [r for r in release["urls"] if r["filename"] == path.name and r["digests"]["sha256"] == sha(path)]
        rows.append({"filename": path.name, "name": str(name), "version": str(version), "sha256": sha(path),
                     "bytes": path.stat().st_size, "metadata_sha256": hashlib.sha256(metadata).hexdigest(),
                     "official_release_hash_verified": len(matches) == 1, "source_url": matches[0]["url"] if len(matches) == 1 else None,
                     "release_json": str(release_path.relative_to(ROOT)), "release_json_sha256": sha(release_path)})
    return rows


def installed_file_audit(inventory, wheelhouse, wheel_rows):
    issues, unknown, rows = [], [], []
    for dist in inventory["installed"]:
        name = canonicalize_name(dist["name"])
        info = Path(dist["dist_info"])
        matches = [r for r in wheel_rows if r["name"] == name and Version(r["version"]) == Version(dist["version"]) and r["metadata_sha256"] == sha(info / "METADATA")]
        if len(matches) != 1:
            issues.append({"kind": "installed_metadata_no_unique_wheel", "name": name, "matches": len(matches)})
            continue
        wheel = matches[0]
        original_count = record_count = 0
        with zipfile.ZipFile(wheelhouse / wheel["filename"]) as archive:
            for filename in archive.namelist():
                if filename.endswith("/") or filename.endswith(".dist-info/RECORD"):
                    continue
                if ".data/" in filename:
                    unknown.append({"kind": "wheel_data_path_transform", "name": name, "path": filename})
                    continue
                target = info.parent / filename
                if not target.is_file() or hashlib.sha256(archive.read(filename)).hexdigest() != sha(target):
                    issues.append({"kind": "installed_wheel_payload_mismatch", "name": name, "path": filename})
                original_count += 1
        record = info / "RECORD"
        if not record.is_file():
            issues.append({"kind": "missing_installed_record", "name": name})
        else:
            for filename, digest, size in csv.reader(io.StringIO(record.read_text(encoding="utf-8"))):
                if not digest:
                    continue
                algorithm, expected = digest.split("=", 1)
                target = info.parent / filename
                if algorithm != "sha256":
                    unknown.append({"kind": "unsupported_record_hash", "name": name, "algorithm": algorithm})
                elif not target.is_file() or base64.urlsafe_b64encode(hashlib.sha256(target.read_bytes()).digest()).decode().rstrip("=") != expected:
                    issues.append({"kind": "installed_record_payload_mismatch", "name": name, "path": filename})
                record_count += 1
        rows.append({"name": name, "version": dist["version"], "wheel_sha256": wheel["sha256"],
                     "original_wheel_files_checked": original_count, "installed_record_hashes_checked": record_count})
    return {"distributions": rows, "violations": issues, "unknown": unknown}


def execute(row, runtimes, uv):
    directory = OUT / "runs" / row["canonical_name"]
    directory.mkdir(parents=True, exist_ok=True)
    summary = {"name": row["canonical_name"], "request": row.get("request"), "started_at_utc": now(), "status": "unknown", "attempts": [], "confirmed_defects": 0}
    if row["status"] != "registered" or not row["correspondence_verified"] or not row["importance_verified"]:
        summary.update(status="unmeasured_selection_evidence", selection=row)
        dump(directory / "summary.json", summary)
        return summary
    compatible = []
    for executable in runtimes:
        version = subprocess.check_output([executable, "-I", "-c", "import platform; print(platform.python_version())"], text=True).strip()
        if SpecifierSet(row["requires_python"]).contains(version, prereleases=True):
            compatible.append((Version(version), executable))
    if not compatible:
        summary.update(status="unmeasured_native_python", requires_python=row["requires_python"])
        dump(directory / "summary.json", summary)
        return summary
    _, runtime = min(compatible)
    summary["runtime"] = runtime
    environment = dict(os.environ)
    for key in list(environment):
        if key.startswith(("PIP_", "UV_")) or key in ("PYTHONPATH", "VIRTUAL_ENV"):
            del environment[key]
    environment.update(PIP_CONFIG_FILE=os.devnull, PIP_DISABLE_PIP_VERSION_CHECK="1", UV_NO_CONFIG="1", UV_NO_MANAGED_PYTHON="1")
    wheelhouse = directory / "wheelhouse"
    wheelhouse.mkdir(exist_ok=True)
    bootstrap = OUT / "bootstrap-wheels"
    # Resolve actual artifacts first. Both later installers see this explicitly restricted universe.
    command = [sys.executable, "-m", "pip", "--python", runtime, "download", "--only-binary=:all:", "--index-url", "https://pypi.org/simple", "--dest", wheelhouse, row["request"]]
    summary["attempts"].append(run(command, directory, "download", env=environment))
    if summary["attempts"][-1]["exit"]:
        summary["status"] = "unknown_artifact_download_or_binary_policy"
        dump(directory / "summary.json", summary)
        return summary
    for path in bootstrap.glob("*.whl"):
        target = wheelhouse / path.name
        if not target.exists():
            target.write_bytes(path.read_bytes())
    try:
        wheels = audit_wheels(wheelhouse)
        dump(directory / "wheel-manifest.json", wheels)
        if not all(r["official_release_hash_verified"] for r in wheels):
            raise RuntimeError("A downloaded wheel lacks exact official-release hash identity")
        installer_results = {}
        for installer in ("pip", "uv"):
            envdir = directory / (installer + "-environment")
            if envdir.exists():
                raise RuntimeError("Fresh environment path already exists")
            subprocess.run([runtime, "-m", "venv", "--without-pip", str(envdir)], check=True, env=environment, capture_output=True)
            python = envdir / "bin/python"
            bootstrap_cmd = [sys.executable, "-m", "pip", "--python", python, "install", "--no-index", "--find-links", bootstrap, "pip==26.3"]
            seeded = run(bootstrap_cmd, directory, installer + "-bootstrap", env=environment)
            summary["attempts"].append(seeded)
            if seeded["exit"]:
                installer_results[installer] = {"status": "unknown_bootstrap"}
                continue
            if installer == "pip":
                command = [python, "-m", "pip", "install", "--no-index", "--find-links", wheelhouse, "--report", directory / "pip-install-report.json", row["request"]]
            else:
                command = [uv, "--no-config", "pip", "install", "--python", python, "--no-index", "--find-links", wheelhouse, "--offline", "--cache-dir", OUT / "uv-artifact-cache", row["request"]]
            installed = run(command, directory, installer + "-install", env=environment)
            summary["attempts"].append(installed)
            if installed["exit"]:
                installer_results[installer] = {"status": "unknown_install_failure"}
                continue
            inventory = json.loads(subprocess.check_output([python, "-I", "-c", COLLECT], text=True, env=environment))
            dump(directory / (installer + "-installed.json"), inventory)
            inspect = run([python, "-m", "pip", "inspect", "--local"], directory, installer + "-inspect", env=environment)
            check = run([python, "-m", "pip", "check"], directory, installer + "-check", env=environment)
            uvcheck = run([uv, "--no-config", "pip", "check", "--python", python], directory, installer + "-uv-check", env=environment)
            graph = closure(inventory, row["canonical_name"], row["version"])
            files = installed_file_audit(inventory, wheelhouse, wheels)
            dump(directory / (installer + "-graph-audit.json"), graph)
            dump(directory / (installer + "-file-audit.json"), files)
            status = "candidate_requires_independent_review" if graph["violations"] or files["violations"] or check["exit"] or uvcheck["exit"] else "installed_constraints_and_payload_checked"
            installer_results[installer] = {"status": status, "installed_distributions": len(inventory["installed"]), "reachable_names": len(graph["reachable_names"]),
                "active_edges": len(graph["active_edges"]), "constraint_violations": len(graph["violations"]), "file_violations": len(files["violations"]),
                "unmodeled_file_paths": len(files["unknown"]), "unknown_constraints": len(graph["unknown"]), "pip_check_exit": check["exit"], "uv_check_exit": uvcheck["exit"], "inspect_exit": inspect["exit"]}
            print(json.dumps({"root": row["canonical_name"], "installer": installer, **installer_results[installer]}), flush=True)
        summary["installers"] = installer_results
        summary["status"] = "completed_controlled_actual_install_pair" if len(installer_results) == 2 and all(r["status"] == "installed_constraints_and_payload_checked" for r in installer_results.values()) else "requires_review_or_incomplete_install_pair"
    except Exception as exc:
        summary.update(status="unknown_evidence_or_execution", error=str(exc))
    summary["finished_at_utc"] = now()
    dump(directory / "summary.json", summary)
    return summary


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--select", action="store_true")
    parser.add_argument("--run", action="store_true")
    parser.add_argument("--runtime", action="append")
    parser.add_argument("--uv")
    args = parser.parse_args()
    OUT.mkdir(parents=True, exist_ok=True)
    if args.select:
        select()
    if args.run:
        if not args.runtime or not args.uv:
            parser.error("Actual run requires --runtime and --uv")
        protocol = OUT / "execution-protocol.json"
        if protocol.exists():
            raise RuntimeError("A run protocol is already registered; use a new output batch for any recovery")
        dump(protocol, {"registered_at_utc": now(), "selection_sha256": sha(OUT / "selection.json"), "script_sha256": sha(__file__),
            "runtimes": args.runtime, "uv": args.uv, "uv_sha256": sha(args.uv), "workers": 3, "per_command_timeout_seconds": 600,
            "request": "Per root exact latest stable pin; base extras only. Resolve/download binary wheels using public PyPI, then two fresh environments use the identical per-root restricted wheelhouse.",
            "bootstrap": "Both environments start with the same official pip==26.3 wheel and otherwise no distributions.",
            "validation": "pip inspect/check and uv pip check; independent installed-METADATA extra fixed point/active Requires-Dist validation; actual wheel PyPI release SHA, installed original wheel bytes and installed RECORD SHA.",
            "limits": "Controlled artifact and installer consistency, not independent live-registry resolver diversity, repository HEAD install, extras coverage, application behavior, or absence of bugs. Wheel .data path transformations are explicitly unmodeled; installed RECORD hashes still checked. Source-only/binary-policy failures remain unknown. No issue published and no findings promoted without independent review."})
        bootstrap = OUT / "bootstrap-wheels"
        bootstrap.mkdir(exist_ok=True)
        command = [sys.executable, "-m", "pip", "download", "--only-binary=:all:", "--no-deps", "--index-url", "https://pypi.org/simple", "--dest", bootstrap, "pip==26.3"]
        bootstrap_result = run(command, OUT, "bootstrap-download")
        if bootstrap_result["exit"]:
            raise RuntimeError("Cannot obtain controlled bootstrap wheel")
        selection = load(OUT / "selection.json")
        results = []
        with ThreadPoolExecutor(max_workers=3) as executor:
            futures = {executor.submit(execute, row, args.runtime, args.uv): row for row in selection["projects"]}
            for future in as_completed(futures):
                try:
                    results.append(future.result())
                except Exception as exc:
                    row = futures[future]
                    results.append({"name": row["canonical_name"], "status": "unknown_worker_error", "error": str(exc)})
                dump(OUT / "progress.json", {"finished": len(results), "total": 20, "results": sorted(results, key=lambda row: row["name"])})
        dump(OUT / "summary.json", {"finished_at_utc": now(), "selection_sha256": sha(OUT / "selection.json"), "protocol_sha256": sha(protocol),
            "counts": dict(Counter(r["status"] for r in results)), "confirmed_defects": 0, "projects": sorted(results, key=lambda row: row["name"])})


if __name__ == "__main__":
    main()
