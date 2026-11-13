"""Actual official-wheel update, extra toggling and relocking controls."""
from __future__ import annotations

import argparse
import base64
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
import csv
from email.parser import BytesParser
import hashlib
from http.server import ThreadingHTTPServer
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
from threading import Thread
import time
import tomllib
import traceback
from urllib.parse import unquote, urlsplit
import urllib.request
import zipfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from packaging.requirements import Requirement
from packaging.utils import canonicalize_name, parse_wheel_filename
from scripts.validate_foundational_installs_1111 import COLLECT
from scripts.review_recovery_1111 import check_metadata
from scripts.run_expanded_validation import dump, digest, now

DRIVER = ROOT / "work/runtime-linux/bin/python"
UV = ROOT / "work/runtime-linux/bin/uv"
FOUND = ROOT / "work/expanded-validation-20261111/foundational-installs"
WORKFLOWS = ("update", "extras", "relock")


class CoverageLimit(RuntimeError):
    pass


def load(path):
    return json.loads(Path(path).read_text(encoding="utf-8-sig"))


def environment(directory):
    env = {k: v for k, v in os.environ.items() if not k.startswith(("PIP_", "UV_", "DRC_"))
           and k not in {"PYTHONPATH", "PYTHONHOME", "VIRTUAL_ENV", "CONDA_PREFIX"}}
    env.update(HOME=str(directory / "home"), XDG_CONFIG_HOME=str(directory / "config"),
               PIP_CONFIG_FILE=os.devnull, PIP_DISABLE_PIP_VERSION_CHECK="1", PYTHONNOUSERSITE="1",
               UV_PYTHON_DOWNLOADS="never", UV_LINK_MODE="copy", UV_NO_PROGRESS="1", NO_COLOR="1",
               PIP_CACHE_DIR=str(directory / "pip-cache"), UV_CACHE_DIR=str(directory / "uv-cache"))
    return env


class Recorder:
    def __init__(self, directory, seconds=900):
        self.directory = directory
        self.started = time.monotonic()
        self.deadline = self.started + seconds
        self.commands = []

    def remaining(self):
        value = self.deadline - time.monotonic()
        if value <= 0:
            raise CoverageLimit("workflow wall-clock budget exhausted")
        return value

    def command(self, argv, label, cwd=None, env=None, required=True):
        folder = self.directory / "commands" / label
        folder.mkdir(parents=True, exist_ok=False)
        command = list(map(str, argv))
        began = time.monotonic()
        with (folder / "stdout.txt").open("wb") as stdout, (folder / "stderr.txt").open("wb") as stderr:
            process = subprocess.Popen(command, cwd=cwd or self.directory, env=env or environment(self.directory), stdout=stdout, stderr=stderr)
            try:
                code = process.wait(timeout=max(.1, self.remaining()))
            except subprocess.TimeoutExpired:
                # Workers are independent process-group leaders. Killing only
                # an external pip driver can leave its target interpreter alive.
                if os.getpgrp() == os.getpid():
                    os.killpg(os.getpgrp(), signal.SIGKILL)
                process.kill()
                process.wait()
                raise CoverageLimit("command exhausted workflow budget: " + label)
        row = {"label": label, "argv": command, "cwd": str(cwd or self.directory), "exit": code,
               "seconds": round(time.monotonic() - began, 3), "stdout_sha256": digest(folder / "stdout.txt"),
               "stderr_sha256": digest(folder / "stderr.txt"), "environment_controls": {k: (env or environment(self.directory)).get(k) for k in
               ("HOME", "XDG_CONFIG_HOME", "PIP_CONFIG_FILE", "PIP_CACHE_DIR", "UV_CACHE_DIR", "UV_PROJECT_ENVIRONMENT", "UV_LINK_MODE", "UV_PYTHON_DOWNLOADS")}}
        dump(folder / "command.json", row)
        self.commands.append(row)
        dump(self.directory / "commands.json", self.commands)
        print(json.dumps({"phase": label, "exit": code, "seconds": row["seconds"]}), flush=True)
        if code and required:
            raise CoverageLimit("native command returned nonzero: " + label)
        return code, (folder / "stdout.txt").read_text(errors="replace"), (folder / "stderr.txt").read_text(errors="replace")


def prepare(args):
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=False)
    cohort, selection = load(args.cohort), load(args.selection)
    assert digest(args.cohort) == selection["cohort_sha256"]
    by_name = {r["canonical_name"]: r for r in cohort["roots"]}
    workflows = {r["canonical_name"]: r for r in selection["roots"]}
    original = load(FOUND / "selection.json")["projects"]
    foundation_names = {r["canonical_name"] for r in original if r["importance_verified"] and r["correspondence_verified"]}
    names = foundation_names if args.group == "foundational" else set(by_name) - foundation_names
    ordered_names = ([r["canonical_name"] for r in original if r["canonical_name"] in names]
                     if args.group == "foundational" else [r["canonical_name"] for r in cohort["roots"] if r["canonical_name"] in names])
    rows = [{**by_name[n], "workflow_selection": workflows[n]} for n in ordered_names]
    excluded = [r for r in original if r["canonical_name"] not in foundation_names] if args.group == "foundational" else []
    inputs = {str(args.cohort.resolve()): digest(args.cohort), str(args.selection.resolve()): digest(args.selection),
              str(FOUND / "selection.json"): digest(FOUND / "selection.json")}
    for row in rows:
        p = ROOT / row["pypi_json_path"]
        assert digest(p) == row["pypi_json_sha256"]
        inputs[str(p)] = digest(p)
        u = row["workflow_selection"]["update"]
        if u.get("version_json_path"):
            p = ROOT / u["version_json_path"]
            assert digest(p) == u["version_json_sha256"]
            inputs[str(p)] = digest(p)
    dump(out / "cases.json", {"roots": rows, "excluded_coverage_slots": excluded})
    protocol = {"schema": "actual-official-wheel-workflows-v1", "registered_at_utc": now(), "group": args.group,
                "script_sha256": digest(Path(__file__)), "cohort_sha256": digest(args.cohort), "workflow_selection_sha256": digest(args.selection),
                "cases_sha256": digest(out / "cases.json"), "inputs": inputs,
                "driver": str(DRIVER), "driver_sha256": digest(DRIVER.resolve()), "uv": str(UV), "uv_sha256": digest(UV),
                "core_hashes": {str(p.relative_to(ROOT)): digest(p) for p in sorted((ROOT / "drc").rglob("*.py"))},
                "workers": 2, "artifact_preparation_seconds": 900, "per_workflow_seconds": 900,
                "max_single_artifact_bytes": 250 * 1024 ** 2,
                "max_new_single_download_bytes": 250 * 1024 ** 2, "max_new_download_bytes_per_root": 500 * 1024 ** 2,
                "max_union_compressed_bytes": 500 * 1024 ** 2, "max_environment_uncompressed_bytes": 2 * 1024 ** 3,
                "candidate_policy": "Only official native-compatible binary wheels. Metadata-only pip preflight precedes file-size/official-release-SHA checks. Hash-verified existing actual wheel bytes are reused before new transfer limits are considered. Installed workflows share the explicitly restricted union of prepared base/old/extra artifacts.",
                "workflow_protocols": {
                    "update": "Empty pip environment: old exact pin then fixed new pin, default incremental dependency update. Empty uv project environment: old exact-pin lock+strict sync; edit only root pin to fixed new, relock+strict sync; fresh environment same final manifest/lock. Pip historical/orphan consistency observations do not alone establish a resolver defect.",
                    "extras": "Current base exact pin lock+strict sync; change requested root to the preregistered actual published extra, relock+strict sync; remove extra, relock+strict sync. Each transition saves complete installed metadata and files. Fresh control shares final base manifest/lock.",
                    "relock": "Independent current exact-pin project. Initial lock uses lowest available versions in the prepared official-wheel universe; strict sync, lock --upgrade using highest, strict sync in the existing environment, then fresh same final lock. Root pin stays fixed; unchanged locks/plans are explicitly counted as no-op rather than upgrades."},
                "validation": "Every actual install/sync has before/after inventories, full native marker environment, manifest/lock snapshots, external pip inspect/check, uv pip check, root/extra closure and all-installed-base Requires-Dist evaluation, original wheel METADATA/regular payload SHA and installed RECORD hash/size verification. No pip is preseeded.",
                "limits": ["Controlled package-root workflows are not repository HEAD or application behavior replays.", "No sdists, dynamic builds, repacked wheels or edited upstream metadata.", "Preparation failures, missing native wheels, quotas and deadlines are coverage outcomes, not package defects.", "Wheel .data path transformations retain explicit original-byte-comparison unknowns while installed RECORD still gets checked.", "Only independently reproducible unsatisfied new requests or strict uv-sync installed-contract violations become candidates; no issue is automatically written or published."]}
    dump(out / "protocol.json", protocol)
    print(json.dumps({"roots": len(rows), "excluded": len(excluded), "protocol_sha256": digest(out / "protocol.json")}), flush=True)


def fetch_json(url, path, recorder):
    if path.exists():
        return load(path)
    with urllib.request.urlopen(urllib.request.Request(url, headers={"User-Agent": "Dependency-Consistency-Research/1111"}), timeout=min(60, recorder.remaining())) as response:
        data = response.read(32 * 1024 ** 2 + 1)
    if len(data) > 32 * 1024 ** 2:
        raise CoverageLimit("release metadata exceeds limit")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    dump(path.with_suffix(".capture.json"), {"url": url, "at_utc": now(), "sha256": digest(path), "bytes": len(data)})
    return json.loads(data)


def existing_archives():
    result = {}
    for p in FOUND.glob("runs/*/wheelhouse/*.whl"):
        result.setdefault(p.name, []).append(p)
    for p in (FOUND / "bootstrap-wheels").glob("*.whl"):
        result.setdefault(p.name, []).append(p)
    for p in (ROOT / "work/expanded-validation-20261111/install-review").rglob("*.whl"):
        result.setdefault(p.name, []).append(p)
    return result


def artifact_worker(out, row):
    from drc import proxy
    from drc.resolvers import unproxy_url
    directory = out / "cases" / row["canonical_name"] / "artifacts"
    directory.mkdir(parents=True, exist_ok=False)
    recorder = Recorder(directory)
    protocol = load(out / "protocol.json")
    cache = existing_archives()
    wheelhouse = directory / "wheelhouse"
    wheelhouse.mkdir()
    store = proxy.configure_snapshot(directory / "metadata-cache", "stateful-" + row["canonical_name"], "record")
    server = ThreadingHTTPServer(("127.0.0.1", 0), proxy.H)
    server.daemon_threads = True
    server.block_on_close = False
    Thread(target=server.serve_forever, daemon=True).start()
    encoded = base64.urlsafe_b64encode(b"https://pypi.org/simple").decode().rstrip("=")
    index = f"http://127.0.0.1:{server.server_port}/s/{store.id}/idx/{encoded}/simple"
    variants = {"base": row["request"]}
    selection = row["workflow_selection"]
    if selection["update"].get("status") == "selected":
        variants["old"] = selection["update"]["from_request"]
    tooling_extra = row["canonical_name"] == "setuptools" and selection["extras"].get("extra") == "cover"
    if selection["extras"].get("status") == "selected" and not tooling_extra:
        variants["extra"] = selection["extras"]["extra_request"]
    manifest, outcomes, transferred = {}, {}, 0
    if tooling_extra:
        outcomes["extra"] = {"status": "unsupported_selected_extra_tooling_semantics", "extra": "cover", "reason": "Frozen v2 selection retained; pytest-cov extra is a tooling control and is not replaced by another extra."}
    try:
        for variant, request in variants.items():
            try:
                if variant == "extra":
                    root_wheel = next(w for w in manifest.values() if w["name"] == row["canonical_name"] and w["version"] == row["version"])
                    with zipfile.ZipFile(wheelhouse / root_wheel["filename"]) as archive:
                        raw = archive.read(next(n for n in archive.namelist() if n.endswith(".dist-info/METADATA")))
                    meta = BytesParser().parsebytes(raw)
                    extra = selection["extras"]["extra"]
                    provided = {canonicalize_name(e) for e in meta.get_all("Provides-Extra", [])}
                    def activated(extra_value):
                        result = set()
                        for value in meta.get_all("Requires-Dist", []):
                            req = Requirement(value)
                            if req.marker is None or any(req.marker.evaluate({**row["marker_environment"], "extra": e}) for e in {"", extra_value}):
                                result.add((canonicalize_name(req.name), tuple(sorted(canonicalize_name(e) for e in req.extras)), str(req.specifier), req.url))
                        return result
                    actual_additions = activated(extra) - activated("")
                    frozen_additions = {tuple([v["identity"][0], tuple(v["identity"][1]), v["identity"][2], v["identity"][3]]) for v in selection["extras"]["additional_active_requirements"]}
                    extra_check = {"extra": extra, "actual_provided_extras": sorted(provided), "actual_additions": sorted(actual_additions), "frozen_additions": sorted(frozen_additions), "metadata_sha256": hashlib.sha256(raw).hexdigest()}
                    dump(directory / "actual-root-extra-selection-check.json", extra_check)
                    if canonicalize_name(extra) not in provided or not actual_additions or actual_additions != frozen_additions:
                        raise CoverageLimit("metadata_selection_mismatch: actual native wheel extra differs from frozen JSON selection")
                report_path = directory / (variant + "-report.json")
                argv = [DRIVER, "-m", "pip", "--python", row["runtime"], "install", "--dry-run", "--ignore-installed", "--only-binary=:all:",
                        "--no-compile", "--report", report_path, "--index-url", index, "--disable-pip-version-check", "--no-input", "--progress-bar", "off", "--retries", "1", "--timeout", "40", request]
                recorder.command(argv, variant + "-metadata-plan")
                report = load(report_path)
                if report["environment"] != row["marker_environment"]:
                    raise CoverageLimit("pip plan target differs from frozen native environment")
                selected = []
                for item in report["install"]:
                    metadata, source = item["metadata"], item["download_info"]
                    url = unproxy_url(source["url"])
                    if not url.startswith("https://files.pythonhosted.org/"):
                        raise CoverageLimit("unrecognized artifact URL: " + url)
                    filename = unquote(urlsplit(url).path.rsplit("/", 1)[-1])
                    name, version, _, _ = parse_wheel_filename(filename)
                    release_path = directory / "release-metadata" / (str(name) + "--" + str(version) + ".json")
                    release = fetch_json(f"https://pypi.org/pypi/{name}/{version}/json", release_path, recorder)
                    matches = [f for f in release["urls"] if f["filename"] == filename and f["url"] == url]
                    if len(matches) != 1:
                        raise CoverageLimit("no unique official release file")
                    official = matches[0]
                    expected = official["digests"]["sha256"]
                    if source.get("archive_info", {}).get("hashes", {}).get("sha256") != expected:
                        raise CoverageLimit("pip report and official release hash differ")
                    reuse = next((p for p in cache.get(filename, []) if p.stat().st_size == official["size"] and digest(p) == expected), None)
                    selected.append({"filename": filename, "name": str(name), "version": str(version), "url": url,
                                     "sha256": expected, "bytes": official["size"], "release_json": str(release_path.relative_to(ROOT)),
                                     "release_json_sha256": digest(release_path), "reuse": str(reuse) if reuse else None})
                proposed = dict(manifest)
                for item in selected:
                    if item["filename"] in proposed and proposed[item["filename"]]["sha256"] != item["sha256"]:
                        raise CoverageLimit("same filename has conflicting official SHA")
                    proposed[item["filename"]] = item
                new = [v for k, v in proposed.items() if k not in manifest and not v["reuse"]]
                union_bytes = sum(v["bytes"] for v in proposed.values())
                transfer_bytes = sum(v["bytes"] for v in new)
                passed = (union_bytes <= protocol["max_union_compressed_bytes"] and
                          all(v["bytes"] <= protocol["max_single_artifact_bytes"] for v in proposed.values()) and
                          all(v["bytes"] <= protocol["max_new_single_download_bytes"] for v in new) and
                          transferred + transfer_bytes <= protocol["max_new_download_bytes_per_root"])
                dump(directory / (variant + "-size-preflight.json"), {"selected": selected, "uncached_new_download_bytes": transfer_bytes,
                     "already_transferred_bytes": transferred, "union_compressed_bytes": union_bytes,
                     "verified_cached_bytes": sum(v["bytes"] for v in selected if v["reuse"]), "passed": passed})
                if union_bytes > protocol["max_union_compressed_bytes"]:
                    raise CoverageLimit("selected union exceeds compressed-byte policy")
                if any(v["bytes"] > protocol["max_single_artifact_bytes"] for v in proposed.values()):
                    raise CoverageLimit("selected artifact exceeds single-artifact byte policy, regardless of cache availability")
                if not passed:
                    raise CoverageLimit("uncached official artifacts exceed download-byte policy")
                for item in selected:
                    target = wheelhouse / item["filename"]
                    if target.exists():
                        assert digest(target) == item["sha256"]
                        continue
                    if item["reuse"]:
                        shutil.copyfile(item["reuse"], target)
                    else:
                        with urllib.request.urlopen(item["url"], timeout=min(60, recorder.remaining())) as response, target.open("wb") as stream:
                            count = 0
                            while chunk := response.read(1024 ** 2):
                                recorder.remaining()
                                count += len(chunk)
                                transferred += len(chunk)
                                dump(directory / "transfer-ledger.json", {"actual_artifact_body_bytes_received": transferred, "current_url": item["url"], "current_file_bytes_received": count})
                                if count > item["bytes"] or count > protocol["max_new_single_download_bytes"] or transferred > protocol["max_new_download_bytes_per_root"]:
                                    raise CoverageLimit("artifact body exceeded official size or quota")
                                stream.write(chunk)
                    assert target.stat().st_size == item["bytes"] and digest(target) == item["sha256"]
                    with zipfile.ZipFile(target) as archive:
                        payload = {}
                        for member in archive.infolist():
                            if member.is_dir() or member.filename.endswith(".dist-info/RECORD"):
                                continue
                            if member.filename.startswith("/") or ".." in Path(member.filename).parts:
                                raise CoverageLimit("unsafe official wheel member path")
                            data = archive.read(member)
                            payload[member.filename] = {"sha256": hashlib.sha256(data).hexdigest(), "bytes": len(data)}
                        meta_name = next(n for n in payload if n.endswith(".dist-info/METADATA"))
                        item["metadata_sha256"] = payload[meta_name]["sha256"]
                        item["payload"] = payload
                        item["uncompressed_bytes"] = sum(v["bytes"] for v in payload.values())
                    manifest[item["filename"]] = item
                if sum(v["uncompressed_bytes"] for v in manifest.values()) > protocol["max_environment_uncompressed_bytes"]:
                    raise CoverageLimit("prepared payload exceeds uncompressed environment policy")
                outcomes[variant] = {"status": "prepared", "request": request, "files": [v["filename"] for v in selected]}
            except Exception as exc:
                outcomes[variant] = {"status": "unknown_artifact_preparation", "request": request, "reason": str(exc)}
            dump(directory / "variant-results.json", outcomes)
            dump(directory / "wheel-manifest.json", list(manifest.values()))
        dump(directory / "snapshot-health.json", store.health())
        result = {"status": "artifact_preparation_finished", "variants": outcomes, "wheel_count": len(manifest), "new_download_bytes": transferred,
                  "candidate_world": "Prepared union only; not the complete public-index universe.", "confirmed_defects": 0}
        dump(directory / "results.json", result)
    finally:
        server.shutdown()
        server.server_close()


def file_digest(path):
    digestor = hashlib.sha256()
    size = 0
    with path.open("rb") as stream:
        while data := stream.read(1024 ** 2):
            digestor.update(data)
            size += len(data)
    return digestor.hexdigest(), size


def audit_files(inventory, wheels, envdir):
    problems, unknown, rows, jobs, expected = [], [], [], set(), []
    for distribution in inventory["installed"]:
        info = Path(distribution["dist_info"])
        meta_sha = digest(info / "METADATA")
        matches = [w for w in wheels if canonicalize_name(w["name"]) == canonicalize_name(distribution["name"])
                   and w["version"] == distribution["version"] and w["metadata_sha256"] == meta_sha]
        if len(matches) != 1:
            problems.append({"kind": "installed_metadata_no_unique_official_wheel", "name": distribution["name"], "matches": len(matches)})
            continue
        wheel = matches[0]
        count = 0
        for relative, value in wheel["payload"].items():
            if ".data/" in relative:
                unknown.append({"kind": "wheel_data_path_transform", "name": distribution["name"], "path": relative})
                continue
            path = (info.parent / relative).resolve()
            if not path.is_relative_to(envdir.resolve()):
                raise CoverageLimit("installed wheel path escaped target environment")
            expected.append((path, value["sha256"], value["bytes"], "original_payload"))
            jobs.add(path)
            count += 1
        record_count = 0
        for relative, record_hash, size in csv.reader((info / "RECORD").read_text().splitlines()):
            if not record_hash:
                continue
            algorithm, value = record_hash.split("=", 1)
            if algorithm != "sha256":
                unknown.append({"kind": "unsupported_record_hash", "name": distribution["name"], "algorithm": algorithm})
                continue
            path = (info.parent / relative).resolve()
            if not path.is_relative_to(envdir.resolve()):
                raise CoverageLimit("installed RECORD escaped target environment")
            value = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4)).hex()
            expected.append((path, value, int(size) if size else None, "installed_record"))
            jobs.add(path)
            record_count += 1
        rows.append({"name": distribution["name"], "version": distribution["version"], "wheel_sha256": wheel["sha256"],
                     "metadata_sha256": meta_sha, "original_files_checked": count, "record_hashes_checked": record_count})
    def calculate(path):
        try:
            return path, file_digest(path)
        except OSError as exc:
            return path, str(exc)
    with ThreadPoolExecutor(max_workers=4) as pool:
        actual = dict(pool.map(calculate, jobs))
    for path, wanted, size, kind in expected:
        observed = actual[path]
        if not isinstance(observed, tuple) or observed[0] != wanted or size is not None and observed[1] != size:
            problems.append({"kind": kind + "_mismatch", "path": str(path), "expected_sha256": wanted, "actual": observed})
    return {"distributions": rows, "violations": problems, "unknown": unknown, "unique_installed_files_hashed": len(jobs)}


def manifest_text(request, row):
    marker = " and ".join(k + " == " + json.dumps(v) for k, v in sorted(row["marker_environment"].items()))
    return ('[project]\nname = "stateful-control-' + row["canonical_name"] + '"\nversion = "0.0.1"\nrequires-python = "==' + row["target_python"] + '"\ndependencies = [' + json.dumps(request) + ']\n\n[tool.uv]\nenvironments = [' + json.dumps(marker) + ']\n')


def workflow_worker(out, row, workflow):
    directory = out / "cases" / row["canonical_name"] / workflow
    directory.mkdir(parents=True, exist_ok=False)
    recorder = Recorder(directory)
    env = environment(directory)
    artifacts = directory.parent / "artifacts"
    prepared = load(artifacts / "results.json")["variants"]
    wheels = load(artifacts / "wheel-manifest.json")
    wheelhouse = artifacts / "wheelhouse"
    selected = row["workflow_selection"]
    needed = {"update": ("base", "old"), "extras": ("base", "extra"), "relock": ("base",)}[workflow]
    unsupported = workflow != "relock" and selected[workflow].get("status") != "selected"
    missing = [v for v in needed if prepared.get(v, {}).get("status") != "prepared"]
    result = {"name": row["canonical_name"], "workflow": workflow, "started_at_utc": now(), "stages": [], "confirmed_defects": 0,
              "marker_environment": row["marker_environment"], "candidate_world_sha256": digest(artifacts / "wheel-manifest.json")}
    if unsupported or missing:
        result.update(status="unsupported_selection" if unsupported else "unknown_preparation_coverage", reason=selected[workflow] if unsupported else missing)
        dump(directory / "results.json", result)
        return
    project = directory / "project"
    project.mkdir()
    warm, fresh, pipenv = (directory / name for name in ("uv-warm", "uv-fresh", "pip-incremental"))
    for name, target in (("uv-warm", warm), ("uv-fresh", fresh), *(([("pip-incremental", pipenv)]) if workflow == "update" else [])):
        recorder.command([row["runtime"], "-m", "venv", "--without-pip", target], "create-" + name, env=env)
        code, data, _ = recorder.command([target / "bin/python", "-I", "-c", COLLECT], "empty-" + name, env=env)
        assert not json.loads(data)["installed"]

    def capture(label, target, request, strict):
        stage = directory / "stages" / label
        stage.mkdir(parents=True, exist_ok=False)
        for name in ("pyproject.toml", "uv.lock"):
            if (project / name).exists():
                shutil.copyfile(project / name, stage / name)
        _, data, _ = recorder.command([target / "bin/python", "-I", "-c", COLLECT], label + "-inventory", env=env)
        inventory = json.loads(data)
        dump(stage / "installed.json", inventory)
        for dist in inventory["installed"]:
            info = Path(dist["dist_info"])
            stored = stage / "metadata" / canonicalize_name(dist["name"])
            stored.mkdir(parents=True)
            for filename in ("METADATA", "RECORD", "INSTALLER", "direct_url.json"):
                if (info / filename).exists():
                    shutil.copyfile(info / filename, stored / filename)
        assert inventory["environment"] == row["marker_environment"]
        artifacts_by_name = {canonicalize_name(d["name"]): {"name": d["name"], "version": d["version"], "requires_dist": d["requires_dist"]} for d in inventory["installed"]}
        graph = check_metadata([request], [], artifacts_by_name, inventory["environment"])
        # A strict sync must also leave every installed base requirement satisfied.
        roots = [d["name"] + "==" + d["version"] for d in inventory["installed"]] + [request]
        all_installed = check_metadata(roots, [], artifacts_by_name, inventory["environment"])
        files = audit_files(inventory, wheels, target)
        check, _, _ = recorder.command([DRIVER, "-m", "pip", "--python", target / "bin/python", "check"], label + "-pip-check", env=env, required=False)
        uvcheck, _, _ = recorder.command([UV, "--no-config", "pip", "check", "--python", target / "bin/python"], label + "-uv-check", env=env, required=False)
        inspect, _, _ = recorder.command([DRIVER, "-m", "pip", "--python", target / "bin/python", "inspect", "--local"], label + "-inspect", env=env, required=False)
        dump(stage / "root-closure.json", graph)
        dump(stage / "all-installed-closure.json", all_installed)
        dump(stage / "file-audit.json", files)
        entry = {"stage": label, "request": request, "strict_uv_sync": strict, "installed_distributions": len(artifacts_by_name),
                 "root_constraint_violations": graph["constraint_conflicts"], "all_installed_constraint_violations": all_installed["constraint_conflicts"],
                 "file_violations": files["violations"], "unmodeled_file_paths": len(files["unknown"]),
                 "pip_check_exit": check, "uv_check_exit": uvcheck, "inspect_exit": inspect,
                 "names_versions": {n: a["version"] for n, a in artifacts_by_name.items()},
                 "manifest_sha256": digest(project / "pyproject.toml") if (project / "pyproject.toml").exists() else None,
                 "lock_sha256": digest(project / "uv.lock") if (project / "uv.lock").exists() else None}
        requested = Requirement(request)
        installed_root = artifacts_by_name.get(canonicalize_name(requested.name))
        root_identity_satisfied = installed_root is not None and requested.specifier.contains(installed_root["version"], prereleases=True)
        entry["root_identity_satisfied"] = root_identity_satisfied
        entry["pip_incremental_conflicts_are_observations"] = not strict
        entry["candidate"] = bool(not root_identity_satisfied or files["violations"] or strict and (graph["constraint_conflicts"] or all_installed["constraint_conflicts"]))
        result["stages"].append(entry)
        dump(directory / "progress.json", result)
        recorder.remaining()
        return entry

    def lock(request, label, extra_args=()):
        (project / "pyproject.toml").write_text(manifest_text(request, row))
        recorder.command([UV, "lock", "--no-index", "--find-links", wheelhouse, "--offline", "--no-build", "--python", row["runtime"], "--no-python-downloads", *extra_args], label, cwd=project, env=env)
        stored = directory / "locks" / label
        stored.mkdir(parents=True)
        for filename in ("pyproject.toml", "uv.lock"):
            shutil.copyfile(project / filename, stored / filename)

    def sync(request, label, target=warm):
        configured = {**env, "UV_PROJECT_ENVIRONMENT": str(target)}
        # Preserve a before inventory for every actual operation; final observations
        # may legitimately become the next stage's before state.
        recorder.command([target / "bin/python", "-I", "-c", COLLECT], label + "-before", env=env)
        before_lock = digest(project / "uv.lock")
        recorder.command([UV, "sync", "--locked", "--no-install-project", "--no-default-groups", "--no-index", "--find-links", wheelhouse,
                          "--offline", "--no-build", "--python", row["runtime"], "--no-python-downloads"], label, cwd=project, env=configured)
        assert digest(project / "uv.lock") == before_lock
        return capture(label, target, request, True)

    try:
        current = row["request"]
        if workflow == "update":
            old = selected["update"]["from_request"]
            for label, request in (("pip-old", old), ("pip-updated", current)):
                recorder.command([pipenv / "bin/python", "-I", "-c", COLLECT], label + "-before", env=env)
                recorder.command([DRIVER, "-m", "pip", "--python", pipenv / "bin/python", "install", "--no-index", "--find-links", wheelhouse, "--no-compile", "--report", directory / (label + "-report.json"), request], label, env=env)
                capture(label, pipenv, request, False)
            lock(old, "uv-initial-lock")
            sync(old, "uv-old")
            lock(current, "uv-updated-lock")
            sync(current, "uv-updated")
        elif workflow == "extras":
            extra = selected["extras"]["extra_request"]
            lock(current, "uv-base-lock")
            sync(current, "uv-base")
            lock(extra, "uv-extra-lock")
            sync(extra, "uv-extra")
            lock(current, "uv-remove-extra-lock")
            sync(current, "uv-base-restored")
        else:
            lock(current, "uv-initial-lock", ("--resolution", "lowest"))
            initial = sync(current, "uv-before-relock")
            lock(current, "uv-upgrade-lock", ("--upgrade",))
            final = sync(current, "uv-after-relock")
            result["relock_manifest_unchanged"] = initial["manifest_sha256"] == final["manifest_sha256"]
            result["relock_lock_bytes_changed"] = initial["lock_sha256"] != final["lock_sha256"]
            result["relock_installed_plan_changed"] = initial["names_versions"] != final["names_versions"]
        fresh_entry = sync(current, "uv-fresh-final-lock", fresh)
        warm_entry = result["stages"][-2]
        result["same_final_manifest_and_lock"] = (warm_entry["manifest_sha256"], warm_entry["lock_sha256"]) == (fresh_entry["manifest_sha256"], fresh_entry["lock_sha256"])
        result["warm_fresh_same_name_versions"] = warm_entry["names_versions"] == fresh_entry["names_versions"]
        result["status"] = "candidate_actual_installed_contract_violation" if any(s["candidate"] for s in result["stages"]) else "completed_actual_stateful_workflow"
    except Exception as exc:
        result.update(status="unknown_workflow_coverage", reason=str(exc), traceback=traceback.format_exc())
    result["finished_at_utc"] = now()
    result["seconds"] = round(time.monotonic() - recorder.started, 2)
    dump(directory / "results.json", result)


def worker(out, name, phase):
    protocol = load(out / "protocol.json")
    assert digest(Path(__file__)) == protocol["script_sha256"]
    assert all(digest(Path(p)) == s for p, s in protocol["inputs"].items())
    row = next(r for r in load(out / "cases.json")["roots"] if r["canonical_name"] == name)
    if phase == "artifacts":
        artifact_worker(out, row)
    else:
        workflow_worker(out, row, phase)


def execute(out):
    protocol = load(out / "protocol.json")
    assert digest(Path(__file__)) == protocol["script_sha256"]
    cases = load(out / "cases.json")
    if (out / "run-started.json").exists():
        raise FileExistsError("A registered pass already started; use a separate recovery output")
    dump(out / "run-started.json", {"at_utc": now(), "protocol_sha256": digest(out / "protocol.json")})
    logs = out / "logs"
    logs.mkdir()
    def package(row):
        name = row["canonical_name"]
        for phase in ("artifacts", *WORKFLOWS):
            target = out / "cases" / name / phase
            log = logs / (name + "--" + phase + ".log")
            command = [str(DRIVER), str(Path(__file__)), "--out", str(out), "--worker", name, "--phase", phase]
            with log.open("w") as stream:
                process = subprocess.Popen(command, stdout=stream, stderr=subprocess.STDOUT, start_new_session=True)
                try:
                    process.wait(timeout=protocol["artifact_preparation_seconds" if phase == "artifacts" else "per_workflow_seconds"] + 2)
                except subprocess.TimeoutExpired:
                    os.killpg(process.pid, signal.SIGKILL)
                    process.wait()
                # A driver may time out after spawning a native pip child. Keep
                # the entire phase bounded even after its worker has exited.
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                if process.returncode and not (target / "results.json").exists():
                    target.mkdir(parents=True, exist_ok=True)
                    dump(target / "results.json", {"name": name, "workflow": phase, "status": "unknown_worker_or_budget", "returncode": process.returncode, "log": str(log), "confirmed_defects": 0})
        return {"name": name, "workflows": {p: load(out / "cases" / name / p / "results.json")["status"] for p in WORKFLOWS}}
    completed = []
    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = {pool.submit(package, row): row for row in cases["roots"]}
        for future in as_completed(futures):
            try:
                row = future.result()
            except Exception as exc:
                row = {"name": futures[future]["canonical_name"], "status": "unknown_controller", "reason": str(exc)}
            completed.append(row)
            dump(out / "progress.json", {"finished_roots": len(completed), "eligible_roots": len(cases["roots"]), "results": completed})
            print(json.dumps(row), flush=True)
    result = {"schema": "actual-stateful-workflow-summary-v1", "finished_at_utc": now(), "protocol_sha256": digest(out / "protocol.json"),
              "eligible_roots": len(cases["roots"]), "excluded_coverage_slots": cases["excluded_coverage_slots"], "results": completed,
              "workflow_counts": {p: dict(Counter(row.get("workflows", {}).get(p, row.get("status")) for row in completed)) for p in WORKFLOWS},
              "core_unchanged": all(digest(ROOT / p) == s for p, s in protocol["core_hashes"].items()),
              "inputs_unchanged": all(digest(Path(p)) == s for p, s in protocol["inputs"].items()), "confirmed_defects": 0}
    assert result["core_unchanged"] and result["inputs_unchanged"]
    dump(out / "summary.json", result)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--prepare", action="store_true")
    parser.add_argument("--run", action="store_true")
    parser.add_argument("--group", choices=("foundational", "published"))
    parser.add_argument("--cohort", type=Path)
    parser.add_argument("--selection", type=Path)
    parser.add_argument("--out", required=True, type=Path)
    parser.add_argument("--worker")
    parser.add_argument("--phase", choices=("artifacts", *WORKFLOWS))
    args = parser.parse_args()
    if args.prepare:
        prepare(args)
    elif args.worker:
        worker(args.out.resolve(), args.worker, args.phase)
    elif args.run:
        execute(args.out.resolve())
    else:
        parser.error("Choose --prepare or --run")


if __name__ == "__main__":
    main()
