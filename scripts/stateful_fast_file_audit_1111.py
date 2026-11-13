"""Equivalent installed-file audit with cached path resolution in a quiescent environment.

No installer may mutate the environment while this audit runs. The original
stateful pass stays immutable; only a separately preregistered recovery uses it.
"""
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import base64
import csv
from packaging.utils import canonicalize_name
from scripts.stateful_real_workflows_1111 import CoverageLimit, file_digest, digest


class StableEnvironmentPaths:
    """Match Path.resolve while avoiding repeated ancestor work for unchanged paths."""
    def __init__(self, environment):
        self.environment = Path(environment).resolve()
        self.parents = {}
        self.files = {}

    def resolve(self, path):
        path = Path(path)
        # Preserve '..' until parent.resolve(): lexical normalization would be
        # wrong when a parent component is a symbolic link.
        absolute = path if path.is_absolute() else Path.cwd() / path
        cached = self.files.get(absolute)
        if cached is not None:
            return cached
        if absolute.name in {".", ".."}:
            resolved = absolute.resolve()
            self.files[absolute] = resolved
            return resolved
        parent = self.parents.get(absolute.parent)
        if parent is None:
            parent = absolute.parent.resolve()
            self.parents[absolute.parent] = parent
        resolved = absolute.resolve() if absolute.is_symlink() else parent / absolute.name
        self.files[absolute] = resolved
        return resolved


def audit_files(inventory, wheels, envdir):
    resolver = StableEnvironmentPaths(envdir)
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
            path = resolver.resolve(info.parent / relative)
            if not path.is_relative_to(resolver.environment):
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
            path = resolver.resolve(info.parent / relative)
            if not path.is_relative_to(resolver.environment):
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

