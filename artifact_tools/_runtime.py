"""Shared path and command helpers; original implementation files are unchanged."""
from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]


def digest(path):
    value = hashlib.sha256()
    with Path(path).open("rb") as source:
        for block in iter(lambda: source.read(4 * 1024**2), b""):
            value.update(block)
    return value.hexdigest()


def dump(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")


def executable(value):
    candidate = shutil.which(str(value)) if len(Path(value).parts) == 1 else str(value)
    if candidate is None or not Path(candidate).is_file():
        raise ValueError(f"Executable not found: {value}")
    # Preserve a virtual environment's interpreter path. Resolving its symlink
    # would select the base interpreter and discard that environment's packages.
    return Path(os.path.abspath(os.path.expanduser(candidate)))


def python_path(value=None):
    return executable(value or sys.executable)


def uv_path(value=None, python=None, required=False):
    if value:
        return executable(value)
    sibling = Path(python or sys.executable).parent / ("uv.exe" if os.name == "nt" else "uv")
    if sibling.is_file():
        return sibling.resolve()
    found = shutil.which("uv")
    if found:
        return Path(found).resolve()
    if required:
        raise ValueError("uv is unavailable; install requirements.txt in the selected Python environment or pass --uv.")
    return None


def output_path(value):
    result = Path(value).expanduser().resolve()
    if result.exists():
        raise ValueError(f"Use a new output directory: {result}")
    for name in ("evidence", "inputs", "outputs", "work", "data", "corpus", "drc", "scripts", "tests", "docs", "artifact_tools", "reproductions"):
        protected = ROOT / name
        if result == protected or protected in result.parents:
            raise ValueError(f"Choose an output directory outside {protected}")
    return result


def environment(out, target=None, cache=None):
    values = {key: value for key, value in os.environ.items()
              if not key.startswith(("PIP_", "UV_", "DRC_"))
              and key not in ("PYTHONPATH", "PYTHONHOME", "VIRTUAL_ENV", "CONDA_PREFIX")}
    values.update(HOME=str(out / "home"), XDG_CONFIG_HOME=str(out / "config"),
                  PIP_CONFIG_FILE=os.devnull, PIP_DISABLE_PIP_VERSION_CHECK="1",
                  PYTHONNOUSERSITE="1", PYTHONDONTWRITEBYTECODE="1", UV_LINK_MODE="copy",
                  UV_PYTHON_DOWNLOADS="never", UV_NO_INPUT="1", UV_NO_PROGRESS="1",
                  UV_CACHE_DIR=str(cache or out / "cache"), PIP_CACHE_DIR=str(out / "pip-cache"),
                  YOLO_AUTOINSTALL="false", YOLO_CONFIG_DIR=str(out / "ultralytics-config"))
    if target is not None:
        values["UV_PROJECT_ENVIRONMENT"] = str(target)
    return values


def command(argv, folder, env, timeout=900):
    folder = Path(folder)
    folder.mkdir(parents=True, exist_ok=False)
    argv = list(map(str, argv))
    began = datetime.now(timezone.utc)
    with (folder / "stdout.txt").open("wb") as stdout, (folder / "stderr.txt").open("wb") as stderr:
        process = subprocess.Popen(argv, stdout=stdout, stderr=stderr, env=env,
                                   start_new_session=os.name != "nt", stdin=subprocess.DEVNULL)
        timed_out = False
        try:
            code = process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
            if os.name != "nt":
                os.killpg(process.pid, signal.SIGKILL)
            else:
                process.kill()
            code = process.wait()
    result = {"argv": argv, "exit": code, "timeout": timed_out,
              "seconds": (datetime.now(timezone.utc) - began).total_seconds(),
              "stdout_sha256": digest(folder / "stdout.txt"), "stderr_sha256": digest(folder / "stderr.txt")}
    dump(folder / "command.json", result)
    return result
