"""CI workflows, Dockerfiles, docs/README, scripts -> install paths (via shell.py)."""
from __future__ import annotations
import re, pathlib
from typing import Optional
import yaml
from .shell import extract_install_paths, scan_env
from ..model import InstallPath

def _read(p: pathlib.Path) -> str:
    try: return p.read_text(encoding="utf-8", errors="replace")
    except OSError: return ""

def _flatten_env(*envs) -> dict:
    out = {}
    for e in envs:
        if isinstance(e, dict):
            for k, v in e.items():
                if isinstance(k, str) and k.upper() == k and isinstance(v, (str, int, float)): out[k] = str(v)
    return out

def github_workflow(path: pathlib.Path, rel: str) -> list[InstallPath]:
    text = _read(path)
    out = []
    try:
        data = yaml.safe_load(text)
    except Exception:
        data = None
    if not isinstance(data, dict):
        out = extract_install_paths(text, rel, "ci", rel)
        for ip in out:
            ip.limitations.append("workflow structure and runner environment are unresolved")
        return out
    wf_env = _flatten_env(data.get("env"))
    wf_cwd = ((data.get("defaults") or {}).get("run") or {}).get("working-directory", ".")
    n = 0
    for jname, job in (data.get("jobs") or {}).items():
        if not isinstance(job, dict): continue
        jenv = _flatten_env(wf_env, job.get("env"))
        runner = job.get("runs-on", "unspecified")
        target_limitations = [f"CI runner environment requires original-job replay: {runner}"]
        if (job.get("strategy") or {}).get("matrix"):
            target_limitations.append("CI matrix is not expanded")
        if job.get("container"):
            container = job["container"]
            image = container.get("image", "unspecified") if isinstance(container, dict) else container
            target_limitations.append(f"CI container environment requires original-job replay: {image}")
        if job.get("if"):
            target_limitations.append("CI job condition is not evaluated")
        python_version = None
        prior_environment_step = False
        for si, step in enumerate(job.get("steps") or []):
            if not isinstance(step, dict): continue
            uses = step.get("uses", "")
            if isinstance(uses, str) and uses.startswith("actions/setup-python@"):
                python_version = (step.get("with") or {}).get("python-version") or (step.get("with") or {}).get("python-version-file") or "unspecified"
            elif isinstance(uses, str) and uses.startswith("astral-sh/setup-uv@") and (step.get("with") or {}).get("python-version"):
                python_version = step["with"]["python-version"]
            senv = _flatten_env(jenv, step.get("env"))
            run = step.get("run")
            if isinstance(run, str) and run.strip():
                cwd = step.get("working-directory", ((job.get("defaults") or {}).get("run") or {}).get("working-directory", wf_cwd))
                cwd = cwd if isinstance(cwd, str) and not re.search(r"\$|[{}]", cwd) else None
                ips = extract_install_paths(run, rel, "ci", f"{rel}::{jname}[{si}]", senv, working_directory=cwd)
                for ip in ips:
                    ip.line += _find_line(text, run.splitlines()[0], 1) - 1
                    ip.job = jname; ip.step = step.get("name") or f"step{si}"
                    ip.limitations.extend(target_limitations)
                    if python_version is not None:
                        ip.limitations.append(f"CI Python selection requires original-job replay: {python_version}")
                    if step.get("if"):
                        ip.limitations.append("CI step condition is not evaluated")
                    if prior_environment_step:
                        ip.limitations.append("earlier CI steps require sequential environment replay")
                    if cwd is None:
                        ip.limitations.append("CI working-directory is unresolved")
                if ips or re.search(r"\b(?:venv|activate|uninstall)\b", run):
                    prior_environment_step = True
                out += ips; n += len(ips)
            # setup-uv / setup-python 'with' rarely set indexes; skip
    return out

def gitlab_ci(path: pathlib.Path, rel: str) -> list[InstallPath]:
    text = _read(path)
    try: data = yaml.safe_load(text)
    except Exception: return extract_install_paths(text, rel, "ci", rel)
    if not isinstance(data, dict): return extract_install_paths(text, rel, "ci", rel)
    genv = _flatten_env(data.get("variables"))
    out = []
    for jname, job in data.items():
        if not isinstance(job, dict): continue
        env = _flatten_env(genv, job.get("variables"))
        for key in ("before_script", "script", "after_script"):
            sc = job.get(key)
            if isinstance(sc, list): sc = "\n".join(str(x) for x in sc)
            if isinstance(sc, str) and sc.strip():
                ips = extract_install_paths(sc, rel, "ci", f"{rel}::{jname}.{key}", env)
                for ip in ips:
                    ip.line = _find_line(text, ip.command.split()[0] if ip.command else "", ip.line)
                    ip.limitations.append("GitLab runner, image and cross-step environment require original-job replay")
                out += ips
    return out

def generic_yaml_ci(path: pathlib.Path, rel: str) -> list[InstallPath]:
    """azure-pipelines / circleci / travis / others: scan all string scalars that look like shell."""
    text = _read(path)
    out = extract_install_paths(text, rel, "ci", rel)
    for ip in out:
        ip.limitations.append("CI runner, target and step state are not modeled")
    return out

def dockerfile(path: pathlib.Path, rel: str) -> list[InstallPath]:
    text = _read(path)
    stages = list(re.finditer(r"^\s*FROM\s+(.+)$", text, re.M | re.I))
    if not stages:
        out = extract_install_paths(text, rel, "dockerfile", rel)
        for ip in out:
            ip.limitations.append("Docker base image and build environment are unresolved")
        return out
    out = []
    for index, stage in enumerate(stages):
        end = stages[index + 1].start() if index + 1 < len(stages) else len(text)
        block = text[stage.start():end]
        offset = text[:stage.start()].count("\n")
        ips = extract_install_paths(block, rel, "dockerfile", f"{rel}::stage{index}")
        bare_args = [(block[:match.start()].count("\n") + 1, match.group(1))
                     for match in re.finditer(r"^\s*ARG\s+([A-Za-z_][A-Za-z0-9_]*)\s*$", block, re.M)]
        for ip in ips:
            for line, name in bare_args:
                if line < ip.line and name not in ip.env:
                    ip.limitations.append(f"Docker ARG redeclaration requires a build-time value: {name}")
            ip.line += offset
            ip.limitations.append(f"Docker stage environment requires original-build replay: {stage.group(1).strip()}")
            ip.limitations.append("Docker working-directory, copied files and prior image state are not replayed")
        out.extend(ips)
    return out

_FENCE_RE = re.compile(r"```[^\n]*\n(.*?)```", re.S)
_RST_CODE_RE = re.compile(r"(?:\.\. code(?:-block)?::[^\n]*\n|::\n)((?:\n|[ \t]+[^\n]*\n?)+)")

def markdown_doc(path: pathlib.Path, rel: str, kind: str = "readme") -> list[InstallPath]:
    text = _read(path)
    out = []
    # code fences (markdown)
    for m in _FENCE_RE.finditer(text):
        block = m.group(1)
        start_line = text[: m.start(1)].count("\n") + 1
        ips = extract_install_paths(block, rel, kind, f"{rel}@L{start_line}")
        for ip in ips: ip.line += start_line - 1
        out += ips
    # rst literal blocks
    if path.suffix.lower() == ".rst":
        for m in _RST_CODE_RE.finditer(text):
            block = "\n".join(l.strip() for l in m.group(1).splitlines())
            start_line = text[: m.start(1)].count("\n") + 1
            ips = extract_install_paths(block, rel, kind, f"{rel}@L{start_line}")
            for ip in ips: ip.line += start_line - 1
            out += ips
    # inline lines outside fences that start with pip/uv (rare but common in READMEs)
    if not out:
        for i, l in enumerate(text.splitlines(), 1):
            if re.match(r"^\s*(\$\s*)?(pip[0-9]*|uv|poetry|pdm|python[0-9.]*\s+-m\s+pip)\s+(install|pip|add|sync)\b", l):
                out += [ip for ip in extract_install_paths(l, rel, kind, f"{rel}@L{i}") if ip]
                for ip in out:
                    if ip.line == 1: ip.line = i
    return out

def script_file(path: pathlib.Path, rel: str, kind: str = "script") -> list[InstallPath]:
    text = _read(path)
    out = extract_install_paths(text, rel, kind, rel)
    if re.search(r"^\s*(?:if|for|while|case|function|select)\b", text, re.M):
        for ip in out:
            ip.limitations.append("shell control flow requires original-script replay")
    if path.suffix.lower() in (".ps1", ".bat", ".cmd"):
        for ip in out:
            ip.limitations.append("Windows script interpreter and syntax require original-script replay")
    return out

def makefile(path: pathlib.Path, rel: str) -> list[InstallPath]:
    text = _read(path)
    # resolve simple variable definitions PIP := ... / PYTHON ?= ...
    vars_ = dict(re.findall(r"^([A-Z_]+)\s*[:?]?=\s*(.+)$", text, re.M))
    for k, v in vars_.items():
        text = text.replace(f"$({k})", v.strip()).replace(f"${{{k}}}", v.strip())
    return extract_install_paths(text, rel, "makefile", rel)

def tox_ini(path: pathlib.Path, rel: str) -> list[InstallPath]:
    text = _read(path)
    out = []
    # install_command / commands / deps may contain -i / --extra-index-url ; pip_pre ; indexserver
    for m in re.finditer(r"^(install_command|commands|commands_pre|deps)\s*=\s*(.*(?:\n[ \t]+.*)*)", text, re.M):
        block = m.group(2)
        ln = text[: m.start()].count("\n") + 1
        ips = extract_install_paths(block.replace("{opts}", "").replace("{packages}", "PKG"), rel, "tox", f"{rel}@L{ln}", scan_env(text))
        for ip in ips: ip.line += ln - 1; ip.packages = [p for p in ip.packages if p != "PKG"]
        out += ips
    if re.search(r"^\[testenv[^\]]*\]\s*$", text, re.M) and re.search(r"^(setenv|passenv)\s*=.*PIP_(EXTRA_)?INDEX_URL", text, re.M | re.S):
        pass
    return out

def conda_env_yaml(path: pathlib.Path, rel: str) -> list[InstallPath]:
    text = _read(path)
    try: data = yaml.safe_load(text)
    except Exception: return []
    if not isinstance(data, dict): return []
    out = []
    for d in data.get("dependencies") or []:
        if isinstance(d, dict) and "pip" in d and isinstance(d["pip"], list):
            lines = [str(x) for x in d["pip"]]
            idx = [l for l in lines if l.startswith("--")]
            pkgs = [l for l in lines if not l.startswith("--")]
            cmd = "pip install " + " ".join(idx + pkgs)
            ips = extract_install_paths(cmd, rel, "conda-env", rel)
            for ip in ips: ip.line = _find_line(text, "pip:", 1)
            out += ips
    return out

def _find_line(text: str, needle: str, default: int) -> int:
    if not needle: return default
    for i, l in enumerate(text.splitlines(), 1):
        if needle[:60] in l: return i
    return default
