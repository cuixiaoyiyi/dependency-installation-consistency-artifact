"""Extract package-manager install commands (and PIP_*/UV_* env assignments) from shell-like text:
README code blocks, CI `run:` steps, Dockerfile RUN lines, Makefiles, .sh scripts."""
from __future__ import annotations
import re, shlex
import posixpath
from typing import Iterable, Optional
from ..model import InstallPath

ENV_KEYS = ("PIP_INDEX_URL", "PIP_EXTRA_INDEX_URL", "PIP_FIND_LINKS", "PIP_NO_INDEX", "PIP_PRE", "PIP_REQUIRE_HASHES",
            "PIP_CONSTRAINT", "PIP_ONLY_BINARY", "PIP_NO_DEPS",
            "UV_INDEX_URL", "UV_EXTRA_INDEX_URL", "UV_INDEX", "UV_DEFAULT_INDEX", "UV_INDEX_STRATEGY", "UV_FIND_LINKS",
            "PIP_TRUSTED_HOST", "POETRY_REPOSITORIES_", "PDM_PYPI_URL", "PIPENV_PYPI_MIRROR")

_ENV_RE = re.compile(r"(?:^|\s|;|&&)\s*(?:export\s+|ENV\s+|ARG\s+|set\s+)?(" + "|".join(ENV_KEYS) + r"[A-Z0-9_]*)\s*[=:]\s*[\"']?([^\"'\s]+)")

def scan_env(text: str) -> dict:
    env = {}
    for m in _ENV_RE.finditer(text):
        env[m.group(1)] = m.group(2)
    return env

_PROMPT_RE = re.compile(r"^\s*(?:\$|>|%|#|!|PS>|\(.*?\)\s*\$|\[[^\]]*\]\$)\s*")
_RUN_RE = re.compile(r"^\s*RUN\s+(?:--mount=[^\s]+\s+)*(?:--network=[^\s]+\s+)*", re.I)
_CMD_START = re.compile(
    r"(?:^|[;&|(]\s*|\bthen\s+|\bdo\s+|\belse\s+|\bexec\s+|\bsh\s+-c\s+[\"'])\s*"
    r"((?:(?:sudo\s+)?(?:\S*python[0-9.]*|py|\$\(PYTHON\)|\$\{PYTHON\}|\$PYTHON|\$\{?PY\}?)\s+-m\s+(?:pip|uv)\b|(?:sudo\s+)?(?:\S*/)?pip[0-9.]*\b|\$\(PIP\)|\$\{PIP\}|\$PIP\b|(?:sudo\s+)?uvx?\b|poetry\b|pdm\b|pipenv\b|pipx\b|micromamba\b|conda\b)[^\n]*)")

_ASSIGN_RE = re.compile(r"^\s*(?:(?:ARG|export|set)\s+([A-Za-z_][A-Za-z0-9_]*)\s*=\s*|ENV\s+([A-Za-z_][A-Za-z0-9_]*)(?:\s*=\s*|\s+)|([A-Za-z_][A-Za-z0-9_]*)=)(\"[^\"]*\"|'[^']*'|\S+)\s*$")

class _AM:
    """Adapter so callers can use .group(1)=name, .group(2)=value on the new assignment regex."""
    def __init__(self, m): self.m = m
    def group(self, i):
        if i == 1: return self.m.group(1) or self.m.group(2) or self.m.group(3)
        if i == 2: return self.m.group(4)
        return self.m.group(0)

def _assign_match(line: str):
    m = _ASSIGN_RE.match(line)
    return _AM(m) if m else None
_ASSIGN_INLINE_RE = re.compile(r"(?:^|\s)(?:ARG|ENV|export)\s+([A-Za-z_][A-Za-z0-9_]*)=(\"[^\"]*\"|'[^']*'|\S+)")

def _strip_substitutions(s: str) -> str:
    """Replace $( ... ) and backtick substitutions with a placeholder so pipes inside them do not split the command."""
    out = []; i = 0; depth = 0; start = None
    while i < len(s):
        if s.startswith("$(", i):
            if depth == 0: start = i
            depth += 1; i += 2; continue
        if s[i] == ")" and depth > 0:
            depth -= 1; i += 1
            if depth == 0: out.append("__SUBST__"); start = None
            continue
        if depth == 0: out.append(s[i])
        i += 1
    s2 = "".join(out)
    s2 = re.sub(r"\$\{\{[^}]*\}\}", "__SUBST__", s2)          # GitHub Actions expressions ${{ matrix.x }}
    s2 = re.sub(r"\{\{[^}]*\}\}", "__SUBST__", s2)             # jinja/ansible templates
    return re.sub(r"`[^`]*`", "__SUBST__", s2)

_VAR_RE = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)(?::?([-=+?])([^}]*))?\}|\$([A-Za-z_][A-Za-z0-9_]*)")

def _shell_parts(text):
    """Split shell operators only outside quoted PEP 508 requirements."""
    start = 0; quote = None; escaped = False; i = 0
    while i < len(text):
        char = text[i]
        if escaped: escaped = False; i += 1; continue
        if char == "\\" and quote != "'": escaped = True; i += 1; continue
        if quote:
            if char == quote: quote = None
        elif char in ("'", '"'):
            quote = char
        elif char in ";|&":
            if char == "&" and ((i and text[i - 1] in "<>") or text[i:i + 2] == "&>"):
                i += 1
                continue
            yield text[start:i]
            if i + 1 < len(text) and text[i + 1] == char: i += 1
            start = i + 1
        i += 1
    yield text[start:]

def expand_vars(s: str, env: dict) -> str:
    """Expand ${VAR}, $VAR and ${VAR:-default} using env; unknown variables are left untouched."""
    def rep(m):
        name = m.group(1) or m.group(4)
        op, default = m.group(2), m.group(3)
        val = env.get(name)
        if val not in ("", None): return val
        if op in ("-", "=") and default is not None: return default
        return m.group(0)
    return _VAR_RE.sub(rep, s)

def collect_assignments(text: str) -> dict:
    """ARG/ENV/export/plain NAME=value across the text (Dockerfile ARG defaults become globally visible)."""
    env = {}
    for raw in text.splitlines():
        line = raw.strip()
        m = _assign_match(line)
        if m and (line.startswith(("ARG ", "ENV ", "export ")) or re.match(r"^[A-Z_][A-Z0-9_]*=", line)):
            v = m.group(2).strip("\"'")
            if m.group(1) not in env or line.startswith(("ARG ", "ENV ")): env[m.group(1)] = v
        for m2 in _ASSIGN_INLINE_RE.finditer(line):
            env.setdefault(m2.group(1), m2.group(2).strip("\"'"))
    # resolve one level of self-reference (ARG UV_INDEX_URL=${PIP_INDEX_URL})
    for k, v in list(env.items()):
        if "$" in v:
            nv = expand_vars(v, {kk: vv for kk, vv in env.items() if kk != k and "$" not in vv})
            env[k] = nv if "$" not in nv else v
    return {k: v for k, v in env.items() if "$" not in v}

def split_commands(text: str, env: Optional[dict] = None) -> Iterable[tuple[int, str]]:
    """Yield (line_no, command) for shell-ish text, joining backslash continuations and splitting on && ; ||."""
    env = env if env is not None else {}
    lines = text.splitlines()
    i = 0
    while i < len(lines):
        ln = i + 1
        cur = lines[i].rstrip("\r")
        # join continuations
        while cur.rstrip().endswith("\\") and i + 1 < len(lines):
            i += 1; cur = cur.rstrip()[:-1] + " " + lines[i].strip()
        i += 1
        s = _RUN_RE.sub("", cur)
        s = _PROMPT_RE.sub("", s) if re.match(r"^\s*(\$|>|!|%)\s*\S", s) else s
        s = s.replace("$(PIP)", "pip").replace("${PIP}", "pip").replace("$PIP ", "pip ").replace("$(PYTHON)", "python").replace("${PYTHON}", "python").replace("$PYTHON ", "python ")
        s = _strip_substitutions(s)
        for part in _shell_parts(s):
            part = part.strip()
            if not part: continue
            # track assignments as we go (later commands see earlier ENV/export)
            m = _assign_match(part)
            if m and (part.startswith(("ARG ", "ENV ", "export ")) or re.match(r"^[A-Za-z_][A-Za-z0-9_]*=\S", part)):
                v = expand_vars(m.group(2).strip("\"'"), env)
                if "$" not in v: env[m.group(1)] = v
            yield ln, expand_vars(part, env)

_INSTALL_TOOLS = re.compile(r"^(?:sudo\s+)?(?:(?P<py>\S*python[0-9.]*|py)\s+-m\s+(?P<mod>pip|uv)|(?P<pip>(?:\S*/)?pip[0-9.]*)|(?P<uv>uvx?)|(?P<poetry>poetry)|(?P<pdm>pdm)|(?P<pipenv>pipenv)|(?P<pipx>pipx)|(?P<conda>conda|micromamba|mamba))\b")

VALUE_OPTS = {"-i", "--index-url", "--extra-index-url", "-f", "--find-links", "-r", "--requirement", "-c", "--constraint", "--only-binary", "--no-binary",
              "--trusted-host", "--index-strategy", "--index", "--default-index", "--python", "-p", "--python-version", "--python-platform", "--platform",
              "--target", "-t", "--prefix", "--root", "--src", "--use-feature", "--config-settings", "--global-option", "--install-option", "--proxy",
              "--retries", "--timeout", "--cache-dir", "--log", "--exists-action", "--abi", "--implementation", "--progress-bar", "--root-user-action",
              "--report", "--keyring-provider", "--cert", "--client-cert", "--hash", "--source", "--group", "--with", "--without", "--only", "-E", "--extras",
              "--extra", "--link-mode", "--resolution", "--exclude-newer", "--refresh-package", "--reinstall-package", "--upgrade-package", "-P", "--no-binary-package",
              "--only-binary-package", "--constraints", "--overrides", "--build-constraints", "-o", "--output-file", "--annotation-style", "--custom-compile-command",
              "--format", "-n", "--name", "--env", "--file", "--requirements", "--unsafe-package", "--prerelease", "-e", "--editable", "--color"}

_OUTPUT_OPTS = {"--report", "--log", "--progress-bar", "--cache-dir", "--retries", "--timeout", "-o", "--output-file",
                "--annotation-style", "--custom-compile-command", "--format", "--color"}
_DISPLAY_FLAGS = {"--quiet", "-q", "--verbose", "-v", "--dry-run", "--ignore-installed", "--no-progress", "--no-header",
                  "--no-cache-dir", "--disable-pip-version-check", "--system", "--emit-index-annotation"}
_STATE_FLAGS = {"--upgrade", "-U", "--force-reinstall", "--reinstall", "--no-build", "--no-build-isolation", "--no-sources"}


def _without_redirections(command: str) -> str:
    """Remove shell redirections without altering quoted requirement markers."""
    token = r'''(?:"(?:\\.|[^"\\])*"|'[^']*'|[^\s'"<>])+'''
    redirection = re.compile(r"(?:\d*(?:>>?|<<?|<>)(?:&\d+|&-|\s*" + token + r")|&>>?\s*" + token + r")")
    out = []
    quote = None
    i = 0
    while i < len(command):
        char = command[i]
        if char == "\\" and quote != "'" and i + 1 < len(command):
            out.append(command[i:i + 2])
            i += 2
            continue
        if quote:
            out.append(char)
            if char == quote:
                quote = None
            i += 1
            continue
        if char in ("'", '"'):
            quote = char
        elif char in "<>" or (char.isdigit() or char == "&") and (i == 0 or command[i - 1].isspace()):
            match = redirection.match(command, i)
            if match:
                out.append(" ")
                i = match.end()
                continue
        out.append(char)
        i += 1
    return "".join(out)

def parse_install_command(cmd: str, env: Optional[dict] = None) -> Optional[dict]:
    """Return dict describing an install command or None."""
    env = env or {}
    # Inline assignments affect this invocation only. Keep their values as
    # explicit evidence instead of treating a later assignment as global config.
    cmd = re.sub(r"^(?:[A-Za-z_][A-Za-z0-9_]*=(?:\"[^\"]*\"|'[^']*'|\S+)\s+)+", "", cmd.strip())
    m = _INSTALL_TOOLS.match(cmd.strip())
    if not m: return None
    token_error = None
    token_command = _without_redirections(cmd)
    try:
        toks = shlex.split(token_command, comments=True, posix=True)
    except ValueError as error:
        token_error = str(error)
        toks = cmd.split()[:2]
    if not toks: return None
    # normalise tool + subcommand
    if m.group("py"):
        tool = m.group("mod"); toks = toks[toks.index("-m") + 2:] if "-m" in toks else toks[3:]
    else:
        tool = {"pip": "pip", "uv": "uv", "poetry": "poetry", "pdm": "pdm", "pipenv": "pipenv", "pipx": "pipx", "conda": "conda"}[next(k for k in ("pip", "uv", "poetry", "pdm", "pipenv", "pipx", "conda") if m.group(k))]
        toks = toks[1:] if toks[0].lower() != "sudo" else toks[2:]
        if tool == "uv" and m.group("uv") == "uvx": return None
    sub = toks[0] if toks else ""
    kind = None
    if tool == "pip" and sub in ("install", "download", "wheel"): kind = f"pip {sub}"
    elif tool == "uv" and sub == "pip" and len(toks) > 1 and toks[1] in ("install", "compile", "sync"): kind = f"uv pip {toks[1]}"; toks = toks[1:]
    elif tool == "uv" and sub in ("add", "sync", "lock", "run", "tool", "export"): kind = f"uv {sub}"
    elif tool == "poetry" and sub in ("add", "install", "lock", "update"): kind = f"poetry {sub}"
    elif tool == "pdm" and sub in ("add", "install", "sync", "lock"): kind = f"pdm {sub}"
    elif tool == "pipenv" and sub in ("install", "sync", "lock"): kind = f"pipenv {sub}"
    elif tool == "pipx" and sub in ("install", "run"): kind = f"pipx {sub}"
    elif tool == "conda" and sub in ("install", "create", "env"): return None
    if not kind: return None
    if kind == "uv tool" and not (len(toks) > 1 and toks[1] == "install"): return None
    args = toks[2:] if kind == "uv tool" else toks[1:]
    ip = {"tool": tool, "kind": kind, "packages": [], "req_files": [], "constraint_files": [], "index_url": None, "extra_index_urls": [], "find_links": [],
          "no_index": False, "pre": False, "no_deps": False, "require_hashes": False, "only_binary": None, "index_strategy": None, "named_index": [],
          "default_index": None, "uv_sync": kind in ("uv sync", "uv lock", "uv run", "poetry install", "poetry lock", "pdm install", "pdm sync", "pdm lock", "pipenv install", "pipenv sync"),
          "editable_local": False, "extras_of_project": [], "source": None, "group_flags": [], "limitations": [],
          "lock_mode": "off" if tool == "pip" or kind.startswith("uv pip") else "unknown"}
    if token_error:
        ip["limitations"].append(f"command tokenization failed: {token_error}")
        args = []
    if token_command != cmd and re.search(r"[A-Za-z][A-Za-z0-9_.-]*[<>]", cmd):
        ip["limitations"].append("unquoted shell redirection changes the positional request")
    if m.group("py"):
        ip["limitations"].append(f"original command interpreter requires replay: {m.group('py')}")
    if kind in ("uv run", "pipx run"):
        ip["limitations"].append("executed application arguments are not an install request")
        args = []
    positionals_only = False
    i = 0
    while i < len(args):
        a = args[i]; val = None
        if a == "--" and not positionals_only:
            positionals_only = True
            i += 1
            continue
        if not positionals_only:
            if a.startswith("--") and "=" in a:
                a, val = a.split("=", 1)
                if a in VALUE_OPTS and not val:
                    ip["limitations"].append(f"missing value for install option: {a}")
                    break
            elif a in VALUE_OPTS:
                if i + 1 == len(args) or not args[i + 1] or args[i + 1].startswith("-"):
                    ip["limitations"].append(f"missing value for install option: {a}")
                    break
                val = args[i + 1]
                i += 1
            elif re.match(r"^-[ifrctpe]\S+$", a):
                val = a[2:]
                a = a[:2]
        if positionals_only:
            if a.startswith("-"):
                ip["limitations"].append(f"invalid requirement after end of options: {a}")
            elif kind in ("uv pip compile", "uv pip sync"):
                ip["req_files"].append(a)
            elif _is_local(a):
                ip["editable_local"] = True
                ip["extras_of_project"] += _extras_of(a)
                if a not in (".", "./") and not a.startswith(".["):
                    ip["limitations"].append(f"local install target requires original-path replay: {a}")
            else:
                ip["packages"].append(a)
            i += 1
            continue
        if a in ("-i", "--index-url"): ip["index_url"] = val
        elif a == "--extra-index-url": ip["extra_index_urls"] += [v for v in (val or "").split() if v]
        elif a in ("-f", "--find-links"): ip["find_links"].append(val)
        elif a in ("-r", "--requirement", "--requirements"): ip["req_files"].append(val)
        elif a in ("-c", "--constraint", "--constraints"): ip["constraint_files"].append(val)
        elif a == "--no-index": ip["no_index"] = True
        elif a == "--pre": ip["pre"] = True
        elif a == "--prerelease":
            if val == "allow": ip["pre"] = True
            else: ip["limitations"].append(f"original prerelease policy requires replay: {val}")
        elif a == "--no-deps": ip["no_deps"] = True
        elif a == "--require-hashes": ip["require_hashes"] = True
        elif a == "--only-binary": ip["only_binary"] = val
        elif a == "--index-strategy": ip["index_strategy"] = val
        elif a == "--index": ip["named_index"].append(val)
        elif a == "--default-index": ip["default_index"] = val
        elif a == "--source": ip["source"] = val
        elif a in ("--frozen", "--locked"): ip["lock_mode"] = a[2:]
        elif a in ("--group", "--with", "--without", "--only", "-E", "--extras", "--extra", "--all-extras", "--all-groups", "--dev", "--no-dev"):
            ip["group_flags"].append(a + ("=" + val if val else ""))
            if a == "--extra" and tool == "uv":
                ip["extras_of_project"].append(val)
            elif a != "--all-extras" or tool != "uv":
                ip["limitations"].append(f"original dependency group policy requires replay: {a}")
        elif a in ("-e", "--editable"):
            if _is_local(val):
                ip["editable_local"] = True
                ip["extras_of_project"] += _extras_of(val)
                if val not in (".", "./") and not val.startswith(".["):
                    ip["limitations"].append(f"local install target requires original-path replay: {val}")
            else:
                ip["packages"].append(val)
        elif a in _OUTPUT_OPTS or a in _DISPLAY_FLAGS:
            pass
        elif a in VALUE_OPTS or a in _STATE_FLAGS:
            ip["limitations"].append(f"original install option requires replay: {a}" + (f"={val}" if val else ""))
        elif a.startswith("-"):
            ip["limitations"].append(f"unsupported install option: {a}")
            if val is None:
                # The next token could be an option value or a requirement.
                # Preserve the original command and stop claiming a full request.
                break
        else:
            t = a
            if kind in ("uv pip compile", "uv pip sync"):
                ip["req_files"].append(t)
            elif _is_local(t):
                ip["editable_local"] = True
                ip["extras_of_project"] += _extras_of(t)
                if t not in (".", "./") and not t.startswith(".["):
                    ip["limitations"].append(f"local install target requires original-path replay: {t}")
            elif t and not t.startswith("$") and re.match(r"^[A-Za-z0-9]", t): ip["packages"].append(t)
            elif t.startswith("$") and re.search(r"REQ|requirements", t, re.I): ip["req_files"].append(t)
        i += 1
    # env fallbacks (pip/uv honour these)
    if ip["index_url"] is None:
        ip["index_url"] = env.get("PIP_INDEX_URL") if tool == "pip" else env.get("UV_INDEX_URL") or env.get("UV_DEFAULT_INDEX") if tool == "uv" else None
    if not ip["extra_index_urls"]:
        ev = env.get("PIP_EXTRA_INDEX_URL") if tool == "pip" else env.get("UV_EXTRA_INDEX_URL") if tool == "uv" else None
        if ev: ip["extra_index_urls"] = [v for v in ev.split() if v]
    if tool == "uv" and not ip["index_strategy"] and env.get("UV_INDEX_STRATEGY"): ip["index_strategy"] = env["UV_INDEX_STRATEGY"]
    if tool == "uv" and env.get("UV_INDEX"): ip["named_index"] += env["UV_INDEX"].split()
    truth = lambda value: str(value).lower() not in ("", "0", "false", "no", "off", "none")
    for key, field in (("PIP_NO_INDEX", "no_index"), ("PIP_PRE", "pre"), ("PIP_REQUIRE_HASHES", "require_hashes"), ("PIP_NO_DEPS", "no_deps")):
        if tool == "pip" and key in env: ip[field] = ip[field] or truth(env[key])
    if tool == "pip" and env.get("PIP_ONLY_BINARY"): ip["only_binary"] = ip["only_binary"] or env["PIP_ONLY_BINARY"]
    if tool == "pip" and env.get("PIP_CONSTRAINT"): ip["constraint_files"] += env["PIP_CONSTRAINT"].split()
    if kind == "pip download": ip["kind"] = "pip download"
    return ip

def _is_local(t: str) -> bool:
    t = t.strip("'\"")
    if t.startswith(("http://", "https://", "git+", "ssh://", "file:")): return False
    if "://" in t or "@" in t and "/" in t: return False
    return t in (".", "./") or t.startswith(("./", "../", "/", ".[", "src/", "python/", "~")) or re.match(r"^\.\[[^\]]+\]$", t) is not None \
        or ("/" in t and not re.match(r"^[A-Za-z0-9][A-Za-z0-9._-]*(\[[^\]]*\])?\s*([<>=!~].*)?$", t)) or t.endswith((".whl", ".tar.gz", ".zip", ".txt", ".toml", ".py"))

def _extras_of(t: str) -> list:
    m = re.search(r"\[([^\]]+)\]", t)
    return [x.strip() for x in m.group(1).split(",")] if m else []

def extract_install_paths(text: str, file: str, kind: str, id_prefix: str, base_env: Optional[dict] = None, working_directory: Optional[str] = None) -> list[InstallPath]:
    """Scan text; return InstallPath list. Env assignments earlier in the text apply to later commands."""
    out = []
    env = dict(base_env or {})
    cwd = working_directory
    prior_environment_step = False
    n = 0
    for ln, cmd in split_commands(text, env):
        if cmd.startswith("cd "):
            try: dest = shlex.split(cmd)[1]
            except (ValueError, IndexError): dest = "$unknown"
            cwd = posixpath.normpath(posixpath.join(cwd, dest)) if cwd is not None and not dest.startswith(("/", "~", "$")) else None
            continue
        command_env = dict(env); command_env.update(scan_env(cmd))
        ip = parse_install_command(cmd, command_env)
        if not ip:
            if re.search(r"\b(?:uninstall|venv|activate|conda\s+(?:create|activate))\b", cmd):
                prior_environment_step = True
            continue
        if prior_environment_step:
            ip["limitations"].append("earlier package or environment steps require sequential replay")
        if "$" in cmd or "__SUBST__" in cmd:
            ip["limitations"].append("command contains unresolved variables or substitutions")
        ip["packages"] = [p for p in ip["packages"] if "__SUBST__" not in p and "$" not in p and "{" not in p and "}" not in p and not p.startswith(("(", ")", "`", "\\"))]
        ip["req_files"] = [p for p in ip["req_files"] if p and "__SUBST__" not in p]
        if ip["index_url"] and ("__SUBST__" in ip["index_url"] or "$" in ip["index_url"]): ip["unresolved_index"] = ip["index_url"]; ip["index_url"] = None
        ip["extra_index_urls"] = [u for u in ip["extra_index_urls"] if u and "__SUBST__" not in u and "$" not in u]
        if not (ip["packages"] or ip["req_files"] or ip["editable_local"] or ip["uv_sync"] or ip["limitations"]): continue
        n += 1
        out.append(InstallPath(id=f"{id_prefix}#{n}", kind=kind, file=file, line=ln, tool=ip["tool"] if ip["kind"] != "uv pip install" else "uv-pip", command=cmd.strip(),
                               packages=ip["packages"], req_files=ip["req_files"], constraint_files=ip["constraint_files"], index_url=ip["index_url"],
                               extra_index_urls=ip["extra_index_urls"], find_links=ip["find_links"], no_index=ip["no_index"], pre=ip["pre"], no_deps=ip["no_deps"],
                               require_hashes=ip["require_hashes"], only_binary=ip["only_binary"], index_strategy=ip["index_strategy"], env=command_env,
                               uv_sync=ip["uv_sync"], editable_local=ip["editable_local"], extras_of_project=ip["extras_of_project"],
                               working_directory=cwd, limitations=list(ip["limitations"]), group_flags=ip["group_flags"], lock_mode=ip["lock_mode"]))
        out[-1].command_kind = ip["kind"]  # dynamic attr for reporting
        out[-1].named_index = ip["named_index"]; out[-1].default_index = ip["default_index"]; out[-1].source = ip["source"]
        if ip["kind"] not in ("pip download", "pip wheel", "uv pip compile", "uv export") and "--dry-run" not in cmd:
            prior_environment_step = True
    return out
