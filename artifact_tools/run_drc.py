"""Plan or run DRC with an explicitly selected local Python and uv."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from artifact_tools._runtime import output_path, python_path, uv_path


def parser():
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("project", type=Path)
    result.add_argument("--out", type=Path, required=True)
    result.add_argument("--python", type=Path)
    result.add_argument("--uv", type=Path)
    result.add_argument("--max-contexts", type=int, default=4)
    result.add_argument("--max-rtos", type=int, default=2)
    mode = result.add_mutually_exclusive_group()
    mode.add_argument("--execute", action="store_true", help="Run resolver commands; the default only prints the plan.")
    mode.add_argument("--dry-run", action="store_true", help="Validate paths and print the plan without resolver execution.")
    return result


def main(argv=None):
    options = parser()
    args = options.parse_args(argv)
    try:
        project = args.project.expanduser().resolve(strict=True)
        if not project.is_dir():
            raise ValueError("The project path must be a directory.")
        out, python = output_path(args.out), python_path(args.python)
        uv = uv_path(args.uv, python)
        if args.max_contexts < 1 or args.max_rtos < 1:
            raise ValueError("Context and transformation budgets must be positive.")
    except (ValueError, OSError) as exc:
        options.error(str(exc))
    plan = {"mode": "execute" if args.execute else "dry-run", "project": str(project), "out": str(out),
            "python": str(python), "uv": str(uv) if uv else "selected Python's uv module",
            "execution_backend": "host", "language_model": "disabled",
            "max_contexts": args.max_contexts, "max_rtos": args.max_rtos,
            "scope": "DRC input extraction, resolver execution and scoped contracts; this is not the multi-step installation harness."}
    if not args.execute:
        print(json.dumps(plan, indent=2))
        return 0
    if python != Path(os.path.abspath(sys.executable)):
        command = [python, Path(__file__).resolve(), project, "--out", out, "--execute",
                   "--max-contexts", str(args.max_contexts), "--max-rtos", str(args.max_rtos)]
        if uv:
            command += ["--uv", uv]
        return subprocess.run(list(map(str, command)), stdin=subprocess.DEVNULL).returncode
    os.environ["DRC_EXEC"] = "host"
    os.environ["DRC_CACHE"] = str(out.parent / (out.name + "-resolver-cache"))
    from drc import resolvers
    if uv:
        original = resolvers._run

        def local_run(command, cwd, env, timeout, tool, pyver="3.12"):
            if tool == "uv" and list(command[:3]) == [resolvers.PY, "-m", "uv"]:
                command = [str(uv), *command[3:]]
            return original(command, cwd, env, timeout, tool, pyver)

        resolvers._run = local_run
        resolvers._versions = lambda: (resolvers._version([resolvers.PY, "-m", "pip", "--version"]),
                                      resolvers._version([str(uv), "--version"]))
    from drc.cli import main as drc_main
    drc_main(["analyze", str(project), "--out", str(out), "--no-llm",
              "--max-contexts", str(args.max_contexts), "--max-rtos", str(args.max_rtos)])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
