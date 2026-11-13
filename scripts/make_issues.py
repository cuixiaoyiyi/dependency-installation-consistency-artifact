"""Generate review drafts for independently verified dependency contract breaches.

Historical observations and drafts are preserved. Default output is a new directory
under work/; mined intent and a declared context label never establish a defect.
"""
from __future__ import annotations
import json, pathlib, re, glob, collections, datetime, urllib.parse
import yaml
import sys
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
from drc.report import render_issue
from drc.report.reliability import assess_case, context_label, context_reliability, verified_text

ROOT = pathlib.Path(__file__).resolve().parents[1]
OUT = ROOT / 'work' / 'verified-issue-drafts'
RESULTS_ROOT = ROOT / 'results' / 'projects'
CORPUS_ROOT = ROOT / 'corpus' / 'repos'
DATE = "2026-09-07"  # date of the resolver executions (run 2)
TOOLS = "pip 26.2.1 and uv 0.12.10 on Ubuntu (WSL2), Linux x86_64"

def load(p, default=None):
    try: return json.loads(pathlib.Path(p).read_text(encoding="utf-8"))
    except Exception: return default

def real(c, ctxs=None):
    """A label such as declared is not proof that the original command was replayed."""
    if ctxs is None:
        return False
    return all(context_reliability(ctxs.get(c.get(s, {}).get('context'), {}))['faithful_replay'] for s in ('a', 'b'))

def snapshot_skew(c, ctxs):
    """pip resolved through the recording proxy (PyPI page frozen at first fetch) while uv fetched PyPI live: a PyPI-vs-PyPI
    version difference between a pip and a uv context can be our measurement artefact, not the project's problem -> excluded."""
    left = ctxs.get(c["a"]["context"], {})
    right = ctxs.get(c["b"]["context"], {})
    if left.get("snapshot_id") and left["snapshot_id"] == right.get("snapshot_id") and all(
            item.get("snapshot_mode") == "replay" for item in (left, right)):
        return False
    a, b = c["a"]["artifact"], c["b"]["artifact"]
    return (c["cls"] == "DIFF_VERSION_SAME_REGISTRY" and a and b and a["registry"] == "pypi" == b["registry"]
            and ctxs.get(c["a"]["context"], {}).get("resolver") != ctxs.get(c["b"]["context"], {}).get("resolver"))

# ----------------------------------------------------------------------------- templates
def find_template(repo_dir: pathlib.Path):
    cands = sorted(list(repo_dir.glob(".github/ISSUE_TEMPLATE/*.yml")) + list(repo_dir.glob(".github/ISSUE_TEMPLATE/*.yaml")) + list(repo_dir.glob(".github/ISSUE_TEMPLATE/*.md")))
    cfg = load_yaml(repo_dir / ".github/ISSUE_TEMPLATE/config.yml") or {}
    blank = cfg.get("blank_issues_enabled", True) if isinstance(cfg, dict) else True
    single = None
    for p in (repo_dir / ".github/ISSUE_TEMPLATE.md", repo_dir / ".github/issue_template.md", repo_dir / "ISSUE_TEMPLATE.md"):
        if p.exists(): single = p
    def score(p):
        n = p.name.lower()
        if "config" in n: return 99
        if "bug-misc" in n or "bug_misc" in n: return 0
        if "bug" in n and not any(x in n for x in ("compil", "result")): return 1
        if "issue" in n: return 2
        if "installation" in n: return 3
        if "usage" in n: return 4
        if any(x in n for x in ("feature", "enhanc", "question", "doc", "epic", "contribute", "help")): return 50
        return 10
    cands = [p for p in cands if score(p) < 50]
    cands.sort(key=score)
    if cands: return cands[0], blank, "form" if cands[0].suffix in (".yml", ".yaml") else "md"
    if single: return single, blank, "md"
    return None, blank, None

def load_yaml(p):
    try: return yaml.safe_load(p.read_text(encoding="utf-8"))
    except Exception: return None

def parse_md_template(p: pathlib.Path):
    text = p.read_text(encoding="utf-8", errors="replace")
    meta = {}
    m = re.match(r"^---\n(.*?)\n---\n(.*)$", text, re.S)
    body = text
    if m:
        try: meta = yaml.safe_load(m.group(1)) or {}
        except Exception: meta = {}
        body = m.group(2)
    heads = [h.strip() for h in re.findall(r"^#{1,4}\s*\**(.+?)\**\s*$", body, re.M)]
    if not heads: heads = [h.strip("* :") for h in re.findall(r"^\*\*(.+?)\*\*\s*$", body, re.M)]
    return meta, heads, body

def parse_form_template(p: pathlib.Path):
    d = load_yaml(p) or {}
    items = []
    for it in d.get("body", []) or []:
        t = it.get("type"); lab = (it.get("attributes") or {}).get("label") or it.get("id") or t
        items.append({"type": t, "label": lab, "options": [o.get("label") if isinstance(o, dict) else o for o in (it.get("attributes") or {}).get("options", [])], "required": (it.get("validations") or {}).get("required", False)})
    return d, items

# ----------------------------------------------------------------------------- content
def ctx_human(side, ctxs, ips):
    derived = str(side.get('derived_from', 'unknown'))
    ip = ips.get(derived.split(':', 1)[1]) if derived.startswith('install-path:') else None
    return context_label(side, ctxs, ips), ip

def ctx_short(side, ctxs, ips):
    return context_label(side, ctxs, ips)

def art_short(a):
    if not a: return "_not resolved_"
    return f"`{a['version']}` from **{a['registry']}**"

def friendly_reason(r: str) -> str:
    if "too large" in r: return "files not compared (a wheel exceeds the 400 MB download limit); the versions/registries above differ as shown"
    return r

def art_line(a):
    if not a: return "_not resolved in this context_"
    reg = a["registry"]
    sha = f"sha256 `{a['sha256'][:16]}…`" if a.get("sha256") else "sha256 not published by the index"
    return f"`{a['name']}=={a['version']}` from **{reg}** (`{a['filename']}`, {sha})"

def cmd_for(side, ctxs, reqs):
    context = ctxs.get(side.get('context'), {})
    origin = context.get('origin') or {}
    command = origin.get('command') or origin.get('original_command')
    if command:
        return '# Recorded original command; preserve its working directory, configuration and environment.\n' + command
    return '# No faithful original command recorded.\n# Extracted requirements (not a project-install reproducer): ' + json.dumps(reqs)

def _newer(va, vb):
    from packaging.version import Version, InvalidVersion
    try: return Version(va) > Version(vb)
    except InvalidVersion: return va > vb

def why(c, ctxs):
    return verified_text(c, 'root_cause', 'Root cause has not been independently verified; the recorded selections differ.')

def impact(c, ctxs):
    return [verified_text(c, 'impact', 'User-visible impact has not been verified.')]

def fixes(c, ctxs, pkg_is_torch):
    return [verified_text(c, 'fix', 'No repair has been validated against the original execution and contract.')]

def build(proj: str, cases: list, sel: dict):
    pdir = RESULTS_ROOT / proj
    repo = sel[proj]['repo'].replace('github.com/', '')
    commit = sel[proj].get('commit', '?')
    ctxs = {c['id']: c for r in load(pdir / 'rtos.json', []) for c in r.get('contexts', [])}
    rejected = [c.get('case_id', c.get('package')) for c in cases if not assess_case(c, ctxs)['developer_ready']]
    if rejected:
        raise ValueError('Unverified cases cannot be rendered as developer-ready drafts: ' + ', '.join(map(str, rejected)))
    body = '\n\n---\n\n'.join(render_issue(c, ctxs, repo, commit, c.get('triage'), c.get('minimal')) for c in cases)
    pkgs = sorted({c['package'] for c in cases})
    title = 'Verified dependency contract violation: ' + ', '.join(pkgs)
    url = f'https://github.com/{repo}/issues/new/choose'
    return body, url, None, len(cases), pkgs, title

def render(S, title, tmpl, kind, cases):
    if tmpl is None:
        return "\n".join(["### Summary", "", S["summary"], "", "### Impact / potential consequences", "", S["impact"], "", "### Steps to reproduce", "", S["repro"], "",
                          "### Root cause", "", S["cause"], "", "### Suggested fix", "", S["fix"], "", "### Environment", "", S["env"], "", "### Notes", "", S["method"]])
    if kind == "form":
        d, items = parse_form_template(tmpl)
        out = []
        used = set()
        for it in items:
            lab = it["label"] or ""; low = lab.lower(); t = it["type"]
            if t == "markdown": continue
            if t == "checkboxes":
                out += [f"### {lab}", ""] + [f"- [ ] {o}" for o in it["options"]] + [""]; continue
            if t == "dropdown":
                pick = next((o for o in it["options"] if o and re.search(r"linux|ubuntu|other|pip|install|python|cuda|bug|medium|no", str(o), re.I)), it["options"][0] if it["options"] else "")
                out += [f"### {lab}", "", f"{pick}", ""]; continue
            if re.search(r"reproduc|steps|how to", low) and "repro" not in used: out += [f"### {lab}", "", S["repro"], ""]; used.add("repro")
            elif re.search(r"expected", low) and "expected" not in used: out += [f"### {lab}", "", "The applicable verified contract must hold for the affected execution. See the contract and evidence in the description.", ""]; used.add("expected")
            elif re.search(r"environment|version|os|platform|python|system info|hardware|install method|gpu|cuda|which", low) and "env" not in used: out += [f"### {lab}", "", S["env"], ""]; used.add("env")
            elif re.search(r"log|output|traceback|error|relevant", low) and "logs" not in used: out += [f"### {lab}", "", "```text", "(dry-run resolver reports; selected files and their origins are listed in the description above)", "```", ""]; used.add("logs")
            elif re.search(r"additional|context|anything else|comment|note|other", low) and "extra" not in used: out += [f"### {lab}", "", "**Root cause**", "", S["cause"], "", "**Suggested fix**", "", S["fix"], "", S["method"], ""]; used.add("extra")
            elif re.search(r"describe|what happened|summary|bug|problem|description|issue|behavio", low) and "summary" not in used: out += [f"### {lab}", "", S["summary"], "", "**Impact / potential consequences**", "", S["impact"], ""]; used.add("summary")
            elif re.search(r"name|title|model|command|contact|email|url|link", low): out += [f"### {lab}", "", "N/A", ""]
            else: out += [f"### {lab}", "", "N/A", ""]
        for k, sec in (("summary", ["### Description", "", S["summary"], "", "**Impact / potential consequences**", "", S["impact"], ""]), ("repro", ["### Steps to reproduce", "", S["repro"], ""]), ("extra", ["### Root cause and suggested fix", "", S["cause"], "", S["fix"], "", S["method"], ""]), ("env", ["### Environment", "", S["env"], ""])):
            if k not in used: out += sec
        return "\n".join(out)
    # markdown template
    meta, heads, body = parse_md_template(tmpl)
    out = []; used = set()
    for h in heads:
        low = h.lower()
        if re.search(r"reproduc|steps", low) and "repro" not in used: out += [f"## {h}", "", S["repro"], ""]; used.add("repro")
        elif re.search(r"expected", low) and "expected" not in used: out += [f"## {h}", "", "The applicable verified contract must hold for the affected execution. See the contract and evidence in the description.", ""]; used.add("expected")
        elif re.search(r"environment|version|desktop|system|platform|setup|python|os\b", low) and "env" not in used: out += [f"## {h}", "", S["env"], ""]; used.add("env")
        elif re.search(r"screenshot|log|output", low) and "logs" not in used: out += [f"## {h}", "", "N/A (dry-run resolver reports available on request)", ""]; used.add("logs")
        elif re.search(r"additional|context|anything|note|possible|solution|fix|suggest", low) and "extra" not in used: out += [f"## {h}", "", "**Root cause**", "", S["cause"], "", "**Suggested fix**", "", S["fix"], "", S["method"], ""]; used.add("extra")
        elif re.search(r"describe|bug|summary|problem|description|what|issue|current|behavio", low) and "summary" not in used: out += [f"## {h}", "", S["summary"], "", "**Impact / potential consequences**", "", S["impact"], ""]; used.add("summary")
        else: out += [f"## {h}", "", "N/A", ""]
    for k, sec in (("summary", ["## Description", "", S["summary"], "", "**Impact / potential consequences**", "", S["impact"], ""]), ("repro", ["## Steps to reproduce", "", S["repro"], ""]), ("extra", ["## Root cause and suggested fix", "", S["cause"], "", S["fix"], "", S["method"], ""]), ("env", ["## Environment", "", S["env"], ""])):
        if k not in used: out += sec
    return "\n".join(out)

def main():
    import argparse
    global OUT, RESULTS_ROOT, CORPUS_ROOT
    parser = argparse.ArgumentParser(description='Generate review drafts only for evidence-backed contract violations. Historical drafts are protected.')
    parser.add_argument('--results-dir', type=pathlib.Path, default=ROOT / 'results' / 'projects')
    parser.add_argument('--corpus-dir', type=pathlib.Path, default=ROOT / 'corpus' / 'repos')
    parser.add_argument('--output-dir', type=pathlib.Path, default=OUT)
    args = parser.parse_args()
    RESULTS_ROOT, CORPUS_ROOT = args.results_dir.resolve(), args.corpus_dir.resolve()
    OUT = args.output_dir.resolve()
    for protected in (ROOT / '0909ISSUEs', ROOT / '0910issues', ROOT / 'results', ROOT / 'reports', RESULTS_ROOT, CORPUS_ROOT):
        if OUT == protected.resolve() or protected.resolve() in OUT.parents:
            parser.error(f'Output must not overwrite historical evidence: {protected}')
    OUT.mkdir(parents=True, exist_ok=True)
    selected = load(ROOT / 'corpus' / 'selected.json', {}).get('repos', [])
    sel = {pathlib.Path(r['dir']).name: r for r in selected}
    by = collections.defaultdict(list)
    excluded = collections.Counter()
    for path in sorted(RESULTS_ROOT.glob('*/cases_triaged.json')):
        ctxs = {c['id']: c for r in load(path.parent / 'rtos.json', []) for c in r.get('contexts', [])}
        for case in load(path, []):
            assessment = assess_case(case, ctxs)
            if not assessment['developer_ready'] or snapshot_skew(case, ctxs):
                excluded[assessment['classification']] += 1
                continue
            by[path.parent.name].append(case)
    index = ['# Verified dependency contract drafts', '', 'Drafts require faithful original executions and recorded contract verification. No issue is submitted.', '', '| project | cases | draft |', '|---|---|---|']
    for project, cases in sorted(by.items()):
        if project not in sel:
            sel[project] = {'repo': project.replace('__', '/'), 'commit': 'not recorded'}
        text, _, _, count, _, _ = build(project, cases, sel)
        path = OUT / f'{project}.md'
        with path.open('x', encoding='utf-8') as stream:
            stream.write(text)
        index.append(f'| {project} | {count} | [{path.name}]({path.name}) |')
    index += ['', 'Excluded observations: ' + json.dumps(dict(excluded), sort_keys=True)]
    with (OUT / 'README.md').open('x', encoding='utf-8') as stream:
        stream.write('\n'.join(index) + '\n')
    print(json.dumps({'developer_ready_cases': sum(map(len, by.values())), 'projects': len(by), 'excluded': dict(excluded), 'output': str(OUT)}, sort_keys=True))

if __name__ == "__main__":
    main()
