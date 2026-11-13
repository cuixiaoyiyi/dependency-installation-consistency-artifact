"""Compatibility entry point for verified dependency-contract drafts.

Default output is work/verified-issue-drafts-v2. Existing historical drafts are
protected; templates never assert that unchecked human actions were completed.
"""
from __future__ import annotations
import json, pathlib, re, glob, collections, urllib.parse, sys
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from make_issues import load, real, snapshot_skew, find_template, parse_md_template, parse_form_template, ROOT, DATE, cmd_for
from drc.report import render_issue
from drc.report.reliability import assess_case, context_label, verified_text

OUT = ROOT / 'work' / 'verified-issue-drafts-v2'
PYVER = "3.11"

def reg_name(r: str) -> str:
    if r == "pypi": return "PyPI"
    if r == "pytorch:default": return "download.pytorch.org/whl"
    if r.startswith("pytorch:"): return f"download.pytorch.org/whl/{r.split(':', 1)[1]}"
    if r.startswith("testpypi") or r.startswith("test-files"): return "test.pypi.org"
    if r.startswith("nvidia:"): return r.split(":", 1)[1]
    return r

def art(a):  # `torch 2.6.0+cu124` (download.pytorch.org/whl/cu124)
    if not a: return "not present in the resolution result"
    return f"`{a['name']} {a['version']}` from {reg_name(a['registry'])}"

def path_label(side, ctxs, ips):
    return context_label(side, ctxs, ips)

def cmd(side, ctxs, reqs, tag):
    return cmd_for(side, ctxs, reqs)

def _newer(va, vb):
    from packaging.version import Version, InvalidVersion
    try: return Version(va) > Version(vb)
    except InvalidVersion: return va > vb

TORCHLIKE = ("torch", "triton", "pytorch", "nvidia", "cuda", "xformers")

def cause(c, ctxs):
    return verified_text(c, 'root_cause', 'Root cause has not been independently verified; the recorded selections differ.')

def fix_lines(cases, ctxs, ips):
    return list(dict.fromkeys(verified_text(c, 'fix', 'No repair has been validated against the original execution and contract.') for c in cases))

def artifacts_table(cases, ctxs, ips):
    rows = ["| case | install path | package | version | index | file | sha256 |", "|---|---|---|---|---|---|---|"]
    for i, c in enumerate(cases, 1):
        for s in ("a", "b"):
            a = c[s]["artifact"]
            if not a: rows.append(f"| {i} | {path_label(c[s], ctxs, ips)} | `{c['package']}` | – | – | not installed | – |"); continue
            rows.append(f"| {i} | {path_label(c[s], ctxs, ips)} | `{a['name']}` | {a['version']} | {reg_name(a['registry'])} | [{a['filename']}]({a['url']}) | `{(a.get('sha256') or 'not published')[:16]}` |")
    return "\n".join(rows)

def group_by_pkg(cases):
    g = collections.OrderedDict()
    for c in cases: g.setdefault(c["package"], []).append(c)
    return g

def make_title(cases, ctxs, ips):
    return 'Verified dependency contract violation: ' + ', '.join(sorted({c['package'] for c in cases}))

def sections(proj, cases, sel):
    pdir = ROOT / 'results' / 'projects' / proj
    repo = sel[proj]['repo'].replace('github.com/', '')
    commit = sel[proj].get('commit', '?')
    ctxs = {c['id']: c for r in load(pdir / 'rtos.json', []) for c in r.get('contexts', [])}
    ips = {ip['id']: ip for ip in load(pdir / 'ir.json', {}).get('install_paths', [])}
    if any(not assess_case(c, ctxs)['developer_ready'] for c in cases):
        raise ValueError('Only independently verified contract violations can be rendered as developer-ready drafts')
    reports = '\n\n---\n\n'.join(render_issue(c, ctxs, repo, commit, c.get('triage'), c.get('minimal')) for c in cases)
    contracts = '\n\n'.join(str(assess_case(c, ctxs)['contract']['contract']) for c in cases)
    original = '\n\n'.join(cmd_for(c[s], ctxs, ctxs.get(c[s]['context'], {}).get('requirements', [])) for c in cases for s in ('a', 'b'))
    safe = {
        'summary': reports, 'description': 'Recorded selections and limitations are included above.',
        'steps': original, 'logs': 'See the saved resolution records.', 'expected': contracts,
        'actual': 'The verified contract failed in the recorded execution; see the evidence above.',
        'consequences': '\n'.join(verified_text(c, 'impact', 'User-visible impact has not been verified.') for c in cases),
        'cause': '\n'.join(cause(c, ctxs) for c in cases), 'intent': '',
        'fix': '\n'.join(fix_lines(cases, ctxs, ips)), 'artifacts': artifacts_table(cases, ctxs, ips),
        'env': 'See per-context targets, lock modes, scope, versions and snapshot identities above.',
        'os': 'See recorded target', 'project_version': commit, 'py': 'See recorded target',
        'note': 'Generated for review; no human review or submission is implied.'}
    return safe, make_title(cases, ctxs, ips), repo, commit, ctxs, ips

def render_default(S):
    return "\n".join(["### Summary", "", S["summary"], "", "### Description", "", S["description"], "", "### Steps to reproduce", "", S["steps"], "", "### Expected behavior", "", S["expected"], "", "### Actual behavior", "", S["actual"], "",
                      "### Consequences", "", S["consequences"], "", "### Root cause", "", S["cause"], "",
                      *(["### Where the repo binds these packages to an index", "", S["intent"], ""] if S["intent"] else []),
                      "### Proposed fix", "", S["fix"], "", "### Environment", "", S["env"], "", "### Selected files", "", S["artifacts"], "", "---", S["note"]])

def render_form(S, tmpl):
    d, items = parse_form_template(tmpl)
    out = []; used = set()
    def put(lab, body): out.extend([f"### {lab}", "", body, ""])
    for it in items:
        lab = it["label"] or ""; low = lab.lower(); t = it["type"]
        if t == "markdown": continue
        if t == "checkboxes": out += [f"### {lab}", ""] + [f"- [ ] {o}" for o in it["options"]] + [""]; continue
        if t == "dropdown":
            pick = next((o for o in it["options"] if o and re.search(r"linux|ubuntu|pip|install|python|other|bug|no", str(o), re.I)), it["options"][0] if it["options"] else "")
            put(lab, str(pick)); continue
        if re.search(r"reproduc|steps|how to", low) and "steps" not in used: put(lab, S["steps"]); used.add("steps")
        elif re.search(r"expected", low) and "expected" not in used: put(lab, S["expected"]); used.add("expected")
        elif re.search(r"actual|current behavio|what happened", low) and "actual" not in used: put(lab, S["actual"]); used.add("actual")
        elif re.search(r"operating system|\bos\b|platform", low) and "os" not in used: put(lab, S["os"]); used.add("os")
        elif re.search(r"python version", low): put(lab, f"CPython {S['py']}")
        elif re.search(r"version|commit|release", low) and "pv" not in used: put(lab, S["project_version"]); used.add("pv")
        elif re.search(r"environment|system|hardware|install method|gpu|cuda|which|device", low) and "env" not in used: put(lab, S["env"] if "environment" in low or "system" in low else "N/A (dependency resolution only, no GPU involved)"); used.add("env")
        elif re.search(r"log|output|traceback|error|relevant", low) and "logs" not in used: put(lab, "```text\n# pip --report / uv lock: selected files\n" + S["logs"] + "\n```"); used.add("logs")
        elif re.search(r"additional|context|anything else|comment|note|other|solution|suggest", low) and "extra" not in used:
            put(lab, "\n\n".join(x for x in ["**Consequences**\n\n" + S["consequences"], "**Root cause**\n\n" + S["cause"], ("**Where the repo binds these packages to an index**\n\n" + S["intent"]) if S["intent"] else "", "**Proposed fix**\n\n" + S["fix"], "**Selected files**\n\n" + S["artifacts"], S["note"]] if x)); used.add("extra")
        elif re.search(r"describe|summary|bug|problem|description|issue|behavio|story|challenge", low) and "desc" not in used:
            put(lab, S["summary"] + "\n\n" + S["description"]); used.add("desc"); used.add("actual")
        elif re.search(r"name|title|model|command|contact|email|url|link|checkpoint", low): put(lab, "N/A")
        else: put(lab, "N/A")
    extra = "\n\n".join(x for x in ["**Consequences**\n\n" + S["consequences"], "**Root cause**\n\n" + S["cause"], ("**Where the repo binds these packages to an index**\n\n" + S["intent"]) if S["intent"] else "", "**Proposed fix**\n\n" + S["fix"], "**Selected files**\n\n" + S["artifacts"], S["note"]] if x)
    tail = [("desc", ["### Description", "", S["summary"], "", S["description"], ""]), ("steps", ["### Steps to reproduce", "", S["steps"], ""]), ("expected", ["### Expected behavior", "", S["expected"], ""]),
            ("extra", ["### Root cause and proposed fix", "", extra, ""]), ("env", ["### Environment", "", S["env"], ""])]
    # "expected" goes right after the steps section when the form has no such field
    if "expected" not in used and "steps" in used:
        for j, l in enumerate(out):
            if l.startswith("### ") and j + 2 < len(out) and out[j + 2].startswith("Dry-run resolutions"):
                k = j + 1
                while k < len(out) and not out[k].startswith("### "): k += 1
                out[k:k] = ["### Expected behavior", "", S["expected"], ""]; used.add("expected"); break
    # insert missing sections before trailing checkbox blocks (e.g. Code of Conduct) so they are not orphaned at the end
    missing = [sec for k, sec in tail if k not in used]
    if missing:
        idx = len(out)
        for j in range(len(out) - 1, -1, -1):
            if out[j].startswith("### ") and j + 2 < len(out) and out[j + 2].startswith("- [x]"): idx = j
            elif out[j].startswith("### "): break
        out[idx:idx] = [l for sec in missing for l in sec]
    return "\n".join(out)

def render_md(S, tmpl):
    meta, heads, body = parse_md_template(tmpl)
    out = []; used = set()
    def put(h, body): out.extend([f"## {h}", "", body, ""])
    for h in heads:
        low = h.lower()
        if re.search(r"reproduc|steps|code to", low) and "steps" not in used: put(h, S["steps"]); used.add("steps")
        elif re.search(r"expected", low) and "expected" not in used: put(h, S["expected"]); used.add("expected")
        elif re.search(r"actual|current", low) and "actual" not in used: put(h, S["actual"]); used.add("actual")
        elif re.search(r"environment|version|desktop|system|platform|setup|python|os\b", low) and "env" not in used: put(h, S["env"]); used.add("env")
        elif re.search(r"screenshot|log|output", low) and "logs" not in used: put(h, "N/A"); used.add("logs")
        elif re.search(r"additional|context|anything|note|possible|solution|fix|suggest|impact", low) and "extra" not in used:
            put(h, "\n\n".join(x for x in ["**Consequences**\n\n" + S["consequences"], "**Root cause**\n\n" + S["cause"], ("**Where the repo binds these packages to an index**\n\n" + S["intent"]) if S["intent"] else "", "**Proposed fix**\n\n" + S["fix"], "**Selected files**\n\n" + S["artifacts"], S["note"]] if x)); used.add("extra")
        elif re.search(r"describe|bug|summary|problem|description|what|issue|behavio", low) and "desc" not in used: put(h, S["summary"] + "\n\n" + S["description"]); used.add("desc"); used.add("actual")
        else: put(h, "N/A")
    extra = "\n\n".join(x for x in ["**Consequences**\n\n" + S["consequences"], "**Root cause**\n\n" + S["cause"], ("**Where the repo binds these packages to an index**\n\n" + S["intent"]) if S["intent"] else "", "**Proposed fix**\n\n" + S["fix"], "**Selected files**\n\n" + S["artifacts"], S["note"]] if x)
    tail = {"desc": ["## Description", "", S["summary"], "", S["description"], ""], "steps": ["## Steps to reproduce", "", S["steps"], ""], "expected": ["## Expected behavior", "", S["expected"], ""],
            "extra": ["## Root cause and proposed fix", "", extra, ""], "env": ["## Environment", "", S["env"], ""]}
    for k, sec in tail.items():
        if k not in used: out += sec
    return "\n".join(out)

def main():
    # Reuse the same evidence gate and protected output handling as the first entry point.
    import make_issues
    make_issues.OUT = OUT
    return make_issues.main()

if __name__ == "__main__":
    main()
