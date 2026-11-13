"""Evidence-backed reports and internal observation bundles; no automatic submission."""
from __future__ import annotations
import json
import pathlib
from typing import Optional
from .reliability import assess_case, context_label, context_reliability, verified_text


def _art(artifact: Optional[dict]) -> str:
    if not artifact:
        return "_(not present in this resolution result; installation was not measured)_"
    return (f"`{artifact['name']}=={artifact['version']}` from **{artifact['registry']}**  \n"
            f"file: `{artifact.get('filename', '?')}`  \n"
            f"sha256: `{artifact.get('sha256') or 'not recorded'}`  \n"
            f"url: {artifact.get('url', 'not recorded')}")


def _ctx_md(side: dict, context: Optional[dict]) -> str:
    context = context or {}
    reliability = context_reliability(context)
    lines = [f"- context id: `{side.get('context', '?')}`",
             f"- origin: `{json.dumps(context.get('origin') or {}, ensure_ascii=False)}`",
             f"- derived from: `{context.get('derived_from', side.get('derived_from', 'unknown'))}`",
             f"- replay faithfulness: **{reliability['faithfulness']}**",
             f"- complete original request: {context.get('request_complete') is True}",
             f"- resolver: `{context.get('resolver', 'unknown')}`",
             f"- extracted requirements: `{json.dumps(context.get('requirements', []))}`",
             f"- constraints: `{json.dumps(context.get('constraints', []))}`",
             f"- primary index: `{context.get('index_url') or 'resolver default'}`; extra indexes: `{context.get('extra_index_urls') or []}`",
             f"- source bindings: `{json.dumps(context.get('sources') or {})}`; enabled: `{context.get('source_bindings_enabled')}`",
             f"- project extras: `{context.get('project_extras')}`; scope: `{context.get('scope', 'unknown')}`",
             f"- lock mode: `{context.get('lock_mode', 'unknown')}`; lock file: `{context.get('lock_file') or 'not recorded'}`",
             f"- target: `{context.get('platform', 'unknown')}` / CPython `{context.get('python_version', 'unknown')}`",
             f"- snapshot id: `{context.get('snapshot_id') or 'not recorded'}`; mode: `{context.get('snapshot_mode', 'unknown')}`"]
    if context.get('description'):
        lines.append(f"- description: {context['description']}")
    for limitation in reliability['reasons']:
        lines.append(f"- limitation: {limitation}")
    return "\n".join(lines)


WHY = {
    'SAME_VERSION_DIFF_REGISTRY': 'The recorded version appears in different registries. Artifact identity and intended provenance require separate verification.',
    'DIFF_VERSION_DIFF_REGISTRY': 'The recorded resolutions select different versions and registries.',
    'DIFF_VERSION_SAME_REGISTRY': 'The recorded resolutions select different versions from the same registry.',
    'LOCAL_VARIANT': 'The recorded artifacts have different local build variants. Hardware-specific variants may be intentional.',
    'SAME_VERSION_DIFF_HASH_SAME_REGISTRY': 'The recorded files differ within a version and registry. Wheel tags, rebuilds, and metadata may explain the difference.',
    'WHEEL_VS_SDIST': 'One result selects a wheel and the other an sdist. This difference alone does not establish a defect.',
    'ONLY_IN_A': 'The package appears only in result A. Dependency metadata, markers, and extras require investigation.',
    'ONLY_IN_B': 'The package appears only in result B. Dependency metadata, markers, and extras require investigation.',
}


def render_issue(case: dict, contexts: dict, repo: str, commit: str,
                 triage: Optional[dict] = None, minimal: Optional[dict] = None,
                 resolver_versions: Optional[dict] = None) -> str:
    """Render a verified draft, or an explicitly internal observation for legacy data."""
    audit_case = dict(case)
    if triage is not None:
        audit_case['triage'] = triage
    assessment = assess_case(audit_case, contexts)
    ready = assessment['developer_ready']
    prefix = 'Verified contract violation' if ready else 'Resolution observation — internal review'
    md = [f"# {prefix}: `{case.get('package', '?')}`", '',
          f"**Project:** {repo} @ `{commit}`  ",
          f"**Evidence classification:** `{assessment['classification']}`  ",
          f"**Developer-ready:** {'yes' if ready else 'no'}  ",
          f"**Legacy oracle label (not independent validation):** `{case.get('type', 'not recorded')}`  ",
          f"**Requirement set origin:** `{case.get('reqset_origin', 'not recorded')}`", '',
          '## Recorded observation', '',
          WHY.get(case.get('cls'), 'The recorded artifact selections differ.'), '',
          f"- Context A: {context_label(case.get('a', {}), contexts)} → {_art(case.get('a', {}).get('artifact')).splitlines()[0]}",
          f"- Context B: {context_label(case.get('b', {}), contexts)} → {_art(case.get('b', {}).get('artifact')).splitlines()[0]}", '',
          '## Verification and limits', '',
          f"- Request comparability: {assessment['comparison_status']}",
          f"- Contract violation: {assessment['contract_status']}"]
    md.extend(f'- {reason}' for reason in assessment['reasons'])
    contract = assessment['contract']
    if ready:
        md.extend(['', 'Verified contract:', '', str(contract['contract']), '',
                   'Recorded supporting evidence:', '', json.dumps(contract['evidence'], indent=2, ensure_ascii=False)])
    else:
        md.extend(['', 'Different versions, registries, hashes, or dependency graphs alone do not establish a defect. '
                   'The original request, its supported environment, and the applicable contract must be checked before reporting a bug.'])
    for side, label in (('a', 'A'), ('b', 'B')):
        record = case.get(side, {})
        md.extend(['', f'## Context {label}', '', _ctx_md(record, contexts.get(record.get('context'))), '',
                   'Recorded artifact:', '', _art(record.get('artifact'))])
    intent = case.get('intent') or {}
    if intent:
        md.extend(['', '## Mined intent evidence', '',
                   'This evidence is conditional on its original scope, markers, and extras; it is not a verified contract by itself.', '',
                   f"```json\n{json.dumps(intent, indent=2, ensure_ascii=False)}\n```"])
    if triage:
        md.extend(['', '## Artifact triage', '', f"Label: `{triage.get('label', '?')}`", '',
                   str(triage.get('reason', 'No explanation recorded.'))])
        content = triage.get('content_diff') or {}
        if content:
            md.extend(['', 'Content comparison record:', '', f"```json\n{json.dumps(content, indent=2, ensure_ascii=False)}\n```"])
    md.extend(['', '## Impact and repair', '',
               verified_text(case, 'impact', 'User-visible impact has not been verified.'), '',
               verified_text(case, 'fix', 'No repair has been validated against the original execution and contract.')])
    if minimal:
        md.extend(['', '## Reduced resolution probe', '',
                   'This reduced request demonstrates an artifact-selection difference only. It does not replace replay of the original project command.', '',
                   '```text', *minimal.get('requirements', []), '```', '',
                   f"Minimization record: `{minimal.get('method', 'not recorded')}`; probes: `{minimal.get('probes', 'not recorded')}`."])
    md.extend(['', '## Reproducibility', '',
               f"Resolver versions: `{json.dumps(resolver_versions or {})}`.", '',
               'Targets, snapshot identities, constraints, and origin commands are recorded per context above. '
               'A saved URL and hash identify a selected file; they do not establish that historical index contents can be replayed.', '',
               '_Generated for review. No human review or submission is implied._'])
    return '\n'.join(md) + '\n'


def write_case_bundle(out_dir: pathlib.Path, case: dict, contexts: dict, resolutions: dict,
                      repo: str, commit: str, triage=None, minimal=None, resolver_versions=None):
    """Write a new bundle only; historical evidence is never overwritten."""
    directory = pathlib.Path(out_dir) / case['case_id']
    directory.mkdir(parents=True, exist_ok=False)
    checked = dict(case)
    if triage is not None:
        checked['triage'] = triage
    assessment = assess_case(checked, contexts)
    filename = 'issue.md' if assessment['developer_ready'] else 'observation.md'
    (directory / filename).write_text(render_issue(case, contexts, repo, commit, triage, minimal, resolver_versions), encoding='utf-8')
    (directory / 'assessment.json').write_text(json.dumps(assessment, indent=2, ensure_ascii=False), encoding='utf-8')
    (directory / 'case.json').write_text(json.dumps(case, indent=2, default=str), encoding='utf-8')
    for side in ('a', 'b'):
        identifier = case[side]['context']
        if identifier in contexts:
            (directory / f'context_{side}.json').write_text(json.dumps(contexts[identifier], indent=2, default=str), encoding='utf-8')
        if identifier in resolutions:
            (directory / f'artifact_{side}.json').write_text(json.dumps(resolutions[identifier], indent=2, default=str), encoding='utf-8')
    for name, value in (('triage', triage), ('minimal', minimal)):
        if value is not None:
            (directory / f'{name}.json').write_text(json.dumps(value, indent=2, default=str), encoding='utf-8')
    return directory