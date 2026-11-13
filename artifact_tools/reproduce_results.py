"""Recompute experiment counts from saved observations, without installation."""
from __future__ import annotations
import argparse,csv,hashlib,json
from collections import Counter
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
def read(relative):
    return json.loads((ROOT/relative).read_text(encoding='utf-8-sig'))
def write(path,value):
    path.parent.mkdir(parents=True,exist_ok=True)
    path.write_text(json.dumps(value,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')

def verify_report_references(report, root=None):
    """Check experimental records; list excluded narrative references separately."""
    root=Path(root) if root is not None else ROOT
    aliases={'1110ISSUEs/02-ultralytics-extra-inputs/inputs.json':'inputs/ultralytics-extra/inputs.json'}
    omitted=[]; verified=[]
    for relative,expected_hash in report['references_sha256'].items():
        target=aliases.get(relative,relative)
        if target==relative and (relative.startswith(('1110ISSUEs/','0910issues/','paper/')) or '/count-ledger-readme-archive-' in relative):
            omitted.append(relative)
            continue
        actual=hashlib.sha256((root/target).read_bytes()).hexdigest()
        if actual!=expected_hash:
            raise ValueError('Reference hash mismatch: '+target)
        verified.append({'original_path':relative,'included_path':target,'sha256':actual})
    return {'included_verified':len(verified),'verified_references':verified,'omitted_reference_paths':omitted}

def mechanism_measurements(source_reuse, extra_removal):
    """Keep synthetic mechanisms and real project roots as different units."""
    if not source_reuse['runs'] or not all(run['independent_reaudit_passed'] and run['checks_reported_true']==run['checks_reported_total'] for run in source_reuse['runs']):
        raise ValueError('Source-reuse observations do not pass their recorded checks.')
    if extra_removal['status']!='confirmed_real_project_incompatible_provider_declaration_and_extra_removal_failure':
        raise ValueError('Extra-removal observations have no matching confirmation.')
    return {'MechanismCount':source_reuse['independent_mechanisms']+extra_removal['counts']['locally_confirmed_failure_families_in_this_case'],
            'RealRootCount':len({extra_removal['canonical_root']})}

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out',type=Path,default=ROOT/'runs/summary')
    args=parser.parse_args(); out=args.out.resolve()
    for protected in ['outputs','work','inputs','drc','scripts','tests','data']:
        p=(ROOT/protected).resolve()
        if out==p or p in out.parents: parser.error('Choose an output directory outside the supplied input folders.')
    report=read('outputs/1111-stateful-workflow-report.json')
    audit=read('outputs/issue-validity-audit-20261110.json')
    source_reuse=read('work/expanded-validation-20261111/install-review/uv-closure-review.json')
    case=read('work/stateful-workflows-20261111/review/ultralytics-extra-final-admission.json')
    rows=report['main_rows']
    assert len(rows)==len({(r['canonical_name'],r['workflow']) for r in rows})
    workflows={}
    for name in ['update','extras','relock']:
        group=[r for r in rows if r['workflow']==name]
        workflows[name]={'applicable':sum(r['semantic_applicable'] for r in group),'complete':sum(r['completed_actual_sequence'] for r in group),'gap':sum(r['semantic_applicable'] and not r['completed_actual_sequence'] for r in group)}
        assert workflows[name]=={'applicable':report['main_workflow_progress']['by_workflow'][name]['applicable'],'complete':report['main_workflow_progress']['by_workflow'][name]['complete'],'gap':report['main_workflow_progress']['by_workflow'][name]['closed_gap']}
    verdicts=dict(Counter(issue['technical_verdict'] for issue in audit['issues']))
    assert verdicts==audit['report_verdict_counts']
    delta={'update_both_installers_root_version_changed':0,'extras_added_distribution_occurrences':0,'extras_removed_distribution_occurrences':0,'relock_name_version_changed':0,'relock_no_name_version_change':0}
    for row in rows:
        if not row['completed_actual_sequence']:continue
        change=row['actual_delta']
        if row['workflow']=='update':
            if 'pip' in change:
                changed=change['pip']['root_version_actually_changed'] and change['uv']['root_version_actually_changed']
            else:
                versions=change['root_versions']
                changed=bool(versions['pip-old'] and versions['pip-updated'] and versions['uv-old'] and versions['uv-updated'] and versions['pip-old']!=versions['pip-updated'] and versions['uv-old']!=versions['uv-updated'])
            delta['update_both_installers_root_version_changed']+=bool(changed)
        elif row['workflow']=='extras':
            addition=change['base_to_extra']
            removal=change.get('extra_to_base',change.get('extra_to_restored_base'))
            delta['extras_added_distribution_occurrences']+=len(addition['added'] if 'added' in addition else addition['added_names'])
            delta['extras_removed_distribution_occurrences']+=len(removal['removed'] if 'removed' in removal else removal['removed_names'])
        elif row['workflow']=='relock':
            changed=change['before_to_after_relock']['name_version_map_changed'] if 'before_to_after_relock' in change else change['relock']['name_version_plan_changed']
            delta['relock_name_version_changed']+=bool(changed);delta['relock_no_name_version_change']+=not changed
    for key,value in delta.items():assert value==report['actual_delta_from_bound_completed_rows'][key],key
    measured={'MainRoots':len({r['canonical_name'] for r in rows}),'LogicalSlots':len(rows),'ApplicableWorkflows':sum(r['semantic_applicable'] for r in rows),'CompletedWorkflows':sum(r['completed_actual_sequence'] for r in rows),'CoverageGaps':sum(r['semantic_applicable'] and not r['completed_actual_sequence'] for r in rows),'HistoricalReports':len(audit['issues']),'HistoricalCases':sum(i['original_case_count'] for i in audit['issues']),'RefutedReports':verdicts['原报告已证误报'],'MismatchedReports':verdicts['原报告证据失配'],'SupportedReports':audit['related_narrower_documentation_fixes_merged'],'ChangedUpdates':delta['update_both_installers_root_version_changed'],'ExtraOccurrences':delta['extras_added_distribution_occurrences'],'ChangedRelocks':delta['relock_name_version_changed'],'UnchangedRelocks':delta['relock_no_name_version_change']}
    measured.update(mechanism_measurements(source_reuse,case))
    expected=read('outputs/expected-results.json')['numbers']
    by_root={name:[r for r in rows if r['canonical_name']==name and r['semantic_applicable']] for name in {r['canonical_name'] for r in rows}}
    measured['CompleteRoots']=sum(any(r['completed_actual_sequence'] for r in group) for group in by_root.values())
    measured['FullyCompleteRoots']=sum(bool(group) and all(r['completed_actual_sequence'] for r in group) for group in by_root.values())
    references=verify_report_references(report)
    stages={s['label']:s for s in case['stages']}
    overlap=read('work/stateful-workflows-20261111/review/ultralytics-extra-actual-01/namespace-provider-overlap.json')
    measured.update(BaseDists=stages['base']['installed_distributions'],ExtraDists=stages['extra']['installed_distributions'],SharedPaths=overlap['shared_path_count'],DifferentSharedBytes=len(overlap['original_shared_paths_with_different_expected_bytes']))
    broken=stages['base-restored']
    assert broken['actual_command']['exit']==0 and broken['cv2_smoke_exit']!=0
    assert broken['check_and_inspect_commands']['pip-check']['exit']==0 and broken['check_and_inspect_commands']['uv-check']['exit']==0
    assert len(broken['normal_cv2_missing'])==measured['SharedPaths']
    assert all(stages[x]['cv2_smoke_exit']==0 and stages[x]['unique_file_paths_violating']==0 for x in ['base','fresh-final','forced-reinstall-final'])
    for key,value in measured.items(): assert value==expected[key],(key,value,expected[key])
    assert sum(v['complete']+v['gap'] for v in workflows.values())==measured['ApplicableWorkflows']
    out.mkdir(parents=True,exist_ok=True)
    write(out/'summary.json',{'status':'passed','measurements':measured,'workflows':workflows,'historical_report_categories':verdicts,'state_changes':delta,'reference_checks':references,'scope':'Counts reproduced from saved records. This task does not perform new installations or measure detection effectiveness.'})
    with (out/'workflows.csv').open('w',encoding='utf-8',newline='') as f:
        writer=csv.DictWriter(f,fieldnames=['workflow','applicable','complete','gap']);writer.writeheader();writer.writerows({'workflow':k,**v} for k,v in workflows.items())
    with (out/'cohort-status.csv').open('w',encoding='utf-8',newline='') as f:
        fields=['canonical_name','workflow','semantic_applicable','completed_actual_sequence','closure_state','effective_reason'];writer=csv.DictWriter(f,fieldnames=fields,extrasaction='ignore');writer.writeheader();writer.writerows(rows)
    with (out/'ultralytics-states.csv').open('w',encoding='utf-8',newline='') as f:
        fields=['label','installed_distributions','unique_file_paths_violating','cv2_smoke_exit','headless_installed'];writer=csv.DictWriter(f,fieldnames=fields,extrasaction='ignore');writer.writeheader();writer.writerows(case['stages'])
    lines=['# Experiment result summary','','| Workflow | Applicable | Complete | Gap |','|---|---:|---:|---:|']
    lines += [f"| {name} | {v['applicable']} | {v['complete']} | {v['gap']} |" for name,v in workflows.items()]
    lines += ['',f"Package roots: {measured['MainRoots']}. Historical reports: {measured['HistoricalReports']}. Reproduced mechanism categories: {measured['MechanismCount']}; real affected roots: {measured['RealRootCount']}.",'','Incomplete workflows are not negative results. The ordinary completed batch has no admitted positive; the real Ultralytics witness is a separate targeted workflow.']
    (out/'summary.md').write_text('\n'.join(lines)+'\n',encoding='utf-8')
    print(json.dumps({'status':'passed','out':str(out),'measurements':measured},ensure_ascii=False))
if __name__=='__main__': main()
