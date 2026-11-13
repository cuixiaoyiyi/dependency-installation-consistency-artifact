"""One auditable root-by-sequence ledger for original, interruption and continuation."""
from collections import Counter,defaultdict
import argparse
from datetime import datetime,timezone
import hashlib
import json
import re
from pathlib import Path
import sys
import tomllib
from packaging.requirements import Requirement
from packaging.utils import canonicalize_name
from packaging.version import Version
ROOT=Path(__file__).resolve().parents[1]
BASE=ROOT/'work/stateful-workflows-20261111/published'
CUTOFF=None
VARIANT_CACHE={}
def load(p):return json.loads(p.read_text())
def available(p):return p.exists() and (CUTOFF is None or p.stat().st_mtime<=CUTOFF)
def ref(p):
 p=Path(p);p=p if p.is_absolute() else p.resolve()
 return {'path':p.relative_to(ROOT).as_posix(),'sha256':hashlib.sha256(p.read_bytes()).hexdigest()} if available(p) else None
def graph(inventory,request):
 artifacts={canonicalize_name(d['name']):d for d in inventory['installed']};req=Requirement(request);extras=defaultdict(set);name=canonicalize_name(req.name);extras[name].update(canonicalize_name(e) for e in req.extras);reached={name};edges=set()
 changed=True
 while changed:
  old=(frozenset(reached),frozenset((n,frozenset(es)) for n,es in extras.items()))
  for parent in list(reached):
   for raw in artifacts.get(parent,{}).get('requires_dist',[]):
    r=Requirement(raw)
    if r.marker and not any(r.marker.evaluate({**inventory['environment'],'extra':e}) for e in {'',*extras[parent]}):continue
    child=canonicalize_name(r.name);reached.add(child);extras[child].update(canonicalize_name(e) for e in r.extras)
    edges.add((parent,child,str(r.specifier),tuple(sorted(canonicalize_name(e) for e in r.extras)),r.url or '',str(r.marker) if r.marker else ''))
  changed=old!=(frozenset(reached),frozenset((n,frozenset(es)) for n,es in extras.items()))
 versions={n:artifacts[n]['version'] if n in artifacts else None for n in sorted(reached)}
 return {'versions':versions,'edges':sorted(edges),'unreachable_installed':sorted(set(artifacts)-reached)}
def read_attempt(out,row,wf):
 directory=out/'cases'/row['canonical_name']/wf;p=directory/'results.json';result=load(p) if available(p) else None
 entries={s['stage']:s for s in (result or {}).get('stages',[])};stages={};commands=[]
 for cmd in directory.glob('commands/*/command.json'):
  if not available(cmd):continue
  c=load(cmd);argv=c.get('argv',[])
  if c.get('executed') is False or not argv:continue
  actual=('install' in argv and '--dry-run' not in argv) or len(argv)>1 and argv[1]=='sync'
  if actual:commands.append({'record':ref(cmd),'exit':c.get('exit'),'argv':argv})
 for inventory_path in directory.glob('stages/*/installed.json'):
  if not available(inventory_path):continue
  label=inventory_path.parent.name;entry=entries.get(label,{});manifest=inventory_path.parent/'pyproject.toml';request=entry.get('request')
  if available(manifest):request=tomllib.loads(manifest.read_text())['project']['dependencies'][0]
  if not request:request=row['workflow_selection']['update'].get('from_request') if label=='pip-old' else row['request']
  inventory=load(inventory_path);data={'inventory':ref(inventory_path),'aggregated':label in entries,'request':request,
   'native_environment':inventory['environment'],'installed_distributions':len(inventory['installed']),
   'main_versions':[d['version'] for d in inventory['installed'] if canonicalize_name(d['name'])==row['canonical_name']],
   'file_audit':ref(inventory_path.parent/'file-audit.json'),'root_closure':ref(inventory_path.parent/'root-closure.json'),
   'manifest':ref(manifest),'lock':ref(inventory_path.parent/'uv.lock')}
  try:data['active_graph']=graph(inventory,request)
  except Exception as error:data['graph_unknown']=str(error)
  stages[label]=data
 return {'out':out.relative_to(ROOT).as_posix(),'protocol':ref(out/'protocol.json'),'result':ref(p),'status':result.get('status') if result else None,
  'reason':result.get('reason') if result else None,'executed_native_installer':bool(commands),'native_installer_commands':commands,
  'observed_installed_main':any(s['main_versions'] for s in stages.values()),'saved_stages':stages,
  'completed':bool(result and result['status'] in {'completed_actual_stateful_workflow','candidate_actual_installed_contract_violation'}),
  'candidate_reported_by_execution':bool(result and result['status']=='candidate_actual_installed_contract_violation'),'raw_result':result}
def delta(attempt,row,wf):
 stages=attempt['saved_stages'];result=attempt['raw_result'] or {};out={'complete_sequence':attempt['completed'],'partial_observations_only':not attempt['completed']}
 def compare(a,b):
  if not all(k in stages and 'active_graph' in stages[k] for k in (a,b)):return None
  ga,gb=stages[a]['active_graph'],stages[b]['active_graph']
  return {'reachable_set_changed':set(ga['versions'])!=set(gb['versions']),'name_version_plan_changed':ga['versions']!=gb['versions'],
    'active_edges_changed':ga['edges']!=gb['edges'],'active_graph_changed':(ga['versions'],ga['edges'])!=(gb['versions'],gb['edges']),
    'added_names':sorted(set(gb['versions'])-set(ga['versions'])),'removed_names':sorted(set(ga['versions'])-set(gb['versions']))}
 if wf=='update':
  out.update(pip_old_to_new=compare('pip-old','pip-updated'),uv_old_to_new=compare('uv-old','uv-updated'),
    root_versions={label:stages[label]['main_versions'] for label in ('pip-old','pip-updated','uv-old','uv-updated') if label in stages})
 elif wf=='extras':out.update(base_to_extra=compare('uv-base','uv-extra'),extra_to_restored_base=compare('uv-extra','uv-base-restored'),base_to_restored=compare('uv-base','uv-base-restored'))
 else:
  change=compare('uv-before-relock','uv-after-relock');locks=[(stages.get(label,{}).get('lock') or {}).get('sha256') for label in ('uv-before-relock','uv-after-relock')]
  out.update(relock=change,lock_bytes_changed=(locks[0]!=locks[1]) if all(locks) else result.get('relock_lock_bytes_changed'),
    active_graph_noop=not change['active_graph_changed'] if change is not None else None)
 return out
def describe_variant(directory,variant,value,artifact_result):
 key=(str(directory),variant)
 if key in VARIANT_CACHE:return VARIANT_CACHE[key]
 result=dict(value);command=directory/'commands'/(variant+'-metadata-plan')/'command.json';stderr=command.with_name('stderr.txt')
 command_data=load(command) if available(command) else {}
 retained=command_data.get('retained_original_variant_failure',{})
 if retained.get('source_command'):
  command=Path(retained['source_command']);stderr=Path(retained['source_stderr']) if retained.get('source_stderr') else command.with_name('stderr.txt')
 text=str(result.get('reason',''))+'\n'+(stderr.read_text(errors='replace') if available(stderr) else '')
 if result.get('status')=='prepared':kind='prepared'
 elif re.search(r'too many 50[0-9]|HTTP Error 50[0-9]|SSL|UNEXPECTED_EOF|ConnectionError|ConnectionPool|ReadTimeout|ConnectTimeout|Temporary failure|connection reset',text,re.I):kind='network_or_metadata_transport_gap'
 elif re.search(r'resolution-too-deep',text,re.I):kind='resolver_complexity_limit'
 elif re.search(r'budget|timed? ?out',text,re.I) or artifact_result.get('status')=='unknown_worker_or_budget' and artifact_result.get('returncode') in (-9,-15):kind='bounded_preparation_budget_or_worker_gap'
 elif re.search(r'(?:byte|payload|compressed|artifact).*(?:exceed|policy|quota)|(?:exceed|policy|quota).*(?:byte|payload|compressed|artifact)',text,re.I):kind='registered_artifact_or_world_resource_limit'
 elif re.search(r'No matching distribution|Could not find a version|ResolutionImpossible|No solution found',text,re.I):kind='candidate_resolution_failure_under_restricted_policy_unconfirmed'
 elif re.search(r'metadata_selection_mismatch|target differs|unrecognized artifact|no unique official|hash differ',text,re.I):kind='selection_target_or_source_representation_gap'
 else:kind='unclassified_preparation_coverage_gap'
 result.update(coverage_class=kind,metadata_command=ref(command),metadata_stderr=ref(stderr),interpretation='A preparation/transport/policy outcome is not a proved upstream dependency defect. Exact captured stderr and variant reason remain authoritative.')
 VARIANT_CACHE[key]=result;return result
def preparation(out,row,wf):
 directory=out/'cases'/row['canonical_name']/'artifacts';path=directory/'results.json';result=load(path) if available(path) else {}
 required={'update':('base','old'),'extras':('base','extra'),'relock':('base',)}[wf]
 variants=result.get('variants',{});manifest=directory/'wheel-manifest.json'
 return {'out':out.relative_to(ROOT).as_posix(),'result':ref(path),'wheel_manifest':ref(manifest),'complete_world_reuse_witness':ref(directory/'complete-world-reuse.json'),
  'required_variants':{v:describe_variant(directory,v,variants.get(v,{'status':'not_prepared_or_not_recorded'}),result) for v in required},
  'required_variants_recorded_prepared':bool(available(manifest) and all(variants.get(v,{}).get('status')=='prepared' for v in required))}
def main():
 global CUTOFF
 parser=argparse.ArgumentParser();parser.add_argument('--readonly-result',action='append',default=[],type=Path);parser.add_argument('--readonly-admission',action='append',default=[],type=Path);parser.add_argument('--staged-out',type=Path,default=BASE/'staged-continuation2');parser.add_argument('--working',action='store_true');parser.add_argument('--cutoff-utc');args=parser.parse_args()
 if args.cutoff_utc:assert args.working;CUTOFF=datetime.fromisoformat(args.cutoff_utc.replace('Z','+00:00')).timestamp()
 if args.cutoff_utc:assert not (BASE/'effective-ledger-cutoff071043.json').exists(),'The frozen interim snapshot must not be overwritten'
 original=BASE/'run1';continuation=BASE/'corrected-continuation1';staged=args.staged_out.resolve();assert args.working or (staged/'summary.json').exists(),'Staged continuation is not finished'
 admissions={}
 for path in args.readonly_admission:
  value=load(path);assert value['status']=='accepted_as_one_composite_workflow';admissions[value['result_sha256']]=ref(path)
 supplements={}
 for path in args.readonly_result:
  path=path.resolve();value=load(path);protocol_path=path.parents[2]/'protocol.json';protocol=load(protocol_path)
  assert value['status']=='actual_operation_chain_completed_with_additional_readonly_validation'
  assert value['original_metadata_record_unchanged'] and value['core_unchanged'] and not value['related_processes_after']
  source_out=Path(protocol['source_out']).resolve();assert source_out in (continuation.resolve(),staged.resolve())
  assert ref(protocol_path)['sha256']==value['protocol_sha256']
  assert protocol['source_protocol_sha256']==ref(source_out/'protocol.json')['sha256']
  assert all(ref(Path(p))['sha256']==sha for p,sha in value['parent_input_hashes'].items())
  assert ref(path)['sha256'] in admissions,'Read-only supplement still needs independent admission'
  supplements[(value['name'],value['workflow'])]={'result':ref(path),'protocol':ref(protocol_path),'source_out':str(source_out),'independent_admission':admissions[ref(path)['sha256']],'status':value['status']}
 cases=load(original/'cases.json')['roots'];registration=load(staged/'cases.json');repair={r['row']['canonical_name']:r for r in registration['recovery_cases']};interrupt=load(BASE/'interruption-record.json')
 active={(w['argv'][w['argv'].index('--worker')+1],w['argv'][w['argv'].index('--phase')+1]) for w in interrupt['workers']}
 rows=[];projects=[]
 for case in cases:
  name=case['canonical_name'];project={'canonical_name':name,'current_pin':case['request'],'repositories':case['repositories'],'workflows':{}}
  for wf in ('update','extras','relock'):
   old=read_attempt(original,case,wf);new=read_attempt(continuation,case,wf);last=read_attempt(staged,case,wf)
   applicable=wf=='relock' or case['workflow_selection'][wf]['status']=='selected'
   assert not (old['completed'] and (new['executed_native_installer'] or last['executed_native_installer'])),'Completed original sequence was reexecuted'
   assert not (new['completed'] and last['executed_native_installer']),'Completed corrected900 sequence was reexecuted'
   selected=wf in repair[name]['workflows_to_attempt'];effective=last if last['result'] else new if new['result'] else old
   preparations=[preparation(out,case,wf) for out in (original,continuation,staged)]
   old_state=old['status'] or ('explicitly_interrupted_method_repair' if (name,wf) in active else 'not_started_original_pass')
   supplement=supplements.get((name,wf));completed=effective['completed'] or supplement is not None
   staged_started=any(available(p) for p in (staged/'cases'/name/wf/'commands').glob('*/command.json'))
   assert not (supplement and supplement['source_out']==str(continuation.resolve()) and last['executed_native_installer']),'A read-only-completed corrected900 chain was reinstalled'
   status=('completed_actual_chain_with_later_readonly_validation' if supplement else effective['status'] or 'not_started_registered_workflow') if applicable else 'not_applicable_registered_selection'
   record={'canonical_name':name,'upstream_repositories':case['repositories'],'current_pin':case['request'],'target_python':case['target_python'],
    'workflow':wf,'applicable':applicable,'static_selected':case['workflow_selection'].get(wf,{}).get('status')=='selected','semantic_applicable':applicable,
    'prepared_world_recorded_executable':applicable and any(p['required_variants_recorded_prepared'] for p in preparations),'preparation_layers':preparations,
    'executable_definition':'At least one registered layer records all complete required native-wheel variants prepared with a manifest. This is preparation coverage, distinct from an actual installer invocation and a completed validated sequence. Final lock/source/integrity review is separately bound.',
    'registered_selection':case['workflow_selection'].get(wf),
    'original':{**{k:v for k,v in old.items() if k!='raw_result'},'explicit_original_state':old_state},
    'interruption':{'record':ref(BASE/'interruption-record.json'),'was_active_workflow_at_stop':(name,wf) in active,'artifact_stage_active_at_stop':(name,'artifacts') in active},
    'safe_drain':ref(BASE/'drain-to-staged-record.json'),
    'corrected900':{k:v for k,v in new.items() if k!='raw_result'},'staged':{k:v for k,v in last.items() if k!='raw_result'},'selected_for_staged_continuation':selected,
    'staged_dispatch_preservation_reason':repair[name].get('preserved_workflows',{}).get(wf),
    'effective_status':status,'effective_reason':effective['reason'] if applicable else case['workflow_selection'][wf]['status'],
    'unmeasured_reason':None if completed and applicable else {'status':status,'reason':effective['reason'],'preservation_reason':repair[name].get('preserved_workflows',{}).get(wf),'has_unstarted_registered_job':selected and not last['result']},
    'additional_readonly_supplement':supplement,'original_budget_status_preserved':bool(supplement),
    'actually_executed_any_install':old['executed_native_installer'] or new['executed_native_installer'] or last['executed_native_installer'],
    'native_installer_invocation_is_an_attempt_not_an_install_certificate':True,
    'main_distribution_observed_installed_any_stage':old['observed_installed_main'] or new['observed_installed_main'] or last['observed_installed_main'],
    'completed_actual_sequence':completed if applicable else False,
    'closure_state':'not_applicable' if not applicable else 'completed' if completed else 'closed_unmeasured' if last['result'] or repair[name].get('preserved_workflows',{}).get(wf) else 'pending_active' if staged_started else 'pending_queued',
    'staged_started_by_evidence_cutoff':staged_started,
    'actual_delta':delta(effective,case,wf) if applicable else None,'logical_unit_count':1,
    'limits':'Restricted verified native-wheel world; published controlled consumer sequence. Not full PyPI candidate coverage, repo HEAD replay or application/hardware validation.'}
   if supplement:record['actual_delta'].update(complete_sequence=True,partial_observations_only=False,completion_evidence='Actual operation chain plus separately registered later read-only validation; original budget outcome remains unchanged.')
   rows.append(record);project['workflows'][wf]=record
  projects.append(project)
 result={'schema':'published-stateful-effective-ledger-v1','is_final':not args.working,'generated_at_utc':datetime.now(timezone.utc).isoformat(),'evidence_cutoff_utc':args.cutoff_utc,'cutoff_method':'Interim cutoff admits only immutable operation/result/stage records whose filesystem modification time is no later than the cutoff; mutable later progress is not used to backdate evidence.' if args.cutoff_utc else None,'finalized_at_utc':None if args.working else datetime.now(timezone.utc).isoformat(),'unique_published_roots':len(cases),
  'logical_root_sequence_rows':len(rows),'source_cases':ref(original/'cases.json'),'original_protocol':ref(original/'protocol.json'),
  'interruption_record':ref(BASE/'interruption-record.json'),'corrected900_protocol':ref(continuation/'protocol.json'),'safe_drain_record':ref(BASE/'drain-to-staged-record.json'),
  'staged_protocol':ref(staged/'protocol.json'),'staged_summary':ref(staged/'summary.json'),
  'status_counts':dict(Counter(r['effective_status'] for r in rows)),'completed_unique_roots':len({r['canonical_name'] for r in rows if r['completed_actual_sequence']}),
  'closure_counts':dict(Counter(r['closure_state'] for r in rows)),
  'static_selected_sequences':sum(r['static_selected'] for r in rows),'semantic_applicable_sequences':sum(r['semantic_applicable'] for r in rows),'prepared_world_recorded_executable_sequences':sum(r['prepared_world_recorded_executable'] for r in rows),
  'actually_installer_executed_unique_roots':len({r['canonical_name'] for r in rows if r['actually_executed_any_install']}),
  'main_distribution_observed_installed_unique_roots':len({r['canonical_name'] for r in rows if r['main_distribution_observed_installed_any_stage']}),
  'all_applicable_sequences_completed_unique_roots':sum(all(not r['applicable'] or r['completed_actual_sequence'] for r in p['workflows'].values()) for p in projects),
  'completed_by_workflow':{wf:sum(r['workflow']==wf and r['completed_actual_sequence'] for r in rows) for wf in ('update','extras','relock')},
  'complete_update_root_version_changes':sum(r['workflow']=='update' and r['completed_actual_sequence'] and
    r['actual_delta'].get('root_versions',{}).get('pip-old')!=r['actual_delta'].get('root_versions',{}).get('pip-updated') and
    r['actual_delta'].get('root_versions',{}).get('uv-old')!=r['actual_delta'].get('root_versions',{}).get('uv-updated') for r in rows),
  'complete_extra_active_graph_changes':sum(r['workflow']=='extras' and r['completed_actual_sequence'] and (r['actual_delta'].get('base_to_extra') or {}).get('active_graph_changed',False) for r in rows),
  'complete_extra_reachable_name_set_changes':sum(r['workflow']=='extras' and r['completed_actual_sequence'] and (r['actual_delta'].get('base_to_extra') or {}).get('reachable_set_changed',False) for r in rows),
  'complete_extra_roundtrip_active_graph_restored':sum(r['workflow']=='extras' and r['completed_actual_sequence'] and (r['actual_delta'].get('base_to_restored') or {}).get('active_graph_changed') is False for r in rows),
  'complete_relock_graph_changes':sum(r['workflow']=='relock' and r['completed_actual_sequence'] and (r['actual_delta'].get('relock') or {}).get('active_graph_changed',False) for r in rows),
  'complete_relock_graph_noops':sum(r['workflow']=='relock' and r['completed_actual_sequence'] and r['actual_delta'].get('active_graph_noop') is True for r in rows),
  'rows':rows,'interpretation':'Each canonical root-by-sequence counted once; original and continuation are provenance layers, not independent project findings. A graph/version delta is an observation until installed contracts and independent admission establish a defect. No ecosystem prevalence or precision/recall claim.'}
 manual=ROOT/'work/stateful-workflows-20261111/review/ultralytics-extra-final-admission.json'
 if available(manual):result['separate_manual_observation']={'canonical_name':'ultralytics','certificate':ref(manual),'report':ref(ROOT/'1110ISSUEs/02-ultralytics__ultralytics.md'),
  'scope':'A separately registered explicit official-CPU consumer configuration tested the same root pin and official extra. It is supplementary real-project evidence, not a replacement for this frozen restricted-PyPI world, and does not change any batch row status or double-count the root. Shared-cv2 mechanism is already known; see the independently admitted report.'}
 suffix='-cutoff071043' if args.cutoff_utc else '-working' if args.working else ''
 (BASE/('effective-ledger'+suffix+'.json')).write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n')
 lines=['Published controlled stateful workflows (one row per canonical main distribution)','Scope: restricted verified native wheels; fixed public pins; original/interruption/continuation retained.','', 'Distribution | update | extra | relock','--- | --- | --- | ---']
 for project in projects:
  cells=[]
  for wf in ('update','extras','relock'):
   r=project['workflows'][wf];text=r['effective_status']
   if r['completed_actual_sequence']:
    d=r['actual_delta'];text='completed'
    if wf=='update':text+=' '+str(r['registered_selection'].get('from_version',''))+'→'+project['current_pin'].split('==')[1]
    elif wf=='extras':text+='; reachable delta='+str((d.get('base_to_extra') or {}).get('reachable_set_changed'))
    else:text+='; graph '+('no-op' if d.get('active_graph_noop') else 'changed')
   cells.append(text)
  lines.append(project['current_pin']+' | '+' | '.join(cells))
 (BASE/('actual-delta-table'+suffix+'.txt')).write_text('\n'.join(lines)+'\n')
 print(json.dumps({k:v for k,v in result.items() if k not in ('rows','interpretation')},ensure_ascii=False))
if __name__=='__main__':main()
