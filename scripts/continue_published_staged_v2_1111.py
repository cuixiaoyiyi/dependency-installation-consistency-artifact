"""Explicit multi-layer continuation, preserving the frozen33 consumer requests."""
from __future__ import annotations
import argparse
import inspect
import json
import os
from pathlib import Path
import shutil
import signal
import sys
import time

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from scripts import recover_stateful_preparation_1111 as parent
from scripts import stateful_real_workflows_1111 as base
from scripts import stateful_fast_file_audit_1111 as fast
from scripts.run_expanded_validation import digest,dump,now
from packaging.requirements import Requirement
from packaging.utils import canonicalize_name
PARENT_PATH=Path(parent.__file__)
PARENT_SHA='a8e6c7021528e41a9829b51023cba5ed027597dbe90307b01bde83eaccb3c016'
BASE_SHA='adac69aa7d91832a8e11add933c20f859e98502da2397ec7dc78767cae0e943e'
FAST_SHA='b688b8eea4f80ccc5ac4fa18447fcbde097f585a422cb175e473083bb9ff910e'
ORIGINAL=ROOT/'work/stateful-workflows-20261111/published/run1'
CORRECTED=ORIGINAL.parent/'corrected-continuation1'
NEEDED={'update':('base','old'),'extras':('base','extra'),'relock':('base',)}

def helpers():
 assert digest(PARENT_PATH)==PARENT_SHA and digest(Path(base.__file__))==BASE_SHA and digest(Path(fast.__file__))==FAST_SHA
def successful_reports_layered(source,row):
 result={};directory=source/'cases'/row['canonical_name']/'artifacts'
 for variant,request in parent.expected_requests(row).items():
  report_path=directory/(variant+'-report.json');command_path=directory/'commands'/(variant+'-metadata-plan')/'command.json'
  if not report_path.exists() or not command_path.exists():continue
  data=parent.load(report_path);command=parent.load(command_path);chain=[];seen=set();native_command_path=command_path
  while command.get('executed') is False:
   proof=command.get('reused_successful_original_report')
   if not proof:break
   assert str(native_command_path) not in seen,'Cyclic metadata report reuse proof'
   seen.add(str(native_command_path));assert len(seen)<=8
   assert proof['request']==request
   leaf_report=Path(proof['report']);leaf_command=Path(proof['command'])
   assert leaf_report.resolve().is_relative_to(ROOT) and leaf_command.resolve().is_relative_to(ROOT)
   assert digest(leaf_report)==proof['report_sha256'] and digest(leaf_command)==proof['command_sha256']
   assert digest(report_path)==proof['report_sha256'],'A reused report must remain byte-identical to its native provenance report'
   chain.append({'path':str(native_command_path),'sha256':digest(native_command_path),'executed':False,'source_report':str(leaf_report),'source_report_sha256':proof['report_sha256']})
   native_command_path=leaf_command;command=parent.load(native_command_path)
  argv=command.get('argv',[])
  if command.get('executed') is False or command.get('exit')!=0 or not argv:continue
  if argv[-1]!=request or '--only-binary=:all:' not in argv or '--python' not in argv or argv[argv.index('--python')+1]!=row['runtime']:continue
  if data.get('environment')!=row['marker_environment']:continue
  req=Requirement(request);roots=[r for r in data.get('install',[]) if canonicalize_name(r['metadata']['name'])==row['canonical_name']]
  if len(roots)!=1 or not req.specifier.contains(roots[0]['metadata']['version'],prereleases=True):continue
  result[variant]={'report':str(report_path),'report_sha256':digest(report_path),'command':str(native_command_path),'command_sha256':digest(native_command_path),'request':request,'transparent_reuse_chain':chain,'new_resolver_invocation':False}
 return result
def workflow_layer(source,name,wf):
 directory=source/'cases'/name/wf;path=directory/'results.json'
 if not path.exists():return None
 value=parent.load(path);failures=[];command_paths=list((directory/'commands').glob('*/command.json'))
 for command_path in command_paths:
  command=parent.load(command_path);argv=command.get('argv',[])
  if command.get('executed') is False or not command.get('exit') or not argv:continue
  operation=('install' in argv and '--dry-run' not in argv) or 'lock' in argv or 'sync' in argv
  if not operation:continue
  stderr_path=command_path.with_name('stderr.txt');text=stderr_path.read_text(errors='replace') if stderr_path.exists() else ''
  initial=directory/'commands/uv-initial-lock/command.json';initial_command=parent.load(initial) if initial.exists() else {}
  lowest_repair=(wf=='relock' and command_path.parent.name=='uv-before-relock' and 'sync' in argv and '--locked' in argv and '--resolution' not in argv and
   initial_command.get('exit')==0 and '--resolution' in initial_command.get('argv',[]) and initial_command['argv'][initial_command['argv'].index('--resolution')+1]=='lowest' and
   'Ignoring existing lockfile due to change in resolution mode: `lowest` vs. `highest`' in text and 'needs to be updated, but `--locked` was provided' in text and not any(s in text.lower() for s in ('no solution','no matching','requires-python')))
  failures.append({'command':str(command_path),'command_sha256':digest(command_path),'label':command_path.parent.name,'exit':command['exit'],'stderr':str(stderr_path),'stderr_sha256':digest(stderr_path) if stderr_path.exists() else None,
   'classification':'authorized_initial_lowest_strategy_method_repair' if lowest_repair else 'preserve_completed_nonzero_workflow_operation','authorized_lowest_repair':lowest_repair})
 reason=value.get('reason','');status=value['status'];prep_propagation=None
 artifact_result_path=source/'cases'/name/'artifacts/results.json';log=source/'logs'/(name+'--'+wf+'.log')
 if status=='unknown_worker_or_budget' and value.get('returncode')==1 and not command_paths and not list((directory/'stages').glob('*/installed.json')) and artifact_result_path.exists() and log.exists():
  artifact=parent.load(artifact_result_path);text=log.read_text(errors='replace')
  if artifact.get('status')=='unknown_worker_or_budget' and artifact.get('returncode') in (-9,-15) and 'variants' not in artifact and 'prepared = load(artifacts / "results.json")["variants"]' in text and "KeyError: 'variants'" in text:
   prep_propagation={'classification':'proven_preparation_budget_propagation_before_any_workflow_command','artifact_result':str(artifact_result_path),'artifact_result_sha256':digest(artifact_result_path),'workflow_traceback':str(log),'workflow_traceback_sha256':digest(log),'native_operation_count':0}
 method_unknown=(status=='unknown_worker_or_budget' and value.get('returncode') in (-9,-15)) or (status=='unknown_workflow_coverage' and any(s in str(reason).lower() for s in ('budget','timed out','input/output error','i/o error'))) or bool(failures and all(f['authorized_lowest_repair'] for f in failures)) or bool(prep_propagation)
 return {'out':str(source),'path':str(path),'sha256':digest(path),'status':status,'reason':reason,'returncode':value.get('returncode'),'failed_workflow_operations':failures,'has_nonmechanical_failed_operation':any(not f['authorized_lowest_repair'] for f in failures),'eligible_known_method_unknown':method_unknown,'preparation_budget_propagation':prep_propagation}
def readonly_proofs(paths,admissions,inputs):
 gates={}
 for path in admissions:
  value=parent.load(path);assert value['status']=='accepted_as_one_composite_workflow';gates[value['result_sha256']]=str(path.resolve());inputs[str(path.resolve())]=digest(path)
 result={}
 for path in paths:
  path=path.resolve();value=parent.load(path);protocol_path=path.parents[2]/'protocol.json';protocol=parent.load(protocol_path)
  assert value['status']=='actual_operation_chain_completed_with_additional_readonly_validation'
  assert value['original_metadata_record_unchanged'] and value['core_unchanged'] and not value['related_processes_after']
  assert digest(protocol_path)==value['protocol_sha256'] and Path(protocol['source_out'])==CORRECTED and protocol['source_protocol_sha256']==digest(CORRECTED/'protocol.json')
  assert all(digest(Path(p))==sha for p,sha in value['parent_input_hashes'].items())
  assert digest(path) in gates
  result[value['name']+':'+value['workflow']]={'path':str(path),'sha256':digest(path),'independent_admission':gates[digest(path)]}
  inputs[str(path)]=digest(path);inputs[str(protocol_path)]=digest(protocol_path)
 return result
def prepare(args):
 helpers();out=args.out.resolve();drain_path=ORIGINAL.parent/'drain-to-staged-record.json';drain=parent.load(drain_path)
 assert drain['status']=='controlled_method_repair_drain_completed' and drain['all_owned_living_processes_terminated']
 assert drain['source_protocol_sha256']==digest(CORRECTED/'protocol.json') and drain['source_cases_sha256']==digest(CORRECTED/'cases.json')
 original_protocol=parent.load(ORIGINAL/'protocol.json');cases=parent.load(ORIGINAL/'cases.json');latest_registration=parent.load(CORRECTED/'cases.json')
 assert cases['roots']==latest_registration['roots'] and len(cases['roots'])==33
 old_gate_path=ROOT/'work/stateful-workflows-20261111/review/published-final-saved-stage-review.json'
 assert digest(old_gate_path)=='39fd2e8507a61b25d6e0e3d4b4ae31b4666cf501a59380f859ca7d12ccb438e7'
 old_reviewed={str((ROOT/r['inventory']['path']).resolve()):r for r in parent.load(old_gate_path)['rows']}
 for path in (ORIGINAL/'cases').glob('*/*/stages/*/installed.json'):
  assert str(path.resolve()) in old_reviewed and old_reviewed[str(path.resolve())]['inventory']['sha256']==digest(path)
 review=parent.load(args.partial_review);reviewed={str((ROOT/r['inventory']['path']).resolve()):r for r in review['rows']}
 independent_gate_path=ROOT/'work/stateful-workflows-20261111/review/corrected900-independent-stage-gate.json';independent_gate=parent.load(independent_gate_path)
 assert digest(independent_gate_path)=='6d986771a877017a3c39cfb23d2404b8bee186c17c640845586afe23e8e9f1d9' and independent_gate['status']=='accepted_for_bounded_methods_continuation'
 assert independent_gate['review_sha256']==digest(args.partial_review) and independent_gate['complete_source_inventory_path_coverage'] and independent_gate['counts']['candidates']==independent_gate['counts']['unknowns']==0
 for path in (CORRECTED/'cases').glob('*/*/stages/*/installed.json'):
  assert str(path.resolve()) in reviewed and reviewed[str(path.resolve())]['inventory']['sha256']==digest(path)
 inputs={str(p):digest(p) for p in (ORIGINAL/'protocol.json',ORIGINAL/'cases.json',CORRECTED/'protocol.json',CORRECTED/'cases.json',drain_path,args.partial_review.resolve(),old_gate_path)}
 inputs[str(independent_gate_path)]=digest(independent_gate_path)
 prior_registration=ORIGINAL.parent/'staged-continuation1/protocol.json';revision_note=ORIGINAL.parent/'staged-v1-registration-not-executed.json'
 assert not (prior_registration.parent/'run-started.json').exists()
 inputs[str(prior_registration)]=digest(prior_registration);inputs[str(revision_note)]=digest(revision_note)
 approved=readonly_proofs(args.readonly_result,args.readonly_admission,inputs)
 rows=[];latest_by_name={r['row']['canonical_name']:r for r in latest_registration['recovery_cases']}
 for row in cases['roots']:
  name=row['canonical_name'];latest=latest_by_name[name]
  sources=[ORIGINAL,CORRECTED];artifact_source=next((s for s in reversed(sources) if (s/'cases'/name/'artifacts').exists()),ORIGINAL)
  artifact_path=artifact_source/'cases'/name/'artifacts';artifact_result=parent.load(artifact_path/'results.json') if (artifact_path/'results.json').exists() else {}
  variants=artifact_result.get('variants') or (parent.load(artifact_path/'variant-results.json') if (artifact_path/'variant-results.json').exists() else {})
  reports={};retained={}
  for source in sources:reports.update(successful_reports_layered(source,row));retained.update(parent.retained_variant_failures(source,row))
  complete=parent.physical_world_complete(artifact_path);jobs=[];preserved={};states={}
  for wf in base.WORKFLOWS:
   layers=[]
   for source in sources:
    layer=workflow_layer(source,name,wf)
    if layer:
     layers.append(layer);inputs[layer['path']]=layer['sha256']
     if layer['preparation_budget_propagation']:
      propagation=layer['preparation_budget_propagation'];inputs[propagation['artifact_result']]=propagation['artifact_result_sha256'];inputs[propagation['workflow_traceback']]=propagation['workflow_traceback_sha256']
     for failure in layer['failed_workflow_operations']:
      inputs[failure['command']]=failure['command_sha256']
      if failure['stderr_sha256']:inputs[failure['stderr']]=failure['stderr_sha256']
   states[wf]=layers;status=layers[-1]['status'] if layers else 'not_started_any_pass'
   raw_rows=[reviewed[str(path.resolve())] for path in (CORRECTED/'cases'/name/wf).glob('stages/*/installed.json')]+[old_reviewed[str(path.resolve())] for path in (ORIGINAL/'cases'/name/wf).glob('stages/*/installed.json')]
   if wf!='relock' and row['workflow_selection'][wf]['status']!='selected':reason='not_applicable_frozen_selection'
   elif name+':'+wf in approved:reason='completed_actual_chain_plus_independent_readonly_validation'
   elif any(v['status'] in ('completed_actual_stateful_workflow','candidate_actual_installed_contract_violation') for v in layers):reason='completed_or_candidate_prior_actual_sequence'
   elif any(v.get('root_closure',{}).get('violations') or v.get('strict_uv_sync') and v.get('all_installed_base_closure',{}).get('violations') or v['status'].startswith(('candidate','unknown')) for v in raw_rows):reason='held_prior_saved_metadata_candidate_or_unknown'
   elif status.startswith('unsupported'):reason='preserved_prior_unsupported'
   elif any(layer['has_nonmechanical_failed_operation'] for layer in layers):reason='preserved_nonmechanical_workflow_operation_failure'
   elif layers and status in ('unknown_worker_or_budget','unknown_workflow_coverage') and not layers[-1]['eligible_known_method_unknown']:reason='preserved_unclassified_workflow_failure_not_proven_budget_or_io'
   elif any(v in retained for v in NEEDED[wf]):reason='preserved_nonmechanical_metadata_failure'
   elif any(variants.get(v,{}).get('status')!='prepared' and variants.get(v,{}).get('reason') and not ('budget' in variants[v]['reason'].lower() or parent.NETWORK_PATTERN.search(variants[v]['reason'])) for v in NEEDED[wf]):reason='preserved_nonmechanical_preparation_or_resource_gap'
   else:reason=None;jobs.append(wf)
   if reason:preserved[wf]=reason
  if jobs:
   for source in sources:
    directory=source/'cases'/name/'artifacts'
    for path in directory.rglob('*.json'):inputs[str(path)]=digest(path)
    for path in (directory/'commands').glob('*/*.txt'):inputs[str(path)]=digest(path)
    for path in (directory/'wheelhouse').glob('*.whl'):inputs[str(path)]=digest(path)
  rows.append({'row':row,'eligible':bool(jobs),'workflows_to_attempt':jobs,'preserved_workflows':preserved,'prior_workflow_layers':states,'original_artifact_status':artifact_result.get('status','not_started_or_no_result'),
   'artifact_parent_out':str(artifact_source),'original_physical_world_complete':complete,'successful_reports':reports,'retained_variant_failures':retained,'registered_main_size_policy':latest['registered_main_size_policy']})
 out.mkdir(parents=True,exist_ok=False);dump(out/'cases.json',{'roots':cases['roots'],'recovery_cases':rows,'excluded_coverage_slots':cases.get('excluded_coverage_slots',[])})
 protocol={**original_protocol,'schema':'published-multilayer-staged-continuation-v1','registered_at_utc':now(),'script_sha256':digest(Path(__file__)),'frozen_shared_runner_sha256':BASE_SHA,'fast_audit_sha256':FAST_SHA,
  'inherited_preparation_helper_sha256':PARENT_SHA,'cases_sha256':digest(out/'cases.json'),'inputs':inputs,'parent_out':str(CORRECTED),'source_layers':[str(ORIGINAL),str(CORRECTED)],'drain_record':str(drain_path),'drain_record_sha256':digest(drain_path),
  'already_completed_readonly_validated_chains':approved,'eligible_preparation_roots':sum(r['eligible'] for r in rows),'workers':2,'artifact_preparation_seconds':900,'per_workflow_seconds':3600,'per_native_command_seconds':900,'per_file_audit_seconds':900,'workflows':list(base.WORKFLOWS),
  'fast_audit_equivalence_freeze_sha256':digest(ROOT/'work/stateful-workflows-20261111/review/fast-file-audit-freeze.json'),
  'dispatch':'Every frozen33 root remains. Prior completed/candidate/independently read-only-completed sequences and nontransport NoMatching/preparation/resource gaps are preserved, never retried. Still unstarted workflows receive their first measurement under staged budgets; admitted complete-world IO method gaps receive at most this one staged retry.',
  'artifact_policy':'Per-root registered artifact_parent_out points to the latest existing prepared layer. An exact complete prepared world sufficient for all selected workflows is copied and hash-verified with no resolver/network. Otherwise inherited successful reports, exact official JSON and archive SHA, retained nontransport failures and verified raw snapshot seeding remain unchanged. All frozen caps remain.',
  'worker_input_validation':'Each isolated worker verifies global inputs and that root in both source layers; the controller verifies every registered input at completion. Per-root parent directory and filtered input checks are derived only from immutable cases, never from outcomes during execution.',
  'source_scope':'Controlled consumer workflows in a restricted union of original hash-verified official native wheels. Not public PyPI full-candidate coverage, cross-platform metadata or upstream source-repository command replay.',
  'budget_addendum':'Registered before any new staged execution: each native command<=900s, each full file audit<=900s hard isolated-PG cap, whole workflow<=3600s, preparation<=900s, two workers. Original and corrected900 results and explicit drain provenance remain unchanged.',
  'old_data_preserved':True}
 protocol['registration_revision']={'previous_unexecuted_protocol':str(prior_registration),'sha256':digest(prior_registration),'revision_note':str(revision_note),'reason':'Only evidenced upstream preparation-budget propagation before any workflow command is added; no generic return1/path/source failure is made eligible. Original33 requests and all prior completed/candidate/NoMatching/resource holds remain.'}
 dump(out/'protocol.json',protocol);print(json.dumps({'protocol_sha256':digest(out/'protocol.json'),'script_sha256':protocol['script_sha256'],'jobs':{r['row']['canonical_name']:r['workflows_to_attempt'] for r in rows if r['eligible']}}),flush=True)
def worker(out,name,phase):
 helpers();protocol=parent.load(out/'protocol.json');assert digest(Path(__file__))==protocol['script_sha256'] and digest(out/'cases.json')==protocol['cases_sha256']
 selected=next(r for r in parent.load(out/'cases.json')['recovery_cases'] if r['row']['canonical_name']==name);assert selected['eligible']
 own_inputs={p:sha for p,sha in protocol['inputs'].items() if not any(p.startswith(str(Path(s)/'cases')+os.sep) for s in protocol['source_layers']) or any(p.startswith(str(Path(s)/'cases'/name)+os.sep) for s in protocol['source_layers'])}
 assert all(digest(Path(p))==sha for p,sha in own_inputs.items())
 source=Path(selected['artifact_parent_out']);original=source/'cases'/name/'artifacts'
 if phase=='artifacts' and selected['original_physical_world_complete']:
  prepared=parent.load(original/'results.json') if (original/'results.json').exists() else {}
  if all(prepared.get('variants',{}).get(v,{}).get('status')=='prepared' for wf in selected['workflows_to_attempt'] for v in NEEDED[wf]):
   assert parent.physical_world_complete(original);destination=out/'cases'/name/'artifacts';destination.mkdir(parents=True,exist_ok=False);(destination/'wheelhouse').mkdir();checks={}
   for filename in ('results.json','wheel-manifest.json'):
    shutil.copyfile(original/filename,destination/filename);checks[str(original/filename)]=digest(original/filename);assert digest(destination/filename)==checks[str(original/filename)]
   for wheel in parent.load(original/'wheel-manifest.json'):
    src=original/'wheelhouse'/wheel['filename'];dst=destination/'wheelhouse'/wheel['filename'];assert src.stat().st_size==wheel['bytes'] and digest(src)==wheel['sha256'];shutil.copyfile(src,dst);assert dst.stat().st_size==wheel['bytes'] and digest(dst)==wheel['sha256'];checks[str(src)]=wheel['sha256']
   dump(destination/'complete-world-reuse.json',{'parent_input_sha256':checks,'fresh_resolver_invocation':False,'fresh_network_transfer_bytes':0,'complete_world_unchanged':True});return
 parent.__file__=str(Path(__file__).resolve());original_load=parent.load
 def configured_load(path):
  value=original_load(path)
  if Path(path).resolve()==(out/'protocol.json').resolve():value={**value,'parent_out':str(source),'inputs':own_inputs}
  return value
 parent.load=configured_load
 if phase=='artifacts':
  original_archives=base.existing_archives;original_fetch=base.fetch_json
  def layered_archives():
   result=original_archives()
   for layer in protocol['source_layers']:
    for path in (Path(layer)/'cases'/name/'artifacts/wheelhouse').glob('*.whl'):result.setdefault(path.name,[]).append(path)
   return result
  def layered_fetch(url,path,recorder):
   relative=path.relative_to(out/'cases'/name/'artifacts')
   for layer in reversed(protocol['source_layers']):
    saved=Path(layer)/'cases'/name/'artifacts'/relative
    if saved.exists():
     value=parent.load(saved);path.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(saved,path)
     dump(path.with_suffix('.layer-reused.json'),{'url':url,'parent':str(saved),'parent_sha256':digest(saved),'copied_sha256':digest(path),'fresh_observation':False});return value
   return original_fetch(url,path,recorder)
  base.existing_archives=layered_archives;base.fetch_json=layered_fetch
 if phase!='artifacts':
  Recorder=base.Recorder
  class StagedRecorder(Recorder):
   def __init__(self,directory,seconds=3600):super().__init__(directory,protocol['per_workflow_seconds'])
   def command(self,argv,label,**kwargs):
    deadline=self.deadline;self.deadline=min(deadline,time.monotonic()+protocol['per_native_command_seconds'])
    try:return super().command(argv,label,**kwargs)
    finally:self.deadline=deadline
  base.Recorder=StagedRecorder
  def audit(inventory,wheels,envdir):
   previous=signal.getsignal(signal.SIGALRM)
   def expired(signum,frame):
    assert os.getpgrp()==os.getpid();os.killpg(os.getpgrp(),signal.SIGKILL)
   signal.signal(signal.SIGALRM,expired);signal.alarm(protocol['per_file_audit_seconds'])
   try:return fast.audit_files(inventory,wheels,envdir)
   finally:signal.alarm(0);signal.signal(signal.SIGALRM,previous)
  parent.audit_files=audit
 parent.worker(out,name,phase)
def main():
 parser=argparse.ArgumentParser();parser.add_argument('--prepare',action='store_true');parser.add_argument('--run',action='store_true');parser.add_argument('--partial-review',type=Path);parser.add_argument('--readonly-result',action='append',type=Path,default=[]);parser.add_argument('--readonly-admission',action='append',type=Path,default=[]);parser.add_argument('--out',type=Path,required=True);parser.add_argument('--worker');parser.add_argument('--phase',choices=('artifacts',*base.WORKFLOWS));args=parser.parse_args()
 assert sys.platform=='linux' and sys.version_info[:3]==(3,11,16)
 if args.prepare:prepare(args)
 elif args.worker:worker(args.out.resolve(),args.worker,args.phase)
 elif args.run:
  helpers();parent.__file__=str(Path(__file__).resolve());text=inspect.getsource(parent.execute);assert 'p.wait(timeout=902)' in text;text=text.replace('p.wait(timeout=902)',"p.wait(timeout=protocol['artifact_preparation_seconds' if phase=='artifacts' else 'per_workflow_seconds']+2)");namespace=dict(parent.__dict__);exec(compile(text,str(Path(__file__).resolve())+':inherited-controller','exec'),namespace);namespace['execute'](args.out.resolve())
 else:parser.error('Choose a mode')
if __name__=='__main__':main()
