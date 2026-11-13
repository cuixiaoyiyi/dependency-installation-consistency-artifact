"""Once-bounded continuation of mechanically interrupted stateful artifact preparation."""
from __future__ import annotations
import argparse
from concurrent.futures import ThreadPoolExecutor,as_completed
from collections import Counter
import hashlib
import json
import os
import re
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import time
from packaging.requirements import Requirement
from packaging.utils import canonicalize_name,parse_wheel_filename
from packaging.specifiers import SpecifierSet
from packaging.version import Version

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
import scripts.stateful_real_workflows_1111 as base
from scripts.stateful_fast_file_audit_1111 import audit_files
from scripts.run_expanded_validation import digest,dump,now
NETWORK_PATTERN=re.compile(r'too many 50[0-9] error|50[0-9]\s*:?\s*(?:Server Error|Bad Gateway|Service Unavailable)|ReadTimeout|ConnectTimeout|ConnectionError|Temporary failure in name resolution|read operation timed out',re.I)

def load(p):return json.loads(Path(p).read_text())
def expected_requests(row):
 result={'base':row['request']};s=row['workflow_selection']
 if s['update']['status']=='selected':result['old']=s['update']['from_request']
 if s['extras']['status']=='selected' and not(row['canonical_name']=='setuptools' and s['extras'].get('extra')=='cover'):result['extra']=s['extras']['extra_request']
 return result
def retained_variant_failures(source,row):
 result={};directory=source/'cases'/row['canonical_name']/'artifacts'
 for variant,request in expected_requests(row).items():
  command=directory/'commands'/(variant+'-metadata-plan')/'command.json'
  if not command.exists():continue
  data=load(command);stderr=command.with_name('stderr.txt');text=stderr.read_text(errors='replace') if stderr.exists() else ''
  argv=data.get('argv',[])
  if not argv or argv[-1]!=request or '--python' not in argv or argv[argv.index('--python')+1]!=row['runtime']:continue
  if data.get('exit') and not NETWORK_PATTERN.search(text):
   result[variant]={'request':request,'source_command':str(command),'source_command_sha256':digest(command),
                    'source_stderr':str(stderr),'source_stderr_sha256':digest(stderr) if stderr.exists() else None,
                    'reason':'Original completed metadata command failed without a recognized transport condition; retain this failure, do not retry or change its request.'}
 return result
def successful_reports(source,row):
 artifacts=source/'cases'/row['canonical_name']/'artifacts';result={}
 for variant,request in expected_requests(row).items():
  report=artifacts/(variant+'-report.json');command=artifacts/'commands'/(variant+'-metadata-plan')/'command.json'
  if not(report.exists() and command.exists()):continue
  cmd=load(command);data=load(report)
  argv=cmd['argv']
  if cmd['exit'] or argv[-1]!=request or '--only-binary=:all:' not in argv or '--python' not in argv or argv[argv.index('--python')+1]!=row['runtime'] or data['environment']!=row['marker_environment']:continue
  root=Requirement(request);matches=[i for i in data['install'] if canonicalize_name(i['metadata']['name'])==row['canonical_name']]
  if len(matches)!=1 or not root.specifier.contains(matches[0]['metadata']['version'],prereleases=True):continue
  result[variant]={'report':str(report),'report_sha256':digest(report),'command':str(command),'command_sha256':digest(command),'request':request}
 return result
def physical_world_complete(directory):
 manifest=directory/'wheel-manifest.json'
 if not manifest.exists():return False
 try:
  rows=load(manifest);files={p.name:p for p in (directory/'wheelhouse').glob('*.whl')}
  return set(files)=={r['filename'] for r in rows} and all(files[r['filename']].stat().st_size==r['bytes'] and digest(files[r['filename']])==r['sha256'] for r in rows)
 except (OSError,ValueError,KeyError):return False
def registered_main_size_policy(row,profiles,maximum):
 data=load(ROOT/row['pypi_json_path']);tags=set(profiles[row['target_python']]['wheel_tags']);native=[]
 for file in data.get('urls',[]):
  if file.get('packagetype')!='bdist_wheel':continue
  try:
   compatible=bool({str(t) for t in parse_wheel_filename(file['filename'])[3]} & tags) and SpecifierSet(file.get('requires_python') or '').contains(row['target_python'],prereleases=True)
  except (ValueError,KeyError):continue
  if compatible:native.append({'filename':file['filename'],'bytes':file['size'],'sha256':file['digests']['sha256']})
 return {'status':'unsupported_registered_main_wheel_size' if native and all(f['bytes']>maximum for f in native) else 'no_early_size_exclusion',
         'registered_native_wheels':native,'limit_bytes':maximum,'source_json_sha256':digest(ROOT/row['pypi_json_path']),
         'scope':'Precheck of the frozen registered release file catalogue; not a claim about every future/public candidate or the project itself.'}
def prepare(args):
 source=args.source_out.resolve();out=args.out.resolve()
 parent=load(source/'protocol.json');cases=load(source/'cases.json')
 profile_path=ROOT/'work/stateful-validation-20261111/native-profiles.json';profiles=load(profile_path)
 interruption=load(args.interruption_record) if args.interruption_record else None
 if interruption:
  assert interruption['status']=='controlled_method_repair_interruption' and Path(interruption['source_out']).resolve()==source
  assert interruption['source_protocol_sha256']==digest(source/'protocol.json') and interruption['all_owned_processes_terminated']
 summary=load(source/'summary.json') if (source/'summary.json').exists() else None
 assert summary is not None or interruption is not None,'An original final summary or explicit controlled interruption ledger is required'
 assert parent['schema']=='actual-official-wheel-workflows-v1','Only an original registered pass may receive this once-only preparation recovery'
 if summary:assert summary['eligible_roots']==len(cases['roots'])
 saved=[p for wf in base.WORKFLOWS for p in (source/'cases').glob('*/'+wf+'/stages/*/installed.json')]
 admission=load(args.partial_review) if args.partial_review else None
 if saved:
  assert admission is not None,'Supply final independent --partial-review covering every saved inventory before recovery'
  reviewed={str((ROOT/r['inventory']['path']).resolve()):r for r in admission['rows']}
  for p in saved:assert str(p.resolve()) in reviewed and reviewed[str(p.resolve())]['inventory']['sha256']==digest(p),'Independent partial review is stale or incomplete'
 out.mkdir(parents=True,exist_ok=False)
 rows=[];inputs={str(source/'protocol.json'):digest(source/'protocol.json'),str(source/'cases.json'):digest(source/'cases.json')}
 inputs[str(profile_path)]=digest(profile_path)
 if summary:inputs[str(source/'summary.json')]=digest(source/'summary.json')
 if args.interruption_record:inputs[str(args.interruption_record.resolve())]=digest(args.interruption_record)
 if args.partial_review:inputs[str(args.partial_review.resolve())]=digest(args.partial_review)
 for row in cases['roots']:
  directory=source/'cases'/row['canonical_name'];result_path=directory/'artifacts/results.json'
  result=load(result_path) if result_path.exists() else {'status':'not_started_or_interrupted_original_preparation','no_original_result_file':True}
  reports=successful_reports(source,row)
  status=result.get('status');variant_path=directory/'artifacts/variant-results.json'
  variants=result.get('variants') or (load(variant_path) if variant_path.exists() else {})
  network_evidence=[]
  for stderr in (directory/'artifacts/commands').glob('*/stderr.txt'):
   text=stderr.read_text(errors='replace')
   if NETWORK_PATTERN.search(text):
    network_evidence.append({'path':str(stderr),'sha256':digest(stderr)});inputs[str(stderr)]=digest(stderr)
  mechanical=(status=='unknown_worker_or_budget' and result.get('returncode') in (-9,-15) or any('budget' in v.get('reason','').lower() or 'timed out' in v.get('reason','').lower() or NETWORK_PATTERN.search(v.get('reason','')) for v in variants.values()) or bool(network_evidence))
  eligible=bool(mechanical or interruption)
  jobs=[];deferred=[];held=[];original_workflows={};not_applicable=[];complete_world=physical_world_complete(directory/'artifacts') if eligible else False
  for wf in base.WORKFLOWS:
   p=directory/wf/'results.json';r=load(p) if p.exists() else {'status':'not_started_or_interrupted_original_workflow','no_original_result_file':True}
   original_workflows[wf]=r['status']
   if p.exists():inputs[str(p)]=digest(p)
   if wf!='relock' and row['workflow_selection'][wf]['status']!='selected':not_applicable.append(wf);continue
   raw_rows=[reviewed[str(p.resolve())] for p in (directory/wf).glob('stages/*/installed.json')] if saved else []
   raw_candidate=any(v.get('root_closure',{}).get('violations') or v.get('strict_uv_sync') and v.get('all_installed_base_closure',{}).get('violations') or 'candidate' in v.get('status','') or 'unknown' in v.get('status','') for v in raw_rows)
   if raw_candidate:held.append(wf)
   if r['status'] in ('unknown_worker_or_budget','unknown_preparation_coverage','unknown_workflow_coverage','not_started_or_interrupted_original_workflow') and not any(s.get('candidate') for s in r.get('stages',[])) and not raw_candidate:
    needed={'update':('base','old'),'extras':('base','extra'),'relock':('base',)}[wf]
    if not interruption and complete_world and all(variants.get(v,{}).get('status')=='prepared' for v in needed) and r['status'] in ('unknown_worker_or_budget','unknown_workflow_coverage'):
     deferred.append(wf)
    else:jobs.append(wf)
  eligible=bool(eligible and jobs)
  if result_path.exists():inputs[str(result_path)]=digest(result_path)
  if eligible:
   for p in (directory/'artifacts').rglob('*.json'):inputs[str(p)]=digest(p)
   for p in (directory/'artifacts/commands').glob('*/*.txt'):inputs[str(p)]=digest(p)
   # Snapshot bodies and already-downloaded archives are checked on actual read;
   # parent file hashes bind every candidate input before recovery starts.
   for p in (directory/'artifacts/wheelhouse').glob('*.whl'):inputs[str(p)]=digest(p)
  rows.append({'row':row,'eligible':eligible,'original_artifact_status':status,'original_workflow_statuses':original_workflows,'not_applicable_workflows':not_applicable,'successful_reports':reports,'network_evidence':network_evidence,
               'registered_main_size_policy':registered_main_size_policy(row,profiles,parent['max_new_single_download_bytes']),
               'retained_variant_failures':retained_variant_failures(source,row),
               'original_physical_world_complete':complete_world,'workflows_to_attempt':jobs if eligible else [],'workflows_held_for_independent_review':held,
               'workflows_deferred_to_methods_recovery':deferred if eligible else []})
 dump(out/'cases.json',{'roots':cases['roots'],'recovery_cases':rows,'excluded_coverage_slots':cases.get('excluded_coverage_slots',[])})
 protocol={**parent,'schema':'stateful-corrected-continuation-v1' if interruption else 'stateful-artifact-preparation-once-recovery-v1','registered_at_utc':now(),'script_sha256':digest(Path(__file__)),
  'frozen_shared_runner_sha256':digest(Path(base.__file__)),'fast_audit_sha256':digest(ROOT/'scripts/stateful_fast_file_audit_1111.py'),
  'parent_out':str(source),'parent_protocol_sha256':digest(source/'protocol.json'),'parent_summary_sha256':digest(source/'summary.json') if summary else None,
  'controlled_interruption':interruption,'interruption_record_sha256':digest(args.interruption_record) if args.interruption_record else None,
  'cases_sha256':digest(out/'cases.json'),'inputs':inputs,'eligible_preparation_roots':sum(r['eligible'] for r in rows),
  'eligibility':'Normal recovery: finalized preparation budget/5xx/connection/timeout only. Explicit controlled-interruption continuation: all unfinished noncandidate applicable workflows, including previously unstarted original roots, retain the frozen request. Completed/candidate/unsupported workflows do not rerun. Existing successful plans are reused when present; missing plans continue capture from verified seeds. Known nontransport failed variants are retained. Interruption is never relabeled as timeout.',
  'recovery_partition':'Normal completed-original-pass preparation recovery defers complete-world/needed-prepared workflow method failures to generic methods recovery. Explicit controlled-interruption continuation owns all remaining applicable noncandidate workflows and repairs audit/initial sync strategy together; no separate generic method pass overlaps it. No completed/candidate/unsupported workflow is rerun.',
  'per_variant_retention':'Original completed nonzero metadata commands without an explicit recognized transport condition are retained, not retried because another variant had a network/budget error. NoMatching/conflict is not independently a fresh-capture criterion.',
  'partial_stage_admission':'The independent review must cover every saved original inventory by SHA, including entries absent from aggregate stages. Workflows with known candidate/unknown partial evidence are held for independent adjudication, not routine recovery.',
  'fast_audit_equivalence_freeze_sha256':digest(ROOT/'work/stateful-workflows-20261111/review/fast-file-audit-freeze.json'),
  'max_recovery_passes':1,'workers':2,'artifact_preparation_seconds':900,'per_workflow_seconds':900,
  'resume_policy':'Same fixed cohort/request/predecessor/extra/native target. A successful recorded metadata plan is reused only with command exit0, exact request, native environment and root pin checks; raw report SHA retained. Official exact-release JSON reused by SHA. Complete original archives reused only after official size/SHA match; partial original bytes remain untouched. Missing plans continue in a new snapshot seeded via parent SnapshotStore.read/write body/hash verification. No request trimming or new selected variants.',
  'workflows':'After preparation completes, only originally incomplete noncandidate workflows may run in separate new environments. Fast equivalent audit and initial re-lock sync --resolution lowest are explicit method repairs. Completed/candidate/unsupported original workflows are never overwritten or silently retried.',
  'budgets':'Original and recovery budgets are reported separately. Each pass max500MiB new transfer,250MiB single artifact,500MiB official compressed union,2GiB uncompressed world. Old successful downloads may be copied after SHA validation. No builds or --no-deps.',
  'original_data_preserved':True}
 dump(out/'protocol.json',protocol);print(json.dumps({'eligible':protocol['eligible_preparation_roots'],'protocol_sha256':digest(out/'protocol.json')}),flush=True)

def worker(out,name,phase):
 protocol=load(out/'protocol.json');assert digest(Path(__file__))==protocol['script_sha256']
 assert digest(out/'cases.json')==protocol['cases_sha256']
 assert digest(Path(base.__file__))==protocol['frozen_shared_runner_sha256']
 assert digest(ROOT/'scripts/stateful_fast_file_audit_1111.py')==protocol['fast_audit_sha256']
 assert digest(ROOT/'work/stateful-workflows-20261111/review/fast-file-audit-freeze.json')==protocol['fast_audit_equivalence_freeze_sha256']
 assert digest(Path(protocol['driver']).resolve())==protocol['driver_sha256'] and digest(Path(protocol['uv']))==protocol['uv_sha256']
 selected=next(r for r in load(out/'cases.json')['recovery_cases'] if r['row']['canonical_name']==name);assert selected['eligible']
 row=selected['row'];source=Path(protocol['parent_out']);parent_artifacts=source/'cases'/name/'artifacts'
 own_prefix=str(source/'cases'/name)+os.sep
 assert all(digest(Path(p))==s for p,s in protocol['inputs'].items() if p.startswith(own_prefix) or not p.startswith(str(source/'cases')+os.sep))
 if phase=='artifacts':
  from drc import proxy
  original_configure=proxy.configure_snapshot;original_fetch=base.fetch_json;original_archives=base.existing_archives;OriginalRecorder=base.Recorder
  def configure(cache,sid,mode='record'):
   store=original_configure(cache,sid+'-recovery',mode);parents=[]
   for manifest in sorted((parent_artifacts/'metadata-cache/snapshots').glob('*/manifest.json')):
    before=digest(manifest);parent=proxy.SnapshotStore(manifest.parents[2],manifest.parent.name,'record');count=0
    for entry in sorted(parent.manifest['entries'].values(),key=lambda e:(e['kind'],e['key'])):
     status,body,headers=parent.read(entry['kind'],entry['key']);store.write(entry['kind'],entry['key'],status,body,headers);count+=1
    assert digest(manifest)==before;parents.append({'manifest':str(manifest),'sha256':before,'imported_entries':count})
   dump(Path(cache).parent/'seed-import.json',{'new_snapshot_id':store.id,'parents':parents,'parent_unchanged':True});return store
  def archives():
   result=original_archives()
   for p in (parent_artifacts/'wheelhouse').glob('*.whl'):result.setdefault(p.name,[]).append(p)
   return result
  def fetch(url,path,recorder):
   parent=parent_artifacts/path.relative_to(out/'cases'/name/'artifacts')
   if parent.exists():
    try:data=load(parent)
    except (ValueError,OSError):data=None
    if data is not None:
     path.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(parent,path)
     dump(path.with_suffix('.reused.json'),{'url':url,'parent':str(parent),'parent_sha256':digest(parent),'copied_sha256':digest(path),'fresh_observation':False});return data
   return original_fetch(url,path,recorder)
  class Recorder(OriginalRecorder):
   def command(self,argv,label,**kwargs):
    variant=label.removesuffix('-metadata-plan')
    proof=selected['successful_reports'].get(variant) if label.endswith('-metadata-plan') else None
    retained=selected['retained_variant_failures'].get(variant) if label.endswith('-metadata-plan') else None
    if retained:
     folder=self.directory/'commands'/label;folder.mkdir(parents=True,exist_ok=False)
     (folder/'stdout.txt').write_text('Retained original nonmechanical failure; no resolver invocation.\n');(folder/'stderr.txt').write_text('')
     dump(folder/'command.json',{'label':label,'executed':False,'exit':None,'retained_original_variant_failure':retained})
     raise base.CoverageLimit('retained_nonmechanical_original_variant_failure: '+variant)
    if proof:
     assert str(argv[-1])==proof['request'] and digest(Path(proof['report']))==proof['report_sha256']
     target=Path(argv[list(map(str,argv)).index('--report')+1]);target.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(proof['report'],target)
     folder=self.directory/'commands'/label;folder.mkdir(parents=True,exist_ok=False)
     (folder/'stdout.txt').write_text('Reused original successful raw metadata report; no resolver invocation.\n');(folder/'stderr.txt').write_text('')
     command={'label':label,'executed':False,'proposed_argv':list(map(str,argv)),'exit':None,'source_exit':0,'seconds':0,'reused_successful_original_report':proof}
     dump(folder/'command.json',command);self.commands.append(command);dump(self.directory/'commands.json',self.commands);return 0,'',''
    return super().command(argv,label,**kwargs)
  proxy.configure_snapshot=configure;base.existing_archives=archives;base.fetch_json=fetch;base.Recorder=Recorder
  base.artifact_worker(out,row)
 else:
  assert phase in selected['workflows_to_attempt']
  base.audit_files=audit_files;OriginalRecorder=base.Recorder
  class Recorder(OriginalRecorder):
   def command(self,argv,label,**kwargs):
    if phase=='relock' and label=='uv-before-relock':argv=[*argv,'--resolution','lowest']
    return super().command(argv,label,**kwargs)
  base.Recorder=Recorder;base.workflow_worker(out,row,phase)

def execute(out):
 protocol=load(out/'protocol.json');assert not(out/'run-started.json').exists()
 assert digest(Path(__file__))==protocol['script_sha256'] and digest(out/'cases.json')==protocol['cases_sha256']
 dump(out/'run-started.json',{'at_utc':now(),'protocol_sha256':digest(out/'protocol.json')})
 logs=out/'logs';logs.mkdir();rows=load(out/'cases.json')['recovery_cases'];completed=[]
 def package(selected):
  row=selected['row'];name=row['canonical_name']
  if not selected['eligible']:return {'name':name,'status':'not_eligible_for_preparation_recovery','original_artifact_status':selected['original_artifact_status'],'workflows':{}}
  if selected['registered_main_size_policy']['status']=='unsupported_registered_main_wheel_size':
   statuses={}
   for wf in selected['workflows_to_attempt']:
    target=out/'cases'/name/wf;target.mkdir(parents=True,exist_ok=False)
    dump(target/'results.json',{'name':name,'workflow':wf,'status':'unsupported_registered_main_wheel_size','executed':False,'reason':selected['registered_main_size_policy'],'stages':[],'confirmed_defects':0});statuses[wf]='unsupported_registered_main_wheel_size'
   return {'name':name,'status':'registered_resource_coverage_exclusion','workflows':statuses}
  statuses={}
  for phase in ('artifacts',*selected['workflows_to_attempt']):
   target=out/'cases'/name/phase;target.parent.mkdir(parents=True,exist_ok=True);log=logs/(name+'--'+phase+'.log')
   with log.open('w') as stream:
    p=subprocess.Popen([str(base.DRIVER),str(Path(__file__)),'--out',str(out),'--worker',name,'--phase',phase],stdout=stream,stderr=subprocess.STDOUT,start_new_session=True)
    try:p.wait(timeout=902)
    except subprocess.TimeoutExpired:os.killpg(p.pid,signal.SIGKILL);p.wait()
    finally:
     try:os.killpg(p.pid,signal.SIGKILL)
     except ProcessLookupError:pass
   if not(target/'results.json').exists():target.mkdir(parents=True,exist_ok=True);dump(target/'results.json',{'name':name,'workflow':phase,'status':'unknown_worker_or_budget','returncode':p.returncode,'log':str(log),'confirmed_defects':0})
   statuses[phase]=load(target/'results.json')['status']
  return {'name':name,'status':'bounded_preparation_recovery_finished','workflows':statuses}
 with ThreadPoolExecutor(max_workers=2) as pool:
  futures={pool.submit(package,r):r['row']['canonical_name'] for r in rows}
  for future in as_completed(futures):
   try:r=future.result()
   except Exception as error:r={'name':futures[future],'status':'unknown_controller','reason':str(error),'workflows':{}}
   completed.append(r);dump(out/'progress.json',{'finished_roots':len(completed),'roots':len(rows),'results':completed});print(json.dumps(r),flush=True)
 result={'schema':'stateful-artifact-preparation-recovery-summary-v1','finished_at_utc':now(),'protocol_sha256':digest(out/'protocol.json'),'results':completed,'original_data_preserved':True,
   'eligible_preparation_roots':protocol['eligible_preparation_roots'],'inputs_unchanged':all(digest(Path(p))==s for p,s in protocol['inputs'].items()),'core_unchanged':all(digest(ROOT/p)==s for p,s in protocol['core_hashes'].items()),'confirmed_defects':0}
 assert result['inputs_unchanged'] and result['core_unchanged'];dump(out/'summary.json',result)
def main():
 p=argparse.ArgumentParser();p.add_argument('--prepare',action='store_true');p.add_argument('--run',action='store_true');p.add_argument('--source-out',type=Path);p.add_argument('--partial-review',type=Path);p.add_argument('--interruption-record',type=Path);p.add_argument('--out',type=Path,required=True);p.add_argument('--worker');p.add_argument('--phase',choices=('artifacts',*base.WORKFLOWS));args=p.parse_args()
 if sys.platform!='linux' or sys.version_info[:3]!=(3,11,16):p.error('Use the fixed native Linux CPython3.11.16 driver.')
 if args.prepare:prepare(args)
 elif args.worker:worker(args.out.resolve(),args.worker,args.phase)
 elif args.run:execute(args.out.resolve())
 else:p.error('Choose --prepare or --run')
if __name__=='__main__':main()
