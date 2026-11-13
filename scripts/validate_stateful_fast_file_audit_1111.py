"""Compare optimized audit with already-recorded full audits of quiescent real installs."""
from datetime import datetime,timezone
import hashlib
import json
from pathlib import Path
import sys
import time
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from scripts.stateful_fast_file_audit_1111 import audit_files,StableEnvironmentPaths
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def read(p):return json.loads(p.read_text())
def main():
 out=ROOT/'work/stateful-workflows-20261111/review/fast-audit-real-equivalence-rounds'
 out.mkdir(parents=True,exist_ok=False);rows=[]
 for name in ('requests','httpx'):
  for workflow in ('update','extras'):
   base=ROOT/'work/stateful-workflows-20261111/foundational/cases'/name
   stage=base/workflow/'stages/uv-fresh-final-lock';inventory=read(stage/'installed.json');wheels=read(base/'artifacts/wheel-manifest.json')
   result=read(base/workflow/'results.json');assert result['status']=='completed_actual_stateful_workflow'
   envdir=Path(inventory['executable']).parent.parent;hashes={}
   for dist in inventory['installed']:
    for filename in ('METADATA','RECORD'):
     live=Path(dist['dist_info'])/filename;stored=stage/'metadata'/dist['name'].lower().replace('_','-')/filename
     assert sha(live)==sha(stored);hashes[str(live)]=sha(live)
   started=time.monotonic();actual=audit_files(inventory,wheels,envdir);elapsed=time.monotonic()-started
   expected=read(stage/'file-audit.json');assert actual==expected,(name,workflow,'full audit result differs')
   assert all(sha(Path(p))==s for p,s in hashes.items())
   resolver=StableEnvironmentPaths(envdir);path_checks=[]
   for dist in inventory['installed']:
    info=Path(dist['dist_info']);values=[info/'METADATA',info/'RECORD',info.parent/'../../../bin/python']
    for p in values:
     plain=p.resolve();fast=resolver.resolve(p);assert plain==fast
     path_checks.append({'path':str(p),'original_resolved':str(plain),'fast_resolved':str(fast)})
   label=name+'--'+workflow;(out/(label+'.json')).write_text(json.dumps(actual,indent=2)+'\n')
   rows.append({'name':name,'workflow':workflow,'seconds_fast':round(elapsed,3),'installed_distributions':len(inventory['installed']),
     'unique_installed_files_hashed':actual['unique_installed_files_hashed'],'full_result_equal_to_original_recorded_audit':True,
     'live_metadata_and_record_equal_stage_copies_before_after':True,'source_inventory':str(stage/'installed.json'),'source_inventory_sha256':sha(stage/'installed.json'),
     'original_audit_sha256':sha(stage/'file-audit.json'),'fast_audit_sha256':sha(out/(label+'.json')),'resolved_path_checks':path_checks})
 report={'schema':'stateful-fast-audit-real-equivalence-v1','checked_at_utc':datetime.now(timezone.utc).isoformat(),
  'fast_helper_sha256':sha(ROOT/'scripts/stateful_fast_file_audit_1111.py'),'frozen_original_helper_sha256':sha(ROOT/'scripts/stateful_real_workflows_1111.py'),
  'all_four_real_full_audit_objects_equal':True,'real_final_environments_quiescent':True,'rows':rows,
  'scope':'Existing completed final fresh environments only. No installer or wheel/source mutation. Compare all original audit fields, not only counts; independently compare representative Path.resolve outputs.'}
 (out/'summary.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps({k:v for k,v in report.items() if k!='rows'}));print([(r['name'],r['workflow'],r['seconds_fast'],r['unique_installed_files_hashed']) for r in rows])
if __name__=='__main__':main()
