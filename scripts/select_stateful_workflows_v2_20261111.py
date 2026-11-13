"""Freeze the existing official main-distribution union, then select honest workflows."""
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime,timezone
import hashlib
import json
from pathlib import Path
import subprocess
import re
import urllib.request
import urllib.error
from packaging.markers import default_environment
from packaging.requirements import Requirement
from packaging.specifiers import SpecifierSet
from packaging.utils import canonicalize_name,parse_wheel_filename
from packaging.version import Version,InvalidVersion

ROOT=Path(__file__).resolve().parents[1]
OUT=ROOT/'work/stateful-validation-20261111'
INPUTS={
 'new30':ROOT/'work/expanded-validation-20261111/new-packages/distribution-selection.json',
 'foundational20':ROOT/'work/expanded-validation-20261111/foundational-installs/selection.json',
 'published20':ROOT/'work/fp-fixes-20261110/expanded/published/selection.json'}
RUNTIMES={'3.10.21':'runtime-linux-310-1111','3.11.16':'runtime-linux','3.12.14':'runtime-linux-312-1111','3.14.4':'runtime-linux-314'}
EXCLUDE_TOKENS={'all','full','complete','qa','dev','develop','development','test','tests','testing','doc','docs','documentation','benchmark','benchmarks','bench','lint','linting','typing','typecheck','typechecking','ci','build','release','format','formatting','coverage','check','checks'}
def now():return datetime.now(timezone.utc).isoformat()
def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()
def rel(path):return path.relative_to(ROOT).as_posix()
def dump(path,data):
 path.parent.mkdir(parents=True,exist_ok=True);path.write_text(json.dumps(data,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
def read(path):return json.loads(path.read_text())
def pypi_source(row):
 return ROOT/str(row.get('pypi_json_path') or row.get('pypi_json')).replace('\\','/')
def prepare():
 if (OUT/'cohort.json').exists():raise SystemExit('Cohort already frozen')
 OUT.mkdir(parents=True,exist_ok=True)
 protocol={'schema':'stateful-workflow-selection-protocol-v1','registered_at_utc':now(),'script_sha256':sha(Path(__file__)),
  'input_selections':{k:{'path':rel(p),'sha256':sha(p)} for k,p in INPUTS.items()},
  'cohort':'Union of new30 verified22, foundational20 importance+correspondence verified19, priorpublished20 verified12. Deduplicate canonical_name plus exact PEP440-equivalent fixed pin; preserve every repository/candidate-slot provenance. No latest refresh or substitution. Unmapped16 repository slots and excluded foundational build remain explicit coverage.',
  'target':'For roots in foundational19 preserve that layer prior registered311-or314 runtime. Others first available compatible fixed native target in311.16,312.14,314.4,310.21 order. Full marker environments and native wheel tags captured before workflow selection. Current release must permit target; otherwise retain unsupported.',
  'update_predecessor':'Use only the already frozen full-project PyPI JSON releases catalogue. Same epoch and first2 zero-padded release components (major.minor), greatest PEP440 version strictly below frozen current pin, stable (not prerelease/dev), not fully yanked, with at least one unyanked target-native-compatible wheel whose file Requires-Python allows this same native target. No cross-minor fallback. Calendar/single-component versions without a predecessor in this line remain unsupported. Capture exact selected predecessor /pypi/name/version/json only after these rules freeze.',
  'update_compatibility':'Predecessor version-specific Requires-Python must allow same registered native target; frozen catalogue compatible wheel must remain present with matching URL/SHA in exact-version JSON. Failure is unsupported evidence; do not replace with another result-selected predecessor.',
  'extras':'Use published Provides-Extra from frozen current PyPI info.provides_extra. Normalize with canonicalize_name. Exclude names with hyphen-separated tokens in fixed excluded set. Sort remaining normalized extras lexicographically; choose first with >=1 additional marker-active direct requirement identity on full registered native environment versus base. Requirement identity=(canonical name, extras, specifier, URL); omit marker after evaluating it. Empty/inactive extras are skipped with explicit reason. No resolver result influences extra choice.',
  'excluded_extra_tokens':sorted(EXCLUDE_TOKENS),
  'extras_workflow':'Base→one selected published runtime extra→base under exact same package pin; record actual existing state. Extra removal residual packages under ordinary pip install are not automatically defects; strict sync semantics must be distinguished.',
  'relock':'Exact fixed current main pin, declared target, original source policy and complete selected request. Resolver operation/upgrade flags explicit; no requirement weakening or hidden synthesis reported as the official repository install path.',
  'source_switch':'Separate source agent accepts only inspectable official project instructions and actual alternate artifact/index/source binding for this frozen public release. Exact local versions are distinct and must be recorded; no modified metadata/repacked wheels/local synthetic registry counts as real project impact. Absence of supported official alternate preserved.',
  'measurement':'Selection only; installer agents separately freeze executable/runtimes/budget/cache/isolation protocols. Native artifact support and all heavy closure/timeouts remain coverage; never silently trim requested extras or dependencies.',
  'admission':'Differences in valid versions, stale optional packages, minimum-change behavior and planned candidate sets are not automatically bugs. Check actual installed own METADATA active closures/root+extras/source contracts; preserve unknowns. No precision/recall without truth labels.'}
 dump(OUT/'protocol.json',protocol)
 profiles={}
 for version,directory in RUNTIMES.items():
  executable=ROOT/'work'/directory/'bin/python'
  code='import json,sys;from packaging.markers import default_environment;from packaging.tags import sys_tags;print(json.dumps(dict(executable=sys.executable,version=sys.version,environment=default_environment(),wheel_tags=[str(t) for t in sys_tags()])))'
  p=subprocess.run([str(executable),'-c',code],capture_output=True,text=True,check=True,timeout=30)
  data=json.loads(p.stdout);assert data['environment']['python_full_version']==version
  profiles[version]={**data,'executable_sha256':sha(executable.resolve())}
 dump(OUT/'native-profiles.json',profiles)
 roots={};coverage=[]
 for group,input_path in INPUTS.items():
  for source in read(input_path)['projects']:
   eligible=(source.get('correspondence_status')=='verified') if group!='foundational20' else source.get('importance_verified') and source.get('correspondence_verified')
   provenance={'input_group':group,'input_selection':rel(input_path),'input_selection_sha256':sha(input_path),'repository':source.get('repo') or 'github.com/'+source['official_repository'],
      'repository_commit':source.get('repo_commit'),'source_slot':source.get('repo_key') or source.get('canonical_name'),'prior_measurement_status':source.get('measurement_status')}
   if not eligible:
    coverage.append({**provenance,'canonical_name':source.get('canonical_name'),'included':False,'reason':source.get('unsupported_reason') or source.get('reason') or ('importance_not_verified' if group=='foundational20' else 'official_primary_distribution_not_verified')});continue
   name=canonicalize_name(source['canonical_name']);version=source['version'];key=(name,str(Version(version)));path=pypi_source(source)
   expected=source.get('pypi_json_sha256') or source.get('pypi_sha256');assert sha(path)==expected
   data=read(path);assert canonicalize_name(data['info']['name'])==name and Version(data['info']['version'])==Version(version)
   provenance.update(pypi_json_path=rel(path),pypi_json_sha256=expected)
   if key not in roots:
    roots[key]={'canonical_name':name,'version':version,'request':name+'=='+version,'requires_python':source.get('requires_python') or data['info'].get('requires_python') or '',
       'provenance':[],'repositories':[],'pypi_json_path':rel(path),'pypi_json_sha256':expected,'target_python':None}
   root=roots[key];root['provenance'].append(provenance)
   if provenance['repository'] not in root['repositories']:root['repositories'].append(provenance['repository'])
   if group=='foundational20':
    summary=read(ROOT/'work/expanded-validation-20261111/foundational-installs/runs'/name/'summary.json')
    runtime=summary['runtime'];target='3.14.4' if 'runtime-linux-314' in runtime else '3.11.16'
    root['target_python']=target;root['target_basis']='Preserved foundational layer registered runtime; no result-based target substitution.'
 for root in roots.values():
  if root['target_python'] is None:
   root['target_python']=next((v for v in ('3.11.16','3.12.14','3.14.4','3.10.21') if SpecifierSet(root['requires_python']).contains(v,prereleases=True)),None)
   root['target_basis']='First compatible native runtime in preregistered order.'
  target=root['target_python'];assert target is None or SpecifierSet(root['requires_python']).contains(target,prereleases=True)
  if target:root['runtime']=profiles[target]['executable'];root['marker_environment']=profiles[target]['environment']
  root['unit']='canonical distribution name plus fixed public version; package roots are not repository installations'
 rows=sorted(roots.values(),key=lambda r:(r['canonical_name'],Version(r['version'])))
 assert len(rows)==52 and len(coverage)==17
 result={'schema':'stateful-fixed-primary-distribution-cohort-v1','frozen_at_utc':now(),'protocol_sha256':sha(OUT/'protocol.json'),'native_profiles_sha256':sha(OUT/'native-profiles.json'),
  'root_count':len(rows),'included_original_slots':sum(len(r['provenance']) for r in rows),'unique_repositories':len({repo for r in rows for repo in r['repositories']}),
  'deduplication':'Same canonical name+fixed equivalent version merged; numpy2.5.4 appears in new30 and foundational20 and remains one root with2provenances.',
  'roots':rows,'excluded_coverage_slots':coverage}
 dump(OUT/'cohort.json',result)
 print('COHORT',sha(OUT/'cohort.json'),len(rows),flush=True)

def native_wheel(file,root,tags):
 if file.get('yanked') or file.get('packagetype')!='bdist_wheel':return False
 if not SpecifierSet(file.get('requires_python') or '').contains(root['target_python'],prereleases=True):return False
 try:return bool({str(t) for t in parse_wheel_filename(file['filename'])[3]} & tags)
 except ValueError:return False
def active_dependencies(raw,environment,extra):
 result=[]
 for value in raw or []:
  req=Requirement(value)
  if req.marker and not req.marker.evaluate({**environment,'extra':extra}):continue
  identity=(canonicalize_name(req.name),tuple(sorted(req.extras)),str(req.specifier),req.url)
  result.append({'raw':value,'identity':list(identity),'name':canonicalize_name(req.name),'extras':sorted(req.extras),'specifier':str(req.specifier),'url':req.url})
 return result
def exact_capture(name,version):
 path=OUT/'sources/predecessors'/f'{name}--{version}.json'
 if path.exists():return path,read(path.with_suffix('.capture.json'))
 url=f'https://pypi.org/pypi/{name}/{version}/json';errors=[];raw=b'';status=None
 for attempt in range(3):
  try:
   with urllib.request.urlopen(urllib.request.Request(url,headers={'User-Agent':'DRC-stateful-release-metadata/1'}),timeout=45) as r:raw=r.read();status=r.status
   break
  except urllib.error.HTTPError as e:status=e.code;raw=e.read();errors.append(str(e));
  except Exception as e:errors.append(type(e).__name__+': '+str(e))
 path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(raw)
 capture={'url':url,'captured_at_utc':now(),'http_status':status,'errors':errors,'sha256':sha(path),'bytes':len(raw)}
 dump(path.with_suffix('.capture.json'),capture);return path,capture
def select_root(root,profiles):
 data=read(ROOT/root['pypi_json_path']);assert sha(ROOT/root['pypi_json_path'])==root['pypi_json_sha256']
 current=Version(root['version']);target=root['target_python'];row={'canonical_name':root['canonical_name'],'version':root['version'],'request':root['request'],'target_python':target,'runtime':root.get('runtime'),'repositories':root['repositories']}
 if target is None:row.update(update={'status':'unsupported_target'},extras={'status':'unsupported_target'},relock={'status':'unsupported_target'},source={'status':'requires_official_source_agent_selection'});return row
 tags=set(profiles[target]['wheel_tags']);line=tuple((list(current.release)+[0,0])[:2]);candidates=[]
 for value,files in data['releases'].items():
  try:v=Version(value)
  except InvalidVersion:continue
  if v>=current or v.is_prerelease or v.is_devrelease or v.epoch!=current.epoch :continue
  matching=[f for f in files if native_wheel(f,root,tags)]
  if matching:candidates.append((v,value,matching))
 if not candidates:row['update']={'status':'unsupported_no_prior_compatible_stable_release','current_major_minor':list(line),'reason':'No earlier stable unyanked release with a target-native compatible wheel in the frozen catalogue; no outcome-driven substitution.'}
 else:
  _,version,files=max(candidates,key=lambda x:x[0]);path,capture=exact_capture(root['canonical_name'],version)
  selected={'status':'selected','from_version':version,'to_version':root['version'],'from_request':root['canonical_name']+'=='+version,'to_request':root['request'],'current_major_minor':list(line),
    'version_json_path':rel(path),'version_json_sha256':sha(path),'capture':capture,
    'frozen_catalogue_native_files':[{'filename':f['filename'],'url':f['url'],'sha256':f['digests']['sha256']} for f in files]}
  if capture['http_status']!=200:selected.update(status='unsupported_predecessor_metadata_capture')
  else:
   old=read(path);info=old['info'];rp=info.get('requires_python') or ''
   selected['requires_python']=rp
   exact={(f['url'],f['digests']['sha256']) for f in old['urls']}
   if canonicalize_name(info['name'])!=root['canonical_name'] or Version(info['version'])!=Version(version) or not SpecifierSet(rp).contains(target,prereleases=True):selected.update(status='unsupported_predecessor_identity_or_python')
   elif not any((f['url'],f['digests']['sha256']) in exact for f in files):selected.update(status='unsupported_predecessor_catalogue_binding_changed')
  row['update']=selected
 base=active_dependencies(data['info'].get('requires_dist'),root['marker_environment'],'');basekeys={str(v['identity']) for v in base};decisions=[];eligible=[]
 extras=sorted({canonicalize_name(e) for e in data['info'].get('provides_extra') or []})
 for extra in extras:
  if set(extra.split('-')) & EXCLUDE_TOKENS:decisions.append({'extra':extra,'decision':'excluded_development_tooling_or_aggregate_bundle_name'});continue
  active=active_dependencies(data['info'].get('requires_dist'),root['marker_environment'],extra)
  added=[v for v in active if str(v['identity']) not in basekeys]
  if not added:decisions.append({'extra':extra,'decision':'skip_no_additional_active_runtime_constraint'});continue
  eligible.append((len(added),extra,active,added))
 if eligible:
  count,extra,active,added=min(eligible,key=lambda item:(item[0],item[1]))
  row['extras']={'status':'selected','extra':extra,'base_request':root['request'],'extra_request':root['canonical_name']+'['+extra+']=='+root['version'],
   'base_active_requirements':base,'extra_active_requirements':active,'additional_active_requirements':added,'additional_active_count':count}
  decisions.extend({'extra':e,'additional_active_count':n,'decision':'selected_minimum_additional_active_constraints_lexicographic_tie' if e==extra else 'eligible_not_selected'} for n,e,_,_ in eligible)
 else:row['extras']={'status':'unsupported_no_eligible_runtime_extra','base_active_requirements':base}
 row['extras']['published_extras']=extras;row['extras']['selection_decisions']=decisions
 row['relock']={'status':'selected','request':root['request'],'source':'public PyPI fixed pin','scope':'Explicit controlled project request, not repo HEAD install.'}
 row['source']={'status':'pending_official_source_agent_selection','rule':'Only official documented actual source bindings; no modified/repacked metadata.'}
 print(root['canonical_name'],row['update']['status'],row['extras'].get('extra',row['extras']['status']),flush=True)
 return row
def select():
 if (OUT/'workflow-selection-v2.json').exists():raise SystemExit('Workflow selection frozen')
 cohort=read(OUT/'cohort.json');profiles=read(OUT/'native-profiles.json');assert cohort['protocol_sha256']==sha(OUT/'protocol.json')
 with ThreadPoolExecutor(max_workers=4) as pool:rows=list(pool.map(lambda r:select_root(r,profiles),cohort['roots']))
 dump(OUT/'workflow-selection-v2.json',{'schema':'stateful-workflow-selection-v2','frozen_at_utc':now(),'selection_addendum_sha256':sha(OUT/'protocol-v2-addendum.json'),'cohort_sha256':sha(OUT/'cohort.json'),'protocol_sha256':sha(OUT/'protocol.json'),'native_profiles_sha256':sha(OUT/'native-profiles.json'),'roots':rows,
   'source_workflow_note':'Source agent publishes a separate immutable source selection before its own source-switch execution; pending does not mean supported.'})
 print('WORKFLOWS',sha(OUT/'workflow-selection-v2.json'),flush=True)
if __name__=='__main__':
 addendum=OUT/'protocol-v2-addendum.json'
 if addendum.exists():raise SystemExit('v2 addendum already frozen; do not overwrite')
 dump(addendum,{'schema':'stateful-workflow-selection-addendum-v2','registered_at_utc':now(),'before_any_workflow_installation':True,
   'original_protocol_sha256':sha(OUT/'protocol.json'),'original_workflow_selection_sha256':sha(OUT/'workflow-selection.json'),
   'cohort_sha256':sha(OUT/'cohort.json'),'new_script_sha256':sha(Path(__file__)),
   'reason':'Latest parent task specifies previous compatible stable release. Avoid deliberately making pip/no-same-minor-patch updates no-ops; preserve old selection and strengthen transparent runtime-extra selection before installer outcomes.',
   'update':'Greatest PEP440 version below fixed current pin from frozen full-project JSON releases, stable/non-yanked and native-compatible wheel; major/minor crossing permitted, epoch must match. Exact predecessor JSON captured and bound; no current-pin refresh or downgrade and no result-driven substitution.',
   'extras':'Published runtime extra with smallest positive count of additional marker-active direct requirement identities; normalized-extra lexicographic tie. Exclude original tooling tokens plus qa/all/full/complete aggregate bundle names. Static target-environment declarations only; no attempt to guess satisfiability or result-based replacement.',
   'execution_assignment':'Foundation19 by pipeline; other33 unique official distribution roots by rounds; build plus16unmapped repo slots remain explicit coverage. Source-switch independent official-source agent.'})
 select()
