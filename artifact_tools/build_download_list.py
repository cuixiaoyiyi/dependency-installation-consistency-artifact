"""Extract recorded wheel identities from the supplied preparation records."""
from __future__ import annotations
import argparse,json,tarfile
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
def selected(name):
    p=Path(name)
    return name.endswith('.json') and (p.name in {'wheel-manifest.json','artifact-original-metadata.json','artifacts.json'} or '/preparation/' in name)
def collect(value,source,records):
    if isinstance(value,dict):
        url=value.get('url') or value.get('download_url')
        digests=value.get('digests');digests=digests if isinstance(digests,dict) else {}
        digest=value.get('sha256') or digests.get('sha256') or value.get('hash')
        if isinstance(digest,str):digest=digest.removeprefix('sha256:')
        if isinstance(url,str) and url.startswith('https://') and '.whl' in url and isinstance(digest,str) and len(digest)==64:
            item=records.setdefault((url,digest),{'url':url,'sha256':digest,'filename':value.get('filename') or url.split('?')[0].rsplit('/',1)[-1],'records':[]})
            for key in ['name','version','bytes']:
                if key in value and isinstance(value[key],(str,int)):item[key]=value[key]
            if source not in item['records']:item['records'].append(source)
        for key,child in value.items():
            if key!='payload':collect(child,source,records)
    elif isinstance(value,list):
        for child in value:collect(child,source,records)
def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--out',type=Path,default=ROOT/'runs/artifacts.json');p.add_argument('--source-root',type=Path);args=p.parse_args()
    index=json.loads((ROOT/'data/evidence-index.json').read_text(encoding='utf-8'));wanted={x['path']:x for x in index['files'] if selected(x['path'])};records={};seen=set()
    if args.source_root:
        for name in wanted:
            collect(json.loads((args.source_root/name).read_text(encoding='utf-8-sig')),name,records);seen.add(name)
    else:
        for name,item in wanted.items():
            if not item.get('archive'):
                collect(json.loads((ROOT/name).read_text(encoding='utf-8-sig')),name,records);seen.add(name)
        for archive in index['archives']:
            with tarfile.open(ROOT/archive['path'],'r|gz') as bundle:
                for member in bundle:
                    if member.name in wanted:
                        collect(json.load(bundle.extractfile(member)),member.name,records);seen.add(member.name)
    assert seen==set(wanted)
    output={'scope':'Wheel identities appearing in saved native preparation and artifact records; this list does not assert an additional installation or include the entire public index.','source_records':len(seen),'artifacts':sorted(records.values(),key=lambda r:(r['filename'],r['sha256']))}
    args.out.parent.mkdir(parents=True,exist_ok=True);args.out.write_text(json.dumps(output,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    print(json.dumps({'out':str(args.out),'source_records':len(seen),'archive_identities':len(records)}))
if __name__=='__main__':main()
