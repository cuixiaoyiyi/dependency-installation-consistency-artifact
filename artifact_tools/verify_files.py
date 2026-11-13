"""Verify repository files and the original members in evidence archives."""
from __future__ import annotations
import argparse,hashlib,json,tarfile
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
def sha(stream):
    h=hashlib.sha256()
    for chunk in iter(lambda:stream.read(1024*1024),b''):h.update(chunk)
    return h.hexdigest()
def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--quick',action='store_true');args=p.parse_args()
    with (ROOT/'manifest.json').open('rb') as f: manifest_sha=sha(f)
    if manifest_sha!=(ROOT/'manifest.sha256').read_text(encoding='ascii').split()[0]:raise ValueError('Manifest hash mismatch')
    manifest=json.loads((ROOT/'manifest.json').read_text(encoding='utf-8'));failures=[]
    for entry in manifest['files']:
        path=ROOT/entry['path']
        if not path.is_file():failures.append({'path':entry['path'],'error':'missing'});continue
        with path.open('rb') as f: actual=sha(f)
        if actual!=entry['sha256']: failures.append({'path':entry['path'],'error':'hash mismatch'})
    members=0
    if not args.quick:
        index=json.loads((ROOT/'data/evidence-index.json').read_text(encoding='utf-8'))
        expected={e['path']:e for e in index['files'] if e.get('archive')}
        seen=set()
        for archive in index['archives']:
            with tarfile.open(ROOT/archive['path'],'r|gz') as bundle:
                for member in bundle:
                    entry=expected.get(member.name)
                    if not member.isfile() or entry is None or entry['archive']!=archive['path'] or member.name in seen:
                        failures.append({'path':member.name,'error':'unexpected archive member'});continue
                    seen.add(member.name)
                    f=bundle.extractfile(member)
                    if member.size!=entry['bytes'] or sha(f)!=entry['sha256']:failures.append({'path':member.name,'error':'archive content mismatch'})
                    members+=1
            print(json.dumps({'archive':archive['path'],'checked_members':members}),flush=True)
        failures += [{'path':x,'error':'archive member missing'} for x in sorted(set(expected)-seen)]
    result={'status':'passed' if not failures else 'failed','repository_files':len(manifest['files']),'archive_members':members,'failures':failures}
    print(json.dumps(result,indent=2));raise SystemExit(bool(failures))
if __name__=='__main__':main()
