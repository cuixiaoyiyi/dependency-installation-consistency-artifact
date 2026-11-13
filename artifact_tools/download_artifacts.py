"""List or download recorded wheel archives and check their recorded SHA-256."""
from __future__ import annotations
import argparse,hashlib,json,urllib.request
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
def file_sha(path):
    h=hashlib.sha256()
    with path.open('rb') as f:
        for b in iter(lambda:f.read(1024*1024),b''):h.update(b)
    return h.hexdigest()
def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--manifest',type=Path,default=ROOT/'inputs/artifacts.json');p.add_argument('--out',type=Path,default=ROOT/'downloads');p.add_argument('--limit',type=int);p.add_argument('--execute',action='store_true');p.add_argument('--max-mib',type=int,default=500);args=p.parse_args()
    rows=json.loads(args.manifest.read_text(encoding='utf-8'))['artifacts']
    if args.limit is not None:rows=rows[:args.limit]
    if not args.execute:
        print(json.dumps({'mode':'preview','archive_identities':len(rows),'out':str(args.out),'first_records':rows[:3]},indent=2));return
    args.out.mkdir(parents=True,exist_ok=True)
    for row in rows:
        filename=Path(row['filename']).name
        if not filename.endswith('.whl') or not row['url'].startswith('https://'):raise ValueError('Unexpected archive identity')
        target=args.out/(row['sha256'][:16]+'-'+filename)
        if target.exists():
            if file_sha(target)!=row['sha256']:raise FileExistsError('Different existing file: '+str(target))
            continue
        temp=target.with_suffix(target.suffix+'.part');total=0;h=hashlib.sha256()
        try:
            with urllib.request.urlopen(row['url'],timeout=90) as response,temp.open('xb') as f:
                length=response.headers.get('Content-Length')
                if length and int(length)>args.max_mib*1024*1024:raise ValueError('Archive exceeds --max-mib')
                for b in iter(lambda:response.read(1024*1024),b''):
                    total+=len(b)
                    if total>args.max_mib*1024*1024:raise ValueError('Archive exceeds --max-mib')
                    h.update(b);f.write(b)
            if h.hexdigest()!=row['sha256']:raise ValueError('SHA-256 mismatch for '+filename)
            temp.replace(target)
        except Exception:
            if temp.is_file():temp.unlink()
            raise
        print(json.dumps({'file':str(target),'bytes':total,'sha256':row['sha256']}),flush=True)
if __name__=='__main__':main()
