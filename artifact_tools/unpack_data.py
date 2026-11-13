"""Restore saved evidence to its original relative paths."""
from __future__ import annotations
import argparse,hashlib,json,os,tarfile
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
def filesystem_path(path):
    text=str(path)
    if os.name=='nt' and not text.startswith('\\\\?\\'):
        if text.startswith('\\\\'):return Path('\\\\?\\UNC\\'+text[2:])
        return Path('\\\\?\\'+text)
    return path
def digest(path):
    h=hashlib.sha256()
    with path.open('rb') as f:
        for chunk in iter(lambda:f.read(1024*1024),b''):h.update(chunk)
    return h.hexdigest()
def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--destination',type=Path,default=ROOT);args=parser.parse_args();dest=args.destination.resolve();dest.mkdir(parents=True,exist_ok=True)
    index=json.loads((ROOT/'data/evidence-index.json').read_text(encoding='utf-8'))
    expected={e['path']:e for e in index['files'] if e.get('archive')};count=0
    for archive in index['archives']:
        with tarfile.open(ROOT/archive['path'],'r|gz') as bundle:
            for member in bundle:
                record=expected.get(member.name);target=(dest/member.name).resolve()
                if not member.isfile() or record is None or record['archive']!=archive['path'] or not target.is_relative_to(dest) or '.git' in target.relative_to(dest).parts:raise ValueError('Invalid archive member')
                io_target=filesystem_path(target)
                if io_target.exists():
                    if not io_target.is_file() or digest(io_target)!=record['sha256']:raise FileExistsError('Existing different file: '+str(target))
                    continue
                io_target.parent.mkdir(parents=True,exist_ok=True)
                h=hashlib.sha256();source=bundle.extractfile(member)
                temporary=io_target.with_name(io_target.name+'.extracting')
                with temporary.open('xb') as f:
                    for block in iter(lambda:source.read(1024*1024),b''):h.update(block);f.write(block)
                if h.hexdigest()!=record['sha256']:raise ValueError('Archive member hash mismatch: '+member.name)
                temporary.replace(io_target);count+=1
        print(json.dumps({'archive':archive['path'],'restored':count}),flush=True)
    print(json.dumps({'status':'passed','destination':str(dest),'restored':count}))
if __name__=='__main__':main()
