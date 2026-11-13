"""Same-version source rebind with different dependencies: inert local wheels only."""
from __future__ import annotations

import argparse
import base64
from contextlib import ExitStack, contextmanager
from datetime import datetime, timezone
from email.parser import BytesParser
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import io
import json
import os
from pathlib import Path
import platform
import shlex
import subprocess
import sys
import threading
import tomllib
from urllib.parse import urlsplit
import zipfile

PROBE = 'warm-closure-probe'


def canonicalize_name(name):
    # All fixture names are fixed lower-case ASCII with '-' separators.
    return name.lower().replace('_', '-')


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def wheel(name, origin, requirements=()):
    filename = name.replace('-', '_') + '-1.0-py3-none-any.whl'
    prefix = name.replace('-', '_') + '-1.0.dist-info/'
    metadata = ('Metadata-Version: 2.3\nName: ' + name + '\nVersion: 1.0\nRequires-Python: >=3.11\nX-Repro-Origin: ' + origin + '\n' + ''.join('Requires-Dist: ' + req + '\n' for req in requirements) + '\n').encode()
    files = {prefix + 'METADATA': metadata, prefix + 'WHEEL': b'Wheel-Version: 1.0\nGenerator: inert-closure-repro\nRoot-Is-Purelib: true\nTag: py3-none-any\n'}
    records = [f"{name},sha256={base64.urlsafe_b64encode(hashlib.sha256(raw).digest()).decode().rstrip('=')},{len(raw)}" for name, raw in files.items()]
    files[prefix + 'RECORD'] = ('\n'.join(records + [prefix + 'RECORD,,']) + '\n').encode()
    output = io.BytesIO()
    with zipfile.ZipFile(output, 'w') as archive:
        for member, raw in files.items():
            info = zipfile.ZipInfo(member, (2020, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(info, raw)
    return {'name': name, 'filename': filename, 'body': output.getvalue(), 'metadata': metadata, 'sha256': sha(output.getvalue()), 'metadata_sha256': sha(metadata), 'requirements': list(requirements), 'origin': origin}


@contextmanager
def server(label, distributions, events):
    by_name = {item['name']: item for item in distributions}
    by_file = {f'/{label}/files/{item["filename"]}': item for item in distributions}

    class Handler(BaseHTTPRequestHandler):
        def respond(self, head=False):
            path = urlsplit(self.path).path.rstrip('/')
            item = by_file.get(path)
            if item:
                status, body, mime = 200, item['body'], 'application/octet-stream'
            elif path.startswith(f'/{label}/simple/') and path.rsplit('/', 1)[-1] in by_name:
                item = by_name[path.rsplit('/', 1)[-1]]
                body = f'<a href="/{label}/files/{item["filename"]}#sha256={item["sha256"]}">{item["filename"]}</a>'.encode()
                status, mime = 200, 'text/html'
            else:
                status, body, mime = 404, b'', 'text/plain'
            self.send_response(status)
            self.send_header('Content-Type', mime)
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            if not head:
                self.wfile.write(body)
            events.append({'method': 'HEAD' if head else 'GET', 'path': path, 'port': self.server.server_port, 'status': status, 'response_sha256': sha(body), 'bytes': len(body), 'body_written': not head, 'range_requested': self.headers.get('Range')})

        def do_GET(self): self.respond()
        def do_HEAD(self): self.respond(True)
        def log_message(self, *args): pass

    instance = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    thread = threading.Thread(target=instance.serve_forever, kwargs={'poll_interval': .05}, daemon=True)
    thread.start()
    try:
        yield f'http://127.0.0.1:{instance.server_port}/{label}/simple/'
    finally:
        instance.shutdown()
        instance.server_close()
        thread.join()


def manifest(source, indexes):
    return f'''[project]
name = "warm-closure-control"
version = "0.0.1"
requires-python = ">=3.11"
dependencies = ["{PROBE}==1.0"]

[tool.uv.sources]
{PROBE} = {{ index = "{source}" }}

[[tool.uv.index]]
name = "old"
url = "{indexes['old']}"
explicit = true

[[tool.uv.index]]
name = "new"
url = "{indexes['new']}"
default = true
'''


COLLECT = '''import base64,csv,hashlib,importlib.metadata as m,json,os,pathlib,platform,sys
env={"implementation_name":sys.implementation.name,"implementation_version":platform.python_version(),"os_name":os.name,"platform_machine":platform.machine(),"platform_release":platform.release(),"platform_system":platform.system(),"platform_version":platform.version(),"python_full_version":platform.python_version(),"platform_python_implementation":platform.python_implementation(),"python_version":".".join(platform.python_version_tuple()[:2]),"sys_platform":sys.platform}
out=pathlib.Path(sys.argv[1]);rows=[]
for d in m.distributions():
 p=pathlib.Path(d._path);raw=(p/"METADATA").read_bytes();rec=(p/"RECORD").read_bytes();bad=[];count=0
 for f,h,s in csv.reader(rec.decode().splitlines()):
  if h:
   algo,expected=h.split("=",1);file=pathlib.Path(d.locate_file(f));actual=base64.urlsafe_b64encode(hashlib.new(algo,file.read_bytes()).digest()).decode().rstrip("=");count+=1
   if expected!=actual or(s and file.stat().st_size!=int(s)):bad.append(f)
 (out/(d.metadata["Name"]+".METADATA")).write_bytes(raw)
 rows.append({"name":d.metadata["Name"],"version":d.version,"requires_dist":d.metadata.get_all("Requires-Dist",[]),"origin":d.metadata.get("X-Repro-Origin"),"metadata_sha256":hashlib.sha256(raw).hexdigest(),"record_sha256":hashlib.sha256(rec).hexdigest(),"record_files_checked":count,"record_mismatches":bad})
print(json.dumps({"environment":env,"executable":sys.executable,"installed":rows}))
'''


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--uv', required=True, type=Path)
    parser.add_argument('--out', required=True, type=Path)
    args = parser.parse_args()
    uv = args.uv.resolve(strict=True)
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=False)
    project = out / 'project'
    project.mkdir()
    fixtures = {'old': wheel(PROBE, 'old', ['old-dep==1.0']), 'new': wheel(PROBE, 'new', ['new-dep==1.0']), 'old-dep': wheel('old-dep', 'dependency-old'), 'new-dep': wheel('new-dep', 'dependency-new')}
    for key, item in fixtures.items():
        directory = out / 'fixtures' / key
        directory.mkdir(parents=True)
        (directory / item['filename']).write_bytes(item['body'])
        (directory / 'METADATA').write_bytes(item['metadata'])
    events, steps = [], []
    version = subprocess.run([str(uv), '--version'], check=True, text=True, capture_output=True).stdout.strip()

    def execute(argv, folder, label, env):
        result = subprocess.run(list(map(str, argv)), cwd=project, env=env, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=90)
        (folder / f'{label}.stdout').write_text(result.stdout)
        (folder / f'{label}.stderr').write_text(result.stderr)
        return {'argv': list(map(str, argv)), 'command': shlex.join(list(map(str, argv))), 'exit': result.returncode, 'stdout': result.stdout, 'stderr': result.stderr}

    def run(name, target, lock_only=False, reinstall=False):
        folder = out / name
        folder.mkdir()
        envdir = out / 'environments' / target
        env = {k: v for k, v in os.environ.items() if not k.startswith(('PIP_', 'UV_')) and k not in ['VIRTUAL_ENV', 'CONDA_PREFIX', 'PYTHONPATH', 'PYTHONHOME']}
        env.update(HOME=str(folder / 'home'), XDG_CONFIG_HOME=str(folder / 'config'), UV_CACHE_DIR=str(folder / 'cache'), UV_PROJECT_ENVIRONMENT=str(envdir), UV_NO_INPUT='1', UV_PYTHON_DOWNLOADS='never', UV_LINK_MODE='copy', PIP_CONFIG_FILE=os.devnull, PIP_DISABLE_PIP_VERSION_CHECK='1', PYTHONNOUSERSITE='1')
        argv = [uv, 'lock' if lock_only else 'sync', '--no-build', '--python', sys.executable, '--no-python-downloads']
        if not lock_only:
            argv += ['--no-install-project', '--locked', '--verbose']
        if reinstall:
            argv += ['--reinstall-package', PROBE]
        before = len(events)
        result = execute(argv, folder, 'uv', env)
        record = {'step': name, 'environment_path': str(envdir), 'cwd': str(project), 'cache_path': env['UV_CACHE_DIR'], 'environment_controls': {k: env[k] for k in ['HOME', 'XDG_CONFIG_HOME', 'UV_CACHE_DIR', 'UV_PROJECT_ENVIRONMENT', 'UV_NO_INPUT', 'UV_PYTHON_DOWNLOADS', 'UV_LINK_MODE', 'PIP_CONFIG_FILE', 'PIP_DISABLE_PIP_VERSION_CHECK', 'PYTHONNOUSERSITE']}, 'command': result, 'http': events[before:]}
        for filename in ['pyproject.toml', 'uv.lock']:
            path = project / filename
            if path.exists():
                data = path.read_bytes()
                (folder / filename).write_bytes(data)
                record[filename + '_sha256'] = sha(data)
        python = envdir / 'bin/python'
        if python.exists():
            collect = execute([python, '-I', '-c', COLLECT, folder], folder, 'inventory', env)
            assert collect['exit'] == 0
            inventory = json.loads(collect['stdout'])
            record['inventory'] = inventory
            installed = {canonicalize_name(d['name']): d for d in inventory['installed']}
            violations = []
            for parent in inventory['installed']:
                for raw in parent['requires_dist']:
                    # This fixture deliberately uses only two exact requirements,
                    # so its independent check needs no third-party parser.
                    assert raw in ['old-dep==1.0', 'new-dep==1.0'], raw
                    dependency_name, required_version = raw.split('==')
                    actual = installed.get(canonicalize_name(dependency_name))
                    if not actual or actual['version'] != required_version:
                        violations.append({'parent': parent['name'], 'requirement': raw, 'actual_version': actual['version'] if actual else None})
            record['independent_constraint_violations'] = violations
            record['pip_check'] = execute([sys.executable, '-m', 'pip', '--python', python, 'check'], folder, 'pip-check', env)
            record['uv_check'] = execute([uv, '--no-config', 'pip', 'check', '--python', python], folder, 'uv-check', env)
            record['pip_inspect'] = execute([sys.executable, '-m', 'pip', '--python', python, 'inspect', '--local'], folder, 'pip-inspect', env)
        (folder / 'step.json').write_text(json.dumps(record, indent=2) + '\n')
        steps.append(record)
        print(json.dumps({'step': name, 'exit': result['exit'], 'installed': [(d['name'], d['origin']) for d in record.get('inventory', {}).get('installed', [])], 'violations': record.get('independent_constraint_violations'), 'pip_check_exit': record.get('pip_check', {}).get('exit'), 'uv_check_exit': record.get('uv_check', {}).get('exit')}), flush=True)
        if result['exit']:
            (out / 'partial-results.json').write_text(json.dumps(steps, indent=2))
            raise RuntimeError('uv command failed: ' + name)
        return record

    with ExitStack() as stack:
        indexes = {'old': stack.enter_context(server('old', [fixtures['old']], events)), 'new': stack.enter_context(server('new', [fixtures['new'], fixtures['old-dep'], fixtures['new-dep']], events))}
        (project / 'pyproject.toml').write_text(manifest('old', indexes))
        run('01-initial-lock', 'shared', True)
        initial = run('02-initial-sync', 'shared')
        (project / 'pyproject.toml').write_text(manifest('new', indexes))
        relock = run('03-relock-new-source', 'shared', True)
        warm = run('04-warm-sync', 'shared')
        fresh = run('05-fresh-sync', 'fresh')
        reinstall = run('06-reinstall-probe', 'shared', reinstall=True)

    def names(step): return {d['name'] for d in step['inventory']['installed']}
    def probe(step): return next(d for d in step['inventory']['installed'] if d['name'] == PROBE)
    def good(step): return step['pip_check']['exit'] == step['uv_check']['exit'] == 0 and not step['independent_constraint_violations']
    lock_text = (out / '04-warm-sync/uv.lock').read_text()
    locked = tomllib.loads(lock_text)
    node = next(p for p in locked['package'] if p['name'] == PROBE)
    checks = {
        'initial_old_probe_old_dep_consistent': probe(initial)['origin'] == 'old' and names(initial) == {PROBE, 'old-dep'} and good(initial),
        'relock_leaves_old_environment_consistent': probe(relock)['origin'] == 'old' and names(relock) == {PROBE, 'old-dep'} and good(relock),
        'new_lock_selects_new_probe_hash_registry_and_dep': node['source']['registry'].rstrip('/') == indexes['new'].rstrip('/') and fixtures['new']['sha256'] in lock_text and fixtures['old']['sha256'] not in lock_text and 'old-dep' not in lock_text and any(d['name'] == 'new-dep' for d in node.get('dependencies', [])),
        'warm_fresh_reinstall_identical_manifest': len({s['pyproject.toml_sha256'] for s in [warm, fresh, reinstall]}) == 1,
        'warm_fresh_reinstall_identical_lock': len({s['uv.lock_sha256'] for s in [warm, fresh, reinstall]}) == 1,
        'warm_keeps_exact_old_probe_metadata': probe(warm)['metadata_sha256'] == fixtures['old']['metadata_sha256'],
        'warm_removes_old_dep_installs_new_dep': names(warm) == {PROBE, 'new-dep'},
        'warm_both_checkers_fail': warm['pip_check']['exit'] != 0 and warm['uv_check']['exit'] != 0,
        'warm_independent_missing_old_dep': warm['independent_constraint_violations'] == [{'parent': PROBE, 'requirement': 'old-dep==1.0', 'actual_version': None}],
        'fresh_new_probe_new_dep_consistent': probe(fresh)['metadata_sha256'] == fixtures['new']['metadata_sha256'] and names(fresh) == {PROBE, 'new-dep'} and good(fresh),
        'reinstall_new_probe_new_dep_consistent': probe(reinstall)['metadata_sha256'] == fixtures['new']['metadata_sha256'] and names(reinstall) == {PROBE, 'new-dep'} and good(reinstall),
        'all_installed_record_hashes_match': not any(d['record_mismatches'] for step in [initial, relock, warm, fresh, reinstall] for d in step['inventory']['installed']),
        'same_full_target_environment': len({json.dumps(s['inventory']['environment'], sort_keys=True) for s in [initial, relock, warm, fresh, reinstall]}) == 1,
    }
    for label, step, fixture in [('initial_probe', initial, fixtures['old']), ('initial_dep', initial, fixtures['old-dep']), ('warm_new_dep', warm, fixtures['new-dep']), ('fresh_probe', fresh, fixtures['new']), ('fresh_dep', fresh, fixtures['new-dep']), ('reinstall_probe', reinstall, fixtures['new'])]:
        index_name = 'old' if label == 'initial_probe' else 'new'
        checks[label + '_http_full_bytes_sha'] = any(e['method'] == 'GET' and e['status'] == 200 and e['body_written'] and e['response_sha256'] == fixture['sha256'] and e['bytes'] == len(fixture['body']) and e['path'] == '/' + index_name + '/files/' + fixture['filename'] and e['port'] == urlsplit(indexes[index_name]).port for e in step['http'])
    output = {'schema': 'uv-warm-closure-repro-v1', 'at_utc': datetime.now(timezone.utc).isoformat(), 'tool': version, 'uv_binary_sha256': sha(uv.read_bytes()), 'python': sys.version, 'python_binary_sha256': sha(Path(sys.executable).resolve().read_bytes()), 'platform': platform.platform(), 'script_sha256': sha(Path(__file__).read_bytes()), 'checks': checks, 'reproduced_closure_violation': all(checks.values()), 'steps': steps, 'fixtures': {k: {field: value for field, value in item.items() if field not in ['body', 'metadata']} for k, item in fixtures.items()}, 'indexes': indexes, 'scope': 'Inert local dist-info-only wheels; no package modules or build hooks; same-version cross-index reuse with dependency closure observation, not another mechanism count.'}
    (out / 'results.json').write_text(json.dumps(output, indent=2) + '\n')
    print(json.dumps({'output': str(out), 'tool': version, 'reproduced_closure_violation': output['reproduced_closure_violation'], 'checks': checks}, indent=2))


if __name__ == '__main__':
    main()
