"""Metadata-only recording index proxy (PEP 503 pass-through).

Why: pip only needs a wheel's METADATA to resolve, but indexes without PEP 658 support (e.g. pypi.nvidia.com, the
nvidia-* mirrors on download.pytorch.org) force pip to download entire multi-hundred-MB wheels during
`pip install --dry-run`. This proxy rewrites simple-index pages so that every wheel link advertises PEP 658 metadata
served by the proxy; the metadata is produced with HTTP Range requests against the upstream wheel (a few KB) and cached.
File bodies are never proxied: /f/<id> redirects (302) to the upstream URL, so the artifact identity stays upstream.
Pages are cached for the lifetime of the proxy process (registry state frozen within a run) and on disk.

URL scheme:
  /health
  /idx/<b64(upstream_index_url)>/simple/<project>/      -> rewritten upstream page
  /f/<b64(upstream_file_url)>                           -> 302 to upstream
  /f/<b64(upstream_file_url)>.metadata                  -> core METADATA bytes
"""
from __future__ import annotations
import argparse, base64, hashlib, html, io, json, os, pathlib, re, struct, sys, threading, time, urllib.parse, urllib.request, urllib.error, zlib
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler

UA = {"User-Agent": "pip/26 drc-metadata-proxy/0.1"}
DROP_UNSAFE_SDISTS = os.environ.get("DRC_PROXY_KEEP_SDISTS", "0") != "1"
CACHE = None
SNAPSHOT = None
PAGE_CACHE: dict[str, tuple[bytes, str]] = {}
LOCK = threading.Lock()
STATS = {"pages": 0, "page_cache_hits": 0, "meta_upstream": 0, "meta_range": 0, "meta_cache_hits": 0, "redirects": 0, "errors": 0, "range_bytes": 0,
         "started": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}

class SnapshotError(RuntimeError):
    """A missing or damaged frozen input must not turn into a live request."""
    def __init__(self, message, status=409):
        super().__init__(message)
        self.status = status

class SnapshotStore:
    """Isolated, hash-checked first-observation recording and read-only replay.

    Legacy caches are deliberately not imported. A snapshot is sealed explicitly
    after recording; replay refuses an unsealed manifest and never writes files.
    Absence (HTTP 404) is recorded just like a successful index page.
    """
    def __init__(self, cache_root, snapshot_id, mode="record"):
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", snapshot_id or ""):
            raise SnapshotError("invalid snapshot id")
        if mode not in ("record", "replay"):
            raise SnapshotError("snapshot mode must be record or replay")
        self.id = snapshot_id
        self.mode = mode
        self.root = pathlib.Path(cache_root) / "snapshots" / snapshot_id
        self.path = self.root / "manifest.json"
        self.lock = threading.RLock()
        self.stats = {"cache_hits": 0, "record_misses": 0, "missing_entries": 0,
                      "integrity_errors": 0, "fetch_errors": 0, "blocked_artifact_requests": 0,
                      "network_requests": 0, "sdists_dropped": 0}
        if self.path.exists():
            try:
                self.manifest = json.loads(self.path.read_text(encoding="utf-8"))
            except (OSError, ValueError) as exc:
                raise SnapshotError(f"unreadable snapshot manifest: {exc}") from exc
            if not isinstance(self.manifest, dict) or self.manifest.get("snapshot_id") != self.id or self.manifest.get("schema") != 1:
                raise SnapshotError("snapshot manifest identity/schema mismatch")
            if not isinstance(self.manifest.get("entries"), dict):
                raise SnapshotError("snapshot manifest has no entry map")
        else:
            if mode == "replay":
                raise SnapshotError("snapshot manifest missing; replay cannot fetch live inputs")
            self.root.mkdir(parents=True, exist_ok=True)
            self.manifest = {"schema": 1, "snapshot_id": self.id, "created_at": time.time(),
                             "frozen": False, "entries": {}, "candidate_policy": {
                                 "drop_sdists_without_static_metadata": DROP_UNSAFE_SDISTS,
                                 "artifact_bodies": "blocked", "metadata_only": True}}
            self._save()
        if mode == "replay" and not self.manifest.get("frozen"):
            raise SnapshotError("snapshot is not sealed; run proxy.py --snapshot-id ID --freeze first")

    def _save(self):
        tmp = self.path.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(self.manifest, indent=2, sort_keys=True), encoding="utf-8")
        os.replace(tmp, self.path)

    def _refresh(self):
        # A separate --freeze invocation may seal a running recording service.
        try:
            manifest = json.loads(self.path.read_text(encoding="utf-8"))
            if not isinstance(manifest, dict) or manifest.get("snapshot_id") != self.id or manifest.get("schema") != 1 or not isinstance(manifest.get("entries"), dict):
                raise ValueError("manifest identity/schema mismatch")
            policy = manifest.get("candidate_policy")
            if not isinstance(policy, dict) or policy.get("drop_sdists_without_static_metadata") != DROP_UNSAFE_SDISTS:
                raise ValueError("snapshot candidate policy is missing or differs from this proxy")
            self.manifest = manifest
        except (OSError, ValueError, TypeError) as exc:
            self.stats["integrity_errors"] += 1
            raise SnapshotError(f"snapshot manifest integrity failure: {exc}", 412) from exc

    def _key(self, kind, key):
        return kind + ":" + hashlib.sha256(key.encode()).hexdigest()

    def _body_path(self, kind, key):
        if kind not in ("page", "metadata"):
            raise SnapshotError("unsupported snapshot entry kind")
        return self.root / kind / (hashlib.sha256(key.encode()).hexdigest() + ".bin")

    def read(self, kind, key):
        with self.lock:
            self._refresh()
            entry = self.manifest["entries"].get(self._key(kind, key))
            if entry is None:
                if self.mode == "replay" or self.manifest.get("frozen"):
                    self.stats["missing_entries"] += 1
                    raise SnapshotError(f"snapshot {self.id}: missing {kind} entry for {key}")
                self.stats["record_misses"] += 1
                return None
            try:
                if not isinstance(entry, dict) or not isinstance(entry.get("headers", {}), dict):
                    raise ValueError("malformed entry/headers")
                body = self._body_path(kind, key).read_bytes()
                if entry.get("key") != key or entry.get("kind") != kind:
                    raise ValueError("entry identity mismatch")
                if len(body) != entry["bytes"] or hashlib.sha256(body).hexdigest() != entry["sha256"]:
                    raise ValueError("body length/hash mismatch")
                if entry["status"] not in (200, 404):
                    raise ValueError("invalid recorded HTTP status")
            except (OSError, ValueError, KeyError, TypeError) as exc:
                self.stats["integrity_errors"] += 1
                raise SnapshotError(f"snapshot {self.id}: integrity check failed for {kind}: {exc}", 412) from exc
            self.stats["cache_hits"] += 1
            return entry["status"], body, entry.get("headers", {})

    def write(self, kind, key, status, body, headers=None):
        with self.lock:
            self._refresh()
            # First observation wins even if two request threads fetched at once.
            if self._key(kind, key) in self.manifest["entries"]:
                return self.read(kind, key)
            if self.mode != "record" or self.manifest.get("frozen"):
                raise SnapshotError("cannot write a replay/sealed snapshot")
            if status not in (200, 404):
                self.stats["fetch_errors"] += 1
                raise SnapshotError(f"upstream status {status} was not recorded", 502)
            disk = self._body_path(kind, key)
            disk.parent.mkdir(parents=True, exist_ok=True)
            disk.write_bytes(body)
            self.manifest["entries"][self._key(kind, key)] = {
                "kind": kind, "key": key, "status": status, "bytes": len(body),
                "sha256": hashlib.sha256(body).hexdigest(), "headers": headers or {}}
            self._save()
            return status, body, headers or {}

    def freeze(self):
        with self.lock:
            self._refresh()
            if self.mode != "record":
                raise SnapshotError("replay is read-only")
            for entry in self.manifest["entries"].values():
                self.read(entry["kind"], entry["key"])
            self.manifest["frozen"] = True
            self.manifest["frozen_at"] = time.time()
            self._save()

    def health(self):
        with self.lock:
            self._refresh()
            return {"id": self.id, "mode": self.mode, "frozen": bool(self.manifest.get("frozen")),
                    "candidate_policy": self.manifest.get("candidate_policy"),
                    "manifest_entries": len(self.manifest["entries"]),
                    "manifest_sha256": hashlib.sha256(json.dumps(self.manifest, sort_keys=True).encode()).hexdigest(),
                    "integrity_ok": self.stats["integrity_errors"] == 0, **self.stats}

def configure_snapshot(cache_root, snapshot_id=None, mode="record"):
    """Configure before starting the HTTP server; also usable in offline tests."""
    global CACHE, SNAPSHOT
    SNAPSHOT = SnapshotStore(cache_root, snapshot_id, mode) if snapshot_id else None
    CACHE = pathlib.Path(cache_root) if SNAPSHOT is None else SNAPSHOT.root
    if SNAPSHOT is None:
        if mode != "record":
            raise SnapshotError("replay requires an explicit snapshot id")
        CACHE.mkdir(parents=True, exist_ok=True)
    with LOCK:
        PAGE_CACHE.clear()
    return SNAPSHOT

def _route_prefix():
    return f"/s/{SNAPSHOT.id}" if SNAPSHOT is not None else ""

def b64e(s: str) -> str: return base64.urlsafe_b64encode(s.encode()).decode().rstrip("=")
def b64d(s: str) -> str: return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4)).decode()

def fetch(url: str, headers=None, timeout=120) -> tuple[int, dict, bytes]:
    req = urllib.request.Request(url, headers={**UA, **(headers or {})})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, dict(r.headers), r.read()
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers or {}), b""

_A_RE = re.compile(r"<a\s+([^>]*?)href=\"([^\"]+)\"([^>]*)>(.*?)</a>", re.I | re.S)

def rewrite_page(upstream_index: str, project: str, body: bytes) -> bytes:
    base = upstream_index.rstrip("/") + "/" + project + "/"
    text = body.decode("utf-8", "replace")
    def rep(m):
        pre, href, post, label = m.group(1), m.group(2), m.group(3), m.group(4)
        href = html.unescape(href)
        absu = urllib.parse.urljoin(base, href)
        frag = ""
        if "#" in absu: absu, frag = absu.split("#", 1); frag = "#" + frag
        attrs = pre + " " + post
        fname = urllib.parse.unquote(absu.rstrip("/").split("/")[-1])
        is_wheel = fname.lower().endswith(".whl")
        has_meta = re.search(r"data-(core|dist-info)-metadata=", attrs) is not None
        # SAFETY: drop sdist links that carry no static metadata -- pip would otherwise download and *build* them
        # (executing third-party setup.py) during resolution. Wheels and metadata-bearing sdists are kept.
        if not is_wheel and not has_meta and DROP_UNSAFE_SDISTS:
            with LOCK: STATS["sdists_dropped"] = STATS.get("sdists_dropped", 0) + 1
            if SNAPSHOT is not None: SNAPSHOT.stats["sdists_dropped"] += 1
            return ""
        new_href = _route_prefix() + "/f/" + b64e(absu) + "/" + urllib.parse.quote(fname, safe="") + frag
        if is_wheel and not has_meta:
            attrs += ' data-core-metadata="true" data-dist-info-metadata="true"'
        # mark whether upstream metadata exists so /f/...metadata knows how to obtain it
        if has_meta: attrs += ' data-drc-upstream-meta="1"'
        return f'<a {attrs.strip()} href="{new_href}">{label}</a>'
    out = _A_RE.sub(rep, text)
    return out.encode("utf-8")

def get_page(upstream_index: str, project: str) -> tuple[int, bytes]:
    key = upstream_index.rstrip("/") + "/" + project
    if SNAPSHOT is not None:
        try:
            cached = SNAPSHOT.read("page", key)
            if cached is None:
                SNAPSHOT.stats["network_requests"] += 1
                try:
                    st, hdr, body = fetch(key + "/", headers={"Accept": "text/html, application/vnd.pypi.simple.v1+html;q=0.9"})
                except (OSError, ValueError) as exc:
                    SNAPSHOT.stats["fetch_errors"] += 1
                    raise SnapshotError(f"snapshot upstream page fetch failed: {exc}", 502) from exc
                cached = SNAPSHOT.write("page", key, st, body, {"content-type": hdr.get("Content-Type", "")})
            st, body, hdr = cached
            if st != 200:
                return st, body
            if "json" in hdr.get("content-type", ""):
                body = json_to_html(body, key + "/")
            return 200, rewrite_page(upstream_index, project, body)
        except SnapshotError as exc:
            return exc.status, str(exc).encode()
    with LOCK:
        if key in PAGE_CACHE:
            STATS["page_cache_hits"] += 1; return 200, PAGE_CACHE[key][0]
    disk = CACHE / "pages" / (hashlib.sha256(key.encode()).hexdigest() + ".html")
    if disk.exists():
        body = disk.read_bytes()
        with LOCK: PAGE_CACHE[key] = (body, "disk")
        return 200, body
    st, hdr, body = fetch(key + "/", headers={"Accept": "text/html, application/vnd.pypi.simple.v1+html;q=0.9"})
    if st != 200:
        return st, body
    ct = hdr.get("Content-Type", "")
    if "json" in ct:
        body = json_to_html(body, key + "/")
    out = rewrite_page(upstream_index, project, body)
    disk.parent.mkdir(parents=True, exist_ok=True); disk.write_bytes(out)
    with LOCK:
        PAGE_CACHE[key] = (out, "net"); STATS["pages"] += 1
    return 200, out

def json_to_html(body: bytes, base: str) -> bytes:
    d = json.loads(body.decode("utf-8"))
    rows = []
    for f in d.get("files", []):
        attrs = []
        h = f.get("hashes", {}).get("sha256")
        url = f["url"] + (f"#sha256={h}" if h else "")
        if f.get("requires-python"): attrs.append(f'data-requires-python="{html.escape(f["requires-python"], quote=True)}"')
        cm = f.get("core-metadata") or f.get("dist-info-metadata")
        if cm: attrs.append('data-core-metadata="' + (f"sha256={cm['sha256']}" if isinstance(cm, dict) and cm.get("sha256") else "true") + '"')
        if f.get("yanked"): attrs.append('data-yanked=""')
        rows.append(f'<a href="{html.escape(url, quote=True)}" {" ".join(attrs)}>{html.escape(f["filename"])}</a><br/>')
    return ("<!DOCTYPE html><html><head><meta name=\"pypi:repository-version\" content=\"1.0\"></head><body>" + "\n".join(rows) + "</body></html>").encode("utf-8")

def get_metadata(file_url: str, upstream_meta_hint: bool) -> tuple[int, bytes]:
    if SNAPSHOT is not None:
        try:
            cached = SNAPSHOT.read("metadata", file_url)
            if cached is not None:
                return cached[0], cached[1]
        except SnapshotError as exc:
            return exc.status, str(exc).encode()
    disk = CACHE / "meta" / (hashlib.sha256(file_url.encode()).hexdigest() + ".metadata")
    if SNAPSHOT is None and disk.exists():
        with LOCK: STATS["meta_cache_hits"] += 1
        return 200, disk.read_bytes()
    body = b""
    if SNAPSHOT is not None: SNAPSHOT.stats["network_requests"] += 1
    try:
        st, _, body = fetch(file_url + ".metadata")
    except (OSError, ValueError) as exc:
        if SNAPSHOT is None: raise
        SNAPSHOT.stats["fetch_errors"] += 1
        return 502, f"snapshot upstream metadata fetch failed: {exc}".encode()
    if st == 200 and body:
        with LOCK: STATS["meta_upstream"] += 1
    else:
        try:
            body = range_metadata(file_url)
            with LOCK: STATS["meta_range"] += 1
        except Exception as e:
            with LOCK:
                STATS["errors"] += 1
                STATS.setdefault("last_errors", []); STATS["last_errors"] = (STATS["last_errors"] + [f"{file_url[:120]} :: {type(e).__name__}: {str(e)[:80]}"])[-20:]
                host = urllib.parse.urlsplit(file_url).hostname or "?"
                STATS.setdefault("errors_by_host", {}); STATS["errors_by_host"][host] = STATS["errors_by_host"].get(host, 0) + 1
            if SNAPSHOT is not None: SNAPSHOT.stats["fetch_errors"] += 1
            return 502, f"metadata extraction failed: {type(e).__name__}: {e}".encode()
    if SNAPSHOT is not None:
        try:
            cached = SNAPSHOT.write("metadata", file_url, 200, body)
            return cached[0], cached[1]
        except SnapshotError as exc:
            return exc.status, str(exc).encode()
    disk.parent.mkdir(parents=True, exist_ok=True); disk.write_bytes(body)
    return 200, body

def _range(url: str, a: int, b: int) -> bytes:
    req = urllib.request.Request(url, headers={**UA, "Range": f"bytes={a}-{b}"})
    with urllib.request.urlopen(req, timeout=120) as r:
        if r.status != 206:
            raise ValueError(f"server ignored Range (status {r.status}); refusing full download")
        data = r.read(b - a + 2)
    with LOCK: STATS["range_bytes"] += len(data)
    return data

def range_metadata(url: str) -> bytes:
    req = urllib.request.Request(url, method="HEAD", headers=UA)
    with urllib.request.urlopen(req, timeout=60) as r:
        size = int(r.headers["Content-Length"]); final = r.geturl()
    url = final or url
    tail = _range(url, max(0, size - 65536), size - 1)
    eocd = tail.rfind(b"PK\x05\x06")
    if eocd < 0: raise ValueError("no EOCD in tail")
    cd_size, cd_off = struct.unpack("<II", tail[eocd + 12: eocd + 20])
    if cd_off == 0xFFFFFFFF or cd_size == 0xFFFFFFFF:
        loc = tail.rfind(b"PK\x06\x07"); z64off = struct.unpack("<Q", tail[loc + 8: loc + 16])[0]
        z64 = _range(url, z64off, z64off + 55); cd_size, cd_off = struct.unpack("<QQ", z64[40:56])
    cd = _range(url, cd_off, cd_off + cd_size - 1) if not (cd_off >= size - 65536) else tail[cd_off - (size - len(tail)): cd_off - (size - len(tail)) + cd_size]
    i = 0; meta = None
    while i + 46 <= len(cd):
        if cd[i:i + 4] != b"PK\x01\x02": break
        n, m, k = struct.unpack("<HHH", cd[i + 28: i + 34]); name = cd[i + 46: i + 46 + n].decode("utf-8", "replace")
        csize = struct.unpack("<I", cd[i + 20: i + 24])[0]; lho = struct.unpack("<I", cd[i + 42: i + 46])[0]
        if name.endswith(".dist-info/METADATA") and name.count("/") == 1:
            meta = (name, csize, lho); break
        i += 46 + n + m + k
    if not meta: raise ValueError("METADATA not found in central directory")
    name, csize, lho = meta
    lh = _range(url, lho, lho + 29); n2, m2 = struct.unpack("<HH", lh[26:30]); comp = struct.unpack("<H", lh[8:10])[0]
    data = _range(url, lho + 30 + n2 + m2, lho + 30 + n2 + m2 + csize - 1)
    if comp == 8: data = zlib.decompress(data, -15)
    return data

class H(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    def log_message(self, fmt, *args):  # quiet
        pass
    def _send(self, code: int, body: bytes, ctype="text/html; charset=utf-8", extra=None):
        self.send_response(code)
        self.send_header("Content-Type", ctype); self.send_header("Content-Length", str(len(body)))
        for k, v in (extra or {}).items(): self.send_header(k, v)
        self.end_headers()
        if self.command != "HEAD": self.wfile.write(body)
    def do_HEAD(self): self.do_GET()
    def do_GET(self):
        path = urllib.parse.unquote(self.path.split("?")[0])
        try:
            if path == "/health":
                health = dict(STATS)
                health["snapshot"] = SNAPSHOT.health() if SNAPSHOT is not None else None
                return self._send(200, json.dumps(health).encode(), "application/json")
            if SNAPSHOT is not None:
                prefix = _route_prefix()
                if not path.startswith(prefix + "/"):
                    return self._send(409, b"snapshot route/identity mismatch")
                path = path[len(prefix):]
            m = re.match(r"^/idx/([A-Za-z0-9_-]+)/simple/([^/]+)/?$", path)
            if m:
                st, body = get_page(b64d(m.group(1)), m.group(2))
                return self._send(st if st in (200, 404, 409, 412) else 502, body)
            m = re.match(r"^/idx/([A-Za-z0-9_-]+)/simple/?$", path)
            if m:
                return self._send(200, b"<html><body>drc proxy root (per-project pages only)</body></html>")
            m = re.match(r"^/f/([A-Za-z0-9_-]+)/[^/]+\.metadata$", path)
            if m:
                st, body = get_metadata(b64d(m.group(1)), True)
                return self._send(st, body, "application/octet-stream")
            m = re.match(r"^/f/([A-Za-z0-9_-]+)/[^/]+$", path)
            if m:
                if SNAPSHOT is not None:
                    SNAPSHOT.stats["blocked_artifact_requests"] += 1
                    return self._send(409, b"snapshot contains metadata only; artifact download/redirect is blocked")
                with LOCK: STATS["redirects"] += 1
                self.send_response(302); self.send_header("Location", b64d(m.group(1))); self.send_header("Content-Length", "0"); self.end_headers(); return
            return self._send(404, b"not found")
        except Exception as e:
            with LOCK: STATS["errors"] += 1
            return self._send(500, f"proxy error: {type(e).__name__}: {e}".encode())

def main():
    ap = argparse.ArgumentParser(); ap.add_argument("--port", type=int, default=8765); ap.add_argument("--cache", default=os.path.expanduser("~/drc-cache/proxy"))
    ap.add_argument("--snapshot-id", help="isolated snapshot under CACHE/snapshots/ID; never imports legacy caches")
    ap.add_argument("--mode", choices=("record", "replay"), default="record")
    ap.add_argument("--freeze", action="store_true", help="verify and seal a recorded snapshot, then exit")
    a = ap.parse_args()
    try:
        store = configure_snapshot(a.cache, a.snapshot_id, "record" if a.freeze else a.mode)
        if a.freeze:
            if store is None: raise SnapshotError("--freeze requires --snapshot-id")
            store.freeze()
            print(json.dumps(store.health()), flush=True)
            return
    except SnapshotError as exc:
        ap.error(str(exc))
    srv = ThreadingHTTPServer(("127.0.0.1", a.port), H)
    print(f"drc proxy on 127.0.0.1:{a.port} cache={CACHE}", flush=True)
    srv.serve_forever()

if __name__ == "__main__":
    main()
