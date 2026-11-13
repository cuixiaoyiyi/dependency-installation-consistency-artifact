"""Offline regression tests: no package installs, public requests or large files."""
from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import tomllib
import unittest
from unittest.mock import patch
import urllib.error
import urllib.request

from drc import proxy
from drc import resolvers
from drc.model import Context, Resolution


TMP_ROOT = Path(__file__).resolve().parents[1] / "work" / "resolver-test-tmp"
SIMPLE = "https://example.invalid/simple"
FILE = "https://example.invalid/files/demo-1.0-py3-none-any.whl"
PAGE = ('<a href="' + FILE + '#sha256=' + 'a' * 64 + '">demo-1.0-py3-none-any.whl</a>').encode()


class SnapshotTests(unittest.TestCase):
    def setUp(self):
        TMP_ROOT.mkdir(parents=True, exist_ok=True)
        self.temp = tempfile.TemporaryDirectory(dir=TMP_ROOT)
        self.root = Path(self.temp.name)
        self.saved = proxy.CACHE, proxy.SNAPSHOT

    def tearDown(self):
        proxy.CACHE, proxy.SNAPSHOT = self.saved
        proxy.PAGE_CACHE.clear()
        self.temp.cleanup()

    def record(self):
        store = proxy.configure_snapshot(self.root, "test-snapshot")
        with patch.object(proxy, "fetch", return_value=(200, {"Content-Type": "text/html"}, PAGE)) as fetch:
            self.assertEqual(proxy.get_page(SIMPLE, "demo")[0], 200)
            first = proxy.get_page(SIMPLE, "demo")
            self.assertIn(b"/s/test-snapshot/f/", first[1])
            self.assertEqual(fetch.call_count, 1)
        return store

    def test_sealed_replay_is_identical_and_read_only(self):
        store = self.record()
        store.write("metadata", FILE, 200, b"Name: demo\nVersion: 1.0\n")
        store.freeze()
        before = {str(p.relative_to(store.root)): p.read_bytes() for p in store.root.rglob("*") if p.is_file()}
        proxy.configure_snapshot(self.root, "test-snapshot", "replay")
        with patch.object(proxy, "fetch", side_effect=AssertionError("external fetch")), patch.object(proxy, "range_metadata", side_effect=AssertionError("external range")):
            self.assertEqual(proxy.get_page(SIMPLE, "demo")[0], 200)
            self.assertEqual(proxy.get_metadata(FILE, True)[1], b"Name: demo\nVersion: 1.0\n")
        after = {str(p.relative_to(store.root)): p.read_bytes() for p in store.root.rglob("*") if p.is_file()}
        self.assertEqual(before, after)

    def test_replay_missing_page_and_metadata_never_fetch_live(self):
        store = self.record()
        store.freeze()
        proxy.configure_snapshot(self.root, "test-snapshot", "replay")
        with patch.object(proxy, "fetch", side_effect=AssertionError("external fetch")):
            self.assertEqual(proxy.get_page(SIMPLE, "missing")[0], 409)
            self.assertEqual(proxy.get_metadata(FILE, True)[0], 409)
        self.assertEqual(proxy.SNAPSHOT.health()["missing_entries"], 2)

    def test_replay_corrupt_page_fails_hash_check(self):
        store = self.record()
        store.freeze()
        store._body_path("page", SIMPLE + "/demo").write_bytes(b"modified")
        proxy.configure_snapshot(self.root, "test-snapshot", "replay")
        with patch.object(proxy, "fetch", side_effect=AssertionError("external fetch")):
            self.assertEqual(proxy.get_page(SIMPLE, "demo")[0], 412)
        self.assertFalse(proxy.SNAPSHOT.health()["integrity_ok"])

    def test_unavailable_upstream_is_counted_as_incomplete_recording(self):
        store = proxy.configure_snapshot(self.root, "network-error")
        with patch.object(proxy, "fetch", side_effect=OSError("offline")):
            self.assertEqual(proxy.get_page(SIMPLE, "demo")[0], 502)
            self.assertEqual(proxy.get_metadata(FILE, True)[0], 502)
        self.assertEqual(store.health()["fetch_errors"], 2)

    def test_malformed_manifest_entry_fails_integrity_not_live_fallback(self):
        store = self.record()
        store.freeze()
        manifest = json.loads(store.path.read_text(encoding="utf-8"))
        manifest["entries"][store._key("page", SIMPLE + "/demo")] = []
        store.path.write_text(json.dumps(manifest), encoding="utf-8")
        proxy.configure_snapshot(self.root, "test-snapshot", "replay")
        with patch.object(proxy, "fetch", side_effect=AssertionError("external fetch")):
            self.assertEqual(proxy.get_page(SIMPLE, "demo")[0], 412)
        self.assertFalse(proxy.SNAPSHOT.health()["integrity_ok"])

    def test_absent_package_is_recorded_not_refetched(self):
        store = proxy.configure_snapshot(self.root, "absence")
        with patch.object(proxy, "fetch", return_value=(404, {}, b"absent")) as fetch:
            self.assertEqual(proxy.get_page(SIMPLE, "missing"), (404, b"absent"))
            self.assertEqual(proxy.get_page(SIMPLE, "missing"), (404, b"absent"))
            self.assertEqual(fetch.call_count, 1)
        store.freeze()
        proxy.configure_snapshot(self.root, "absence", "replay")
        with patch.object(proxy, "fetch", side_effect=AssertionError("external fetch")):
            self.assertEqual(proxy.get_page(SIMPLE, "missing"), (404, b"absent"))

    def test_replay_requires_sealed_manifest_and_explicit_id(self):
        self.record()
        with self.assertRaises(proxy.SnapshotError): proxy.configure_snapshot(self.root, "test-snapshot", "replay")
        with self.assertRaises(proxy.SnapshotError): proxy.configure_snapshot(self.root, None, "replay")
        with self.assertRaises(proxy.SnapshotError): proxy.configure_snapshot(self.root, "../escape")

    def test_existing_legacy_pages_are_not_imported(self):
        disk = self.root / "pages" / (hashlib.sha256((SIMPLE + "/demo").encode()).hexdigest() + ".html")
        disk.parent.mkdir()
        disk.write_bytes(b"stale legacy input")
        store = proxy.configure_snapshot(self.root, "new-isolated")
        with patch.object(proxy, "fetch", return_value=(200, {}, PAGE)) as fetch:
            self.assertEqual(proxy.get_page(SIMPLE, "demo")[0], 200)
            self.assertEqual(fetch.call_count, 1)
        self.assertEqual(disk.read_bytes(), b"stale legacy input")
        self.assertNotEqual(store.root, self.root)

    def test_freeze_is_seen_by_running_recorder(self):
        recorder = self.record()
        sealer = proxy.SnapshotStore(self.root, "test-snapshot")
        sealer.freeze()
        with self.assertRaises(proxy.SnapshotError): recorder.write("metadata", FILE, 200, b"late")

    def test_http_replay_blocks_download_and_identity_mismatch(self):
        store = self.record()
        store.freeze()
        proxy.configure_snapshot(self.root, "test-snapshot", "replay")
        server = proxy.ThreadingHTTPServer(("127.0.0.1", 0), proxy.H)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        base = f"http://127.0.0.1:{server.server_port}"
        try:
            with patch.object(proxy, "fetch", side_effect=AssertionError("external fetch")):
                with self.assertRaises(urllib.error.HTTPError) as caught:
                    urllib.request.urlopen(base + "/s/test-snapshot/f/" + proxy.b64e(FILE) + "/demo.whl")
                self.assertEqual(caught.exception.code, 409)
                with self.assertRaises(urllib.error.HTTPError) as caught:
                    urllib.request.urlopen(base + "/s/wrong/idx/x/simple/demo/")
                self.assertEqual(caught.exception.code, 409)
                with urllib.request.urlopen(base + "/health") as response:
                    health = json.load(response)
                self.assertEqual(health["snapshot"]["blocked_artifact_requests"], 1)
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=3)


class AdapterTests(unittest.TestCase):
    def setUp(self):
        TMP_ROOT.mkdir(parents=True, exist_ok=True)
        self.temp = tempfile.TemporaryDirectory(dir=TMP_ROOT)
        self.root = Path(self.temp.name)
        self.patches = [patch.object(resolvers, "CACHE_ROOT", self.root / "cache"),
                        patch.object(resolvers, "USE_PROXY", False),
                        patch.object(resolvers, "PIP_VERSION", "pip-test"),
                        patch.object(resolvers, "UV_VERSION", "uv-test"),
                        patch.dict("os.environ", {"DRC_SNAPSHOT_ID": "", "DRC_STRICT_REPRODUCIBILITY": "0"})]
        for p in self.patches: p.start()

    def tearDown(self):
        for p in reversed(self.patches): p.stop()
        self.temp.cleanup()

    def context(self, resolver="uv", **kwargs):
        return Context(id="test", resolver=resolver, requirements=["demo==1.0"], request_complete=True, faithfulness="verified", **kwargs)

    def fake_uv(self, cmd, cwd, env, timeout, tool, pyver):
        (cwd / "uv.lock").write_text('''version = 1
[[package]]
name = "demo"
version = "1.0"
source = { registry = "https://pypi.org/simple" }
wheels = [
 {url="https://example.invalid/demo-1.0-py3-none-any.whl",hash="sha256:aaaa"},
 {url="https://example.invalid/demo-1.0-cp312-cp312-win_amd64.whl",hash="sha256:bbbb"},
]
''', encoding="utf-8")
        return subprocess.CompletedProcess(cmd, 0, "", ""), "uv lock (mock)"

    def test_uv_preserves_candidates_without_claiming_selected_file(self):
        with patch.object(resolvers, "_run", side_effect=self.fake_uv):
            result = resolvers.run_uv(self.context(), self.root / "run")
        self.assertTrue(result.ok, result.error)
        artifact = result.artifacts["demo"]
        self.assertEqual(artifact.selection_evidence, "uv-lock-candidates")
        self.assertFalse(artifact.selected_artifact_verified)
        self.assertEqual((artifact.url, artifact.filename, artifact.sha256), ("", "", None))
        self.assertEqual(len(artifact.candidate_artifacts), 2)
        self.assertFalse(result.to_dict()["artifacts"]["demo"]["selected_artifact_verified"])

    def test_uv_multiple_lock_forks_are_explicitly_unverified(self):
        def run(*args):
            result = self.fake_uv(*args)
            with (args[1] / "uv.lock").open("a", encoding="utf-8") as file:
                file.write('\n[[package]]\nname="demo"\nversion="2.0"\nsource={registry="https://pypi.org/simple"}\n')
            return result
        with patch.object(resolvers, "_run", side_effect=run):
            result = resolvers.run_uv(self.context(), self.root / "run")
        self.assertEqual(result.artifacts["demo"].selection_evidence, "uv-lock-fork-unverified")
        self.assertIn("2.0", [c["package_version"] for c in result.artifacts["demo"].candidate_artifacts])

    def test_pip_report_is_selected_evidence_and_flags_are_preserved(self):
        def run(cmd, cwd, *args):
            self.assertIn("--no-deps", cmd)
            self.assertIn("--require-hashes", cmd)
            self.assertIn("--only-binary", cmd)
            (cwd / "pip-report.json").write_text(json.dumps({"install": [{
                "metadata": {"name": "demo", "version": "1.0"}, "requested": True,
                "download_info": {"url": FILE, "archive_info": {"hashes": {"sha256": "aaaa"}}}}]}), encoding="utf-8")
            return subprocess.CompletedProcess(cmd, 0, "", ""), "pip report (mock)"
        ctx = self.context("pip", no_deps=True, require_hashes=True, only_binary=":all:")
        with patch.object(resolvers, "_run", side_effect=run):
            result = resolvers.run_pip(ctx, self.root / "run")
        self.assertTrue(result.ok, result.error)
        self.assertTrue(result.artifacts["demo"].selected_artifact_verified)
        self.assertEqual(result.artifacts["demo"].selection_evidence, "pip-report-selected")

    def test_unsupported_uv_flags_and_incomplete_requests_fail_before_execution(self):
        for kwargs in ({"no_deps": True}, {"require_hashes": True}, {"only_binary": ":all:"}):
            with self.subTest(kwargs=kwargs), patch.object(resolvers, "_run") as run:
                result = resolvers.run_uv(self.context(**kwargs), self.root / "run")
                self.assertFalse(result.ok)
                self.assertIn("cannot", result.error)
                run.assert_not_called()
        ctx = self.context()
        ctx.request_complete = False
        with patch.object(resolvers, "_run") as run:
            self.assertFalse(resolvers.run_uv(ctx, self.root / "run").ok)
            run.assert_not_called()

    def test_both_adapters_rewrite_all_indexes_including_implicit_pypi(self):
        ctx = self.context(snapshot_id="same-universe", extra_index_urls=[SIMPLE])
        health = {"proxy_verified": True, "id": None, "mode": "mock"}
        with patch.object(resolvers, "_prepare_snapshot", return_value=health), patch.object(resolvers, "_run", side_effect=self.fake_uv):
            result = resolvers.run_uv(ctx, self.root / "run")
        self.assertTrue(result.ok, result.error)
        project = tomllib.loads((self.root / "run" / "pyproject.toml").read_text(encoding="utf-8"))
        indexes = project["tool"]["uv"]["index"]
        self.assertEqual({resolvers.unproxy_index(ix["url"]) for ix in indexes}, {SIMPLE, resolvers.PYPI_SIMPLE})
        self.assertTrue(all("/s/same-universe/" in ix["url"] for ix in indexes))
        pip_args = resolvers._pip_index_args(ctx, use_proxy=True)
        self.assertIn(resolvers.proxy_index(SIMPLE, ctx), pip_args)
        self.assertIn(resolvers.proxy_index(resolvers.PYPI_SIMPLE, ctx), pip_args)

    def test_wrong_snapshot_proxy_is_refused_without_replacing_it(self):
        health = {"pages": 1, "snapshot": {"id": "other", "mode": "record"}}
        with patch.object(resolvers, "_proxy_health", return_value=health), patch.object(resolvers.subprocess, "Popen") as start:
            self.assertFalse(resolvers.ensure_proxy(self.context(snapshot_id="requested")))
            start.assert_not_called()

    def test_replay_miss_cannot_be_hidden_by_successful_resolver_exit(self):
        ctx = self.context(snapshot_id="sealed", snapshot_mode="replay")
        before = {"id": "sealed", "mode": "replay", "frozen": True, "integrity_ok": True,
                  "manifest_sha256": "abc", "missing_entries": 0}
        after = dict(before, missing_entries=1)
        result = Resolution("test", "uv", True, {}, 0.0, "mock")
        snapshot = {"id": "sealed", "mode": "replay", "proxy_verified": True, "health_before": before}
        with patch.object(resolvers, "_proxy_health", return_value={"snapshot": after}):
            result = resolvers._finish_snapshot(result, ctx, snapshot)
        self.assertFalse(result.ok)
        self.assertFalse(result.snapshot["complete"])
        self.assertIn("missing_entries", result.error)

    def test_successful_replay_has_sealed_integrity_evidence(self):
        ctx = self.context(snapshot_id="sealed", snapshot_mode="replay")
        health = {"id": "sealed", "mode": "replay", "frozen": True, "integrity_ok": True,
                  "manifest_sha256": "abc", "missing_entries": 0}
        snapshot = {"id": "sealed", "mode": "replay", "proxy_verified": True, "health_before": health}
        with patch.object(resolvers, "_proxy_health", return_value={"snapshot": health}):
            result = resolvers._finish_snapshot(Resolution("test", "uv", True, {}, 0.0, "mock"), ctx, snapshot)
        self.assertTrue(result.snapshot["sealed"])
        self.assertTrue(result.snapshot["integrity_verified"])
        self.assertEqual(result.snapshot["manifest_sha256"], "abc")

    def test_real_pip_resolves_only_sealed_local_metadata_without_downloads(self):
        """Exercise the actual pip report + proxy protocol, not a mocked solver."""
        saved = proxy.CACHE, proxy.SNAPSHOT
        store = proxy.configure_snapshot(self.root / "snapshots-fixture", "real-pip")
        store.write("page", SIMPLE + "/demo", 200, PAGE, {"content-type": "text/html"})
        store.write("metadata", FILE, 200, b"Metadata-Version: 2.1\nName: demo\nVersion: 1.0\nRequires-Python: >=3.8\n\n")
        store.freeze()
        proxy.configure_snapshot(self.root / "snapshots-fixture", "real-pip", "replay")
        server = proxy.ThreadingHTTPServer(("127.0.0.1", 0), proxy.H)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            target = "windows-x86_64" if sys.platform == "win32" else "macos-arm64" if sys.platform == "darwin" else "linux-x86_64"
            ctx = self.context("pip", index_url=SIMPLE, snapshot_id="real-pip", snapshot_mode="replay", platform=target,
                               python_version=f"{sys.version_info.major}.{sys.version_info.minor}")
            with patch.object(resolvers, "EXEC", "host"), patch.object(resolvers, "PROXY_PORT", server.server_port), patch.object(proxy, "fetch", side_effect=AssertionError("external fetch")):
                result = resolvers.run_pip(ctx, self.root / "real-pip-run")
            self.assertTrue(result.ok, result.error)
            self.assertTrue(result.artifacts["demo"].selected_artifact_verified)
            self.assertEqual(result.artifacts["demo"].sha256, "a" * 64)
            self.assertTrue(result.snapshot["sealed"])
            self.assertTrue(result.snapshot["complete"])
            self.assertEqual(proxy.SNAPSHOT.health()["network_requests"], 0)
            self.assertEqual(proxy.SNAPSHOT.health()["blocked_artifact_requests"], 0)
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=3)
            proxy.CACHE, proxy.SNAPSHOT = saved

    @unittest.skipUnless(importlib.util.find_spec("uv"), "optional local uv executable is unavailable")
    def test_real_uv_lock_uses_the_same_sealed_metadata_protocol(self):
        saved = proxy.CACHE, proxy.SNAPSHOT
        store = proxy.configure_snapshot(self.root / "snapshots-fixture", "real-uv")
        store.write("page", SIMPLE + "/demo", 200, PAGE, {"content-type": "text/html"})
        store.write("metadata", FILE, 200, b"Metadata-Version: 2.1\nName: demo\nVersion: 1.0\nRequires-Python: >=3.8\n\n")
        store.freeze()
        proxy.configure_snapshot(self.root / "snapshots-fixture", "real-uv", "replay")
        server = proxy.ThreadingHTTPServer(("127.0.0.1", 0), proxy.H)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            target = "windows-x86_64" if sys.platform == "win32" else "macos-arm64" if sys.platform == "darwin" else "linux-x86_64"
            ctx = self.context("uv", index_url=SIMPLE, snapshot_id="real-uv", snapshot_mode="replay", strict_reproducibility=True,
                               platform=target, python_version=f"{sys.version_info.major}.{sys.version_info.minor}")
            with patch.object(resolvers, "EXEC", "host"), patch.object(resolvers, "PROXY_PORT", server.server_port), patch.object(proxy, "fetch", side_effect=AssertionError("external fetch")):
                result = resolvers.run_uv(ctx, self.root / "real-uv-run")
            self.assertTrue(result.ok, result.error)
            self.assertEqual(result.artifacts["demo"].version, "1.0")
            self.assertFalse(result.artifacts["demo"].selected_artifact_verified)
            self.assertEqual(result.artifacts["demo"].registry, resolvers.registry_id(SIMPLE))
            self.assertTrue(result.snapshot["sealed"])
            self.assertTrue(result.snapshot["complete"])
            self.assertEqual(proxy.SNAPSHOT.health()["network_requests"], 0)
            self.assertEqual(proxy.SNAPSHOT.health()["blocked_artifact_requests"], 0)
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=3)
            proxy.CACHE, proxy.SNAPSHOT = saved


if __name__ == "__main__":
    unittest.main()
