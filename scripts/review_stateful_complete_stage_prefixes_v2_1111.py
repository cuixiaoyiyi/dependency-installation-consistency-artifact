"""Target-lock review of complete saved stages, including unknown-chain prefixes.

Reuses an immutable stage reviewer.  It never upgrades a partial workflow to a
completed chain and never manufactures a missing historical file audit.
"""
from __future__ import annotations
import argparse
import inspect
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from scripts import review_stateful_workflows_1111 as base
from scripts.run_expanded_validation import digest

BASE_SHA = "7f0d122d2018118e436bb23d54ee689b697e373b38b0025cd4c03b7c4e50ddea"


def review(out, destination):
    assert digest(Path(base.__file__)) == BASE_SHA
    text = inspect.getsource(base.review)
    # A controlled interruption can preserve a fully audited progress prefix
    # without any final results.json; bind the progress without creating one.
    original_guard = '            if not result_path.exists():\n'
    assert text.count(original_guard) == 1
    text = text.replace(original_guard, '            if not result_path.exists() and not (root / workflow / "progress.json").exists():\n')
    original_hash = '            inputs[str(result_path)] = digest(result_path)\n'
    assert text.count(original_hash) == 1
    text = text.replace(original_hash, '            if result_path.exists():\n                inputs[str(result_path)] = digest(result_path)\n')
    old = 'for workflow in protocol.get("workflows", (("relock",) if protocol.get("source_out") else ("update", "extras", "relock"))):'
    new = 'for workflow in (protocol["workflows"] if isinstance(protocol.get("workflows"), (list, tuple)) else ("update", "extras", "relock")):'
    assert text.count(old) == 1
    text = text.replace(old, new)
    old = '            result = json.loads(result_path.read_text())\n'
    new = '''            result = json.loads(result_path.read_text()) if result_path.exists() else {}
            evidence_source = "results.json"
            progress_path = root / workflow / "progress.json"
            if not result.get("stages") and progress_path.exists():
                inputs[str(progress_path)] = digest(progress_path)
                prefix = json.loads(progress_path.read_text())
                assert prefix.get("name") == case["canonical_name"] and prefix.get("workflow") == workflow
                result = {**result, "stages": prefix.get("stages", [])}
                evidence_source = "complete saved stage prefix in progress.json; whole chain outcome unchanged"
'''
    assert text.count(old) == 1
    text = text.replace(old, new)
    old = '"request": entry["request"], "status": "unknown", "source_unknowns": [], "source_mismatches": []}'
    new = '"request": entry["request"], "status": "unknown", "source_unknowns": [], "source_mismatches": [], "stage_evidence_source": evidence_source}'
    assert text.count(old) == 1
    text = text.replace(old, new)
    text = text.replace('"schema": "stateful-target-lock-installed-review-v1"',
                        '"schema": "stateful-complete-stage-prefix-target-lock-review-v2", "immutable_stage_reviewer_sha256": BASE_SHA')
    old = '    assert result["all_reviewed_inputs_unchanged"] and result["core_unchanged"]'
    new = '''    result["limits"].append("Complete progress-prefix stages of an unknown workflow are reviewed separately; the original workflow outcome and any missing historical file audit remain unchanged. No final live environment is substituted for an earlier state.")
    assert result["all_reviewed_inputs_unchanged"] and result["core_unchanged"]'''
    assert text.count(old) == 1
    text = text.replace(old, new)
    namespace = dict(base.__dict__)
    namespace.update(__file__=str(Path(__file__).resolve()), BASE_SHA=BASE_SHA)
    exec(compile(text, str(Path(__file__).resolve()) + ":immutable-stage-review", "exec"), namespace)
    namespace["review"](out, destination)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", required=True, type=Path)
    parser.add_argument("--write", required=True, type=Path)
    args = parser.parse_args()
    review(args.out.resolve(), args.write.resolve())
