# Experiment Guide

Run commands from the repository root. Clone/ZIP links and Python environment setup are in [README.md](../README.md). Place new observations under `runs/`, using a new directory for each installation replay. Portable installation entry points show a plan by default; `--execute` starts the requested run.

## Saved-result reproduction

With Python 3.11 or later:

```sh
python3 artifact_tools/verify_files.py
python3 artifact_tools/reproduce_results.py --out runs/summary
```

Use `python` in place of `python3` on Windows. Both commands use the standard library and work without installing runner dependencies. The verifier streams through the evidence archives. The summary writes `summary.json`, `summary.md`, `workflows.csv`, `cohort-status.csv`, and `ultralytics-states.csv`. Both commands should report `"status": "passed"`.

Expected totals are 29 historical audit items, 61 package contrasts, 52 roots, 133 applicable workflows, 82 complete workflows, 51 gaps, 2 mechanism examples, and 1 real affected root. Values in `outputs/expected-results.json` are checked against measurements recomputed from saved data. This task performs no new installations.

## Regression tests

Activate the environment prepared in README.md, then run:

```sh
python -m unittest discover -s tests -v
```

The small source, context, and resolver-output fixtures used by the tests are ordinary files. Tests do not require extracting detailed evidence. `requirements.txt` records runner dependencies.

## Audit data

Read `inputs/historical-reports.csv` with `outputs/issue-validity-audit-20261110.json`. These data associate assessments with source revisions, installation entry points, measured requests, and applicable contracts. Original descriptions and discussion captures are excluded.

The offline summary recovers 7 refuted reports, 21 input/scope mismatches, and 1 narrower documentation fix with repair support. Some report-level input mismatches contain individual package-level refutations. No complete original report is certified in its original scope.

`scripts/revalidate_audited_cases.py` reinterprets captured resolver evidence through the repaired projection/context logic. This older script retains original machine-path assumptions. Rebuilding a source context does not establish that a historical command used it; source revision and entry-point data remain part of the interpretation.

## Workflow coverage and core analysis

`inputs/cohort.csv` and `inputs/workflows.json` are readable indexes. Selection/native-target records are under `work/stateful-validation-20261111/`; the aggregate report is `outputs/1111-stateful-workflow-report.json`.

| Workflow | Applicable | Complete | Gap |
| --- | ---: | ---: | ---: |
| Update | 50 | 33 | 17 |
| Extras round trip | 31 | 15 | 16 |
| Relock | 52 | 34 | 18 |
| Total | 133 | 82 | 51 |

All 33 complete updates change the root version with both installers. The 15 complete extras workflows add and remove 65 distribution occurrences. Of 34 complete relocks, 2 change installed names/versions and 32 do not. These are state changes rather than defect counts.

Inspect a core-analysis plan for the supplied base consumer project:

```sh
python artifact_tools/run_drc.py inputs/ultralytics-extra/base --out runs/drc-preview --dry-run
```

To execute resolver analysis, use a different output directory:

```sh
python artifact_tools/run_drc.py inputs/ultralytics-extra/base --out runs/drc-analysis --execute
```

Use `--python PATH --uv PATH` to select executables. This entry point performs input extraction, resolution, and scoped checks; it does not recreate saved multi-step installation workflows. Results are candidates requiring installation evidence and case-specific review.

The original cohort harness is `scripts/stateful_real_workflows_1111.py`. A new full-cohort run requires adapting its historical machine paths, preparing each root's recorded native Python target, and fetching the complete official package closure. Before running an older script that reads detailed saved records, extract them with:

```sh
python artifact_tools/unpack_data.py
```

The repository does not offer a single portable command that reruns all 82 saved sequences. Coverage gaps include native-wheel/build boundaries, resource limits, transport failures, time/I/O limits, preparation boundaries, and resolver-depth limits. A gap does not mean a package is inherently uninstallable. Some complete sequences retain unknown archive-to-installed-file mappings.

## M1: synthetic source reuse

This replay uses inert local wheels and two localhost index endpoints. Root artifacts have the same distribution name, version, filename, and tags but declare different child requirements. The source changes while the declared root version stays the same. The recorded warm transition retains old root metadata while updating the child set; fresh and reinstallation runs provide matching-final-input observations.

Execute from Linux x86-64 or a WSL shell with Python 3.11 or later and the installed uv 0.13.7:

```sh
python artifact_tools/replay_cases.py m1 --out runs/m1-preview --dry-run
python artifact_tools/replay_cases.py m1 --out runs/m1-execution --execute
```

The preview creates no output directory. Execution creates local HTTP servers and new environments; it fetches no third-party packages. `runs/m1-execution/results.json` should report `reproduced_closure_violation: true` and all recorded checks as true. Raw command outputs and wheel identities are saved alongside it. The original fixture is `reproductions/source_reuse.py`.

This is one synthetic mechanism example and zero real affected roots.

## M2: Ultralytics extras removal

This case uses the authentic `ultralytics==8.4.208` closure on Linux x86-64 with CPython 3.11.16, uv 0.13.7, and pip 26.3. Exact manifests and locks are under `inputs/ultralytics-extra/{base,extra,base-restored}/`. The inputs explicitly repeat active Torch and TorchVision requirements to select the official CPU index; other dependencies use official PyPI.

The following setup uses the uv installed by README.md. It downloads the exact Python runtime if necessary and prepares a separate runner environment:

```sh
uv python install 3.11.16
uv venv --python 3.11.16 .venv-m2
uv pip install --python .venv-m2/bin/python -r requirements.txt
```

Preview the inputs and execution sequence:

```sh
.venv-m2/bin/python artifact_tools/replay_cases.py m2 --inputs inputs/ultralytics-extra --out runs/m2-preview --python .venv-m2/bin/python --uv .venv-m2/bin/uv --dry-run
```

The replay downloads the complete official CPU closure and requires at least 60 GiB of free space at startup. This preflight is not a measurement of peak storage. Run the installation when the runtime, network access, and storage are ready:

```sh
.venv-m2/bin/python artifact_tools/replay_cases.py m2 --inputs inputs/ultralytics-extra --out runs/m2-execution --python .venv-m2/bin/python --uv .venv-m2/bin/uv --execute
```

The task creates base, extra, base-restored, fresh-final, and OpenCV-only repair observations in the output directory. Success is reported as `reproduced_missing_provider_payload: true` in `results.json`, with all replay checks true. This portable entry point has been checked with input/command previews; a new full M2 installation was not performed while preparing the repository.

The saved transition contains 39 distributions in base, 66 with the extra, and 39 after extra removal. The extra installs `opencv-python-headless` alongside `opencv-python`; their wheels share 39 paths, including 3 with different expected bytes. After extra removal, the warm run reports successful sync and metadata checks while those 39 shared `cv2` paths are absent. The runtime witness tests `cvtColor` and a YOLO import because a bare namespace import can pass. Matching-final-input fresh/repair observations and an independent repetition establish the history-dependent failure.

This is one real affected root. Dependency nodes do not add affected projects. Earlier public reports describe the shared-file mechanism and related Ultralytics symptoms; the local replay does not establish first discovery. It runs no model inference and downloads no weights.

## Source-switch supplements

Torch and vLLM source-switch observations are separate from the main 133 workflows. Torch changes from a 10-distribution CPU state to a 29-distribution PyPI state; its predefined negative-case stop leaves no paired fresh/repair observation. vLLM changes from 152 to 198 distributions and includes matching-final-input fresh/reinstallation observations. Neither admits a new defect.

The vLLM observations concern installation metadata and selected checks, without GPU inference or a later full rehash of every CUDA payload. The recorded Intel OpenMP metadata difference explains a known compatibility boundary and does not add a mechanism or affected root.
