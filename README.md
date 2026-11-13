# Dependency Installation Consistency

Implementation, experiment inputs, saved installation observations, and reproduction tools for checking Python dependency installations across environment transitions.

The method follows dependency declarations through resolution, installed metadata, installed files, and selected runtime entry points. It checks the obligations that apply to the actual installation request. Differences between installers or package versions are candidate signals; classifying them as defects requires installation evidence and a matching-input comparison.

## Get the implementation and data

The experiment data are included in this repository. No separate account, access request, Git LFS setup, or dataset service is needed.

```sh
git clone https://github.com/cuixiaoyiyi/dependency-installation-consistency-artifact.git
cd dependency-installation-consistency-artifact
```

Alternatively, download [the complete repository ZIP](https://github.com/cuixiaoyiyi/dependency-installation-consistency-artifact/archive/refs/heads/main.zip), extract it, and open a terminal in the extracted directory. The [data directory](https://github.com/cuixiaoyiyi/dependency-installation-consistency-artifact/tree/main/data) contains the detailed evidence volumes; [the evidence index](https://raw.githubusercontent.com/cuixiaoyiyi/dependency-installation-consistency-artifact/main/data/evidence-index.json) records their paths, sizes, and SHA-256 values. A clone or ZIP already includes all volumes.

Third-party wheels are downloaded separately when rerunning installations. Their recorded URLs and SHA-256 values are in [`inputs/artifacts.json`](inputs/artifacts.json). See [data downloads](docs/DATA.md#third-party-wheel-downloads) for the download command and its size limit.

## Recompute the saved results

Use Python 3.11 or later from the repository root. These commands use only the Python standard library:

```sh
python3 artifact_tools/verify_files.py
python3 artifact_tools/reproduce_results.py --out runs/summary
```

On Windows, use `python` in place of `python3`. The verifier checks supplied files and archive members without extracting them. The summary command writes `summary.json`, `summary.md`, and CSV tables under `runs/summary`; a successful run reports `"status": "passed"`. Neither command installs the tested packages.

| Experiment component | Saved result |
| --- | --- |
| Historical evidence audit | 29 reports, 61 package-level contrasts: 7 reports refuted, 21 input/scope mismatches, and 1 narrower documentation fix with repair support |
| Workflow cohort | 52 exact published roots; 156 root-workflow slots; 133 applicable workflows |
| Execution coverage | 82 complete workflows: 33 updates, 15 extras round trips, and 34 relocks; 51 coverage gaps |
| Complete main-batch workflows | No admitted defect; file-inspection unknowns remain recorded |
| Supplementary mechanism examples | 2 locally reproduced mechanisms: synthetic source reuse and Ultralytics extras removal; 1 real affected root |

The supplementary examples are separate from the main-batch coverage totals. Dependency nodes and repeated runs do not add affected roots. These observations do not estimate detector precision, recall, or ecosystem-wide defect prevalence.

## Prepare the tools and run the tests

On Linux or in a WSL shell:

```sh
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -r requirements.txt
python -m unittest discover -s tests -v
```

On Windows, create the environment with `python -m venv .venv` and activate it in PowerShell with `.venv\Scripts\Activate.ps1`. The offline tasks and tests can run on Windows; installation replays require Linux x86-64.

The requirements file records the runner dependencies, including uv 0.13.7 and pip 26.3. Tests use the supplied small fixtures and do not require extracting evidence volumes. The [experiment guide](docs/EXPERIMENTS.md) gives commands for core analysis, the localhost-only source-reuse replay, and the larger Ultralytics replay. Installation entry points default to showing a plan; add `--execute` to run an installation.

## Repository contents

| Directory | Contents |
| --- | --- |
| [`drc/`](drc/) | Declaration parsing, context construction, resolver adapters, and scoped consistency checks |
| [`artifact_tools/`](artifact_tools/) | Portable entry points for verification, summaries, downloads, and replays |
| [`scripts/`](scripts/) and [`tests/`](tests/) | Experiment code and regression tests |
| [`inputs/`](inputs/) | Cohort/workflow indexes, recorded wheel downloads, and exact three-state Ultralytics inputs |
| [`reproductions/`](reproductions/) | Synthetic source-reuse reproduction |
| [`outputs/`](outputs/) | Experiment summaries and expected numerical results |
| [`work/`](work/) | Key experimental records in their original relative layout |
| [`data/`](data/) | Detailed metadata, logs, evidence volumes, provenance, and file indexes |

See [DATA.md](docs/DATA.md) for selection rules, native targets, provenance, and omitted large files. New run outputs belong under `runs/`. Saved observations describe recorded inputs and dates; live package indexes may change. The full cohort harness retains original machine paths, so rerunning all workflows requires adapting those paths and preparing the recorded runtimes and package closures.
