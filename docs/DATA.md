# Data and Provenance

The repository includes implementation, experiment inputs, saved observations, and tools for recomputing recorded results. [`outputs/expected-results.json`](../outputs/expected-results.json) contains expected numerical values; [EXPERIMENTS.md](EXPERIMENTS.md) maps tasks to their input records. Key inputs and summaries are ordinary files. Detailed stage metadata and command logs are in `data/evidence-*.tar.gz`; `data/evidence-index.json` lists original paths, hashes, and volume membership.

## Download the dataset

Clone the [public repository](https://github.com/cuixiaoyiyi/dependency-installation-consistency-artifact) or download [the complete ZIP](https://github.com/cuixiaoyiyi/dependency-installation-consistency-artifact/archive/refs/heads/main.zip). Both include the implementation and all evidence volumes. No separate dataset download or authentication is required.

For individual files, browse [data/](https://github.com/cuixiaoyiyi/dependency-installation-consistency-artifact/tree/main/data). The [raw evidence index](https://raw.githubusercontent.com/cuixiaoyiyi/dependency-installation-consistency-artifact/main/data/evidence-index.json) lists each volume's repository-relative path and SHA-256. For example, the first volume is [evidence-01.tar.gz](https://raw.githubusercontent.com/cuixiaoyiyi/dependency-installation-consistency-artifact/main/data/evidence-01.tar.gz).

The original experiment records comprise 36,076 files and 789,362,891 bytes before compression. Thirteen evidence volumes occupy 209,914,826 bytes and contain 36,003 members. These original-record totals include the key ordinary files indexed alongside the volumes. Additional portable entry points and convenience indexes are separate. Each volume is below 64 MiB. Exact counts and sizes are also in `data/inclusion-summary.json`.

Verify a downloaded clone or extracted ZIP with:

```sh
python3 artifact_tools/verify_files.py
```

This checks the file manifest and streams through archive members without extracting them. The final JSON should report `"status": "passed"` and an empty `failures` list. Use `python` instead of `python3` on Windows.

## Experimental objects

| Object | Meaning |
| --- | --- |
| Historical audit item | One of the 29 saved evidence assessments tied to an original source revision |
| Package-level contrast | One of 61 assessed claims; several can belong to one audit item |
| Canonical root | One exact published distribution/version with verified repository correspondence |
| Logical workflow | A root paired with update, extras round trip, or relock; intermediate/recovery runs do not add workflows |
| Mechanism category | One locally reproduced installation failure mechanism |
| Affected root | A real canonical root with an admitted failure; the synthetic fixture adds none |

The historical audit and later workflow cohort are separate experiments. The main 82 complete workflows have no admitted defect. The two mechanism examples come from supplementary investigations.

## Historical audit data

`inputs/historical-reports.csv` indexes the audit items. `outputs/issue-validity-audit-20261110.json` contains classifications and per-case evidence. Source revision records, resolver captures, and marker checks are retained as experimental inputs and observations. Original report descriptions and discussion captures are excluded.

The saved classifications are 7 refuted reports, 21 input/scope mismatches, and 1 narrower documentation fix with repair support. No complete original report is verified in its original scope. These classifications do not estimate precision or recall. Original revisions matter because a current branch can have different dependencies and installation instructions.

## Cohort and selection

`inputs/cohort.csv` indexes the 52 roots. `work/stateful-validation-20261111/cohort.json` is the detailed record, including full marker environments and provenance. The cohort combines 12 mapped prior roots, 22 mapped new roots, and 19 qualifying foundational roots; the overlapping NumPy version is counted once.

The new-package selection starts from the saved candidate pool and excludes previously selected repositories. The importance rule uses at least 1,000 historical stars, public/nonfork/nonarchived repositories with primary language Python, and the recorded recent-activity threshold. Candidates are ordered by historical stars, then repository name. The selection protocol records API-failure handling and duplicate repository identities. These are selection-time measurements.

Repository selection and distribution correspondence are separate steps. Source records preserve repository URLs and commits, packaging-file URLs and hashes, canonical package names, exact PEP 440 versions, and captured PyPI metadata. A repository without verified correspondence remains a coverage item. Install requests use exact published distributions.

Key records, available after extraction where necessary, are:

- `corpus/candidates.json` and `corpus/selected.json`: saved candidate and earlier selection context.
- `work/expanded-validation-20261111/new-packages/selection-protocol.json`, `repository-selection.json`, and `distribution-selection.json`: new candidates and source correspondence.
- `work/expanded-validation-20261111/foundational-installs/selection-protocol.json` and `selection.json`: foundational group.
- `work/fp-fixes-20261110/expanded/published/selection.json`: mapped prior group.
- `work/stateful-validation-20261111/protocol.json`, `protocol-v2-addendum.json`, `native-profiles.json`, and `workflow-selection-v2.json`: final workflow inputs.

Use the v2 workflow selection with its addendum. Updates choose the greatest lower stable version in the same epoch from the saved release catalogue, requiring an unyanked native-compatible wheel with an allowed Python version. Crossing major/minor boundaries is allowed. Extras choose the runtime extra with the smallest positive number of newly active direct requirement identities; normalized names break ties, and recorded tooling/aggregate names are excluded. The selections precede installation outcomes.

There are 134 static selections. Excluding setuptools' tooling extra leaves 133 applicable workflows. Preparation and installation failures remain coverage gaps in this denominator.

## Native targets and sources

Recorded profiles use CPython 3.11.16, 3.12.14, 3.14.4, or 3.10.21 on Linux x86-64 as assigned per root. The records include full marker environments and compatible wheel tags. Python major/minor versions alone do not reproduce every marker or native-artifact decision.

Source records identify exact requests, source policies, official index/artifact URLs, filenames, full versions including local suffixes, SHA-256, and captured metadata. The main preparation protocol uses a 250 MiB per-artifact and 500 MiB per-union bound, including cached artifacts. Supplementary large-backend cases have separate resource records and do not replace main-cohort gaps.

## Third-party wheel downloads

[`inputs/artifacts.json`](../inputs/artifacts.json) lists recorded wheel URL/SHA-256 identities from saved preparation and artifact records. Preview the first download:

```sh
python3 artifact_tools/download_artifacts.py --limit 1 --out runs/downloads
```

Download it and verify its SHA-256:

```sh
python3 artifact_tools/download_artifacts.py --limit 1 --out runs/downloads --execute
```

Remove `--limit 1` to download the full list. The default per-file limit is 500 MiB; the downloader stops if a response exceeds that limit or its hash differs. Existing files with the expected hash are reused. Exact installation requests and source settings remain in locks and records. These recorded URLs depend on continued upstream availability.

To rebuild the list from included records without downloading wheels or extracting the volumes:

```sh
python3 artifact_tools/build_download_list.py --out runs/artifacts.json
```

The recorded Ultralytics base and extra closures have compressed sizes of 394,918,800 and 509,176,390 bytes. They share artifacts, so adding these values overcounts distinct downloads. The vLLM supplement records 4,266,236,794 bytes of compressed GPU-side archives. These are experiment input sizes, not repository size or measured peak disk usage.

## Detailed records and limitations

To restore original relative paths for scripts that need them:

```sh
python3 artifact_tools/unpack_data.py
```

Extraction stays beneath the repository root. Existing identical files are skipped; different existing files are not overwritten. The offline summary and tests do not need this step.

Whole third-party repositories, installed environments, wheel payloads, caches, runtime binaries, model weights, report descriptions, and editorial material are excluded. Original metadata and logs preserve historical path text, including Windows/WSL machine paths and references to excluded material. Those strings are observations rather than portable entry points. Use `data/evidence-index.json` to locate the records supplied here.

Saved records reproduce aggregate results and permit evidence inspection. They cannot remeasure omitted installed-file bytes. Some main-cohort archive-path mappings remain unknown even when installed RECORD hashes passed. A later case-specific observation does not erase a historical unknown.

Original implementation and small upstream fixture sources are indexed in `data/implementation-sources.json`; regression-only inputs are listed in `data/regression-inputs.json`. Existing copyright headers are retained. No new repository-wide license is assigned to upstream files.
