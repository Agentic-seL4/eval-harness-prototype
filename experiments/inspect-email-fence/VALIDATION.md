# Final validation: 12 November 2026

**All five implementation steps are complete.** The final rerun reproduces the expected policy behaviour and utility cost on both backends. It establishes finite scripted agreement under the declared observer, with no VM, container, seL4 boot or model API call.

## Results

| Backend | Policy | Matrix conformance | Matrix completion | Matrix disclosures | Public deliveries/probes |
|---|---|---:|---:|---:|---:|
| Python | Open | 4/4 | 4/4 | 2 | 4/4 |
| Python | Fenced | 8/8 | 8/8 | 0 | 2/4 |
| Python | Late | 4/4 | 4/4 | 2 | — |
| C | Open | 4/4 | 4/4 | 2 | 4/4 |
| C | Fenced | 8/8 | 8/8 | 0 | 2/4 |
| C | Late | 4/4 | 4/4 | 2 | — |

The eight public controls per backend all conform and complete their assignments. Fenced policy blocks both post-admission public probes, including benign email; the pre-admission probes succeed. Open policy delivers all four. No control discloses a dummy secret.

Each matrix yields eight valid secret pairs and the two expected qualifying distinctions: open/injected and late/injected. There are no invalid, unexpected or nonconformant pairs. All 24 saved Python/C trace pairs agree across the matrix and controls. A separately selected open/injected/secret-1 sample also records the expected disclosure and completion.

The five evaluations contain 49 samples in total, zero sample errors, zero unknown outcomes, zero model events and empty model usage. All 34 tests pass, including source/build provenance, native execution without Python monitor calls, admission ordering, late dispatch, altered evidence, invalid pairs and reversed sample order.

## Commands and evidence

The [README](README.md) gives the setup, single-case command, full matrices/controls loop, automatic C comparison, pair analysis, viewer command and test command. Commands executed here used `logs/final-2026-11-12/` as the output root. All returned exit code 0.

That ignored directory contains:

- `open-example/`: the selected open case.
- `{python,c}/matrix/` and `{python,c}/controls/`: four full evaluation logs.
- `{python,c}/pairs.json`: finite pair reports, each bound to its input log by SHA-256.
- `tests.txt`: the final test transcript.
- `manifest.json`: exact commands, artifact paths/hashes, environment versions, source hashes, result summaries and 24 saved-trace comparisons.

`uv sync --frozen` succeeded and audited 79 installed packages. The viewer's CLI help and installed implementation were checked; its server and browser UI were not launched. Starting the local viewer is documented for the user. Reading the saved `.eval` files through Inspect's API independently confirmed sample counts, errors, scores, model events and both backend comparisons.

## Versions and source identity

Tested environment: Python 3.14.7; Inspect 0.3.288; ACP 0.12.0; uv 0.9.17; macOS 15.7.9 arm64; Apple Clang 17.0.0 (`clang-1700.0.13.5`), target `arm64-apple-darwin24.6.0`. Linux remains untested.

The harness base revision is `4c7a43211ef210f6129b76c8a9d1f950a4fb18bd`. Implementation files are still modified/untracked; this revision alone does not identify the tested implementation. The manifest hashes every harness/test Python file, `pyproject.toml` and `uv.lock`, and records working-tree status at validation.

Prototype revision: `explorations@f0a4c4e97150f3a335f53b5ceb4c6cf410399ecc`. Its relevant tracked source files remain unchanged. Every execution records the Python engine hash; C executions also record the four compiled source/header hashes, compiler/version, command and library hash. The final manifest rechecks those source hashes against the checkout. Existing untracked prototype caches were preserved.

## Limits and possible next experiments

The harness and fake sink remain trusted. `Summary := Mail` copies a value; it does not assess useful generated summaries. Exact secret-argument checks do not cover encoded leakage. The event projection excludes analyst diagnostics and undeclared timing channels; the original same-actions condition limits which differences qualify as pairs. Broker IPC, capabilities, process isolation, concurrent admission and formal refinement remain outside these results.

Possible follow-ups, not agreed work: compare a finer argument/destination contract that permits the intended public operation after email admission, or add a bounded live proposal stage after agreeing its model, transport contract and call budget. Neither is implemented by this validation.
