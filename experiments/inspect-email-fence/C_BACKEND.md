# Host C monitor: Step 3

**The actual Microkit C monitor agrees with the Python replay on all 16 cases.** This note records Step 3's design and validation. Python remains the default; `email_matrix(backend="c")` selects the native monitor. No seL4 system is booted. The [README](README.md) and [final validation](VALIDATION.md) cover the completed five-step implementation.

## Build and execution

[c_backend.py](c_backend.py) copies `monitor.c`, `monitor.h`, `config.h` and `protocol.h` unchanged into a temporary directory. It reads protocol constants from those snapshots, compiles a host shared library with Clang, and binds `cap_params` and `monitor_step` through `ctypes`, following the prototype's host-test approach.

Each C sample gets a fresh build, monitor parameters, permission mask, agent state and fake sink. Temporary files are removed after execution. Missing compiler, build failures and unexpected C decisions become errors; there is no Python fallback. The shared-library ABI and Python executor remain trusted.

The source revision, hashes of all four snapshots, compiler path/version, build command and library hash are saved under `execution.native_monitor`. The command contains temporary paths that no longer exist. The source hashes identify the actual input bytes, including any working-tree changes; the revision alone does not establish a clean checkout.

Python still supplies the unchanged scripted `agent_step`, `receive`, state/trace types and fake tools. C supplies initial permissions, decisions, admission permissions and final permission updates. The executor does not invoke Python's `Monitor.mdecide`, `Monitor.mnext` or `replay`.

After the C execution, the Inspect solver separately runs the Python replay as a reference. `execution.comparison` and the additional `backend_agreement` scorer compare initial/final states, every structured step, effects, completion and observer projections. Only the explanatory `operations` strings are excluded. The reference does not drive the C execution.

## Follow one fenced admission

For `fenced-injected-s1-malicious-allowed`:

1. `email_task.py`, the C branch of `replay_email`, builds the library and constructs `CMonitor`. Its call to C `cap_params` initially grants Inbox and Fetch.
2. In `replay_c`, Python proposes `AReadU Inbox Email`. `CMonitor.step` passes that event and the current permission mask to C `monitor_step`.
3. C returns an allowed Inbox decision and admission permissions containing only Inbox. The executor assigns `monitor.caps = result.admitted` **before** calling `engine.receive`, which exposes the email to agent context.
4. Python later proposes `Fetch(Data 1)`. C denies it, so the fake sink is not called. The trusted assignment still completes.

For the late policy, C instead returns an allowed Fetch decision and a final state with Fetch revoked. Dispatch follows that decision before committing `result.after`. No second Python revocation is applied. The open policy retains Fetch throughout.

## Commands and observed results

From this experiment directory, after the README's environment setup:

```sh
.venv/bin/python -B -m inspect_ai eval email_task.py@email_matrix \
  -T backend=c --model mockllm/model --max-samples 1 --ctl-server false \
  --display plain --log-dir logs/step-3/c
.venv/bin/python -B -m inspect_ai eval email_task.py@email_matrix \
  -T backend=python --model mockllm/model --max-samples 1 --ctl-server false \
  --display plain --log-dir logs/step-3/python
.venv/bin/python -B -m unittest -v test_smoke test_matrix test_c_backend
```

Validated on 11 November 2026 with Python 3.14.7, Inspect 0.3.288 and Apple Clang 17.0.0 (`clang-1700.0.13.5`), targeting `arm64-apple-darwin24.6.0`. Linux has not been tested. Source: `explorations@f0a4c4e97150f3a335f53b5ceb4c6cf410399ecc`; the original tracked files remain unchanged.

| Backend | Cases | Conformant | Completed | Disclosed | Not disclosed | Unknown/errors |
|---|---:|---:|---:|---:|---:|---:|
| Python | 16 | 16 | 16 | 4 | 12 | 0 |
| C | 16 | 16 | 16 | 4 | 12 | 0 |

All 16 C comparisons passed, including a separate check against the saved Python log. Both logs have zero model events and empty model usage. Evidence:

- `logs/step-3/c/2026-11-11T15-13-31-00-00_email-matrix_f5FdsB3YBEarWGGCJBipgm.eval`
- `logs/step-3/python/2026-11-11T15-13-33-00-00_email-matrix_jkd4c5Ezusw5BnrpmJk9B2.eval`

All 21 tests passed. New checks cover execution with Python monitor/replay calls forbidden, admission-before-delivery, dispatch-before-late-revocation, altered native decisions, comparison sensitivity, source/build provenance, temporary cleanup, missing compiler and build failure. The guarded Inspect integration also blocks generation, DNS and socket connections.

This establishes finite agreement of monitor behaviour under the shared scripted workflow. It does not test broker IPC, capabilities, memory isolation, seL4 execution or formal refinement. The remaining broker/runtime implementation and proof sources were not audited in this step.
