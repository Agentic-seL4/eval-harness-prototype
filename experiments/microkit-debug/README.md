# Microkit email-fence debugging

Created 29 October 2026. Work through the tasks in order and record each result before starting the next. The user authorised this debugging experiment; the original repositories and installed SDK remain unchanged.

Goal: observe the same attempted `Fetch(Data 1)` being allowed under `open` and denied under `fenced`, while both runs complete the trusted plan. This is an execution study, not a security proof.

The [extension plan](extension-plan.md) records the original direction and later candidate experiments. The host-backend design has since been selected and implemented as described below.

## Host backend extension

See [HOST_BACKEND.md](HOST_BACKEND.md) for the implemented model link, isolated Python setup, offline validation and opt-in OpenAI campaign. Built-in mode remains the baseline. Live campaign status is recorded in `evidence/llm-campaign/`; do not infer live success from offline tests.

- [x] Initialise the experiment Git repository, baseline commit and `host-llm-backend` branch; preserve original repositories and SDK.
- [x] Implement bounded host backends, alternate guest transport, topology and capability checks.
- [x] Pass offline validation, including the original tests, 16 host configurations and fault checks under both policies.
- [x] Obtain a real API control; replay it under both policies; complete both benign model workflows.
- [ ] Pass every natural model run. The six-attempt campaign is exhausted: malicious 97-byte proposals were rejected against the 64-byte limit. No automatic truncation or successful `none` was substituted. See [results](evidence/validation-2026-11-05.md).

The saved host/reference test logs in `evidence/host-offline/` now complete task 3's
previously pending evidence capture. Historical progress entries below retain the
state at the time of the debugging sessions.

## Fixed configuration

Source: `explorations@f0a4c4e97150f3a335f53b5ceb4c6cf410399ecc`, under `discovery_phase/prototypes/`.

Use `MODE=injected SECRET=1 EMAIL=malicious INBOX=allowed INPUT=file ATTACK=none MICROKIT_CONFIG=debug`. Change only `POLICY` between the two experiments. The normal injected worker uses `ATTACK=none`; bypass variants are excluded.

SDK: `/Users/mt0062/microkit-sdk-2.3.1`. Set `MICROKIT_SDK` explicitly in commands; it is not inherited by the agent's execution shell.

## Tasks

- [x] **1. Inspect source state and installed tools.** Record revision, tracked changes, SDK and tool versions. Do not build or change source. Result below.
- [x] **2. Copy the source into this experiment.** Create `microkit-broker/` and sibling `email-fence/` from the pinned source's tracked files only. Exclude existing builds, output and bytecode. Create `evidence/source-manifest.json` with source revision and SHA-256 hashes; check every copied file against its source. Add local ignore rules for build output and bytecode. Pass: copies match and originals are untouched.
- [x] **3. Run the copied host tests.** In `microkit-broker/`, run `env -u MICROKIT_SDK PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests -v`; run the sibling email-fence tests separately. Save commands, output and exit codes under `evidence/`. Pass: no errors/failures; list skips rather than calling them passes.
- [x] **4. Record the unmodified open baseline.** Set the SDK explicitly and run `make POLICY=open MODE=injected SECRET=1 EMAIL=malicious INBOX=allowed INPUT=file ATTACK=none MICROKIT_CONFIG=debug run`. Save build output and serial log. Compare parsed records with `scripts/expected.py` using its existing comparator. Pass: four broker steps, one `OBS` containing `Data 1`, `Summary=Mail`, final plan counter 3 and `DONE`; all compared fields match.
- [ ] **5. Record the unmodified fenced baseline.** Repeat task 4 with only `POLICY=fenced`. Pass: matching reference records, denied Fetch, no `OBS`, and the same completed plan. Save separately from the open evidence.
- [x] **6. Prepare a source-debug build in the copy.** Retain `-g`; replace `-O2` with `-O0 -fno-inline -fno-omit-frame-pointer`. Copy the SDK linker script to `debug-broker.ld`, changing its initial address from `0x200000` to `0x400000`. Initially link only the broker with that script; the multi-component extension below also gives runner and worker distinct code addresses. Shared-memory mappings stay unchanged. Save a patch of these changes. Use new build directories `build/debug-open` and `build/debug-fenced` so old objects cannot be reused.
- [x] **7. Validate the debug builds before attaching.** Check the generated reports: broker entry `0x400000`, runner `0x600000`, worker `0x800000` (superseding the initial broker-only layout); check LLDB can resolve broker functions and local variables. Boot both images normally and compare their records with the reference and baselines. Pass: unchanged compared behaviour and successful wiring checks. If the layout or behaviour differs unexpectedly, resolve it before continuing.
- [ ] **8. Validate debugger attachment.** Launch the open image directly with the prototype's QEMU machine/device arguments plus `-S -gdb tcp:127.0.0.1:1234`. Load its `broker.elf` in LLDB, connect using `gdb-remote 127.0.0.1:1234`, and set a hardware source breakpoint at `broker.c:204`. Pass: stop in the broker's trusted read with correct source, broker PC, permissions 6 and step count 0. Save the exact working launch and LLDB commands in `evidence/debugger-commands.md`. Debugger compatibility and address-space behaviour must be demonstrated, not assumed.
- [ ] **9. Walk through the open run.** Use the stops below, one breakpoint at a time. Save debugger transcript and serial output. Pass: see secret copying, email admission, worker request, allowed decision and sink effect; final output matches task 4.
- [ ] **10. Walk through the fenced run.** Restart QEMU and LLDB using the fenced image and ELF. Repeat the stops. Pass: permissions become 2 while context is still empty; the same secret-bearing request is denied; dispatch is skipped; plan finishes as in task 5.
- [ ] **11. Record conclusions and limits.** Write a short comparison with observed values and evidence paths. Record debug-build changes and any debugger problems. Recheck original source status. Update this task list and the research index. Separate observations from assumptions; no general containment claim.

## Broker checkpoints for tasks 9–10

Lines refer to the pinned `src/broker.c`, which task 6 does not edit. Stop before the indicated line executes.

| Line | State to inspect | Open expectation | Fenced expectation |
|---|---|---|---|
| 204 | `perms`, `steps`, context count | 6, 0, 0 | Same |
| 206 | `trusted.length`, `trusted.data` | 6 bytes: `Data 1` | Same |
| 210 | `steps`, `perms` | 1, 6 | Same |
| 231 | `email`, context count, `perms` | Malicious email, 0, 6 | Same |
| 234 | `r`, `perms`, context count | Allowed Inbox, 6, 0 | Allowed Inbox, **2**, 0 |
| 238 | Context count and first item | 1, malicious email | Same |
| 251 | `caller`, `request`, `perms` | Worker, Fetch with `Data 1`, 6 | Same request, permissions 2 |
| 254 | `r.decision`, `allowed` | 1, 1 | 2, 0 |
| 258 | Request immediately before sink IPC | Reached | Must be skipped |
| 263 | Post-dispatch/denial state and serial output | One `OBS` | No `OBS` |
| 270 | `steps`, `perms` before final internal step | 3, 6 | 3, 2 |

Permission bits: Inbox=2, Fetch=4, both=6. A value is a length plus bytes: inspect bytes using the recorded length, not an assumed terminating NUL. Inspect runner-owned final memory through `MEM`; it is not mapped into the broker. Use breakpoints across IPC rather than stepping through the kernel. The debug console includes private data and is analyst evidence, not the attacker channel.

## Reusable trace check

From this experiment directory, check an existing run without rebuilding or launching QEMU:

```bash
python3 check_trace.py open-injected-s1-malicious-allowed \
  microkit-broker/build/open-injected-s1-malicious-allowed/serial.log \
  --report evidence/open-comparison.json
```

For the fenced run, replace `open` with `fenced` in the case, log path and report name. Paths are relative to the current directory; the script locates its reference code relative to itself. `--report` is optional and overwrites the named JSON report. Exit codes: 0 match, 1 mismatch, 2 invalid arguments or input/report error.

The script delegates parsing and comparison to the copied `scripts/expected.py`. It checks CONFIG, TRACE, OBS, MEM and DONE, rejects ERR and malformed tagged records, and uses the comparator's per-tag ordering rules. NOTE/boot diagnostics and timing are outside this check. Build/run status must be checked separately. Each report includes the input log's SHA-256 hash.

## Results log

### Task 1 — complete, 29 October 2026

Commands: `git status --short`, `git diff --stat`, `git rev-parse HEAD` in `explorations/`; `command -v` for compiler, linker, QEMU and LLDB; version commands for these tools, Python and Make; read SDK `VERSION` and check its executable/linker-script paths.

- Tracked source has no diff at the pinned revision. Existing untracked `scripts/__pycache__/` and `tests/__pycache__/` under the original broker were left untouched and will not be copied.
- Apple Clang 17.0.0; Homebrew LLD 23.1.4; QEMU 11.1.3; LLDB 1700.0.9.502; Python 3.14.7; GNU Make 3.81.
- SDK reports 2.3.1; executable and AArch64 debug linker script are present at the stated path.
- The user reports `make test` passed in the original prototype. This is user-reported evidence; no new build, QEMU run or debugger attachment was performed in task 1.
- The experiment directory already existed and was empty before this README was added.

### Task 2 — complete, 29 October 2026

- Copied 57 tracked files from the pinned Git revision: 49 in `microkit-broker/`, eight in `email-fence/`. Preserved file modes, including executable scripts.
- Read tracked paths with `git ls-tree` and contents with `git show`; checked the source working files and copied bytes against those blobs.
- [Source manifest](evidence/source-manifest.json) records every path, SHA-256 hash, size and mode, plus the revision and unchanged original Git status.
- Added experiment-local `.gitignore` rules for build/output directories and Python bytecode. Existing build output and untracked bytecode were not copied or removed.
- A separate manifest check verified all 57 copied hashes and modes. No build, test or debug source change was made.

### Host test status

The user's terminal showed the copied broker suite completing with 59 tests reported, 13 skipped, and no failures, and the email-fence suite with 21 passes. Task 3's separate evidence-file capture remains pending; these tests were not rerun for the trace-checker change.

### Task 4 — complete; reusable comparison checked 4 November 2026

- The user ran the open case and saved `evidence/open-baseline.log`; after correcting the terminal PATH, the build and run completed. The serial log shows four transactions, one Fetch observation with `Data 1`, final counter 3, `Summary=Mail`, and DONE.
- Ran `python3 check_trace.py open-injected-s1-malicious-allowed microkit-broker/build/open-injected-s1-malicious-allowed/serial.log --report evidence/open-comparison.json`: PASS, exit 0. The JSON report pins the compared serial log by hash.
- Checked wrapper failure handling with temporary inputs: wrong policy and missing DONE each return 1; missing input file returns 2. Invocation from another directory also worked. No QEMU run or prototype source change was made for this wrapper.

The user subsequently reported PASS for the fenced baseline and both original debug-build checks, then reached broker lines 204 and 206 in terminal LLDB. That walkthrough was allowed to finish; the remaining checkpoints and fenced live walkthrough were not independently recorded here. Task 3 still needs its evidence-file capture.

### Multi-component debugger setup — 4 November 2026

- Added `microkit-broker/debug-runner.ld` and `debug-worker.ld`; explicit Makefile rules link runner at `0x600000` and worker at `0x800000`. Broker remains at `0x400000`. Sink, net and shared-memory mappings are unchanged. The [debug-build patch](evidence/debug-build.patch) records all build changes relative to the pinned discovery Makefile, including the earlier optimisation and broker changes.
- Updated `.vscode/launch.json` for the **microkit-debug workspace root**, fixing the earlier missing `microkit-broker/` path component. Profiles `Microkit: open components` and `Microkit: fenced components` load broker, runner and worker ELF symbols at their linked addresses and connect to QEMU on localhost:1234. `monitor.c` is compiled into broker. Hardware breakpoints remain required. Module load commands use slide 0 without `--load`: they register symbols and do not write code into the guest.
- Rebuilt and booted both debug images using `make BUILD_DIR=build/debug-<policy> POLICY=<policy> MODE=injected SECRET=1 EMAIL=malicious INBOX=allowed INPUT=file ATTACK=none MICROKIT_CONFIG=debug run`, with SDK path set explicitly. Both exit 0 and match the existing comparator. Open emits Fetch with `Data 1`; fenced emits none. Reports confirm all three code-entry addresses. See [validation summary](evidence/components-validation.json) and `evidence/components-{open,fenced}.log`.
- Executed each profile's initialisation and target-creation commands in local LLDB batch mode. All three modules load, and hardware source breakpoints resolve at broker.c:280, monitor.c:38, runner.c:131 and worker.c:170. Outputs: `evidence/components-{open,fenced}-symbols.log`. This checks symbols/configuration with Apple LLDB; it does not claim live attachment through CodeLLDB's bundled backend.

## Using the multi-component VS Code profiles

1. Open `/Users/mt0062/repos/Agentic-seL4/research/experiments/microkit-debug` as the VS Code folder. Its `.vscode/launch.json` contains both profiles.
2. Stop any old QEMU/debugger session. Start a fresh paused QEMU from `microkit-broker/` using the earlier machine arguments and `-S -gdb tcp:127.0.0.1:1234`. For the open profile use `build/debug-open/loader.img`; fenced uses `build/debug-fenced/loader.img`. Images have already been rebuilt for this setup.
3. Set source breakpoints at broker.c:280, runner.c:105, worker.c:140 for startup; monitor.c:38 for policy steps. The debugger may move a function-declaration breakpoint to its first executable line. Request/turn handlers: broker.c:326, runner.c:131, worker.c:170.
4. Select the matching `Microkit: <policy> components` profile and start debugging. Continue past the initial loader stop. Startup stops require a fresh boot. Avoid unqualified function breakpoints such as `init`, because multiple modules define them.
5. Inspect globals belonging to the currently stopped domain. Different domains can reuse shared-memory virtual addresses for different regions, so do not read another domain's globals through the active domain's mappings.

Next: validate live VS Code attachment and component breakpoints, then complete the fenced walkthrough. No source-code changes to the plan, policy or worker were made for this setup.

### VS Code unresolved-breakpoint correction — 4 November 2026

The user's CodeLLDB output showed source locations found but all breakpoints unresolved. The earlier profiles applied module mappings before attachment and set the hardware requirement only before target creation. Updated both profiles: create/add the ELF modules, explicitly require hardware breakpoints on the created target, connect to QEMU, then apply each module's slide-0 mapping. No image rebuild is required.

A separate local QEMU session with CodeLLDB 1.12.3's bundled LLDB 22.1.8 validated the corrected command order: a source breakpoint created before attachment became resolved and hardware-backed, and execution stopped at broker.c:280, PC 0x40001c. See `evidence/attach-fixed.log` and `attach-fixed-serial.log`. Broker/runner/worker module mappings were all registered; live runner/worker stops and the full VS Code adapter path remain to be checked by the user. A diagnostic post-attachment test also stopped there with Apple LLDB (`evidence/attach-apple.log`) and bundled LLDB (`attach-bundled.log`). An initial pre-target-only hardware-setting probe timed out after running to DONE; it did not validate attachment. The probe processes were terminated, and the user's QEMU session was not controlled.

Restart the VS Code debug session and QEMU to catch startup breakpoints. At broker.c:280, `perms` is still zero because initialisation has not executed; the expected value 6 applies after initialisation, for example at broker.c:204.
