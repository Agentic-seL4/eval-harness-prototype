# Airlock: overlap with the discovery prototypes

Inspected 29 October 2026. Local snapshots: `airlock@6557c2693f1de130a95e20c77eccc7b4fe7a5ae2` and `explorations@f0a4c4e97150f3a335f53b5ceb4c6cf410399ecc`. Both checkouts were clean and left unchanged. No remote branches were reviewed.

## Assessment

Airlock is the discovery Microkit broker extracted into a dedicated runtime repository, with the separate LLM sandbox archived alongside it. At this snapshot it has more explicit development plans, but no more mature runtime implementation. Its extraction also leaves broken replay paths. Treat it as the intended continuation described by its authors, not evidence that the planned integration is complete.

For our testing, Airlock is a sensible future home once the extraction faults are repaired. There is no reason to install a second environment: it uses the same native macOS tools, QEMU and Microkit SDK 2.3.1. Until repaired, the discovery broker is the working baseline. This is my recommendation; no setup, repair or experiment has been selected or implemented here.

## Direct overlap

I compared corresponding files byte for byte using Python `Path.read_bytes()`.

| Airlock material | Discovery counterpart | Result |
|---|---|---|
| `src/`, `include/`, `tests/`, `fixtures/` | `microkit-broker/` | All 29 files identical: 15 source/header helpers, one protocol header, eight test modules, five fixtures |
| Ten inherited scripts | `microkit-broker/scripts/` | All identical; Airlock adds `create-issues.py` |
| `Makefile`, `broker.system`, `flow-policy.json` | Same names in `microkit-broker/` | Identical |
| `DESIGN.md`, `PROTOCOL.md`, `DEMO.md`, `LOG.md` | Same names in `microkit-broker/` | Identical |
| Five files in `replay/` | `email-fence/` | Identical copies, but CLI and viewer omitted |
| `archive/sel4-agent-sandbox/` | `sel4-agent-sandbox/` | All 18 files identical |

Counterparts are under `explorations/discovery_phase/prototypes/`. The inherited runtime has five domains: runner, worker, broker, sink and net. The glossary proposes plan, model, monitor, sink and ingress; the code has not yet adopted the rename (backlog issue 1).

There is no integration of the archived sandbox's LLM client, protected store, clock or input checks into the main runtime. Those are backlog issues 5 and 10–13.

## What Airlock adds

- A dedicated [README](../../airlock/README.md), [glossary](../../airlock/docs/GLOSSARY.md), [runtime guide](../../airlock/docs/RUNTIME.md) and separate [claim boundary](../../airlock/docs/CLAIMS.md).
- A [Sprint 2 proposal](../../airlock/docs/PLAN.md) and [26-item backlog](../../airlock/ISSUES.md), covering argument contracts, exact approvals, session epochs, a model connection, trusted logging, CI and evidence reports.
- An issue-creation script. It was inspected selectively and not executed; no issues or messages were sent.

These additions improve organisation and identify implementation gaps. The plans, dates, ownership descriptions and exit criteria are source proposals, not decisions agreed with the user or completed work. `docs/CLAIMS.md` still copies the discovery audit; its promised mapping to deployment assumptions is pending issue 18.

## Extraction faults and documentation cautions

1. **Main tests cannot locate the replay.** [scripts/expected.py:26](../../airlock/scripts/expected.py#L26) still resolves `../email-fence/core.py`, outside Airlock. The actual copy is `replay/core.py`. This affects monitor tests, expected traces and the run-matrix/demo comparison paths. It is independent of installing QEMU or the SDK.
2. **The standalone replay is incomplete.** [replay/test_replay.py:12](../../airlock/replay/test_replay.py#L12) imports `save_html` from the omitted `replay.py`. The copied README also describes CLI/viewer files that are absent. The core engine can still generate reference runs when loaded directly.
3. **Some prose is ahead of the code.** The README opening mentions argument contracts and session fences, but [src/monitor.c](../../airlock/src/monitor.c) and the [Makefile](../../airlock/Makefile) still implement only open, fenced and deliberately late revocation. The glossary correctly lists contract/session as backlog items. Its description of `late` as the paper's Late Fence also conflicts with the inherited protocol's explicit distinction: this implementation is a runtime ordering bug.
4. **Test and matrix counts need care.** The 59-test suite includes SDK-dependent tests, not 59 host-only tests. The matrix has 12 policy/mode/secret combinations plus four benign/denied-Inbox cases; each input mode runs those 16. File/TCP is not an additional factor within a 16-run matrix. The README says preflight runs the matrix; [preflight.sh](../../airlock/scripts/preflight.sh) actually runs the environment check, TCP demonstration, demo and bypass suite, not the full matrix.

## Checks performed

Commands ran in `airlock/` with `PYTHONDONTWRITEBYTECODE=1` and `MICROKIT_SDK` unset. Temporary host compiler outputs were outside the checkout.

| Check | Result |
|---|---|
| `env -u MICROKIT_SDK PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests -q` | Failed: 54 tests reported, 13 skipped, 10 errors, including monitor class setup; errors report the missing sibling replay |
| `env PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s replay -q` | Failed at import: missing `save_html` |
| Main suite with an in-memory path override only | 59 tests reported, 13 skipped; 46 passed |

For the diagnostic override, Python imported `scripts/expected.py`, set `expected.CORE = Path('replay/core.py').resolve()`, then ran `unittest.defaultTestLoader.discover('tests')` through `TextTestRunner`. No source file was patched. The passing result isolates the main host-suite fault to the replay location; it does not validate QEMU execution or repair the checkout.

No SDK build, QEMU run, live model call, CI inspection, Isabelle build or proof check was performed. Discovery QEMU results copied into Airlock remain source-reported, not reproduced here.

## Security and debugging implications

The implementation inherits the discovery scope: a scripted worker, broker-owned permission bits, fixed kernel connections and a fake outgoing sink. Dynamic kernel-capability revocation, fresh-session enforcement, real model integration and realistic benign workloads remain unimplemented in the main runtime.

The worker can leak before the admission fence while Fetch is still allowed. The debug console is an extra unmediated channel; release builds lack the detailed trace. Timing and model-provider disclosure need separate treatment. Tests against handwritten Python definitions do not establish a refinement proof. See [DESIGN.md sections 11–12](../../airlock/DESIGN.md) and the dated claim audit; its kernel-proof status was not independently rechecked in this review.

Airlock adds no debugger integration: it inherits `-g -O2` builds and the same QEMU launcher, without a debugger option. The earlier proposed learning route still applies: reference replay, open/fenced QEMU traces, then focused source debugging. First repair replay packaging and obtain a passing unmodified host suite; discuss any repair or runtime changes before making them.

Inspection covered the file inventory, local history, byte comparisons, README, plans, backlog, claims, glossary, build/launcher/preflight paths and replay/test loading. The discovery core paths were inspected earlier in this chat and are identical here. The copied report PDF, every helper's internals, external planning reports and formal theory sources were not audited in this pass.
