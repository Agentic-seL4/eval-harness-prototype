# Microkit broker: plan and tasks

**Status:** T10 in review (13 October 2026): the observation and proof-scope audit
(DESIGN.md section 12). Every build now also checks the capability tables the
Microkit tool built; a release build prints nothing on the console while the attacker
still sees exactly the `OBS` lines; and no configuration this prototype can be built
in is covered by a completed code-level proof yet. T9 (confinement tests) and T11
(note 06) are in review; `make demo` and [DEMO.md](DEMO.md) are ready for a live
walk-through.

**Goal:** boot a seL4 Microkit system on QEMU whose components and channels realise
paper 1's plan-then-execute information flow for the email example
(*Leaky Summariser / Fenced Summariser*, E1/E2). Its serial trace should match the
[email-fence reference replay](../email-fence/) for every policy, mode and secret.

**Not in scope yet:** a real LLM, real email or network, dynamic kernel-capability
revocation, and proofs. Each enters only through an explicit task below.

## Decisions so far

| Date | Decision |
|---|---|
| 13 Oct | Build natively on macOS: `brew install qemu lld`; Microkit SDK 2.3.1 (macos-aarch64) unpacked outside the repositories and referenced by `MICROKIT_SDK`. |
| 13 Oct | First example: email fence. Exact approval ([note 05](../../notes/05_microkit-mapping/)) follows on the same broker (T12). |
| 13 Oct | Inputs are fixed text files, not real email: the attacker's email and the secret are prefilled at build time into read-only memory regions mapped only into the broker (refined in T2). Runtime attacker input over serial is a later task (T14). |
| 13 Oct | Deliver work to the live repository as numbered patches on a new branch. |
| 13 Oct | T2 questions: the broker decides on tool and arguments only and logs the caller (Q1a); T9 includes a worker that leaks without being injected (Q2); the worker holds the secret, as in the paper (Q3). |
| 13 Oct | Email over TCP comes straight after T8 (T8b): QEMU attaches its second UART to a TCP socket, a small ingress PD fills the inbox, and the attacker receives `OBS` lines on the same socket. The inbox is a mailbox from T3 on, so the switch is a configuration change. TCP/IP inside seL4 (sDDF + lwIP, or a Linux VM) remains a PI scope decision (T14). |

## Pinned environment (T1)

| Component | Version |
|---|---|
| Microkit SDK | 2.3.1, macos-aarch64; SHA-256 `359c2172…1a09475` (full value in the log) |
| Board / configuration | `qemu_virt_aarch64` / `debug` (MCS kernel, seL4 as hypervisor) |
| QEMU | 11.1.2 (Homebrew) |
| Linker | LLD 23.1.3 (Homebrew) |
| Compiler | Apple clang 17.0.0; Homebrew clang 23.1.3 also works |
| Python | 3.14.8 (scripts need 3.9+) |

## Target system

See [DESIGN.md](DESIGN.md) (T2, kept current through T8b). In short: five PDs
(`runner`, `worker`, `broker`, `sink`, `net`) and six memory regions. The secret is a
text file prefilled at build time into a read-only region that only the broker maps;
the email is prefilled into the inbox mailbox in the same way, or written there by the
untrusted `net` PD when it arrives over TCP. Each formal step (`C-ReadT`, `C-ReadU`,
`C-Call`, `C-Tau`) is one broker transaction. The design maps every arrow of the
paper's architecture figure and each of its deployment assumptions to a Microkit
mechanism or a stated gap.

## Tasks

We take these one at a time; each task ends with a short review and a [log](LOG.md) entry.

| ID | Task | Done when | Status |
|---|---|---|---|
| T0 | Decisions and this plan | Plan reviewed | done |
| **M0 · environment** | | | |
| T1 | Toolchain bring-up: QEMU, lld, Microkit SDK 2.3.1; boot the SDK's `hello` example on `qemu_virt_aarch64` | `hello, world` on QEMU from one documented command; versions recorded | done |
| **M1 · design** | | | |
| T2 | Information-flow design (`DESIGN.md`): PDs, memory regions and their read/write rights, channels and priorities, and the transaction order for `AReadT`, `AReadU`, `ACall` and `ATau` | Every arrow in the paper's architecture figure has a named Microkit mechanism or a stated assumption; reviewed by us, ideally by Brijesh | done |
| T3 | Protocol and trace format: request encoding, inbox mailbox layout, buffer sizes, `TRACE`/`OBS` line grammar mapped to `core.py` step fields, build-time configuration | Grammar can express every field the comparison needs; one mailbox layout serves both the file and the socket | done |
| **M2 · email fence end to end** | | | |
| T4 | Skeleton system: system description, Makefile, six PDs that only report start-up | Boots; topology matches `DESIGN.md` | done |
| T5 | Static topology checker: parse the system description, derive the flow graph, check mediation properties; tests include deliberately bad topologies | Good topology passes, every bad one fails with a clear message | done |
| T6 | Monitor core in C (`m0`, `mdecide`, `mnext`, late variant) without Microkit dependencies; host build tested against `email-fence/core.py` | Identical decisions and next states on every input | done |
| T7 | Email-fence PDs: runner, scripted worker, ingress, user data, broker transactions, sink | One configuration boots and prints the expected trace | done |
| T8 | Run matrix: build and boot 12 configurations (open/fenced/late × reference/injected × secret 0/1), parse serial output, compare with `core.py` | All 12 match; injected open and late runs distinguish the secrets, fenced and reference runs do not | done |
| T8b | Email over TCP: QEMU's second UART on a TCP socket; ingress PD (UART driver) fills the inbox mailbox; `OBS` lines go back on the socket; the run matrix sends the same email over the socket | The 12 runs match again with socket input; the attacker's socket shows exactly the `OBS` lines; ingress has no access to the secret, plan memory or context | done |
| **M3 · assurance gaps** | | | |
| T9 | Confinement tests: a worker variant per attempt (undeclared channel via the library and via the kernel, read-only and unmapped memory, forged caller, malformed request, and an un-injected leak); request mutation is impossible by construction | Sink receives the secret only in the un-injected case (Q2); every other attempt stopped by the kernel or broker, each recorded | review |
| T10 | Observation and proof-scope audit: the debug console as an extra channel, separating attacker and analyst output, timing, and which kernel configuration and seL4 proofs apply | Written claim boundary: proven / trusted but unproven / untrusted but confined | review |
| **M4 · write-up** | | | |
| T11 | Note 06 in LaTeX with the report kit: design, results, claim boundary, TikZ topology | PDF built and pages inspected | review |
| **Extensions (scope decisions first)** | | | |
| T12 | Exact approval on the same broker (note 05's first experiment) | Tool-only leaks; exact approval blocks the secret and still sends 7 once | todo |
| T13 | Session lifecycle: broker-owned epoch; restart the worker rather than trusting it to clear context | Old context and old-epoch requests cannot regain authority | todo |
| T14 | TCP/IP inside seL4 (sDDF + lwIP as in LionsOS, or a Linux VM front end); later a Linux VM worker or a real model (tutorial part 4) | Agreed with the PI before starting | todo |

Patches: one per milestone (M1, M2, …) in the workspace `patches/` directory, each
with apply instructions; check with `git apply --check` before applying.

## Claim boundary to carry into every result

Audited in T10; the full version is [DESIGN.md section 12](DESIGN.md).

- **Proven:** nothing about this exact build yet. Microkit always uses the MCS
  kernel; for AArch64 its design proofs are done and the code-level proof is
  scheduled for 2027. A release build does not change this.
- **Trusted but unproven:** the kernel binary in this configuration; the Microkit
  tool (its capability tables are checked against the policy on every build), the
  capDL initialiser, loader, Monitor and libmicrokit; broker, runner, sink and the C
  monitor (tested against `core.py`, not proved); our system description and policy;
  QEMU as the platform.
- **Untrusted but confined:** the worker, `net`, the email and the attacker's client.
- **Not covered:** the debug console as a channel (debug builds), timing, workers that
  leak without an injection (Q2), fresh sessions, an adaptive attacker, and
  correspondence with the Isabelle theories beyond tests.
