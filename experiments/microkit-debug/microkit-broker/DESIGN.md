# Microkit broker: information-flow design

**T2, agreed 13 October 2026; kept current through T8b.** This maps paper 1's email
example onto Microkit mechanisms. It is built: [README.md](README.md) says how to run
it, and the [work log](LOG.md) records what was checked. The design does not prove
anything; section 9 lists what each part of it rests on.

**Sources.**

- *Paper 1:* `prompt-injection-RS@ee890ac`, read-only: the architecture figure
  (`fig:arch`, `figures/architecture.tex`), the deployment assumptions
  (`sections/threat.tex`) and the composite step (`fig:compose`, `sections/language.tex`).
- *Theories:* `Email_Setting`, `Email_Leak`, `Email_Fenced`, `Agent_Lang`,
  `Agent_Compose` and `Inject_Call` are unchanged between `89db278` (the commit the
  [email-fence replay](../email-fence/) follows) and `ee890ac`.
- *Microkit:* SDK 2.3.1 manual, sections 2 (concepts), 3.1.2 (proofs), 6 (libmicrokit)
  and 7 (system description file).

## 1. The system at a glance

Five PDs and six memory regions. The arrows are the only paths the kernel allows. The
`net` PD and the attacker's TCP connection came in T8b (section 10). With file input
the email is prefilled into the inbox, `net` idles, and QEMU's second serial port is
unconnected.

```mermaid
flowchart LR
    A[/attacker<br/>TCP client, or email.txt/] -->|email over TCP| U[(uart1<br/>second PL011)]
    A -. file mode: build-time prefill .-> IN
    U <-->|registers · irq 40| N[net PD · prio 40<br/>the attacker's link]
    N -->|writes one email per line| IN[(inbox<br/>mailbox)]
    N -->|notify: email arrived| B
    SF[/secret.txt<br/>trusted user data/] -. build-time prefill .-> SE[(secret<br/>region)]
    IN -->|read-only map| B
    SE -->|read-only map| B
    R[runner PD · prio 100<br/>fixed plan, pc] -->|call: READ_T, READ_U, TAU| B[broker PD · prio 150<br/>m0 · mdecide · mnext]
    B -->|notify: retry READ_U| R
    R -->|writes| PM[(plan_mem<br/>region)]
    PM -->|read-only map| W[worker PD · prio 50<br/>scripted model]
    B -->|writes, after the fence| CX[(context<br/>region)]
    CX -->|read-only map| W
    R <-->|notify: turn / done| W
    W -->|call: CALL tool args| B
    B -->|call: COMMIT, allowed only| S[sink PD · prio 200<br/>fake Fetch]
    S -->|appends OBS lines| OB[(obs_out<br/>region)]
    OB -->|read-only map| N
    S -->|notify| N
    U -->|OBS lines back over TCP| A
    B -.-> D[TRACE lines<br/>analyst console]

    classDef trusted fill:#E7EEF5,stroke:#24405C,color:#16222E,stroke-width:2px;
    classDef monitor fill:#FDF3E2,stroke:#A5690C,color:#16222E,stroke-width:3px;
    classDef untrusted fill:#FAE9E7,stroke:#A83226,color:#16222E,stroke-width:2px,stroke-dasharray:5 3;
    classDef output fill:#E6F1EB,stroke:#2C6B4F,color:#16222E,stroke-width:2px;
    classDef diagnostic fill:#EEEAF6,stroke:#5B4B8A,color:#16222E,stroke-width:2px;
    classDef region fill:#FFFFFF,stroke:#6B7785,color:#16222E,stroke-width:1px;

    class R,SF,SE trusted;
    class B monitor;
    class W,A,IN,N,U untrusted;
    class S output;
    class D diagnostic;
    class PM,CX,OB region;
```

Colours follow note 05 and the paper: blue trusted, amber broker, dashed red
untrusted or attacker-facing, green mediated output, purple private diagnostics,
white shared memory.

| PD | Role in the paper | Priority | Maps | Channels | Trust |
|---|---|---|---|---|---|
| `sink` | Sink tool `Fetch` (the attacker's server) | 200 | `obs_out` rw | from `broker` (call); to `net` (notify) | trusted code; its `OBS` lines are the attacker view |
| `broker` | Runtime monitor | 150 | `secret` r, `inbox` r, `context` rw | from `runner` and `worker` (call); to `sink` (call); to `runner` and from `net` (notify) | trusted |
| `runner` | Trusted interpreter running the fixed plan | 100 | `plan_mem` rw | to `broker` (call); `worker` (notify both ways) | trusted |
| `worker` | Model | 50 | `plan_mem` r, `context` r | to `broker` (call); `runner` (notify both ways) | untrusted |
| `net` | The attacker's link: source writer and sink transport | 40 | `uart1` rw (device), `inbox` rw, `obs_out` r; interrupt 40 | to `broker` (notify); from `sink` (notify) | untrusted, confined |

Microkit's own Monitor PD (`MON|` lines) remains the default fault handler.
It is not our monitor.

**Sources are memory regions, not PDs** (a change from the plan's first draft). The
manual (§2.4.1, §7.2) lets a region be prefilled from a file at build time, so the
secret is a text file in a read-only region that only the broker maps. In T8b the
ingress PD returned as `net`. It writes the inbox from the attacker's TCP
connection and carries the sink's `OBS` lines back: one PD for the attacker's
link, holding exactly the attacker's two capabilities in the paper, writing the
source and observing the sink.

## 2. Every arrow in the paper's architecture figure

| Arrow in `fig:arch` | Realisation | Enforced by |
|---|---|---|
| user request → planner → plan (fixed) | No planner yet: the plan is hand-written and compiled into `runner` | Build; `runner`'s image is not mapped into any other PD |
| user data → agent ("reads") | `READ_T`: the broker reads `secret` and returns the value; the runner stores it in `plan_mem` | `secret` mapped only into `broker`, read-only |
| plan ↔ model, and the model's prompt (instruction, user data, untrusted content) | The runner signals a turn; the worker reads `plan_mem` and `context`, then signals done | `plan_mem` and `context` read-only in `worker` |
| planned calls → monitor → sinks | `CALL` from `runner` (E1's plan makes none; the approval case will) | Channel `runner`→`broker` (call only) |
| injected call → monitor → sinks | `CALL` from `worker` | `worker`'s only outbound call is to `broker` |
| sources → monitor → model ("untrusted content"; optional sanitiser) | `READ_U`: the broker decides, updates its state, then copies `inbox` into `context` (a sanitiser would sit here) | `inbox` mapped only into `broker` |
| sinks → attacker ("observes allowed calls") | `sink` prints one `OBS` line per committed call; `net` sends it down the attacker's socket | `sink` reachable only from `broker`; `net` can only read `obs_out` |
| attacker → sources ("writes") | `email.txt` prefilled into `inbox`, or a line sent over TCP that `net` writes into the inbox mailbox | Build, or the `net` PD; only `net` and the build write `inbox` |
| monitor drawn across every path | The system description's topology | Kernel: no map and no channel means no access |

## 3. Formal steps as broker transactions

The broker is single-threaded and handles one call at a time, which gives the
paper's "decides one request at a time". Each transaction applies one rule of
`fig:compose` and prints one `TRACE` line.

| Formal rule | Request | Broker transaction |
|---|---|---|
| `C-ReadT` | `READ_T` from runner | `v := secret`; `μ := mnext μ (AReadT v)`; return `v` |
| `C-ReadU` | `READ_U Inbox` from runner | `(Allowed, μ'') := mdecide μ Inbox []`; `μ := mnext μ'' (AReadU Inbox v)`; **then** append `v` to `context`; return `Allowed, v` |
| `C-ReadUDenied` | same | `(Denied, μ') := mdecide μ Inbox []`; `μ := μ'`; `context` unchanged; return `Denied` (the runner stores `fail`) |
| `C-Call` | `CALL t args` from runner or worker | `(Allowed, μ') := mdecide μ t args`; `μ := μ'`; call `sink` with `COMMIT t args`; return `ok` |
| `C-CallDenied` | same | `(Denied, μ') := mdecide μ t args`; `μ := μ'`; nothing reaches `sink`; return `fail` to the caller only |
| `C-Tau` | `TAU` from runner (log only) | No decision and no `mnext`. Lets the broker print the complete step order and apply the late policy's delayed revocation exactly where `core.py` does |
| `C-New` | — | Not in E1; T13 |

The decision on `READ_U` takes no content (`mdecide μ t []`), as in the paper. It
therefore cannot depend on what the email says.

**The monitor in C (T6).** [`src/monitor.c`](src/monitor.c) has no Microkit
dependency:

- `cap_decide` and `cap_obs` transcribe `capDecide` and `capObs` from
  `Agent_Compose.thy`.
- `cap_params` supplies the instance parameters: `open` is `E1L` (`Email_Leak.thy`:
  `{Fetch, Inbox}`, no grants, nothing revoked), `fenced` is `E1F`
  (`Email_Fenced.thy`: `revokeOnU = {Fetch}`), and `late` is `E1L` plus `core.py`'s
  deliberately late revocation.
- `monitor_step` is the monitor's half of each row in the table above; the broker
  carries out the effects.

`tests/test_monitor.py` compiles the file for the host and compares it with
`core.py`'s monitor and with a literal transcription of the Isabelle definitions on
every state, tool and label. It also checks every step of all 16 replays. Planted
bugs in the C code are caught.

**Fenced, injected run (secret 1).** The worker cannot see the email before step 2
completes, because `inbox` is not mapped into it. By the time the email appears in
`context`, Fetch has already been revoked.

```mermaid
sequenceDiagram
    participant R as runner
    participant W as worker
    participant B as broker
    participant S as sink
    R->>W: notify turn  (q = 0)
    W->>R: notify done  (context empty: nothing to obey)
    R->>B: READ_T
    B-->>R: "Data 1"  (step 1, mnext grants nothing)
    R->>W: notify turn  (q = 1)
    W->>R: notify done  (context empty: nothing to obey)
    R->>B: READ_U Inbox
    Note over B: decide Inbox [] → Allowed<br/>mnext: revoke Fetch<br/>then copy email into context
    B-->>R: Allowed, email  (step 2)
    R->>W: notify turn  (q = 2)
    W->>B: CALL Fetch ["Data 1"]  (obeys the email)
    Note over B: decide → Denied (Fetch revoked)
    B-->>W: fail  (step 3; nothing sent to sink)
    W->>R: notify done
    R->>B: TAU  (Summary := Mail, step 4)
```

Under the **open** policy, step 3 is allowed and the sink prints `OBS Fetch [Data 1]`.
Under the deliberately **late** policy, the broker delivers the email first and
revokes Fetch only after the next step, so step 3 still leaks. These are the
behaviours `core.py` computes; T8 compares the two automatically.

**Worker turns.** The runner gives the worker one turn before each planned step and
waits for "done". This matches the formal semantics, which checks for an injection
before every agent step. With `e1_pick`, the worker obeys when its oracle state
`q` (planned steps so far plus its own injected calls) is 2 and the email is in
`context` ([PROTOCOL.md](PROTOCOL.md) §1). Turn discipline is a property of
our *scripted* worker, not something the kernel enforces. An untrusted worker can call
the broker whenever it is scheduled. T9 tests workers that ignore their turns.

## 4. The paper's deployment assumptions

The paper (`sections/threat.tex`) lists seven obligations on a runtime. This is how
each one is met here, or why it is not.

| Assumption | How it is met | Rests on | Gap |
|---|---|---|---|
| Trusted execution | Plan and pc live in `runner`; `worker` can read `plan_mem` but not write it, and cannot reach `runner`'s image | Kernel (address spaces) + `runner` code | — |
| Complete mediation, one request at a time | `worker` has no map of `inbox` or `secret` and no channel to `sink`; `net` reaches the rest only through `inbox` and a notification to the broker; the broker serialises requests | Kernel + system description + `broker` code; checked statically (T5), on the built capability tables (T10) and by misbehaving workers (T9) | Debug console in debug builds (section 12) |
| Mediated reads | The email reaches `context` only inside `READ_U`, after the decision and `mnext` | Kernel (only the broker maps `inbox`) + `broker` code order | — |
| Silent denials | A denial reaches only the caller, never `sink` | `broker` code | A denial is visible to the worker. The worker can signal the attacker only through allowed calls and timing (section 12) |
| Limited observation | The attacker view is `sink`'s `OBS` lines; with TCP input it is the attacker's socket, which carries exactly those lines (checked in every TCP run) | `sink` and `net` code | The analyst's debug console shows everything, and every PD can print to it in debug builds; a release build prints nothing (section 12) |
| Fresh sessions | Not exercised by E1 | — | T13 |
| Trusted channels | `secret.txt` is fixed at build time and mapped read-only into the broker alone | Build + kernel | — |

The paper adds that mediation alone does not stop the model's schedule from depending
on secrets. Our scripted worker's schedule is fixed. A real or adversarial worker
could time its requests on the secret, so this stays open (section 12).

## 5. System description

The real file is [`broker.system`](broker.system) (T4); a test keeps this copy identical.
The build writes `secret.bin` and `inbox.mbox` from the fixtures into each
configuration's build directory, which is the Microkit tool's search path.

```xml
<system>
    <memory_region name="secret"   size="0x1000" page_size="0x1000" prefill_path="secret.bin" />
    <memory_region name="inbox"    size="0x1000" page_size="0x1000" prefill_path="inbox.mbox" />
    <memory_region name="context"  size="0x1000" page_size="0x1000" />
    <memory_region name="plan_mem" size="0x1000" page_size="0x1000" />
    <memory_region name="obs_out"  size="0x1000" page_size="0x1000" />
    <memory_region name="uart1"    size="0x1000" phys_addr="0x9040000" />

    <protection_domain name="sink" priority="200">
        <program_image path="sink.elf" />
        <map mr="obs_out" vaddr="0x2000000" perms="rw" setvar_vaddr="obs_out" />
    </protection_domain>

    <protection_domain name="broker" priority="150">
        <program_image path="broker.elf" />
        <map mr="secret"  vaddr="0x2000000" perms="r"  setvar_vaddr="secret"  setvar_prefill_size="secret_prefill_size" />
        <map mr="inbox"   vaddr="0x2001000" perms="r"  setvar_vaddr="inbox"   setvar_prefill_size="inbox_prefill_size" />
        <map mr="context" vaddr="0x2002000" perms="rw" setvar_vaddr="context" />
    </protection_domain>

    <protection_domain name="runner" priority="100">
        <program_image path="runner.elf" />
        <map mr="plan_mem" vaddr="0x2000000" perms="rw" setvar_vaddr="plan_mem" />
    </protection_domain>

    <protection_domain name="worker" priority="50">
        <program_image path="worker.elf" />
        <map mr="plan_mem" vaddr="0x2000000" perms="r" setvar_vaddr="plan_mem" />
        <map mr="context"  vaddr="0x2001000" perms="r" setvar_vaddr="context" />
    </protection_domain>

    <protection_domain name="net" priority="40">
        <program_image path="net.elf" />
        <map mr="uart1"   vaddr="0x2000000" perms="rw" cached="false" setvar_vaddr="uart_regs" />
        <map mr="inbox"   vaddr="0x2001000" perms="rw" setvar_vaddr="inbox" />
        <map mr="obs_out" vaddr="0x2002000" perms="r"  setvar_vaddr="obs_out" />
        <irq irq="40" id="0" />
    </protection_domain>

    <!-- calls; the broker may wake the runner when the email arrives -->
    <channel>
        <end pd="runner" id="0" pp="true" notify="false" />
        <end pd="broker" id="1" />
    </channel>
    <!-- calls only: neither end may notify -->
    <channel>
        <end pd="worker" id="0" pp="true" notify="false" />
        <end pd="broker" id="2" notify="false" />
    </channel>
    <channel>
        <end pd="broker" id="3" pp="true" notify="false" />
        <end pd="sink"   id="0" notify="false" />
    </channel>
    <!-- turn / done notifications -->
    <channel>
        <end pd="runner" id="1" />
        <end pd="worker" id="1" />
    </channel>
    <!-- one-way notifications: an email has arrived; new OBS lines to send -->
    <channel>
        <end pd="net"    id="1" />
        <end pd="broker" id="4" notify="false" />
    </channel>
    <channel>
        <end pd="sink"   id="1" />
        <end pd="net"    id="2" notify="false" />
    </channel>
</system>
```

Checked on 13 October: the T2 draft was accepted unchanged with stub PDs, and the
broker read both prefilled files with exact sizes from `setvar_prefill_size`. The
tool rejects the description if `worker` is given a higher priority than `broker`.
T4 replaced the stubs with the skeleton PDs in `src/`.

Why it is shaped this way:

- **Priorities** follow the call graph: `runner` and `worker` call `broker`, which
  calls `sink`. Each callee has strictly higher priority, and the graph is acyclic
  (manual §2.5.1).
- **Calls carry the data.** Arguments and results travel in message registers
  (up to 64 words), which the kernel copies (§6.3). A worker therefore cannot change
  a request after the broker has checked it, and no shared request buffer is needed.
- **Caller identity.** The broker learns which channel a call arrived on from the
  kernel. The manual calls this unforgeable, so a `from=runner` field in a message
  proves nothing; the channel does.
- **Least authority on channels.** `notify="false"` removes the ability to signal
  where it is not needed. The worker can call the broker but not wake it; only the
  broker can reach the sink; `net` can wake the broker but not the reverse; the sink
  can wake `net` but not the reverse.
- **`net` has the lowest priority.** It is untrusted, so it may not delay trusted PDs.
  In file mode it starts only after the plan has finished.

## 6. Static checks (T5)

`scripts/check_topology.py` checks `broker.system` against
[`flow-policy.json`](flow-policy.json) and `src/topology.h`. Every build runs it
before the Microkit tool, so a description that fails is never built;
`make check-topology` runs it alone.

**The flow graph** has one node per PD and memory region:

- A read mapping is an edge from the region to the PD, and a write mapping one from
  the PD to the region. A mapping without `perms` counts as read-write, Microkit's
  default.
- A protected call carries data both ways.
- A notification is a one-way edge.
- An interrupt is an edge from its device (`irq 40`) to the PD that receives it.

Every PD except the broker is assumed to forward whatever reaches it. This is
conservative: trusted code that would never forward still counts as a path. Timing
and other covert channels are not modelled (section 12). Section 12 also checks the
capability tables the Microkit tool actually built, after it runs.

The policy gives upper bounds: a description may grant less than it allows, never more.

| Check | Fails when |
|---|---|
| supported | an element whose authority the graph does not model appears: child PDs, virtual machines, capability sharing and so on |
| classified | a PD or region is missing from the policy, or the policy names a PD that does not exist |
| region access | a PD reads or writes a region beyond the policy's readers and writers, or maps anything executable |
| untrusted authority | an untrusted PD holds a mapping, call or notification beyond its bound. `worker`: `plan_mem` and `context` read-only, a call to the broker, notifications to the runner. `net`: `uart1` and `inbox` read-write, `obs_out` read-only, notifications to the broker |
| interrupts | a PD receives an interrupt the policy does not give it (trusted PDs get none), or two PDs share one |
| sink reachability | anything but the broker, or the sink's own `obs_out` buffer, has an edge into the sink |
| mediation | a path avoids the broker from `secret` or `inbox` to `sink`, from `inbox` to `worker`, from `worker` to `sink`, from `secret` or `worker` to `net`, or from `net` to `worker` |
| priorities | a call goes to an equal or lower priority, or the call graph has a cycle |
| channel ids | `src/topology.h` and the description disagree on a channel identifier, or a PD uses one twice |

`tests/test_topology.py` breaks the description in 19 ways. Each must fail the
expected checks with a message that names the problem, for example
"worker reaches sink without broker: worker -> runner -> scratch -> sink" for a
region shared by the runner and the sink. The Microkit tool independently rejects
calls to lower priorities.

The graph derived from `broker.system` (`check_topology.py --mermaid`; a test keeps
this copy current):

```mermaid
flowchart LR
    secret[(secret)]
    inbox[(inbox)]
    context[(context)]
    plan_mem[(plan_mem)]
    obs_out[(obs_out)]
    uart1[(uart1)]
    irq40{{irq 40}}
    sink[sink · prio 200]
    broker[broker · prio 150]
    runner[runner · prio 100]
    worker[worker · prio 50]
    net[net · prio 40]
    obs_out -->|read| sink
    sink -->|write| obs_out
    secret -->|read| broker
    inbox -->|read| broker
    context -->|read| broker
    broker -->|write| context
    plan_mem -->|read| runner
    runner -->|write| plan_mem
    plan_mem -->|read| worker
    context -->|read| worker
    uart1 -->|read| net
    net -->|write| uart1
    inbox -->|read| net
    net -->|write| inbox
    obs_out -->|read| net
    runner <-->|call| broker
    broker -->|notify| runner
    worker <-->|call| broker
    broker <-->|call| sink
    runner -->|notify| worker
    worker -->|notify| runner
    net -->|notify| broker
    sink -->|notify| net
    irq40 -->|interrupt| net
    style sink fill:#E7EEF5,stroke:#24405C
    style broker fill:#FDF3E2,stroke:#A5690C,stroke-width:3px
    style runner fill:#E7EEF5,stroke:#24405C
    style worker fill:#FAE9E7,stroke:#A83226,stroke-dasharray:5 3
    style net fill:#FAE9E7,stroke:#A83226,stroke-dasharray:5 3
```

## 7. Questions settled in review

Decided 13 October: Q1 (a), Q2 as proposed (T9 records the result), Q3 yes; Q4 goes to T3.

**Q1. Should the broker use the caller's identity?** The paper's `mdecide` sees a tool
and arguments, not who asked, because the paper's agent is one stream of events. Here
the kernel tells the broker whether a call came from the runner or the worker.

- *(a) Paper-faithful (recommended for the MVP):* decide on tool and arguments only,
  and log the caller. This reproduces the paper's leak and its fence.
- *(b) Origin-aware:* deny every call that comes from the worker. With a trusted runner,
  injected calls become impossible, and the remaining attacks are values the worker
  writes that the plan later uses (*Poisoned Variable*, *Tagged Branch*). This is a
  stronger design, but it needs its own formal argument and a different reference.

**Q2. What about a worker that leaks without being injected?** Under every policy,
Fetch is allowed until the email is read, and the secret is in `plan_mem` from step 1.
A worker that sends it before any email arrives leaks. Relative security does not cover
this: its model deviates only by obeying injected content. It is the kickoff's
"agentic AI as a threat in its own right". Options are to accept it as out of scope,
to adopt Q1(b), or to withhold the secret from the worker. T9 will include such a
worker so the result is recorded either way.

**Q3. Does the worker need the secret?** In E1 the model's prompt includes the user
data, so faithfulness says yes. Withholding it is a different threat model
(note 05 makes the same point).

**Q4. Values.** The formal values are `Data 0`, `Data 1` and `Email`. The fixtures are
short text files. T3 fixes how each file maps to its formal value for the comparison
with `core.py`, and what phrase the scripted worker recognises as the instruction.

## 8. Trace lines

The grammar is in [PROTOCOL.md](PROTOCOL.md) §5. All records go to the debug console:

- `TRACE` (broker): step number, caller, event, decision, monitor state before and after.
- `OBS` (sink): one line per committed call. This is the attacker view; with TCP input
  the same lines also go down the attacker's socket, and nothing else does.
- `MEM` and `DONE` (runner): plan memory when the plan finishes.
- `NOTE` (any PD): diagnostics, such as the worker's turns and the broker's
  "inbox not ready; runner waits".

## 9. What each part rests on

| Layer | Status |
|---|---|
| seL4 kernel | Microkit always uses the MCS configuration, which "is still undergoing verification, scheduled to complete for RISC-V in 2026 and AArch64 in 2027" (manual §3.1.2). Design-level MCS proofs are done; code-level ones are not. Section 12 has the full claim boundary. |
| Microkit tool and CapDL initialiser | Trusted. The capability tables the tool builds are checked against the policy on every build (section 12); the initialiser's run-time behaviour is not |
| Broker, runner, sink | Our C code; trusted, not verified. The monitor functions are tested against `core.py` (T6) |
| Worker, email | Untrusted; confined by the topology |
| `net` PD | Untrusted; confined like the worker. Its PL011 driver is ours and has run only on QEMU |
| Correspondence with the Isabelle theories | Tested on finite runs only (T8); no refinement proof |

## 10. Email over TCP (T8b)

Built 13 October. The attacker connects to QEMU on the host; inside seL4 the bytes
arrive on QEMU's second PL011 UART, so the system needs no TCP/IP stack.

- **Device and interrupt.** The second PL011 sits at `0x9040000` with interrupt SPI 8,
  which Microkit names `irq="40"` (the GIC interrupt number, SPI + 32, as in the SDK's
  `timer` example). QEMU's `virt` board provides it only when given two `-serial`
  options, so `scripts/run_qemu.py` always passes a second one: `null` with file
  input, `tcp:127.0.0.1:PORT,server=on,wait=off` with TCP input.
- **One PD for the attacker's link.** `net` receives (one email per line, at most
  `MAX_VALUE` bytes; `\r` ignored; longer lines discarded) and transmits the sink's
  `OBS` lines. `flow-policy.json` bounds it as an untrusted PD (section 6).
- **`obs_out` is append-only.** The sink writes the data, then the length; `net`
  can only read it, so it has no way to signal the sink. It holds 4088 bytes of
  `OBS` lines per boot.
- **Mailbox protocol.** `net` writes the data and the length, then a release fence,
  then increments `seq`, then notifies the broker. The broker checks `seq` before
  and after copying (PROTOCOL.md §2) and never writes the mailbox.
- **Waiting for the email.** A `READ_U` on an empty mailbox gets `R_NOT_READY`: no
  step is taken, and the broker notes "inbox not ready; runner waits". When `net`
  signals an arrival, the broker wakes the runner, which retries. The
  broker-to-runner notification is the only channel change to T4's topology.
- **Attacker view.** The socket carries exactly the `OBS` lines. The TCP run matrix
  checks that nothing else arrives on it.
- **Inputs stay fixed per run.** The harness sends the same email in every run, and
  only after the broker reports that the runner is waiting, so all 16 TCP runs
  exercise the waiting path. Interactively: `make INPUT=tcp run`, then
  `nc 127.0.0.1 4444` in another terminal.
- **Formal caveat.** In paper 1 the attacker's input is fixed for a run. A live
  socket lets the attacker choose content and timing after observing allowed calls,
  an adaptive attacker outside the base semantics. In E1 the attacker observes
  nothing before the read, so it gains nothing here.

**Two driver bugs found by the comparisons.**

1. *Clearing the interrupt after draining.* A byte arriving between the last read
   and the clear lost its interrupt. QEMU's PL011 raises the receive interrupt
   again only when its FIFO goes from empty to non-empty, so reception stalled,
   in roughly half of the runs. Fix: clear first, then drain. My first explanation
   (QEMU stops polling the socket while the UART is disabled) was wrong; the
   workaround for it made no difference and was removed.
2. *Enabling the FIFO at start-up.* Setting `LCR_H.FEN` flushes QEMU's receive
   FIFO, which lost the first byte of an email that arrived before `net` started
   (12 of 16 runs). The field-by-field comparison caught it. A check that only
   looked for an `OBS` line had not, since the shortened email still contained the
   instruction. Fix: leave the FIFO off; each byte then raises its own interrupt.

**Larger options** (scope decision, T14): TCP/IP inside seL4 with virtio-net, sDDF
drivers and lwIP as in LionsOS, or a Linux VM front end. Both put a large parser of
attacker input inside the system, which must itself be confined. The SDK's
`ethernet` example targets a TQMa8XQP board, not QEMU.

## 11. Confinement tests (T9)

Built 13 October 2026. The design above says the kernel and the broker confine the
untrusted worker. This task checks that by running workers that deliberately
misbehave and observing what stops each one. It evaluates the confinement of this
prototype; it is not an attack on anything outside it. `make bypass` runs them all
(`scripts/run_bypass.py`); each is a build of `src/worker.c` selected by `CFG_ATTACK`
(`src/config.h`), booted under the fenced policy with secret 1, so a leak would show
`Data 1`.

The worker holds the secret (Q3) and may call the broker and notify the runner. It
has no channel to the sink, no write to any region, and read-only maps of `plan_mem`
and `context`. Each test fires once, after `READ_T` (the real secret is in plan
memory) and before `READ_U` (before any fence).

| Attempt | What should stop it | What we observe |
|---|---|---|
| Call `Fetch[Secret]` with no injection | Nothing: it obeys no injection | **Allowed under every policy; the secret reaches the sink.** This is Q2, outside relative security. |
| Call a channel the worker does not hold, via libmicrokit | The library's own check | `microkit_ppcall` prints "invalid channel" and returns; the worker survives, the sink is silent. Advisory only (next row). |
| Ignore the library and invoke the kernel on a slot it lacks | The kernel | `seL4(...) "worker" ...: Attempted to invoke a null cap`. No capability, no call. |
| Send a trusted `READ_T` as if it were the runner | The broker | The broker learns the caller from the kernel-supplied channel, not the message, so it answers ERR "only the runner may read or take internal steps". |
| Write a forged email into its read-only `context` | The kernel | A VM fault (permission fault, write not read) at the `context` page; the Monitor reports "faulting PD: worker" and the worker stops. Nothing is forged. |
| Read an address it has no mapping for | The kernel | A VM fault (translation fault); the worker stops. |
| Send a structurally invalid request to the broker | The broker | ERR "malformed request". |

`request mutation after submission` is not a separate test: the kernel copies a
call's arguments into the broker's message registers at call time, and the broker
copies them into its own memory before it decides, so there is no shared buffer for
the worker to change (DESIGN.md section 5, "calls carry the data"). There is no path
by which a later write by the worker can reach the request the broker is deciding.

**Result.** Every attempt except the un-injected leak is stopped by the kernel or the
broker, and the sink receives nothing. The un-injected leak succeeds under every
policy, including the fence: it is a worker that is malicious on its own, which the
fence is not meant to stop and which relative security does not model (Q2). This is
the honest boundary of the result, and the reason Q2 stays open.

**What this rests on.** The memory and capability boundaries are the seL4 kernel's,
for the MCS configuration (section 9's proof status applies). libmicrokit's channel
check runs inside the calling PD and is advisory; the "null cap" test shows the
kernel enforces the boundary even when the worker ignores the library. The broker's
own checks (caller channel, request shape) are our C code, trusted and tested, not
verified. Two workers fault and halt the agent rather than leaking; restarting a
faulted worker instead of halting is a later task (T13).

## 12. Observation and proof scope (T10)

Audited 13 October 2026. Sources: the SDK's kernel configurations
(`board/qemu_virt_aarch64/{debug,release}/include/kernel/gen_config.h`), the Microkit
2.3.1 manual (sections 2.7, 2.10, 3.1, 4 and 10), and measurements on QEMU.

### Configurations

| Kernel option | `debug` | `release` |
|---|---|---|
| MCS scheduler (`KERNEL_MCS`) | yes | yes |
| seL4 as hypervisor at EL2 (`ARM_HYPERVISOR_SUPPORT`) | yes | yes |
| Cores (`MAX_NUM_NODES`) | 1 | 1 |
| Scheduling domains (`NUM_DOMAINS`) | 16 | 16 |
| Debug build, kernel printing (`DEBUG_BUILD`, `PRINTING`) | yes | no |
| Hardware debug API (`HARDWARE_DEBUG_API`) | yes | no |
| `VERIFICATION_BUILD` | no | yes |

The manual is explicit (§3.1.2): "making a release build of a Microkit system does not
imply that the seL4 kernel being used is verified", and Microkit always uses the MCS
configuration, whose code-level proof is "scheduled to complete for RISC-V in 2026 and
AArch64 in 2027"; the MCS design proofs are done. So no configuration this prototype
can be built in is covered by a completed code-level proof today. The isolation it
relies on is seL4's, as designed and as implemented, not yet as proved for this
configuration.

### Output channels

| Channel | Written by | Read by | Mediated by | `debug` | `release` (measured) |
|---|---|---|---|---|---|
| Debug console (first UART, the kernel's driver) | the loader, initialiser, kernel and Monitor; **any PD**, through the kernel's debug print | the analyst | nothing: no capability is needed | everything: `TRACE`, `NOTE`, `OBS`, `MEM`, faults | nothing (0 bytes) |
| Attacker's socket (second UART, the `net` PD) | `net` only, from `obs_out` | the attacker | capabilities: only `net` maps `uart1`; `obs_out` is read-only to it | exactly the `OBS` lines | exactly the `OBS` lines |

- **In debug builds the console is an unmediated channel from every PD**, including
  the untrusted worker; its own `NOTE` lines show it (`tests/test_observation.py`).
  Neither the static checker nor the capability check below models it. That is
  acceptable here only because the analyst alone reads the console; in a deployment
  it must not be visible to the attacker. It also means a misbehaving PD could print a
  fake `OBS` line on the console (PROTOCOL.md section 8), so the file-mode matrix
  trusts the console only for well-behaved PDs; the TCP matrix checks the socket,
  which is mediated.
- **In release builds the console is silent, and the leak and the fence are
  unchanged.** Open policy: the attacker receives `OBS {"tool":"Fetch","args":["Data 1"]}`
  and the console 0 bytes. Fenced: nothing reaches the attacker within 6 s (the open
  run delivers in about 1 s), and the console stays empty. The price is that our
  evidence trace exists only in debug builds; a release system that needs an audit
  trail would need its own trusted log channel, such as a region read by a trusted
  logger PD.
- **The hardware debug API** exists only in debug builds and acts through thread
  capabilities, which no PD holds (below).
- **Can the worker signal the attacker?** Only through calls the broker allows, which
  is the channel the paper models, and through timing. It holds no capability to the
  sink, `net`, `obs_out` or `uart1` (below), and its console output reaches the analyst
  only.

### The built capabilities, checked on every build

The Microkit tool's `--viper-output` option writes, for each PD, the capability table
and memory permissions it built into the capDL specification (manual §4).
`scripts/check_built_caps.py` checks these against `flow-policy.json`, after the tool
runs, on every build; an image that fails is deleted. This is a second view,
independent of our own parser of `broker.system`: it sees what the system will hold.

| PD | Capability slots built | Reads | Writes |
|---|---|---|---|
| `sink` | own (1–4); 11: notify `net` | `obs_out` | `obs_out` |
| `broker` | own; 11: notify `runner`; 77: call `sink` | `secret`, `inbox`, `context` | `context` |
| `runner` | own; 11: notify `worker`; 74: call `broker` | `plan_mem` | `plan_mem` |
| `worker` | own; 11: notify `runner`; 74: call `broker` | `plan_mem`, `context` | nothing |
| `net` | own; 11: notify `broker`; 138: interrupt 40 | `uart1`, `inbox`, `obs_out` | `uart1`, `inbox` |

Every slot is explained by libmicrokit's layout (10+id to notify, 74+id to call,
138+id for an interrupt), no PD holds a thread, VCPU, I/O-port or SMC capability, and
only the broker can call the sink. `tests/test_built_caps.py` breaks the description in
four ways that the Microkit tool accepts (the worker's `context` made writable, the
worker given the inbox, a worker-to-sink channel, `net` allowed to call the broker),
bypassing the static checker, and the capability check catches each. It covers the
tool's capDL-level output; the initialiser's run-time behaviour and the kernel remain
trusted. The `.vpr` format is not fixed across Microkit versions; the parser follows
SDK 2.3.1.

### Timing

The results are at the event level, the paper's main attacker. Timing is not
addressed:

- The attacker sees when `OBS` lines arrive; the paper's step-level attacker also sees
  when each step happens. We do not measure timing: QEMU's timing is not
  representative of hardware.
- All PDs share one scheduling domain. The kernel's domain scheduler (16 domains,
  fixed time slices; manual §2.10, the SDK's `domains` example) is the mechanism to
  evaluate, for example by running `net` in its own domain. How protected calls and
  notifications between PDs in different domains behave, and what that costs the
  plan, is an open question; the manual does not say.
- The scripted worker's schedule is fixed. A real model could time its requests on
  the secret, which mediation alone does not prevent (paper 1, deployment assumptions).

### Claim boundary

- **Proven:** nothing about this exact build yet. seL4's proofs cover specific
  configurations; for MCS on AArch64 the design proofs are done and the code-level
  proof is in progress.
- **Trusted but unproven:** the seL4 kernel binary in this configuration; the Microkit
  tool (its capability output is now checked against the policy on every build), the
  capDL initialiser, loader, Monitor and libmicrokit; our broker, runner and sink, and
  the C monitor (tested against `core.py` and a transcription of the Isabelle
  definitions); `broker.system` and `flow-policy.json`; QEMU, as the platform.
- **Untrusted but confined:** the worker, `net`, the email and the attacker's TCP
  client. Confinement is checked three ways: the description against the policy
  (section 6), the built capability tables against the policy (above), and misbehaving
  workers on QEMU (section 11).
- **Not covered:** the debug console as a channel (debug builds), timing, workers
  that leak without an injection (Q2), fresh sessions (T13), an attacker who adapts
  over a live socket (section 10), and correspondence with the Isabelle theories
  beyond tests on finite runs.
