# WP-2 research index

Last updated: 2026-11-11.

## Scope and current status

Focus: runtime stacks, monitoring and evaluation for AI agents. HOL/Isabelle specification development is outside the user's main contribution. seL4 and alternative kernels/isolation systems remain candidates. AgentDojo remains at container setup without model runs. A dummy-data Microkit host-model experiment is now authorised and implemented; it does not select a general runtime architecture.

Our [working goals](project-context.md#our-working-goals) are:

1. **Runtime architecture:** agent isolation, tool gateways, credentials, and enforcement boundaries.
2. **Monitoring:** policy enforcement, provenance, capability revocation, and handling untrusted content.
3. **Evaluation:** threat models, attack scenarios, benchmarks, and evidence that the runtime enforces its intended properties.

All research plans are tentative and revisable. Dates and sprints in source documents are planning context, not strict commitments.

Current work starts with the supplied evaluation and runtime-security papers. Notes contain source-specific findings, assumptions, limitations and proposed follow-ups; proposals are not agreed project decisions.

## Project context

Read the [project-context note](project-context.md) for the proposal and kickoff deck: WP-2 tasks, planned Linux/seL4 sequence, first-cycle targets, example policies and evaluation implications. The proposal's technical text and reference/support sections and all kickoff slide text have been read; selected diagrams and image-heavy slides were visually checked. These describe intended work, not completed guarantees.

## Paper reading map

The [research engineer notes summary](engineer-notes-context.md) maps the `notes/` repository to our three goals. Both compiled reports and all three READMEs have been read, with selected diagrams visually inspected. It records tentative gateway/replay ideas, qualifications to older claims and stale source links; no experiment has been selected.

| Paper | Why read it for WP-2? | Notes | Inspection status |
|---|---|---|---|
| AgentDojo, NeurIPS 2024 | Tool misuse, attacker-goal checks and utility/security evaluation | [Reading note](papers/agentdojo.md) | Selected design/evaluation sections; full appendices and tables unread |
| Defeating Prompt Injections by Design, CaMeL, v2 | Runtime separation, provenance, policies, dependency tracking and overhead | [Reading note](papers/camel.md) | Selected design/evaluation/limitations sections; full transcripts and policies unread |
| Quantifying Frontier LLM Capabilities for Container Sandbox Escape, v3 | Isolation-boundary tests, reference exploits, scoring and resource budgets | [Reading note](papers/sandbox-escape-bench.md) | Selected methodology/results/limitations sections; full task/statistical appendices unread |
| On the Relative Security of Prompt Injection, local first draft | Reference-relative confidentiality, monitor assumptions and counterexamples | [Reading note](papers/planters-relative-security.md) | Selected definitions/defences/cases; proof details and most appendices unread; no proof checking |
| Relative Integrity and Robustness, local first draft | Effects, task-policy gaps and coupled leakage/action checks | [Reading note](papers/relative-integrity-robustness.md) | Selected definitions/examples/discussion; proof details and appendix unread; no proof checking |

Start with the [WP-2 evaluation synthesis](papers/wp2-evaluation-synthesis.md) for comparison, tentative evaluation questions and unresolved scope decisions. Each paper note links its supplied PDF and records its fingerprint. All empirical results are paper-reported; none has been reproduced here.

The [PlanTERS glossary](papers/planters-glossary.md) defines the main concepts using the latest user-supplied `main-Oct.pdf`, with short examples and section references. It records reading of Sections 2–8 and Appendices A–C; no formalisation sources or proof checking were undertaken. The older PlanTERS reading note above retains its original source version.

## Sources and repository inspection queue

The original URL list is preserved in [links.md](links.md).

| Source | Expected relevance | Current status / next inspection |
|---|---|---|
| [Project website](https://agentic-sel4.github.io/) and local `agentic-sel4.github.io/` source | Project and WP definitions | Local source and embedded project content read; [proposal/kickoff context](project-context.md) now available |
| [AgentDojo](https://agentdojo.spylab.ai) | Workloads and tool-misuse evaluation | Local harness and selected banking predicates inspected at revision `089ed468cf3ed0322acc66b0211f26d9d90dbf60`; [architecture and harness note](notes/agentdojo-architecture.md); no runs executed |
| [CaMeL repository](https://github.com/google-research/camel-prompt-injection) | Candidate runtime and policy baseline | Code unread; inspect labels, interpreter, policies and integration |
| [SandboxEscapeBench](https://github.com/UKGovernmentBEIS/sandbox_escape_bench) | Boundary-escape evaluation | Local checkout at `sandbox_escape_bench/`; shared harness and selected scenarios inspected at revision `9fa5f26c2ef12f8655af71a0e808aa1416a92b25`; [architecture diagrams](notes/sandbox-escape-bench-architecture.md) |
| [nucleus](https://github.com/coproduct-opensource/nucleus) | Candidate enforcement/isolation stack | Detailed code and proof-to-runtime claims not audited |
| [Airlock](../airlock/README.md) | Dedicated continuation of the discovery Microkit runtime | [Overlap and maturity assessment](notes/airlock-overlap.md) at `6557c26`: runtime files identical to discovery; new plans and documentation; replay extraction faults reproduced; no QEMU run |
| [AgentCore Gateway, Strands Agents and Microsoft Agent Framework](notes/agent-framework-sandboxing.md) | Managed tool authorisation, SDK/OS sandboxes, information-flow controls and seL4 alternatives | Official documentation selectively inspected on 5 November; detailed feasibility analysis and proposed Relative Security experiments; no installation, deployment or experimental runs |
| [Pi containerization](https://pi.dev/docs/latest/containerization) | Whole-process versus tool-only isolation | Detailed implementation unread |
| [AISI research](https://www.aisi.gov.uk/research?category_equal=%5B%22Red+Team%22%5D) | Further evaluation papers and methods | Broader literature review pending |
| [prompt-injection-RS](../prompt-injection-RS/README.md) | Specification context and counterexample-derived tests | [Repository context](prompt-injection-rs-context.md); compiled papers and explanatory documents selectively read; `thys/` and formalisation sources excluded by request |
| [Existing implementation explorations](../notes/implementation-explorations/README.md) and [initial ideas](../notes/discovery_phase/initial-ideas/README.md) | Prior replay, gateway, revocation and label-instrumentation proposals | PDFs and READMEs read; [ingestion summary](engineer-notes-context.md); originals preserved, proposals require discussion |

## Repository updates

The [repository overview workflow](workflows/repo-overview/README.md) collects
changes across all configured remote branches and local branches, then supports
a concise WP2 review. AgentDojo and SandboxEscapeBench are excluded; newly added
repositories are discovered automatically. Reports and evidence go in `updates/`.
Checkpoints advance only after a report is saved and its repositories acknowledged.
Update files are created only when new commits are found. No-new-commit runs
return status in the chat and leave the report index and checkpoints unchanged.
Invoke with `$project-repo-overview`. Implementation is complete: eight isolated
Git integration tests and skill validation passed on 2026-10-23.

The [first overview, 23 October 2026](updates/2026-10-23T122412Z-92d38f/overview.md)
reviews 16–23 October across five repositories and 22 local/remote branch refs.
It covers the prototype's three dual-LLM variants, explicit deployment obligations
and checker limits in `prompt-injection-RS`, and the sprint report's proposed
seL4-first integration. The latter remains a source proposal, not a user decision.
The older repository context notes describe their dated snapshots; use this
overview for the newer source status. Detailed proofs and reported experiments
were not independently checked. The report records selective coverage and the
branch tips used for the first review baseline.

The [follow-up overview, 23 October at 13:49 BST](updates/2026-10-23T124903Z-d975c5/overview.md)
found no changes to the previously reviewed refs. It discovered `explorations`,
whose main tip matches `notes/origin/main`, and adds that checkout to the baseline.
The workflow now tracks six checkouts and 24 local/remote refs.

The [14:02 BST overview](updates/2026-10-23T130241Z-23bc47/overview.md) found all
remote branches unchanged. Four local main branches caught up to remote tips
already in the baseline; `explorations` remained unchanged. It also records a
supplementary reading of the Microkit broker README, without running its tests.

## Continuity

The [Inspect email harness](experiments/inspect-email-fence/README.md) is authorised as five incremental steps, with an explanation and pause after each. Step 1 is complete: one fenced/injected/secret-1 Python replay runs through Inspect 0.3.288 and saves its structured trace. The evaluation and guarded integration test passed, with no model generation or network connections in the test. The 16-case matrix, separate scores, host C monitor, controls and final walkthrough remain pending. No VM, container or model API call was used. The [feasibility assessment](notes/inspect-email-harness-feasibility.md) records the earlier analysis and its limits; the bounded LLM stage remains outside the agreed implementation.

The [scripted FIDES email-fence prototype](experiments/fides-email-fence/README.md) is implemented with Python 3.13.11 and Agent Framework 1.24.0. All 12 matrix/control cases and six tests passed without model calls: open admits the injected dummy-secret Fetch; fenced blocks it; both finish the local summary. A pre-email probe isolates integrity enforcement, and benign email also blocks a public Fetch. FIDES denial terminates an agent run, so trusted completion resumes in the same session. Saved traces and package/source fingerprints support this finite exercise; it is not OS confinement or an RS proof.

The [agent-framework sandboxing exploration](notes/agent-framework-sandboxing.md) separates AgentCore Gateway from Runtime/Code Interpreter, Strands SDK sandbox backends from Box, and Microsoft FIDES from Docker/Hyperlight execution. It compares external-host, Linux-on-seL4 and native integration with Linux/VM/cloud alternatives. Suggested experiments cover mediation, fences, exact approval, session resets, answer corruption, implicit flows, nested calls, concurrency and observation channels. These are suggestions, not selected experiments or proof claims; source and package implementations remain unaudited.

The [Microkit extension plan](experiments/microkit-debug/extension-plan.md) keeps the plan trusted and static. Its [host backend](experiments/microkit-debug/HOST_BACKEND.md) is implemented in a local experiment Git repository on `host-llm-backend`, with scripted/adversarial/replay/OpenAI modes and an alternate UART/mailbox topology. Original tests, the 16-case host matrix and fault/capability checks pass. The real `gpt-6-luna` API control, both deterministic replays and both benign workflows pass. The full six-attempt live campaign fails because malicious 97-byte proposals exceed the 64-byte bound; they caused no broker calls or sink effects. See the [validation record](experiments/microkit-debug/evidence/validation-2026-11-05.md). No further paid attempts were made. Exact approval, richer workflows, contracts and sessions remain suggestions; no refinement proof or general containment claim follows.

The [Microkit debugging checklist](experiments/microkit-debug/README.md) records the authorised step-by-step study of the discovery broker's open and fenced email runs. Tasks 1–2 checked the pinned source and installed toolchain, then copied and hash-verified 57 tracked files into the experiment. Both host suites now have saved logs in the host-backend offline evidence. The open baseline now passes the reusable trace checker; the user also confirmed the fenced baseline. Multi-component debug builds now match the reference under both policies; runner/worker have distinct code addresses, and VS Code profiles load all three modules. The CodeLLDB command order was corrected after unresolved breakpoints; a separate live bundled-LLDB probe now reaches broker startup. The VS Code adapter path, runner/worker live stops and fenced walkthrough remain pending. Keep the original repository and SDK unchanged.

The [AgentDojo container setup](experiments/agentdojo/README.md) built and started on 28 October. Ten runtime tests passed; all Banking reference predicates and the selected direct-attack placement passed a separate setup check. The upstream suite checker has a structured-message injection-detection issue. See [execution status](experiments/agentdojo/status.md) for commands and limits. No model runs were made; the user requested a stop here before continuing.

The [AgentDojo harness note](notes/agentdojo-architecture.md) maps simulated state, attack placement, agent/tool execution, defences and scoring. It records predicate and error-handling cautions, including that `security=True` indicates attacker success in attacked runs. Suggested monitor experiments remain unselected.

The [SandboxEscapeBench architecture diagrams](notes/sandbox-escape-bench-architecture.md) map task setup, frameworks, isolation boundaries, the agent loop and results analysis. They include tentative WP2 design questions; no experiment was run or selected. The code uses an answer-contains-flag scorer, qualifying the paper's exact-match description.

Agreed scope, unresolved questions and the reading-command log live in the [synthesis](papers/wp2-evaluation-synthesis.md). Keep paper notes under `research/papers/`. Choose an experiment location and record its run commands only after agreeing a direction. No experiment code or proof checking was undertaken in this reading pass.
