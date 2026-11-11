# Agentic-seL4: project documents and WP-2 context

Read on 2026-10-06. This note summarizes project intentions and extracts requirements for discussion. It does not establish completed implementation or verification results.

## Our working goals

Recorded from the user's clarification on 2026-10-06. These three areas guide our research and repository inspection:

1. **Runtime architecture:** agent isolation, tool gateways, credentials, and enforcement boundaries.
2. **Monitoring:** policy enforcement, provenance, capability revocation, and handling untrusted content.
3. **Evaluation:** threat models, attack scenarios, benchmarks, and evidence that the runtime enforces its intended properties.

Everything in this research context is tentative and can change. In particular, dates, sprint numbers, sequencing and targets from the proposal, website and kickoff are illustrative planning context, not strict deadlines or commitments. Architectures, frameworks, kernels, policies, workloads and deliverables remain open to revision. Historical source descriptions and reading dates identify what was inspected; they do not make a plan binding.

Our contribution is primarily WP-2. seL4, Linux and other kernels or isolation mechanisms may be explored. HOL/Isabelle specification and proof development is outside the user's main contribution. No concrete architecture or experiment has been selected; discuss candidate directions before implementing one.

## Sources and reading coverage

| Document | Coverage | Fingerprint (SHA-256) |
|---|---|---|
| [ARIA project proposal](../agentic-sel4.github.io/uploads/ARIA_seL4_project.pdf) | Read extracted text for all 11 pages: technical proposal pp. 1-5, references pp. 6-9, support letters pp. 10-11. Visually checked pp. 3-4. | `394a3973e60e3c124f30abe2495cc64fe169b30fbc53983b7485e3ee5155aa3d` |
| [Kickoff deck](../agentic-sel4.github.io/uploads/Agentic-seL4_Kickoff_3.pdf) | Read extracted text for all 32 slides, including progressive duplicate slides. Visually checked slides 9, 15, 23, 25, 31 and 32. Other image-only details and embedded links have not been exhaustively inspected. | `6eda39db74df2588423b949a846f5076bdb935314dcce442645237a9e67cb897` |

The local website source and the project content embedded in `index.html` were also inspected in the preceding discussion. They agree on the main work-package structure, with some differences in staffing and WP4 wording. The proposal and slides are planning sources, not a current progress report. No cover revision date was identified; support letters are dated 26 and 30 June 2026, and the kickoff cites an August 2026 NCSC post. These dates do not determine the revision date of the entire proposal.

## Project aim and division of work

The project aims to constrain untrusted agents through a verified kernel and an agent-aware userland reference monitor. The monitor manages dynamic authority and runtime contracts; the kernel supplies isolation. The intended end-to-end guarantee requires both, with some trust deliberately moved into userland. A second goal uses AI to assist development and maintenance of the necessary proofs. (Proposal p. 1; kickoff slides 19-23.)

| Package | Intended contribution | WP-2 relationship |
|---|---|---|
| WP1 | Monitor API, capability creation/delegation/revocation, contracts and abstract security specification | WP-2 supplies realistic workflows and implementation feedback |
| WP2 | Runtime architecture, framework/tool integration, logging and evaluation | Produces concrete systems and scenarios |
| WP3 | Dynamic policy definitions and composed kernel/monitor security theorems | Uses concrete WP-2 mechanisms and scenarios to connect proofs to systems |
| WP4 | AI-assisted proof generation, repair and modernization | Supports the WP3 proof effort; separate from agent-runtime evaluation |

Sources: proposal pp. 2-4; kickoff slide 28. The user focuses on WP-2 runtime, monitoring and evaluation; HOL/Isabelle development is outside their main contribution. The user's exploratory scope includes other kernels, while the project documents specifically plan Linux and seL4.

## WP-2 is more concrete than the website overview

Proposal p. 3 defines three tasks:

- **T2.1: runtime architecture.** Identify the agent process, tool wrappers, policy/contract manager, logging and monitoring. Map components to protection domains and WP1 capabilities. Specify IPC and capability hand-off contracts.
- **T2.2: framework integration.** Choose one or more open-source frameworks, replace ad hoc tool access with capability-mediated interfaces, and add hooks for capability use and policy decisions. Named frameworks are examples, not a settled selection or an assessed recommendation.
- **T2.3: adversarial workloads and feedback.** Build on SandboxEscapeBench with the Red Team. Include code refactoring and document summarisation as benign workloads and prompt injection as adversarial workloads. Analyze evolving capability use and refine WP1/WP3 models and the agent threat model.

The kickoff makes the same integration priority explicit: choose frameworks, wrap tools and log every capability use and policy decision. By week 8 it proposes a main agent framework with mediated tool calls and initial monitor requirements. (Slides 30-31.) This is a planned acceptance target; it does not mean such a framework already exists.

## Planned sequence

Proposal p. 4 gives a more detailed implementation sequence than the website. The table records that source's tentative plan; it is not our agreed schedule and may change:

| Stage | Stated plan |
|---|---|
| Sprint 1 | Agent integration with a capability OS; derive monitor requirements |
| Sprints 2-4 | Implement the monitor on Linux as experience for seL4; stress normal operation with Red Team input |
| Sprint 5 | Expected readiness of the seL4 implementation |
| Sprints 5-7 | Stress seL4 under the same conditions as Linux; concurrently explore prompt-injection protections on Linux |

The kickoff specifies weeks 1-8 for the first cycle. Do not infer that every later sprint has the same duration or assign calendar dates from these documents alone. WP3 is the project-long proof strand; WP1, WP2 and WP4 are the experimental sprint strand.

## Concrete policy example and implementation questions

Kickoff slides 24-25 illustrate an agent initially holding access to a project folder, summarizer and outbound mail tool. After it reads confidential data, the monitor tightens policy and revokes outbound authority. A later malicious instruction induces an attempted send, but the kernel rejects it because the capability is gone. The intended defense remains effective even if the agent follows the malicious instruction; detection is not the enforcement mechanism.

This is a **design illustration**, not an implementation trace or a checked theorem delivered by these PDFs. Its trigger is a **confidential read**. Earlier `prompt-injection-RS` examples use a fence after an **untrusted read**; these policies have different utility costs and must not be conflated.

Proposal T3.1, p. 3, additionally suggests approval-triggered permissions, communication conditioned on unrevoked capabilities/contract tokens, trusted context sanitisation and multi-agent streaming with deletion obligations. They are candidate policy requirements, not proven runtime features.

**Questions for WP-2, inferred from these examples:**

1. What must happen atomically between observing a sensitive read, updating policy and delivering its result? What about concurrent or already-issued calls?
2. Does revocation cover delegated capabilities, open handles, queued requests, cached credentials and alternative channels?
3. What exactly is restored by approval or a fresh session, and which trusted component witnesses that event?
4. How is deletion or sanitisation evidenced across model context, process memory, storage and external services?
5. Can a useful refactoring or summarisation task finish under the chosen disclosure restrictions?
6. Which logging events are complete and authentic, and which logs or errors are attacker-visible?

Kernel isolation alone does not answer these questions. WP-2 must supply concrete mechanisms and evidence; WP1/WP3 must state the corresponding assumptions and obligations.

## Evaluation implications

- Evaluate unintentional unsafe behavior under benign prompts as well as externally induced prompt injection. The kickoff explicitly treats the agent as a threat actor in its own right. (Slide 32; proposal p. 1.)
- Include realistic workflows whose authority requirements can change. Slide 32 warns that toy tasks can produce inadequate authority models before the proofs are built.
- Track capability state transitions and actual effects, not only attack success. T2.3 asks how capability use evolves; T2.2 requires decision/use monitoring.
- Keep Linux and seL4 workloads and policies comparable. The proposal calls for the same conditions, but actual platform applicability and authority surfaces still require explicit accounting.
- Connect empirical evidence to specific assumptions. Stress tests do not prove universal containment; the combined-system proof is a separate WP3 deliverable.

## Claims requiring separate verification

The proposal and kickoff use incidents and broad comparisons with containers, microVMs, CaMeL, Fides and Nucleus as motivation. The originals of those incidents and the current repositories have not been audited here. In particular, claims about another system lacking end-to-end guarantees require checking the actual claim scope and trusted computing base, rather than relying on the slides' characterization.

The proposal itself distinguishes seL4's dynamic capability mechanisms from the static-policy assumptions in its existing information-flow proofs. It also says the cited timing-channel framework has not been integrated into the seL4 verification stack. (Proposal p. 2; Proofcraft letter p. 10.) Do not interpret the kernel foundation as automatic coverage of arbitrary dynamic policies or all timing channels.

The support letters establish expressed support and expertise, not technical results. The Melbourne letter explicitly frames its statement as intentions contingent on terms. (Proposal pp. 10-11.)

## Useful reading queue extracted from the proposal

These are identified references, not newly read papers:

| Reference | Why it matters for WP-2 |
|---|---|
| [13] *Securing AI Agents with Information-Flow Control* (FIDES), arXiv 2505.23643 | Alternative confidentiality/integrity-label runtime |
| [28-29] Inspect AI and Inspect Sandboxing Toolkit | Evaluation orchestration and outer containment |
| [41] *Guardians of the Agents*, DOI 10.1145/3777544 | Agent governance/runtime perspective |
| [42] Murray, *Analysing the security properties of object-capability patterns* | Delegation and authority patterns |
| [2] *Towards Proving Security in the Presence of Large Untrusted Components* | Architecture with a small trusted manager |
| [60] *seL4 Enforces Integrity* | Boundary between kernel-enforced authority and userland policy |
| [49] Nucleus repository | Runtime/provenance baseline; assess current proof-to-implementation coverage |

## Reading log

`pdftotext -layout <input.pdf> /tmp/wp2-paper-reading/<name>.txt` completed with exit 0 for both PDFs. Eight selected pages were rendered with `pdftoppm -f <page> -l <page> -scale-to 1300 -singlefile -png <input.pdf> <prefix>` and inspected. Original PDFs were preserved. No runtime experiment or verification tool was run.
