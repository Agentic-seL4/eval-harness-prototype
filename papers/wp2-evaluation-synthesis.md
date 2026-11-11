# WP-2 evaluation: initial paper synthesis

Status: working interpretation and proposals, 2026-10-06. No experiment or runtime architecture selected.

## Agreed scope

The current [working goals](../project-context.md#our-working-goals) cover runtime architecture (isolation, gateways, credentials and boundaries), monitoring (policy, provenance, revocation and untrusted content), and evaluation (threat models, scenarios, benchmarks and enforcement evidence). All plans remain tentative; source dates and sprints are not strict commitments.

The user's contribution centers on runtime stacks, monitoring and evaluation, rather than HOL/Isabelle formal specification. Start with evaluation literature, then inspect relevant repositories. seL4 is a candidate foundation; other kernels and isolation mechanisms remain in scope. There is no concrete WP-2 deliverable yet.

The project is identified by <https://agentic-sel4.github.io/>. Initial web retrieval failed, but the local website source was subsequently read, followed by the proposal and kickoff PDFs. The [project-context note](../project-context.md) records WP-2's explicit tasks: runtime architecture, capability-mediated framework integration, logging and adversarial evaluation. The documents plan parallel Linux and seL4 implementations; the user's exploratory scope additionally permits other kernels.

## What the first three papers contribute

| Source | Evaluation target | Useful evidence | Main transfer limitation |
|---|---|---|---|
| [AgentDojo](agentdojo.md) | Injection-induced misuse of tools | User utility, attacker-goal checks, simulated state changes | Does not test OS confinement or every unauthorized effect |
| [CaMeL](camel.md) | Runtime separation and per-value policy enforcement | Architectural design, policy/isolation ablations, utility and overhead | Depends on policy, labels and trusted implementation; side channels remain |
| [SandboxEscapeBench](sandbox-escape-bench.md) | Escape from container/pod isolation | Exact flag retrieval, reference exploits, resource-conditioned success | Deliberately vulnerable settings; not a deployment compromise probability |

These are complementary tests. A worker can remain confined while misusing an allowed payment tool. A tool policy can correctly reject requests while the worker bypasses it using a host socket. Neither benchmark alone covers both cases. This is our inference from their distinct threat models, not a theorem or a new measured result.

## Proposed evaluation questions

Separate three questions before choosing metrics:

1. **Policy adequacy:** does the specified permission/disclosure policy capture the task's intended authority? Useful checks include legitimate and malicious uses of the same tool. Basis: AgentDojo Section 4.3; CaMeL Sections 4 and 5.2.
2. **Monitor conformance:** does the implementation enforce that policy across arguments, labels, approvals, retries and sessions? Use scripted requests and independently observed effects. Basis: CaMeL Sections 5.3-5.4 and 7.
3. **Complete mediation:** can the worker cause an effect outside the monitored route? Test filesystem, network, credential and orchestration access. Basis: SandboxEscapeBench Sections 3-4.

An LLM attack campaign answers a further question: can the tested models discover and exploit a violation under the campaign's resources? It does not replace direct conformance tests. Keep these evidence classes separate in reports.

## Proposed reporting contract

For each configuration, preserve:

- Intended task, attacker goal, policy and boundary; attacker access, knowledge and observations.
- Runtime/kernel/image versions, source commits, privileges, mounts, network routes, labels and credential ownership.
- Model identifier, prompts, sampling settings, attack adaptation budget, trial count and execution/token limits.
- Benign completion, completion under attack, unauthorized effects, containment bypasses, crashes and timeouts.
- Monitor decisions alongside independently observed effects; latency, token cost and approval burden.
- Positive controls, scorer checks, environment reset rules, commands and exit results.

Use separate denominators and report inapplicable scenarios. A kernel comparison should hold security objectives and workload authority as constant as possible; otherwise it is a stack comparison, with the changed assumptions stated explicitly.

## Directions for discussion, not implementation commitments

| Candidate | Potential contribution, not an established novelty claim | Feasibility and assumptions | Smallest useful experiment |
|---|---|---|---|
| Monitor conformance before model red-teaming | Connect policy decisions to actual effects and expose adapter failures | Small; requires explicit policy and an independent effect recorder | One tool, one allowed destination, one forbidden destination; scripted calls plus an AgentDojo-style task |
| Session and re-grant evaluation | Study retained injection after a later authority grant, a gap raised by AgentDojo | Moderate; requires clear reset semantics and session/approval ownership | Two tasks in one worker: read an injection, then grant a legitimate write tool |
| Boundary-neutral stack comparison | Compare common authority objectives across kernels/isolation systems | Larger; requires genuinely comparable workloads and reachable surfaces | One gateway-only worker on two stacks; test direct egress, forbidden file access and exposed control sockets |

A broader literature and code review is needed before asserting novelty. These proposals must be discussed before building an experiment.

## Open questions for the next discussion

- Is the initial agent a tool-calling assistant, a shell-capable coding worker, or both in separate tracks?
- Is the desired assurance about allowed effects, confidentiality, confinement, availability, or some selected combination?
- Which component owns task policy, provenance and credentials? What external model services are trusted?
- Which kernel/runtime configurations can we actually execute and instrument?
- What would count as the first deliverable: reusable evaluation protocol, benchmark adapter, or a comparative study?

## Inspection and verification log

- Read `research/AGENTS.md` and `research/links.md`; inspected the three supplied PDFs selectively as recorded in each note.
- Extracted text with `pdftotext -layout <PDF> /tmp/wp2-paper-reading/<name>.txt`: exit 0 for all three.
- Rendered CaMeL p. 5 and SandboxEscapeBench p. 2 with `pdftoppm -f <page> -l <page> -scale-to 1200 -singlefile -png <PDF> <prefix>`: exit 0; inspected both images.
- Computed PDF SHA-256 fingerprints with Python `hashlib.sha256` to identify the supplied copies.
- Repository URLs are a follow-up queue, not audited implementations. No benchmark, exploit, Isabelle build or runtime test run in this pass.

Preserve the original PDFs and existing project notes. Future implementation work should receive its own directory and README after choosing a direction; it does not belong in paper-reading notes.
