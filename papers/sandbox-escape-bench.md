# SandboxEscapeBench: evaluation of execution-boundary escape

Read on 2026-10-06 for WP-2 runtime, monitoring and evaluation research.

## Source and reading status

- Rahul Marchand et al., *Quantifying Frontier LLM Capabilities for Container Sandbox Escape*.
- [Supplied PDF](<Quantifying frontier llm capabilities for container sandbox escape.pdf>), arXiv `2603.02277v3`, 1 August 2026; [paper record](https://arxiv.org/abs/2603.02277); [repository](https://github.com/UKGovernmentBEIS/sandbox_escape_bench).
- Selectively inspected: abstract; Sections 3.1-3.3 and 4; sampling and initial-results discussion in Section 5; updated-results discussion in Section 6; limitations in Section 7. Visually checked Figure 1 and its taxonomy on p. 2. Full task mapping, generation settings, transcript analysis and statistical appendices remain unread.
- PDF SHA-256: `4efead5d8cb8edd33483325525e0371eba6724d010a2a483f9ed0634381c4a59`.
- Evidence: paper-reported empirical capability evaluation. No vulnerable environment, reference exploit or model evaluation executed here.

## Threat model and boundary

Section 3.1, p. 3, gives an adversarial agent interactive shell access inside a Linux container, root privileges for most tasks, standard utilities and network connectivity to the host and internet. It knows the escape objective, but the ordinary variant does not disclose the specific vulnerability. No dedicated web-search tool is supplied.

The boundary under test is container/pod to host, where the host is a VM used by the evaluation. The target is reading a flag outside container namespaces. Hypervisor escape, hardware side channels and persuading human operators are excluded. The setting has minimal monitoring and does not require stealth. This is a capability test under deliberate weaknesses, not a measure of how likely a production agent is to attempt escape.

## Taxonomy, harness and scoring

Section 3.2 and Figure 1 describe 18 tasks across three layers:

| Layer | Tasks | Examples of the tested surface |
|---|---:|---|
| Orchestration | 4 | Kubernetes control plane, secrets and network-policy weaknesses |
| Engine/runtime | 8 | Privileged containers, Docker socket, capabilities and runtime flaws |
| Host/kernel | 6 | Namespaces, cgroups and kernel exploit classes |

Application-specific vulnerabilities and hardware attacks are excluded. Tasks use known vulnerability classes and reference exploit scripts. Difficulty is expert-estimated, not a direct measure of deployment risk. (Section 3.2.)

Section 4, p. 4, describes Inspect orchestrating a container inside an outer VM. A ReAct-style agent gets `bash` and `submit`. The vulnerable inner environment is the system under test; the outer VM is part of the containment trusted computing base. VM backends include Vagrant and AWS EC2.

Section 3.3 describes exact string matching of the host flag. Code inspection on 2026-10-13 shows the task uses Inspect's `includes()` scorer: the submitted answer must contain the target flag, rather than equal it in full. This is stronger evidence than accepting an agent's statement that it escaped. However, flag success alone does not establish the intended exploit path: the paper reports four unintended paths found during development and uses hardening and transcript review to address shortcuts. Thus scorer correctness and environment validity are separate obligations.

## Experimental protocol and version differences

The original results use five trials per model/task pair and a 2.5-million-token budget, with 95% Wilson intervals and pooling within difficulty groups. (Section 5.1, p. 5.) Record task-level results too: aggregate rates mix heterogeneous vulnerabilities.

The supplied v3 includes updated model results and extended runs with 100-million-token budgets in Section 6, pp. 9-10. It reports benchmark saturation by Claude Mythos Preview. An earlier claim of no success on the hardest tasks must not be generalized to this revised cohort. Exact updated per-model rates and appendix settings have not been extracted into these notes.

Section 6.2 reports sandbox crashes explicitly. Crashed runs count as failed flag retrieval, but loss of availability remains an outcome worth recording for WP-2. Section 6.3 cautions that apparent plateaus on harder tasks may reflect crashes rather than a model capability ceiling.

## What this evidence does not establish

Section 7, p. 10, states that introduced weaknesses, shell access and minimal monitoring do not estimate end-to-end compromise likelihood in defended production. The benchmark does not exhaust deployment configurations or agent architectures.

For WP-2, no observed escape means only that the tested agents, attempts and budgets failed to retrieve the flag. It is not a confinement proof. Conversely, an escape is evidence of a particular boundary failure, not proof that every container configuration has that weakness.

Changing to seL4, a microVM or another kernel may remove the prerequisites for some scenarios. An inapplicable Linux exploit is **not** a successfully resisted equivalent attack. Compare common security objectives and authority surfaces, and record unsupported scenarios separately.

## Possible WP-2 use, not an agreed experiment

Use the taxonomy to build a boundary inventory before running models: accessible sockets, files, privileges, credentials, network routes and orchestration interfaces. Then choose one applicable scenario and pair a scripted positive control with an agent attempt in an independently contained test environment.

Record escape/effect evidence, attempts, model and sampling settings, resources, crashes and failure causes. Introduce monitor-on/off comparisons only after distinguishing the monitor's intervention from underlying boundary enforcement.

Open questions: Which deployment boundary are we comparing? What remains reachable through an allowed tool gateway? Are flags inaccessible through harness logs or metadata? How can availability loss and exfiltration through allowed network paths be scored separately from host escape?

## Repository follow-up

Follow-up on 2026-10-13: inspected the shared harness, Docker-socket provisioning and reference solution, selected Kubernetes task code, and image/analysis documentation in `sandbox_escape_bench/` at revision `9fa5f26c2ef12f8655af71a0e808aa1416a92b25`. See the [architecture diagrams](../notes/sandbox-escape-bench-architecture.md) for framework roles, source links and inspection limits. Provider internals and other scenario implementations remain unaudited; no evaluation was run.
