# AgentDojo: evaluation of prompt injection in tool-using agents

Read on 2026-10-06 for WP-2 runtime, monitoring and evaluation research.

## Source and reading status

- Edoardo Debenedetti et al., *AgentDojo: A Dynamic Environment to Evaluate Prompt Injection Attacks and Defenses for LLM Agents*, NeurIPS 2024 Datasets and Benchmarks.
- [Supplied PDF](NeurIPS-2024-agentdojo-a-dynamic-environment-to-evaluate-prompt-injection-attacks-llms.pdf); [paper record](https://arxiv.org/abs/2406.13352); [project](https://agentdojo.spylab.ai).
- Selectively inspected: abstract; Sections 3.1-3.4; evaluation discussion in Sections 4.1 and 4.3; conclusion; dataset validation description in Appendix F.11. Not a complete reading of the appendices or results tables. Page numbers below are PDF pages.
- PDF SHA-256: `26a3f0426ee1d533e4dd9f62d1343a7a1d231fe718cfaf3a362cc7de829ae913`.
- Evidence: paper-reported empirical evaluation. No benchmark runs or code checks reproduced here.

## What is being evaluated?

An agent receives a legitimate user task and tools operating on a simulated, mutable environment. An external attacker inserts instructions into data the agent retrieves. The attacker seeks a separate goal, such as sending private data or making an unwanted payment. This tests misuse of available tools, rather than escape from an operating-system sandbox. (Sections 3.1 and 3.3.)

The initial benchmark has 97 user tasks, 27 injection targets and 629 security cases. A security case pairs a user task with an injection task within the same suite. The four suites are Workspace, Slack, Travel and Banking. Table 1, p. 6, provides the suite breakdown. **Source inconsistency:** its caption says 70 tools, while the listed counts, 24 + 11 + 28 + 11, total 74. Resolve against a pinned code revision before recording an implementation inventory.

Tasks supply deterministic utility checks over model output and pre/post environment state. They also provide ground-truth tool sequences that help place attacks where the agent will encounter them. Appendix F.11 describes checking ground-truth executions against the task checks. These are executable evaluation predicates, not tool-checked proofs of general agent correctness. (Section 3.1, pp. 4-5.)

## Metrics and evaluation design

Section 3.4, p. 6, defines:

| Metric | Interpretation |
|---|---|
| Benign utility | Fraction of user tasks solved without an attack |
| Utility under attack | Fraction of security cases where the user task is solved without adversarial side effects |
| Targeted attack success rate (ASR) | Fraction of security cases where the specified attacker goal is achieved |

The denominators differ: benign utility uses user tasks; attack metrics use task pairs. Preserve this distinction when comparing results. The paper sometimes reports the complement of utility under attack as untargeted ASR; ordinary task failures can contribute, so it does not isolate attack-induced failure by itself.

Section 3.3 motivates adaptive attacks: a defense can defeat a fixed prompt template while remaining vulnerable. Section 3.4 also reports collections of attacks where success means any member succeeds on a case. For WP-2, record attack search resources and access to the defense, not just the final attack string.

## Findings relevant to runtime monitoring

**Paper result:** tool filtering substantially reduces ASR in the studied setting. However, Section 4.3, p. 9, identifies two important limits: the required tools may depend on retrieved data, and legitimate and malicious tasks may use the same tools. The latter applies to 17% of its security cases. Tool-name allowlists therefore leave a need for argument, destination and data-flow checks.

The same discussion identifies a persistent-context gap: an injection could wait for a later task to grant a useful tool. This is a proposed limitation of the benchmark setting, not a demonstrated multi-session result in this paper.

**Version caution:** Section 4.3 states 7.5% ASR for the tool-filter defense. Do not substitute a number from an older draft or another local summary without checking the experiment, attack and denominator in Table 5.

## What this evidence does not establish

- A targeted security check captures its specified attacker goal. It does not by itself establish absence of every unauthorized disclosure or effect.
- Low ASR can reflect an agent that fails to execute either the user task or the attack. Security needs to be reported alongside utility. (Section 4.1.)
- Simulated tools do not establish that a deployed agent cannot bypass a gateway using files, networking, subprocesses or credentials.
- Finite sampled runs cannot establish security against all attacks or model behaviors.

These are methodological implications for WP-2, not additional results attributed to the paper.

## Possible WP-2 use, not an agreed experiment

Use one suite to compare an unmodified agent, a tool allowlist, and a monitor that validates arguments and data provenance. Keep the same task cases and record actual effects independently of monitor decisions. Add a case where the attack and user task require the same tool, plus a later-task case that tests retained injection content.

Open questions: Which task policies can be specified independently of attacker goals? Can the runtime expose complete traces without leaking secrets through logs? What does task completion require beyond the existing binary utility check?

## Repository follow-up

Follow-up on 2026-10-14: inspected the local checkout at revision `089ed468cf3ed0322acc66b0211f26d9d90dbf60`. The [repository and harness note](../notes/agentdojo-architecture.md) maps registries, injection placement, state reset, pipeline/tool execution and traces, with selected banking predicate checks. It qualifies the general utility description above: predicates vary, and the inspected bill-payment check accepts the intended payment without excluding extra payments. In attacked runs, `security=True` denotes attacker success; selected error paths also set this value. No tests or model runs were executed; full suite predicates remain unaudited.
