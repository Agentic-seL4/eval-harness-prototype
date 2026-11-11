# CaMeL: runtime separation and data-flow policy enforcement

Read on 2026-10-06 for WP-2 runtime, monitoring and evaluation research.

## Source and reading status

- Edoardo Debenedetti et al., *Defeating Prompt Injections by Design*.
- [Supplied PDF](<Defeating prompt injection by design.pdf>), arXiv `2503.18813v2`, 24 June 2025; [paper record](https://arxiv.org/abs/2503.18813); [repository](https://github.com/google-research/camel-prompt-injection).
- Selectively inspected: abstract; Sections 3.1, 4, 5.2-5.4, 6.1-6.2, 6.4-6.5, opening and examples of Section 7, and Section 9.3. Visually checked p. 5, including Figure 3. Detailed policy appendices, full attack transcripts and all results tables remain unread.
- PDF SHA-256: `4f9557fe01fb96b31841b6e17aac3cc4f69f040c98a169910dcd69e810477fa5`.
- Evidence: security-game definition, architectural argument and paper-reported experiments. No implementation audit, benchmark reproduction or tool-checked proof performed here.

## Runtime design

CaMeL separates a privileged planner from a quarantined LLM that processes untrusted data. A custom interpreter executes the generated plan and tracks dependencies. Tool policies inspect arguments and associated metadata before permitting calls. This places enforcement in software surrounding the model rather than relying solely on model compliance. (Section 5.)

Sections 5.2-5.3, pp. 8-9, describe policies as Python functions and per-value tags recording provenance and allowed readers. A tool may attach an inner source such as an email sender. These value annotations are not automatically equivalent to kernel-enforced object capabilities: they need trusted propagation and enforcement in the interpreter and tool adapters.

The interpreter supports a restricted Python dialect. STRICT mode tracks control dependencies as well as direct data dependencies: a call inside a branch can depend on the branch condition, even if its explicit arguments do not. Figure 7, p. 10, illustrates this distinction; Figure 14, p. 19, shows how counting calls can reveal a private value without direct argument leakage. (Sections 5.4 and 7.)

## Security specification and assumptions

Section 4 and Figure 3, pp. 5-6, define a security game over allowed actions for a prompt. An action includes a tool, its arguments and environment state at that step. The attacker manipulates tool-accessible state to induce an action outside that allowed set.

This makes the allowed-action specification central. Enforcing a policy correctly does not establish that the policy captures the user's intended permissions. Section 5.2 leaves annotation granularity and policy choice dependent on the use case.

Section 3 assumes a trusted user prompt and uncompromised prior memory. Section 3.1 explicitly excludes answer corruption without a prohibited data/control flow, including misleading summaries and some phishing content. It also permits human intervention; this is not a claim of fully autonomous safe operation.

**WP-2 inference:** deployment assurance additionally depends on the interpreter, policy code, source labels, dependency propagation, tool adapters and absence of unmediated effect paths. A sandbox can protect these components or confine workers, but cannot choose a correct disclosure policy by itself. Trust in external model providers also needs an explicit decision when private data enters model requests.

## Evaluation and its limits

Section 6 evaluates on AgentDojo. The abstract reports 77% task completion with its stated security guarantees versus 84% for an undefended system. Treat this as a result for the supplied paper's setting, not a universal performance figure or a reproduced WP-2 result.

Section 6.2 separates **isolation without policies** from **isolation with policies**. These must remain separate baselines: the first still permits problematic flows in some cases. Section 6.4 shows how generated code can route data through a collection of available actions, making data effectively select behavior despite apparent separation.

Section 6.1.2 identifies tasks whose required actions are themselves contained in untrusted data as a utility problem for the privileged planner. This matters for evaluating a runtime: rejection may be the policy's intended behavior, or an inability to support the task, and those outcomes need different labels.

Section 6.5, pp. 18-19, reports median token overhead of 2.82x input and 2.73x output tokens relative to native tool calling in its Claude 3.5 Sonnet experiment. It uses a surrogate tokenizer and excludes tool-documentation tokens. These numbers are not direct wall-clock or financial-cost measurements.

Section 7 discusses indirect-flow, exception and timing channels. STRICT mode addresses the illustrated branch/loop dependency leak; it is not presented here as eliminating all side channels. Section 9.3 explicitly rejects the claim that prompt injection is fully solved and identifies policy maintenance and user burden.

## Possible WP-2 use, not an agreed experiment

Evaluate a policy monitor on a small task set with:

1. Correct and incorrect destination arguments on the same allowed tool.
2. Label propagation through transformations and tool results.
3. Calls conditioned on private data, compared in NORMAL and STRICT modes.
4. Exception handling, retries and user approvals, including what is externally visible.

Measure unauthorized effects, legitimate task completion, approval burden, latency and token usage separately. Add direct scripted requests so a model's failure to discover an attack cannot be mistaken for successful enforcement.

Open questions: Who owns labels and policies? Can approvals be bound to exact arguments and sessions? Does state survive replanning? Which tool adapters can silently drop provenance? What external observation model is intended?

## Repository follow-up

Inspect interpreter coverage, dependency operations, policy hooks, tool labeling, exception/replanning paths, approval handling and AgentDojo integration in a pinned checkout. The release URL is identified; its code has not yet been audited for this note.
