# PlanTERS: prompt injection as relative security

Read selectively on 2026-10-06 for WP-2. Findings describe a draft's formal model, not a deployed runtime guarantee.

## Source and evidence status

- *On the Relative Security of Prompt Injection: Mechanised Definitions, Defences and Verdicts for LLM Agents*, anonymous draft, [compiled PDF](../../prompt-injection-RS/papers/1-PI_as_RS/main.pdf), 36 pages.
- Repository revision: `ee0fa468900019526a84c1f7f724f1582d9fd79f`. The papers README calls this a first draft; publication targets and PDF publication metadata are tentative.
- SHA-256: `7255201fc7a99d83f1f54dc04780451f486ece2eaf9eedca046fd3a3f8443bea`.
- Inspected abstract/introduction selectively; Sections 2.1.4–2.2, monitor/definition passages in Sections 3–4, disclosure-bound result, Section 5.1, Section 6 case table/discussion, selected related work/conclusion, and selected program/dual-LLM appendix examples. Visually checked pp. 6 and 20. Proof details and remaining appendices are largely unread.
- The draft reports mechanised Isabelle/HOL results. We did **not** inspect formalisation sources or run proof checking, as requested. Theorem references below are paper-reported claims.

## What the comparison establishes

PlanTERS combines a trusted plan with a monitor and a model that may obey untrusted instructions. Its reference runs the same plan and monitor without obeying those instructions. Relative security (RS) compares secret distinguishability: a pair of injected runs with the same attacker actions and different observations must have a corresponding distinguishing reference pair. The reference pair may use different attacker inputs from the injected pair. This is not trace equality or an absolute disclosure policy. (Sections 2 and 4.)

The reference is therefore part of the specification. A task that legitimately releases private information needs a disclosure analysis of its reference too. Section 4, Definition 4.7/Theorem 4.8, p. 15, relates RS to a bound on reference disclosures; RS alone does not establish that those disclosures are appropriate.

## Assumptions that matter for WP-2

Section 2.2, pp. 7–8, separates observation models (events, steps and views), control models and injection mechanisms. Universal claims quantify over choices in that model. In particular, the parser and injection oracle are fixed/shared across the compared runs; injection timing cannot adapt to secrets or monitor responses. Injected call arguments can nevertheless depend on private memory. This is broader than one tested prompt, but narrower than an arbitrarily adaptive compromised worker.

The trusted plan, monitor and trusted-input channel are assumptions. Deployment obligations include complete mediation, checking a read before exposing its content, denials with no excluded observable effects, and fresh sessions that actually clear the untrusted influence. Tools in the one-call model return fixed allowed/denied results, with data supplied through separate reads; reactive malicious tool servers need additional modelling. (Section 2.2.)

**WP-2 inference:** fixed refusal text alone does not ensure silent denial. Network traffic, timing, counters and retries can still expose a decision. Concurrent adapters also need an execution/ordering argument connecting their behaviour to the sequential model. These are runtime obligations, not established deployment results.

## Useful counterexamples and defence qualifications

- **Approval scope:** permission for the next call to a tool can be consumed by an injected call before the intended call. Exact-call approval avoids that event-level example under its assumptions, but the draft exhibits a step-count leak. Steps are not a complete wall-clock model. (Section 2.1.4, p. 6; Section 6, pp. 20–21.)
- **Budgets:** limiting call count does not ensure the right call uses the budget. The catalogue's verdicts have different quantifiers: a secure verdict without the table's universal qualification can concern only the selected attack. (Section 6, Table 1.)
- **Fences:** revoking injectable tools when untrusted content is read gives the stated finite-run result if trusted execution does not regrant them. Infinite-run results additionally require progress through a decreasing injection measure. Secrets already present can leak before a later fence. (Section 5.1, Theorems 5.1–5.2, pp. 15–16.)
- **Program injection:** changing a variable can poison a subsequent planned send even without an injected external call. Read-source selection is another potential channel. (Section 6 and Appendix B.)
- **Labels:** data tags alone miss control-dependent leaks. The tagged dual-LLM case also blocks an honest reply, making utility measurement essential. The paper does not model CaMeL's STRICT mode; its example is not a blanket verdict on CaMeL. (Section 6 and Appendix C.)

## Evaluation implications, not selected experiments

Record attacker actions, disclosures, recipients/channels, approvals, capability changes, read admission, session resets and denied requests separately. Pair enforcement checks with legitimate-task completion. Use direct scripted requests to test the boundary as well as LLM-generated attacks; prompt failure is not evidence that mediation works.

Open questions: Which reference plan represents intended permissions? Which observers see denials and timing? Where do credentials live? Can any worker bypass the gateway? What does revocation mean for an in-flight request? Which model behaviours does a proposed runtime actually cover?
