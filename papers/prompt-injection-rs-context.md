# prompt-injection-RS: WP-2 context

Ingested selectively on 2026-10-06 at revision `ee0fa468900019526a84c1f7f724f1582d9fd79f`. Source repository preserved. Everything remains tentative; no runtime or experiment selected.

## Source map and reading coverage

| Source | Inspected | Use and remaining work |
|---|---|---|
| [Repository README](../prompt-injection-RS/README.md), [papers README](../prompt-injection-RS/papers/README.md) | Repository overview/setup and paper status | Source map; build/proof reports are not independently verified |
| [Paper 1 PDF](../prompt-injection-RS/papers/1-PI_as_RS/main.pdf) | Selected definitions, assumptions, defences and examples; visual pp. 6/20 | [Relative-security note](papers/planters-relative-security.md); proofs/appendices largely unread |
| [Paper 2 PDF](../prompt-injection-RS/papers/2-RI_and_RR/main.pdf) | Selected definitions, examples and discussion; visual pp. 3/8 | [Integrity/robustness note](papers/relative-integrity-robustness.md); proof details/appendix largely unread |
| [THREAT_MODEL.md](../prompt-injection-RS/THREAT_MODEL.md) | Scope and attacker/observer discussion | Broader repository scope differs from the narrower paper models |
| [MOTIVATION.md](../prompt-injection-RS/MOTIVATION.md) | Selected overview/examples | Relative baseline and task-policy motivation; remainder not closely read |
| [MULTI_AGENT.md](../prompt-injection-RS/MULTI_AGENT.md) | Introduction, Sections 1–3 and opening limits discussion | Relay injection, scheduler and observation assumptions; remaining detailed results unread |
| [notes/finer-grained-leaks.md](../prompt-injection-RS/notes/finer-grained-leaks.md) | Opening sink-sensitive discussion | Distinguish disclosure destinations; full technical development unread |
| [notes/red-team-tests.md](../prompt-injection-RS/notes/red-team-tests.md) | Test sketches | Earlier counterexample-to-test proposals; not executed and not comprehensive of later additions |
| [notes/agentic-sel4.md](../prompt-injection-RS/notes/agentic-sel4.md) | Sections 1–3 and selected deployment discussion | Exploratory monitor/gateway mapping, not an implemented deployment |
| [notes/paper-plan.md](../prompt-injection-RS/notes/paper-plan.md) | Draft scope/status | Internal working note marked not for distribution; targets/readiness remain tentative |
| [OPEN_ISSUES.md](../prompt-injection-RS/OPEN_ISSUES.md) | Search/status snippets only | No complete issue audit |

`thys/` and other formalisation sources were deliberately excluded. Detailed language/integrity reference documents, full example catalogue and presentation were not inspected in this pass. No proof or implementation audit was performed.

## What this adds to our three goals

**Runtime architecture.** The papers make the trusted plan and monitor explicit. A gateway must mediate reads as well as effectful calls, and read admission must precede exposing content. Credentials outside a compromised worker, complete tool-path coverage and credible session resets are deployment obligations. `notes/agentic-sel4.md` discusses such mappings but does not establish an implementation or kernel-level guarantee. Kernel choice remains open.

**Monitoring.** Approval needs binding to the intended request, not merely the next use of a tool. Revocation must cover indirect paths and later regrant. Data provenance alone can miss control-dependent calls. In multi-agent settings, an agent can relay malicious content to a second agent with a useful sink; per-agent reset/regrant does not automatically reset another agent's state. Internal/MCP sources and trusted-input channels need explicit classification. (Paper 1 Sections 2/5/6; `MULTI_AGENT.md`, Sections 1–3.)

**Evaluation.** Separate disclosure, attacker-induced effects and absolute task correctness, then check their coupling. Preserve trusted-input/effect order and destinations. Supplement model-driven attacks with direct adversarial requests to enforcement boundaries. Include utility: a monitor that rejects honest work can satisfy a security example while being unusable. These are candidate evaluation requirements, not agreed experiment designs. (Paper 1 Section 6; Paper 2 Sections III/VII/VIII.)

## Qualifications to retain

1. **Reported proof versus deployment:** the drafts report mechanisation. We have read explanatory material, not checked those proofs or the correspondence of any gateway to the model.
2. **Universal within a model:** fixed injection scheduling cannot represent all adaptive compromised-worker behaviour. Complete mediation, silent denials, trusted inputs and genuine resets need evidence separately.
3. **Relative versus absolute:** the reference may itself authorize an unsafe disclosure or payee. Canonical RI can ignore a constant benign bug; use separate task-policy checks or deliberately choose a stronger criterion.
4. **Channels and order:** finer-grained leak notes motivate sink-sensitive comparisons. Per-sink checks alone can still lose cross-sink ordering; evaluate route and combined trace as needed. This is an open specification choice.
5. **Test interpretation:** `notes/red-team-tests.md` suggests that one differing pair confirms leakage. For stochastic systems, unequal outputs alone are insufficient: use an explicit private canary at an unauthorized sink or suitable controls/statistical evidence. For a general relative-property refutation, one benign reference run is also insufficient to exclude all possible reference explanations.
6. **Read classification:** the seL4 mapping discusses a secret-read kickoff alongside an untrusted-read fence. Confidential reads and injection-bearing reads need distinct labels and policy decisions; our engineer-notes summary already records this distinction. Do not silently collapse them in a runtime specification.

## Unresolved questions for the next discussion

- Do we evaluate only injection-induced harm, or also malicious workers and ordinary agent bugs?
- What supplies the reference/absolute task policy, and how do we validate it?
- Which observers, destinations, timings and denied effects belong in the trace?
- What state survives reset, retries, inter-agent transfer and revocation?
- Which small counterexample should become the first boundary test, after we agree a runtime target?

## Reading command log

Both commands exited 0 and produced searchable text:

```sh
pdftotext -layout prompt-injection-RS/papers/1-PI_as_RS/main.pdf /tmp/wp2-paper-reading/rs-paper.txt
pdftotext -layout prompt-injection-RS/papers/2-RI_and_RR/main.pdf /tmp/wp2-paper-reading/ri-rr-paper.txt
```

Selected pages were rendered with `pdftoppm -f N -l N -scale-to 1600 -singlefile -png PDF OUTPUT` and visually inspected: paper 1 pages 6/20 and paper 2 pages 3/8. Rendering succeeded. These are reading checks, not security verification. No tests, paper builds or Isabelle commands were run.
