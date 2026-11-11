# Relative integrity and robustness

Read selectively on 2026-10-06 for WP-2. This is specification context, not a checked runtime result.

## Source and evidence status

- *Relative Integrity and Robustness for LLM Agents under Prompt Injection*, anonymous first draft, [compiled PDF](../../prompt-injection-RS/papers/2-RI_and_RR/main.pdf), 12 pages.
- Repository revision: `ee0fa468900019526a84c1f7f724f1582d9fd79f`.
- SHA-256: `873ab21a145febb136f04a4625a686a6d90c5332aade5d3bbb996635de7f9ef4`.
- Inspected abstract/introduction, background and definitions in Sections II–III, selected Section IV, examples/table in Sections VII–VIII, and selected discussion/conclusion in Sections IX–XI. Visually checked pp. 3 and 8. Simulation/proof details in Sections V–VI and appendix remain unread in detail.
- All mechanisation claims are author-reported. No formal sources read and no Isabelle commands run.

## Three distinct properties

| Property | Comparison | Evaluation relevance |
|---|---|---|
| Relative security (RS) | Secret distinctions learned by an observer versus the reference | Disclosure and confidentiality |
| Relative integrity (RI) | Attacker-influenced effects, preserving the interleaving of trusted inputs and effects, versus the reference | Extra payments, sends, deletes and their order |
| Relative robustness (RR) | Leakage and effects explained jointly by a common reference attacker input | A disclosure cannot be justified separately from the action used to obtain it |

RI includes every modelled tool effect, even one invisible to the confidentiality attacker. The interleaved trusted-input/effect trace distinguishes an action before a user cancellation from one after it. Denied requests are assumed to have no effect. (Sections II–III.)

Canonical RI is guarded by a sibling run: the condition concerns two runs with identical trusted inputs whose effects differ. A bug that always pays Bob and Mallory, independently of attacker input, can satisfy RI vacuously. The stronger `RIreach` variant requires every run's trusted-input/effect trace to be reference-reachable and catches this example. **WP-2 inference:** use additional absolute task-policy/correctness checks if evaluation includes benign bugs, not only attacker-induced variation. (Section III, pp. 3–4.)

## The reference can preserve a specification gap

The introduction's invoice example accepts an injected change of payee if the reference would make the same payment when the attacker puts that payee in the invoice data. The reference plan already delegates that decision to untrusted data. Validating the payee against a trusted source is a plan/specification change, not a consequence of RI. Additional payments or deletion are rejected when no reference input can produce them. (Section I.)

This distinction is useful but does not imply that every relatively acceptable payment is user-authorized. Runtime enforcement and correctness of the chosen reference remain separate obligations.

## Why separate leak and action checks are insufficient

RS and RI are incomparable. An extra harmless effect may add no leakage but violate RI; an injected secret-bearing argument can violate RS while remaining a reference-reachable effect. (Section VII.)

The StatusPage example passes RS and RI separately but fails RR: the reference can explain leakage through a status publication and can separately explain a particular email send, yet no common reference input explains both secret-dependent injected sends. RR closes that particular gap by coupling the witnesses. The draft reports RR strictly stronger than RS and RI together. (Section VIII, p. 8.)

**WP-2 inference:** record recipient, channel, payload and effect order together. A reference disclosure somewhere is not automatically permission to send that data to another destination. Neither RR nor RI substitutes for an independently suitable task/disclosure policy.

## Limits and follow-up questions

The paper inherits fixed parser/oracle and trusted-plan/monitor assumptions from the companion paper. Results are qualitative, not attack-success probabilities. Modelled effect ordering does not cover arbitrary wall-clock side channels. See the [companion reading note](planters-relative-security.md).

Monitor strengthening is subtle when it also changes the reference: removing reference behaviours can remove explanations used by a relative property. Do not assume a more restrictive deployed monitor automatically preserves every relative verdict. (Discussion of closure and monitor changes, Sections IV/VII–XI.)

Candidate evaluation additions, still unselected: extra effect without leakage; always-wrong benign effect; changed untrusted payee; effect before/after cancellation; and the coupled StatusPage example. First resolve which properties our runtime is intended to enforce and which traces we can observe faithfully.
