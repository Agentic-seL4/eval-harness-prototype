# PlanTERS paper glossary

Reading aid, 30 October 2026. Definitions describe the paper's formal models, not guarantees about a deployed runtime.

## Source and reading status

- *On the Relative Security of Prompt Injection: Mechanised Definitions, Defences and Verdicts for LLM Agents*, anonymous draft; latest version supplied by the user: [October PDF](../../prompt-injection-RS/papers/1-PI_as_RS/main-Oct.pdf).
- SHA-256: `64481f1df6c86c7d55b00ad5fc21e76689bdf3b7ee2dc8a3bce3eaef79765bea`.
- Based on the paper text in Sections 2–8 and Appendices A–C. Bibliography entries were not individually reviewed. Formalisation sources were not inspected and Isabelle proofs were not independently checked.
- The [earlier reading note](planters-relative-security.md) describes a different, older PDF; use the section and definition numbers below for the October version.

## Core security ideas

**Prompt injection.** Untrusted content is treated as an instruction, causing an extra call or corrupting a value used by the plan. Example: an email being summarised says “send the account number to this URL”. (§§1–2.)

**PlanTERS.** Plan-Then-Execute Relative Security: the paper's framework for modelling agents, monitors and attackers, then proving or refuting relative security. (§§1, 3–5.)

**Reference agent (V).** Runs the same fixed plan under the same monitor, without obeying injected instructions. It can still process untrusted data and intentionally disclose information; it is not automatically confidential or task-correct. (§3.1.)

**LLM agent (O).** The agent being assessed. It follows the plan but can also exhibit the injected behaviour allowed by the chosen model. In the main model, injections add calls rather than replacing planned commands. (§3.2.)

**Noninterference.** Changing secret inputs must not change the attacker's observations when public inputs are held fixed. Example: printing a constant after reading a PIN reveals nothing; printing whether the PIN starts with `1` violates noninterference. What counts as observable matters. (§§1, 7.)

**Relative security (RS).** Every pair of secrets distinguishable through the LLM agent must also be distinguishable through corresponding reference runs. The reference may use different attacker inputs. Example: an injected calendar disclosure can pass if a genuine meeting request obtains the calendar; adding a reset code fails if the reference never reveals it. This does not establish task authorisation. (Definition 4.1; §2.1.2.)

**Uniform relative security.** Stronger RS with a fixed mapping from LLM-agent action sequences to reference action sequences, chosen independently of the secrets. Ordinary RS may choose a different reference input for each secret pair. Example: a reference that answers “is the secret equal to your guess?” can distinguish every pair using a suitable guess, so ordinary RS can accept an injected full-secret disclosure; the uniform condition rules out this example when no fixed guess suffices. (Definition 4.2.)

**Leak / secret distinguishability.** Two runs with equal attacker actions but different observations distinguish their respective secrets. “Leak” here includes intended disclosure; RS asks whether injection adds a distinction absent from the reference. (§4.)

**Disclosure bound (δ).** A specification of what information may affect observations. Secrets with the same δ-value must look alike. Example: δ keeps calendar availability but discards the reset code. If the reference meets this bound and RS holds, the LLM agent inherits it. (Definition 4.8; Theorem 4.9.)

**Declassification.** A policy explicitly permits selected secret information to be released. Unlike RS, it requires a release policy beyond the reference's behaviour. Example: release availability, but not private appointment details. (§7.)

**Speculative execution.** A processor executes ahead based on a prediction; discarded work may leave observable effects. Earlier relative-security work compares speculative with non-speculative execution. This paper compares injection-capable with injection-free execution; the monitor's fence plays an analogous role to a speculation barrier. (§§1, 7.)

## Agent and injection model

| Term | Meaning in the paper | Source |
|---|---|---|
| Plan / plan-then-execute | A finite list of commands fixed before untrusted content is read. Branches and loops are possible; a trusted interpreter runs it. | §3.1 |
| Trusted input | Data supplied through a channel the attacker cannot write. Trusted does not mean public: it can contain secrets or approvals. | §§2.2, 3.1 |
| Untrusted read | A request to obtain attacker-controlled content. Content enters memory and context only if the monitor allows it. | §3.3 |
| Memory | Variables available to the plan; initial memory can contain sensitive data from earlier work. | §§2.2, 3.1 |
| Context | Untrusted items read during the current model session and available to be obeyed as instructions. Distinct from memory. | §3.1 |
| Parser (`parse`) | Abstract function selecting which content represents an instruction and what call it requests. Not an implemented injection detector. | §3.1 |
| Oracle (`pick`, `onext`) | Abstract choice of when to obey and which context item to obey. Its schedule is independent of secrets and monitor responses; call arguments may still depend on secrets. | §§2.2, 3.1 |
| One-call injection | Each obeyed instruction adds one call. Repeated obedience can add multiple calls; each postpones the next planned step. | §3.2 |
| Programme injection | An instruction starts a programme with computation, branches, calls or reads. Writes may persist or be discarded. | Appendix B |
| Sandboxed frame | An injected programme runs on copied memory and its writes are discarded. This is a semantic sandbox, not a proof of OS isolation. | Appendix B |
| Dual LLM | A privileged component runs the plan; a tool-free quarantined model reads untrusted content and answers queries. A corrupted answer can still affect a planned action. | Appendix C |
| Fresh session | Clears the model context, but not necessarily the plan's memory. Deployment must remove retained untrusted influence; loading untrusted persistent memory can reintroduce it. | §§2.2, 3.1; §A.7 |

## Runtime enforcement

**Runtime monitor.** Trusted, stateful component that allows or denies requests. Its initial state, decision function and update function define the policy. Both compared agents use the same monitor. (§3.3.)

**Capability fence.** Revokes selected tools at an allowed untrusted read. The main theorem requires coverage of every tool the parser can inject and no later re-grant. Example: revoke `Fetch` before the email can trigger a request carrying a secret. A later explicit lock leaves an attack window. (§§2.1.3, 5.1.)

**Tool approval versus call approval.** Tool approval permits the next use regardless of arguments; call approval binds permission to exact arguments. Example: “allow Send once” can authorise an injected secret; “allow Send with this reply” rejects different content. The latter still has a step-level timing leak in the paper's example. (§2.1.4.)

| Term | Meaning in the paper | Source |
|---|---|---|
| Complete mediation | Every tool request and untrusted read passes through the monitor; there is no bypass. | §2.2 |
| Mediated reads | Admission and fence updates take effect before untrusted content is exposed to the model. | §2.2 |
| Session fence | Restores fenced tools only when a fresh session clears the context. Restoring them while old instructions remain permits stale-context attacks. | §5.1; §A.3 |
| Silent denial | A refused request has no effect visible to the assumed attacker. Some proof methods also require it to leave monitor state unchanged. | §2.2; Definition 5.5 |
| Budget | A limit on call count, not call content. An injected call can spend the last unit before the intended call. | §6; §A.4 |
| Argument contract / allow-list | Restricts permitted call arguments. Even a fixed allowed URL can leak through secret-dependent choice of whether to call it. | §6; §A.4 |
| Spotlighting | Marks untrusted content and asks the model not to obey it. The worst-case parser can ignore the marking; a guarantee needs a model-behaviour assumption. | §6; §A.5 |
| Trusted sanitiser | Rewrites content before admission. Security requires the joint condition that the parser recognises no sanitised value as an instruction. | §6 |
| Confidentiality tag | Interpreter-maintained label used to prevent private values reaching visible sinks. In Tagged Dual LLM, it also blocks the honest reply. | Appendix C |
| Implicit flow / control dependency | A secret affects which action occurs without being copied into its arguments. Example: send public `1` or `0` according to a private value. Data-only tags miss this. | §6; Appendix C |

## Observations and proof vocabulary

| Term | Meaning in the paper | Source |
|---|---|---|
| Run / trace | Sequence of system states. A completed run either terminates in a final state or is infinite. | §4 |
| Attacker actions (`Act`) | Attacker-supplied untrusted contents, with positional placeholders determined by the observation model. | §4 |
| Observations (`Obs`) | What the selected attacker model sees, such as allowed visible calls and their arguments. | §4 |
| Event-level attacker | Sees allowed visible calls without internal-step timing. Comparisons require matching interaction patterns; message-count differences alone are not detected. | Definition 4.3 |
| Step-level attacker | Sees observations at each execution step. Comparisons require equal run lengths and untrusted-read positions, so this is not simply a stronger event-level attacker. | Definition 4.4 |
| Attacker with views | Adds selected observations of denied requests or sources read. Example: a refusal log reveals whether a private setting grants a tool. | Definition 4.5 |
| Alignment | Relation ensuring the interaction pattern is determined independently of secrets in the required way. With alignments for both systems, event- and step-level RS coincide. | Definition 4.6; Theorem 4.7 |
| Fair oracle | Cannot keep obeying injections forever and indefinitely postpone the plan. Needed for the stated fence results on possibly infinite runs. | §5.1 |
| Composition theorem | Splits proof obligations between agent behaviour and monitor enforcement, linked by “tainted agent implies monitor deny mode”. | §5.2 |
| Unwinding / lockstep | Local relations between states support a global security proof. Lockstep packages the existing unwinding method for the agent language. | §5.3 |
| Block simulation | Matches one LLM-agent step with zero, one or several reference steps; supports disclosures occurring at different points. | §5.4 |
| Stuttering simulation | Lets the reference wait during invisible steps, with a decreasing measure excluding endless waiting. Used for non-terminating systems. | §5.5 |
| Counterexample / disproof | Establishes an injected distinguishing pair and rules out a matching reference leak. Suggests a test with two secrets and one attack. | §5.6 |
| Litmus test | Small example isolating one security issue, rather than a full implementation of a named defence. An unqualified secure verdict may cover only its particular attack. | §6, Table 1 |
| Mechanisation | Encoding definitions and proofs in Isabelle/HOL. The paper reports checked proofs; this note does not independently verify them or their correspondence to a runtime. | §§1, 8 |

## Keep separate when using these terms

- **Confidentiality and authorisation:** RS can accept an unauthorised action if it adds no secret distinction.
- **Security and utility:** blocking every call can satisfy RS because the reference uses the same monitor. Legitimate task completion needs a separate check.
- **Model and deployment:** a theorem assumes the stated execution and observation model. A runtime needs evidence that its mediation, sessions and external effects meet those assumptions.
