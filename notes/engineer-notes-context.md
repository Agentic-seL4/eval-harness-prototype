# Research engineer notes: ingestion and WP-2 relevance

Read on 2026-10-06. These are tentative proposals and interpretations, not agreed architecture, deadlines or delivery commitments. This summary preserves the source repository unchanged and does not select an experiment.

## Source map and reading coverage

| Source | Purpose and inspection |
|---|---|
| [Repository README](../notes/README.md) | Shared living notes; contribution/layout conventions. Read in full. |
| [Initial-ideas README](../notes/discovery_phase/initial-ideas/README.md) | Document/figure map and build instructions. Read in full. |
| [Initial understanding PDF](../notes/discovery_phase/initial-ideas/current-understanding.pdf) | Eight-page picture dated 30 September 2026: formal-paper interpretation, deployment alternatives and prototype proposal. Read all extracted page text; visually checked pp. 6-7. |
| [Implementation-explorations README](../notes/implementation-explorations/README.md) | Reading guide, canonical LaTeX source, build/provenance instructions. Read in full. |
| [Implementation explorations PDF](../notes/implementation-explorations/implementation-explorations.pdf) | Ten-page refinement dated 5 October 2026: deterministic replay, gateway boundary, harness instrumentation and proposed acceptance criteria. Read all extracted page text; visually checked pp. 4-6 and 9. |

The implementation README identifies its LaTeX document as the maintained version of the follow-up; older initial ideas remain a historical snapshot. Build scripts and selected LaTeX passages were inspected in an earlier pass, but neither document was rebuilt. Remaining unread material includes the complete figure/style sources and a current audit of the referenced formal developments. This ingestion is of the notes, not a verification of everything they cite.

## Mapping to our working goals

### Runtime architecture

The initial notes propose a worker whose tools, data and model requests pass through a trusted gateway, with credentials held by tools or a model proxy. The worker is treated as untrusted as a whole. Hosted inference is explicitly a channel: protecting mail/web tools does not prevent disclosure to an inference provider. Provider trust or local inference needs a deliberate choice. (Initial pp. 4-6; follow-up p. 7.)

Three deployment candidates are pictured: a confined Linux process; a Linux guest on seL4 with native gateway/tool components; and a minimal native seL4 agent client. A common evaluation harness is proposed across them. These are alternatives, not chosen platforms. Statements about current platform proof coverage require a fresh configuration-specific check before use. (Initial p. 6, Figures 5-6.)

The notes distinguish two revocation mechanisms: the gateway denies a request while the worker's fixed channel remains, or the kernel revokes a capability held by the worker. Their trust and implementation obligations differ. Neither mechanism reverses an effect already performed or erases data already learned. (Initial p. 7, Figure 7; follow-up p. 7.)

### Monitoring

The follow-up proposes a trusted gateway owning policy state, source labels, session identity and credentials. It must not rely on the worker to identify a request as planned, relabel data, approve itself or declare sanitisation complete. (Follow-up p. 4.)

Its proposed monitor interface is:

```text
decide(state, tool, args) -> (response, next_state)
observe(state, event) -> next_state
```

A decision may consume authority, including on denial; retaining its successor state matters. For an untrusted read, the proposed ordering is **decide -> retain successor state -> observe allowed read/revoke -> deliver content**. A denied read does not deliver content or trigger the allowed-read update. The initial fixture uses one session and one in-flight request. Concurrency would require additional design and evidence. (Follow-up p. 4, Figures 3-4.)

Real data-returning tools require explicit admission and source labeling rather than treating every tool response as the formal model's fixed success/failure result. Fresh model context also differs from erased plan memory, caches, provider state and pending responses. The notes call for an explicit reset mapping and stale-response tests before re-granting authority. (Initial p. 4; follow-up pp. 7 and 9.)

### Evaluation

The primary proposed experiment is a deterministic replay of the email fixture: read a secret, read an injected email and assign the email to a summary variable. A scripted injection issues `Fetch [secret]`. With an open policy the attacker sees the secret argument; with a fence triggered by admission of untrusted content, Fetch is revoked first. This is a boundary fixture, not natural-language summarisation. (Follow-up p. 3.)

Proposed acceptance checks include open-policy leakage for two fixed secrets, fenced behavior, benign completion, a denied read that never reaches worker memory/context, and full pre-state/request/decision/post-state traces with a separate attacker projection. No reset or re-grant is proposed in the first slice. A handwritten replay is experimental code; independent formal export and implementation correspondence remain later obligations. (Follow-up pp. 3 and 9.)

The follow-up suggests regression cases for fence placement, exact-call versus tool approval, budgets/refills, stale sessions, denial/read visibility and repeated injection. For real models it recommends same-secret controls alongside two-secret runs, since random output variation can mimic secret dependence. Record task completion, disclosures, extra effects and refusals separately. (Follow-up p. 5.)

Three evidence claims are explicitly separate: **specification conformance**, **complete mediation**, and **security under an applicable property and its premises**. A blocked sample alone establishes none universally. Fixed error text does not make denials invisible if arguments, counts, retries or remote logs remain observable. (Follow-up pp. 7-9.)

## A second route: label instrumentation

The notes propose a separate finite experiment for Andrei's harness language: compare original tracked semantics, instrumented execution with checks disabled, and execution with checks enabled. Compare values, labels, permissions and knowledge closure at synchronization points, since instrumentation adds steps. Test safe flow, forbidden explicit flow, branch-dependent flow, and permission withdrawal before sanitisation. (Follow-up p. 6.)

At the reviewed `Brainstorming@fcebab2`, the notes report that `instrument_tracks`, `monitor_secure` and the forwarding-harness security result are pending; some auxiliary/erasure results are reported proved. We have not rechecked that repository or its current proof status. The notes do not establish equivalence between its bad-state exclusion property and relative security/integrity/robustness. For our WP-2 scope, a runtime-label experiment is a candidate; proving the connection would require formal collaborators.

## Important refinements and caveats

- The initial p. 2 description says worst-case model verdicts cover adaptive attacks. The follow-up p. 7 qualifies the one-call oracle as a fixed schedule; a fully adaptive model or compromised worker requires a correspondence argument. Use the qualified scope, not the broad initial phrasing.
- The kickoff's confidential-read trigger and the paper fixture's untrusted-read trigger are different policies. The notes already flag this distinction. (Follow-up p. 7.)
- The initial notes' informal relative-security summary is not an allowed-disclosure specification. The follow-up raises pairwise calendar distinguishability as a limitation and asks what one interaction should legitimately reveal. This remains a policy question, not a newly checked result here. (Follow-up p. 8.)
- Reported RS/RI/RR results and the claim that tightening a monitor can break relative security are pointers into the formal development, not proofs reproduced by these documents. One benign reference run does not exhaust the reference witnesses needed for a general relative-property comparison. (Follow-up pp. 5 and 9.)
- The follow-up reports no runtime, export pipeline or new proof built for the document, and no independent Isabelle rerun. Its reviewed commits are historical source pins, not current repository status. (Follow-up pp. 1-2 and 10.)

## Repository hygiene observations

The root README points to `discovery_phase/implementation-explorations/`, but the document is at `implementation-explorations/`. The follow-up README's `../initial-ideas/README.md` target is absent; the actual initial notes are under `discovery_phase/initial-ideas/`. Its advertised `figures/meeting-figures.pdf` is absent in this checkout. A cited `papers/1-PI_as_RS/sections/defence.tex` path is also absent in the current formal checkout. Treat those as historical/stale references; originals were not edited during ingestion.

## What to carry into discussion

The most reusable material is the event/admission boundary, credential ownership, distinction between gateway and kernel revocation, and the trace-based acceptance checklist. The deterministic replay could clarify these cheaply, but it would not replace evaluation on realistic agent workloads or bypass testing. No proposed route has been adopted.

Open choices: which policy and workload to begin with; gateway ownership and source-label convention; hosted-model trust; reset/re-grant semantics; observation audience; and how to align interfaces with the Sheffield runtime/Purple Team effort.

## Inspection log

- `notes` HEAD observed: `6c4729ef9575601a1c157a8cc5fdac22173125ba`; `git -C notes status --short` produced no changes.
- `pdftotext -layout <PDF> /tmp/wp2-paper-reading/engineer-<name>.txt`: exit 0 for both PDFs.
- Six selected pages rendered using `pdftoppm -f <page> -l <page> -scale-to 1400 -singlefile -png <PDF> <prefix>`; all succeeded and were visually inspected.
- Initial PDF SHA-256: `f028908a6f992392d1f2a6a30fa898c07b96717aa69d6e068aee2b50b209c7ae`.
- Follow-up PDF SHA-256: `ba79bd48de2b4eb72eb2dd84df1be8af3e5635c830b12ec3606f4dbe0ebd26dd`.
- No build, export, runtime experiment or proof check performed. Existing `notes/` work preserved.
