# AgentCore Gateway, Strands Agents and Microsoft Agent Framework

Exploration, 5 November 2026. Focus: WP2 runtime boundaries, monitoring and Relative Security experiments. Recommendations below are suggestions, not agreed architecture or experiment decisions.

## 1. Assessment

These systems can supply agent orchestration, tool integration, policy enforcement and execution isolation, but those are different functions. None of the inspected material establishes that an assembled application satisfies our Relative Security model or that it is formally verified end to end.

| Candidate | Most useful role | Sandboxing distinction | Suggested research use |
|---|---|---|---|
| Bedrock AgentCore Gateway | Independent managed entry point for tools and credentials | Gateway mediates requests; Runtime and Code Interpreter supply separate execution environments | Commercial policy-enforcement baseline and stateful-policy experiments |
| Strands Agents SDK | Replaceable agent harness with tool and model adapters | Explicit sandbox backends isolate selected operations; separate Strands Box contains workloads and brokers operations | Flexible local baseline; compare SDK controls with enforcement outside the agent |
| Microsoft Agent Framework | Harness, workflows and information-flow experiments | FIDES is middleware; Docker and Hyperlight provide distinct execution boundaries | Study labels, quarantine, approvals and nested-call coverage |

**Suggested approach:** use a common workload, independent sink and small policy contract across several deployments. Start with deterministic adversarial proposals, then add LLM runs. Treat the framework as a replaceable client of the enforcement boundary. A Linux implementation can answer substantial research questions before a seL4 integration exists.

## 2. Scope, sources and evidence

This is a documentation-led feasibility review. Official documentation was inspected on 5 November 2026; links to moving pages describe that reading snapshot, not a pinned package release. Some Strands pages changed between retrieved snapshots. Its current Box security page explicitly identifies itself as documentation preview. Confirm package versions, platform support and API availability before implementation.

Inspected selectively:

- AWS: Gateway, Policy, enforcement modes, temporal conditions and sessions, interceptors, Runtime sessions/security, Code Interpreter networking, and restricting direct Memory access.
- Strands: SDK sandbox interface, Docker/SSH backends, custom backends, Cedar intervention, Box security and repository design decisions.
- Microsoft: FIDES security page, developer guide and design decision; shell tools; Hyperlight integration. The source page was opened for navigation, but the implementation was not audited.
- Local research: [October PlanTERS glossary](../papers/planters-glossary.md), older RS/RI notes, [Microkit extension discussion](../experiments/microkit-debug/extension-plan.md), and the paper repository's [threat model](../../prompt-injection-RS/THREAT_MODEL.md) and [deployment obligations](../../prompt-injection-RS/INSTANTIATION.md).

Local paper repository: `4c0d9e5d59b90a42dea4cf8a235474b83fbf792e`. The October PDF's SHA-256 was checked: `64481f1df6c86c7d55b00ad5fc21e76689bdf3b7ee2dc8a3bce3eaef79765bea`. Definitions below use the glossary's October section numbering; newer deployment obligations come from the repository document, not an assumed revision of that PDF.

No packages were installed, accounts provisioned, cloud resources deployed, model calls made, attacks executed or proofs rebuilt. No remote source repository was cloned. Vendor descriptions are source-reported capabilities; architecture assessments and experiment designs are our inferences. Full SDK implementations, provider internals, FIDES's underlying paper and complete proof sources remain unread.

## 3. What a sandbox must protect

Specify the adversary before choosing the product:

| Threat | Required boundary | What alone is insufficient |
|---|---|---|
| Model follows malicious document instructions | Mediation of tool effects, reads and destinations | System prompt or tool description |
| Generated code attacks its execution host | OS process restrictions, container or VM with controlled interfaces | Tool approval or function middleware |
| Agent process or dependency is compromised | Monitor and credentials outside that process; deny alternate routes | An in-process hook |
| Malicious tool or MCP server | Separate tool execution and untrusted result admission | Trusting tool metadata or a successful authenticated connection |
| Another tenant attacks the workload | Separate tenant authority and execution state | Separate conversation objects in one privileged process |
| Approved access is abused | Argument, purpose, history and disclosure policy | Authentication or host isolation |

A sandbox can successfully contain a worker while that worker leaks every secret it was deliberately given through an allowed API. Conversely, a sound tool policy can run inside an ordinary Linux process while relying on the process and kernel remaining uncompromised. Evaluate these properties separately.

Model endpoints, logs, file uploads, DNS, browser rendering and returned answers are possible sinks too. A gateway for business tools does not automatically govern any of them. Decide whether the model provider and operator are trusted recipients; a dummy-data experiment can exclude real confidential data without solving that deployment question.

## 4. Bedrock AgentCore Gateway

### 4.1 Product boundary and stack

Gateway is a managed service connecting agents to MCP tools, API/Lambda targets and other supported traffic. It provides inbound authentication and outbound credential handling. It can be used independently of an AWS-hosted agent: a client that can speak its supported protocol and authenticate can call it. This makes it a plausible shared boundary for either Strands or Microsoft clients. [AWS Gateway overview](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/gateway.html).

Policy adds declarative authorisation outside agent code. Standard Cedar conditions concern the current request; the current documentation also describes Dogwood temporal conditions over session history. This distinction matters: plain stateless Cedar does not itself remember that an untrusted read occurred. Policy-language analysis is not a proof of the gateway's implementation or the application's disclosure policy. [Policy concepts](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/policy-core-concepts.html).

Request and response interceptors are Lambda functions before target invocation and before returning its response respectively. AWS documents retries and advises idempotent handlers. A response interceptor cannot undo an already committed target effect. It could participate in read-admission control only if state is updated before any untrusted response bytes become model-visible, with fail-closed delivery. [Gateway interceptors](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/gateway-interceptors.html).

### 4.2 Actual sandboxing is elsewhere

For the standard managed microVM Runtime model, AWS documents a dedicated execution environment per session and state retained within that session. That protects sessions from one another; it does not separate the agent from every tool or credential inside its own environment. AWS also documents a localhost platform server within the session's responsibility boundary. The newer Runtime Instances option has a different management/session model; do not generalise the standard microVM description to every Runtime deployment. [Runtime sessions](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/runtime-sessions.html), [Runtime security](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/runtime-security-best-practices.html), [Runtime Instances](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/runtime-instances-how-it-works.html).

Code Interpreter is another service: AWS describes a microVM for each tool session. Its network modes are consequential. Sandbox mode allows limited AWS-service access, including S3; it does not mean zero egress. Public and VPC modes expose different destinations. Execution-role permissions remain part of the effective authority. [Interpreter sessions](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/code-interpreter-session-characteristics.html), [network settings](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/code-interpreter-resource-management.html).

### 4.3 Stateful enforcement and gaps to test

Temporal policies can correlate current arguments with earlier events and express sequencing or limits. History has explicit event types and time windows; response-dependent rules require the earlier response to have completed. Policy changes invalidate existing temporal sessions. Account, Region and identity-token propagation constrain cross-component enforcement. These are useful features, but they require an ordering and lifecycle argument before representing a permanent capability fence. [Temporal policies](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/policy-temporal.html).

The application supplies the policy-session ID. AWS explicitly says a new ID creates a fresh history boundary, and per-request IDs effectively disable useful history. Authenticated identity binding stops callers sharing a session across identities, but does not prove that a compromised client cannot reset its own history while retaining tainted context. A trusted supervisor must own session creation and map it to the actual workflow/context lifetime. [Policy sessions](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/policy-session-based-temporal.html).

Additional configuration risks:

- `LOG_ONLY` observes decisions without blocking. Permission to update Gateway can change mode or remove the policy engine. Keep it outside worker authority. [Enforcement modes](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/policy-enforcement-modes.html).
- Gateway only controls traffic sent through it. AWS's Memory example explicitly requires target-side restrictions to prevent direct data-plane access. Apply the same reasoning to every target; that example is not a universal recipe for all backends. [Restrict direct Memory access](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/memory-gateway-restrict-access.html).

**WP2 inference:** a useful managed baseline would combine Gateway, enforced policies, protected target credentials, target-side access restrictions and constrained worker egress. Gateway alone is not complete mediation. Interceptor state, retries, approval consumption and target effects need transaction or idempotency semantics. Test them rather than infer exactly-once behaviour from an allow decision.

## 5. Strands Agents

### 5.1 SDK execution and policy controls

The current SDK documentation exposes an explicit sandbox interface. Without a configured sandbox, command/file operations run on the host with the agent process's permissions. Configured sandbox tools support shell and file operations; arbitrary custom Python/TypeScript code is not magically confined merely because the agent has a sandbox object. Custom tools must use the confined backend or another enforced boundary. [SDK sandbox](https://strandsagents.com/docs/user-guide/sdk/sandbox/).

`DockerSandbox` uses `docker exec` in an already running container; Strands does not create that container. Its security therefore depends on how it was launched, including mounts, network and user. `SshSandbox` executes on a remote host: SSH supplies transport and authentication, while remote account/OS configuration supplies confinement. The interface name does not prove that host is restricted. [Available backends](https://strandsagents.com/docs/user-guide/sdk/sandbox/available-sandboxes/).

The custom sandbox interface is an integration seam for other execution services. A seL4-backed adapter is conceivable, but inheriting a POSIX-shell adapter would impose a shell/filesystem interface that a small native domain does not have. Prefer typed tools where that is sufficient. [Custom backends](https://strandsagents.com/docs/user-guide/sdk/sandbox/custom-sandbox/).

Cedar Authorisation is an SDK intervention before tool calls. The documented mapping includes tool arguments and session metadata, default denial and identity resolution. It can supply a policy baseline, but lives in the harness boundary and reports denials to the agent. It cannot constrain a malicious process invoking a backend directly. [Cedar intervention](https://strandsagents.com/docs/user-guide/sdk/agents/interventions/cedar-authorization/).

### 5.2 Strands Box is a separate candidate

Box combines OS restrictions with a trusted process handling policy, interpreters, MCP and egress. Its design decisions describe macOS Seatbelt and Linux namespaces/syscall filtering. That document labels itself historical, so supported architectures and actual mechanisms must be checked against a pinned build before deployment. Box is a useful open-source enforcement candidate, not merely another SDK hook. [Box design decisions](https://github.com/strands-agents/box/blob/main/docs/design/decisions.md).

The current security page distinguishes direct OS filesystem grants from brokered policy operations. Directly granted paths and tool-internal file operations do not receive individual policy decisions. Credentials are attached to permitted gateway requests. HTTP replies and some MCP traffic are not policy-decided. It documents concurrent response-count budget overspend, and that request-history rules can see denied attempts. Thus a single Box deployment has multiple enforcement paths to map. [Box security](https://strandsagents.com/docs/user-guide/box/security/).

**WP2 inference:** Box is attractive for testing whether real process containment makes a logical monitor unavoidable. Use narrow direct grants, put sensitive effects behind brokered operations and independently record sink effects. Do not assume every syscall becomes a policy event. Separate boxes or VMs may be needed where tools must not share authority. Preview status and documentation movement favour a pinned-source pilot before a large benchmark.

## 6. Microsoft Agent Framework

### 6.1 FIDES: a close conceptual comparison

FIDES is experimental, Python-only information-flow middleware. It labels integrity and confidentiality, propagates labels, checks sensitive calls and can keep untrusted bytes behind variable references with a tool-free quarantined model. It is not OS confinement. The documentation notes conservative propagation and that authoritative MCP labels require a trusted server; default confidentiality for unannotated results is public, so sources of secrets need explicit classification. [FIDES security](https://learn.microsoft.com/en-us/agent-framework/agents/security).

The developer guide describes per-item labels and run/session state. Reusable middleware without an explicit session uses isolated security scope per run; explicit sessions carry security state across runs. Consequently, application conversation state and security state must be aligned. A process restart or new run can clear enforcement history without proving that retained summaries or external memory are clean. [FIDES developer guide](https://github.com/microsoft/agent-framework/blob/main/python/samples/02-agents/security/FIDES_DEVELOPER_GUIDE.md).

The design decision describes variable indirection, quarantine and policy middleware as separate pieces. This is particularly relevant to PlanTERS's dual-LLM cases: we can compare concrete labelling and release decisions with a small formal instance. The decision's security claims remain source claims; no correspondence proof to PlanTERS was found or checked. [FIDES design decision](https://github.com/microsoft/agent-framework/blob/main/docs/decisions/0024-prompt-injection-defense.md).

### 6.2 Execution isolation

Microsoft explicitly states that `LocalShellTool` is not a sandbox. `ShellPolicy` filters command text, not the eventual shell semantics or file accesses. Its Docker shell tool documents defaults including no network, a non-root user, read-only root, dropped capabilities and resource limits; developer overrides can weaken them. This confines shell execution, not necessarily the surrounding agent or every registered tool. [Shell tools](https://learn.microsoft.com/en-us/agent-framework/integrations/by-component/tools/shell-tools).

Hyperlight CodeAct supplies a separate execution sandbox and requires KVM on Linux or WHP on Windows. Host callbacks invoked through `call_tool` still run with host authority. Crucially, current documentation says nested provider-managed calls bypass normal per-function middleware and are unsupported by FIDES. An outer approval of `execute_code` is not evidence that each nested effect is checked. Integration packaging is preview-dependent, so establish a buildable version first. [Hyperlight integration](https://learn.microsoft.com/en-us/agent-framework/integrations/by-component/context-providers/hyperlight).

Hosted Code Interpreter is another provider-managed tool option. Its isolation contract belongs to the selected service, not automatically to Agent Framework. Approval support also depends on whether calls execute locally or at a provider. [Tools and provider support](https://learn.microsoft.com/en-us/agent-framework/agents/tools/).

**WP2 inference:** Microsoft is the strongest candidate here for studying information-flow policy and quarantined answers. It also offers an especially useful coverage experiment: compare the same sensitive operation as a direct FIDES-controlled tool and as a nested host callback. A documented unsupported combination is a boundary to characterise, not automatically a new vulnerability. Do not claim compatibility by combining two individually documented features.

## 7. Feasibility with seL4

### 7.1 Three different meanings of integration

| Architecture | Feasibility assessment | What seL4 could establish | What remains outside that boundary |
|---|---|---|---|
| Framework on a separate host; native seL4 broker receives proposals | Practical research path; needs bounded authenticated transport | Control of the guest effects reachable only through that broker | Host process, model endpoint, host networking and credentials |
| Framework in a Linux VM above seL4; broker in a separate native domain | Plausible, substantial engineering | Confinement of guest authority relative to broker-controlled assets, subject to configuration and system correctness | Guest internals; VMM, drivers, adapters and remote services where relevant |
| Framework ported directly into a native seL4 domain | High effort, weak initial research return | Potentially fewer OS services after a deliberate port | Language runtime, libraries, networking and policy implementation still need assurance |

seL4's tutorial demonstrates Linux virtualisation through Microkit; it does not establish a ready-made deployment of these frameworks. Native program images use Microkit's runtime interface. Python, Node and .NET ecosystems expect many OS facilities, so guest Linux or an external host is the more credible initial route. [Microkit VM tutorial](https://docs.sel4.systems/projects/microkit/tutorial/part4.html), [Microkit manual](https://docs.sel4.systems/projects/microkit/manual/2.3.1/).

### 7.2 Suggested separation

```text
Trusted workflow supervisor ── bounded stage request ──> untrusted framework worker
          │                                                │
          │ owns sessions/approvals                         │ typed proposal
          v                                                v
                  independent policy broker
                            │ allowed operation
                            v
                protected backend / independent sink
```

For a Linux-on-seL4 variant, put the framework and its dependencies in the guest and the small policy broker in another protection domain. Do not give the guest direct access to the protected backend, credential store or an unconstrained network device. Use a separate network/credential component where necessary. Enumerate shared memory permissions, DMA, devices and output channels explicitly.

This can remove the guest kernel from the trust required to protect *broker-owned* assets, if guest compromise still cannot bypass the broker. It does not remove the guest kernel from the trust required to protect secrets stored inside that guest. This property-specific TCB distinction is more useful than counting Linux lines once for the entire system.

For an external-host variant, a broker cannot retract secrets already sent to that host or stop its independent network traffic. That variant can test mediated guest effects using dummy data, but cannot substantiate containment of the host. It is consistent with the existing [host-backend discussion](../experiments/microkit-debug/extension-plan.md), while the broader VM and sandbox designs here remain new suggestions.

AgentCore Gateway remains a remote AWS service; it cannot simply be installed into a native seL4 domain. A seL4 broker can call it through a network adapter, or an AWS gateway can front a service ultimately connected to our broker. Either direction adds trusted adapters and remote enforcement assumptions. Choose which component owns each decision; avoid two inconsistent approval/session state machines.

Hyperlight's documented KVM/WHP backend is not a seL4 backend. A port would require new virtualisation integration; Docker likewise requires a suitable guest environment. Strands' custom interface is a cleaner seam for a small typed adapter than pretending a native domain supports arbitrary POSIX shell commands.

### 7.3 Proof scope

Do not describe any proposed system as verified merely because it boots seL4. Record kernel revision, architecture, scheduler configuration, build options, device mappings and the properties actually covered. Microkit's manual explicitly warns that release mode does not imply a verified kernel configuration, and discusses its MCS dependency. Live proof-status documentation can lag milestones; reconcile the exact release with the relevant proof artefacts rather than relying on dates in a manual. [Verified configurations](https://docs.sel4.systems/projects/sel4/verified-configurations.html), [Microkit proof caveat](https://docs.sel4.systems/projects/microkit/manual/2.3.1/).

Kernel assurance does not prove our broker, protocol, workflow, label propagation or the connection between runtime traces and the paper model. Those are separate obligations.

## 8. What we can do without seL4

Removing seL4 still leaves a substantial research programme: specify the monitor, implement it independently, enforce mediation using conventional isolation, and test the paper's deployment assumptions. The resulting claim relies on the selected OS or hypervisor rather than seL4's proof coverage.

| Deployment suggestion | Main benefit | Principal cost or assumption |
|---|---|---|
| Trusted harness with SDK hooks/FIDES | Fastest policy and labelling experiments | Harness and all in-process tools remain trusted |
| Restricted worker process/container plus separate broker | Clear credential separation; direct bypass tests | Linux kernel and sandbox configuration trusted; no Docker socket or host-secret mounts |
| Box around a harness, optionally inside a VM | Existing OS and broker integration | Audit direct grants, preview support and trusted interpreter/gateway surface |
| One VM/microVM per worker or session plus external broker | Better separation from worker kernel compromise | Hypervisor, broker and adapters trusted; lifecycle/provisioning effort |
| AgentCore Runtime plus Gateway and restricted targets | Managed session execution and commercial authorisation baseline | AWS service behaviour, IAM and configuration; cloud cost and less internal visibility |
| Hyperlight for generated computation plus separately authorised callbacks | Small execution environment for a bounded code task | Host callbacks need their own controls; unsupported FIDES composition must remain explicit |

For a local Linux pilot, retain model credentials in a trusted proxy, give the worker only workspace data and a broker connection, and disallow direct sink access. A container running only generated commands is a weaker experiment than isolating the whole framework process when the threat includes a compromised harness.

No isolation choice prevents an allowed request leaking a secret in its body. Conversely, refusing all requests is an unhelpful success. Compare useful authorised completion, confidentiality and integrity separately.

## 9. Relative Security: evaluation method

### 9.1 Reference and observation contract

The October paper defines RS through secret distinguishability relative to a reference, not equality with a benign transcript. The reference follows the same fixed plan and monitor without obeying injections. Ordinary RS can use a different reference attacker input to explain a distinction; uniform RS requires a secret-independent mapping. A same-input injected/reference mismatch is therefore not by itself an RS counterexample. (§§3–4; [glossary](../papers/planters-glossary.md).)

For a small exhaustive experiment, choose a finite secret domain and finite attacker-input set. For each secret pair, enumerate reference observations over the declared attacker inputs. An injected distinguishing pair refutes that bounded instance only if no permitted reference pair explains the distinction. State the finite scope; it is not a universal proof. For broader workloads, call results empirical leakage/effect tests unless an explicit formal mapping supports a stronger verdict.

Use a trusted fixed workflow for the direct PlanTERS instantiation. Framework free-form planning is a separate exploratory condition; freezing its initial prompt does not make the plan static. The framework can instead handle one bounded stage and return a proposal to the trusted executor. An adversarial scripted worker may exceed the paper's scheduling assumptions: that is useful enforcement testing, but label it as a stronger runtime threat rather than claiming every trace is a paper-model execution.

Define observers before recording results:

- External recipient: allowed requests, actual destinations and payloads.
- Malicious source/server: reads and their parameters, including secret-dependent source selection.
- Worker: denials, errors and tool-result feedback; distinguish this from what a remote attacker can actually observe.
- Operator/provider: logs, prompts and policy-service requests, if included in the threat model.
- Timing observer: declared duration/size measurements. Do not equate wall-clock samples with the paper's abstract steps.

Local obligations D1–D7/D9 cover mediation, destination coherence, source classification, visibility, tool results, channels, model-visible retained content and authenticated internal channels. Use them as a deployment checklist, not as claims already discharged. [Instantiation boundary](../../prompt-injection-RS/INSTANTIATION.md#3-assumptions-a-deployment-must-discharge-outside-isabelle).

### 9.2 Proposed experiments

All rows are proposals; none was implemented or selected in this review.

| Experiment | Smallest useful case and expected question | Candidate systems | Evidence sought |
|---|---|---|---|
| 1. Mediation coverage | One protected read and one external send; request the same effect through each registered route, direct HTTP and generated code | All; compare hooks, external Gateway/broker and worker confinement | Actual sink receives only authorised effects; identify routes absent from policy logs |
| 2. Admission fence | Read attacker mail, then submit a secret-bearing send; compare open, immediate and deliberately late fence | Custom monitor, AgentCore temporal/interceptor candidate, Box history candidate | Fence commits before bytes are exposed; benign reply cost recorded; overlap read/send deliberately |
| 3. Approval binding | Approve a specific recipient/body once, then change body, destination, session or request ID | Microsoft approval/FIDES, custom Gateway interceptor, local broker | Exact binding, expiry, single consumption and replay rejection; trusted approval source required |
| 4. History reset | Keep an injected summary but create a new framework/policy session; try privileged action again | AWS policy sessions, FIDES sessions, Box lifecycle, custom epoch broker | Re-grant follows genuine clean state; worker cannot mint a clean epoch; delayed responses rejected |
| 5. Quarantined answer corruption | Tool-free model returns an attacker recipient or a private summary used in the planned send | Microsoft FIDES, a minimal dual-LLM Strands setup | Labels/release checks survive summary and variable expansion; useful summarisation still possible |
| 6. Implicit disclosure | Secret controls whether to send fixed public text or which allowed URL is fetched | Every policy baseline | Difference in attacker observations despite public arguments; examine context labels as well as data tags |
| 7. Nested tool execution | Invoke the same sensitive callback directly and from generated code | Hyperlight direct/nested comparison; custom Strands tools and sandbox route | Identify which policy/approval path executes; documented unsupported coverage remains explicitly outside the claim |
| 8. Concurrent budget/revocation | Two sends race for the final approval/budget; overlap a read with an outbound operation | Box, Gateway policy/interceptors, local broker | Linearisation point, count of committed effects, retry behaviour and legitimate-task failure |
| 9. Destination/source coherence | Allowed URL redirects to a denied host; tool changes endpoint using arguments; MCP result claims trusted labels | Gateway-backed HTTP tool, Box egress, FIDES/MCP adapter | Decision binds to real destination/source; redirects separately mediated; labels supplied by trusted authority |
| 10. Denial and audit channels | Secret changes which denied action is attempted; inspect client errors, telemetry and timings | All | Whether refusal itself leaks to a declared observer; no unsupported claim of silent denial |

For experiment 2, a temporal rule over completed responses may leave an in-flight interval; a rule over requests can fence earlier but may also react to refused reads. Measure both behaviours against the intended state transition. History time windows and expiry must not silently restore authority while tainted context survives.

For experiment 3, approving code or a tool name is not exact-call approval. Bind a trusted approval to the canonical operation, arguments, principal, workflow epoch and nonce, then verify the backend performs that same operation. These are suggested design requirements, not claims about the frameworks' default approval semantics.

For experiment 5, treating a generated answer as trusted because a trusted plan later uses it is the error under test. Data tags may be conservative or incomplete for control flows; test both actual leakage and utility rather than presuming a verdict.

### 9.3 Controls and measurement

Use a fake inbox, fake secret store and independently logged sink with synthetic data. Start with two equal-length secrets that differ only in the protected field. Include a public field the task should release so the useful outcome is explicit.

Maintain the same logical policy and fixed workflow across deployments. Preserve tool visibility when testing an independent broker; otherwise removing a tool from the model changes behaviour as well as enforcement. Where configurations cannot express the same rule, report that difference rather than silently replacing the rule.

Run three evidence modes:

1. Scripted benign proposals: establish that the legitimate workflow completes.
2. Direct adversarial proposals: exercise enforcement even if an LLM refuses the attack.
3. Repeated LLM runs: measure practical attacks and completion; preserve prompts, outputs, settings and model identifiers.

Record request, workflow and epoch IDs; source admission; proposed calls; policy version and decisions; approval state; backend effects; retries; errors; session resets and context retention. Broker decisions and worker telemetry are not substitutes for the independent sink. Protect analyst logs and define who can observe them.

Report task completion under benign and attacked inputs, extra disclosures, unauthorised effects, blocked legitimate actions, bypass success, duplicate effects, latency, cloud/model cost and approval burden. A confidentiality-preserving extra payment still fails authorisation; RS alone does not settle that. Where effects and disclosure must share a justification, use the RI/RR distinctions in the [companion note](../papers/relative-integrity-robustness.md).

## 10. Suggested priorities and open choices

1. **Highest initial value:** a framework-neutral, finite fixed-plan test with an independent sink, two secrets and a scripted attacker. Run it with Strands and Microsoft as replaceable clients of one local broker. This isolates policy semantics from model behaviour.
2. **Closest paper comparison:** FIDES direct-tool/quarantine cases, especially poisoned answers, retained summaries and implicit flows. Require explicit source labels and a separately stated release policy.
3. **Best commercial comparison:** AgentCore Gateway in enforcing mode, with temporal policy/session control and no direct target authority. First establish regional support, precise event semantics and a reproducible configuration; do not start with a large cloud workload.
4. **Most useful confinement comparison:** SDK-only controls versus Box or a restricted Linux worker, then a VM. Test bypass resistance under process compromise separately from prompt injection.
5. **seL4 extension:** move the same small broker contract into an independently isolated domain, initially with synthetic data and no broad networking. A Linux guest becomes worthwhile if whole-framework confinement is the chosen question. Reuse workloads and observation definitions rather than expecting identical timing across substrates.

This programme can produce useful results without seL4: concrete counterexamples, policy expressiveness comparisons, state-lifecycle faults and evidence for deployment assumptions. seL4 would strengthen an explicitly chosen isolation boundary where the exact configuration supports the required assurance; it does not choose the policy or establish the reference's legitimacy.

Before implementing any option, select the threat model, reference plan, legitimate disclosure, attacker observations and first success criterion. Then pin SDK/package versions and container images, save service settings and policies, and check the chosen feature combination. This review does not change the existing Microkit plan or authorise a cloud deployment.
