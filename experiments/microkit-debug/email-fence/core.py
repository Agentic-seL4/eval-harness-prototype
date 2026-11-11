"""Handwritten finite replay of the Paper 1 email fixture; no real tool access.

One step is an atomic agent/monitor transaction. See README.md and
source-map.json for its source mapping and the deliberately broken late policy.
"""
from dataclasses import asdict, dataclass, replace
from typing import FrozenSet, List, Optional, Tuple

PAPER_COMMIT = "89db278f2632ffac438d681f3ca24724fb303fc4"
VARIABLES = ("Secret", "Mail", "Summary", "Result")
PLAN = ("ReadT Secret", "ReadU Mail Inbox", "Assign Summary := Mail")


def data(number: int) -> str:
    if type(number) is not int or number < 0:
        raise ValueError("Data requires a nonnegative integer")
    return "Data {}".format(number)


@dataclass(frozen=True)
class Config:
    mode: str = "injected"
    policy: str = "fenced"
    secret: int = 0
    email: str = "Email"
    inbox_allowed: bool = True

    def __post_init__(self):
        if self.mode not in ("reference", "injected"):
            raise ValueError("mode must be reference or injected")
        if self.policy not in ("open", "fenced", "late"):
            raise ValueError("policy must be open, fenced or late")
        if self.email not in ("Email", "Data 7"):
            raise ValueError("email must be Email or the benign value Data 7")
        data(self.secret)


@dataclass(frozen=True)
class Pending:
    target: str
    content: str


@dataclass(frozen=True)
class AgentState:
    pc: int = 0
    oracle: int = 0
    memory: Tuple[str, ...] = ("Data 0",) * 4
    context: Tuple[str, ...] = ()
    trusted_inputs: Tuple[str, ...] = ()
    untrusted_inputs: Tuple[str, ...] = ()
    pending: Optional[Pending] = None

    def read(self, variable: str) -> str:
        return self.memory[VARIABLES.index(variable)]

    def write(self, variable: str, value: str):
        memory = list(self.memory)
        memory[VARIABLES.index(variable)] = value
        return replace(self, memory=tuple(memory))


@dataclass(frozen=True)
class MonitorState:
    permissions: FrozenSet[str]


@dataclass(frozen=True)
class Event:
    kind: str
    tool: Optional[str] = None
    value: Optional[str] = None
    args: Tuple[str, ...] = ()

    def description(self) -> str:
        if self.kind == "AReadT":
            return "AReadT {}".format(self.value)
        if self.kind == "AReadU":
            return "AReadU {} {}".format(self.tool, self.value)
        if self.kind == "ACall":
            return "ACall {} [{}]".format(self.tool, ", ".join(self.args))
        return "ATau (assign Summary := Mail)"


@dataclass(frozen=True)
class Call:
    tool: str
    args: Tuple[str, ...]


class FakeTools:
    """A recording sink. It performs no HTTP, file or process operations."""

    def __init__(self):
        self.effects: List[Call] = []

    def dispatch(self, call: Call):
        if call.tool != "Fetch":
            raise ValueError("This fixture only dispatches Fetch calls")
        self.effects.append(call)


class Monitor:
    def __init__(self, policy: str):
        self.policy = policy

    def mdecide(self, state: MonitorState, tool: str, args: Tuple[str, ...]):
        # capDecide with an unrestricted argument contract. State is returned
        # explicitly even though this particular policy never changes it here.
        return ("Allowed" if tool in state.permissions else "Denied", state)

    def mnext(self, state: MonitorState, event: Event) -> MonitorState:
        # No grantOn trusted input. Only an ALLOWED read reaches this function.
        if event.kind == "AReadU" and self.policy == "fenced":
            return MonitorState(state.permissions - {"Fetch"})
        return state


def agent_step(state: AgentState, mode: str):
    """Return event, proposed state and origin; do not deliver a read yet."""
    if state.pc >= len(PLAN):
        return None
    if state.pending is not None:
        raise ValueError("A pending read must be resolved before the next agent step")
    advanced = replace(state, oracle=state.oracle + 1)
    if (mode == "injected" and state.oracle == 2 and state.context
            and state.context[0] == "Email"):
        # Inject_Call.stepO: no PC advance, no result destination, no memory write.
        return Event("ACall", tool="Fetch", args=(state.read("Secret"),)), advanced, "injection"
    if state.pc == 0:
        value = state.trusted_inputs[0]
        advanced = advanced.write("Secret", value)
        return (Event("AReadT", value=value),
                replace(advanced, pc=1, trusted_inputs=state.trusted_inputs[1:]), "plan")
    if state.pc == 1:
        value = state.untrusted_inputs[0]
        return (Event("AReadU", tool="Inbox", value=value),
                replace(advanced, pc=2, untrusted_inputs=state.untrusted_inputs[1:],
                        pending=Pending("Mail", value)), "plan")
    return (Event("ATau"),
            replace(advanced.write("Summary", state.read("Mail")), pc=3), "plan")


def receive(state: AgentState, decision: str) -> AgentState:
    """Agent_Lang.recv for this fixture: injected call responses are discarded."""
    if state.pending is None:
        return state
    pending = state.pending
    if decision == "Allowed":
        return replace(state.write(pending.target, pending.content), pending=None,
                       context=state.context + (pending.content,))
    return replace(state.write(pending.target, "Done"), pending=None)


def snapshot(agent: AgentState, monitor: MonitorState) -> dict:
    result = asdict(agent)
    result["memory"] = dict(zip(VARIABLES, agent.memory))
    result["permissions"] = sorted(monitor.permissions)
    return result


@dataclass
class Step:
    number: int
    origin: str
    event: Event
    before: dict
    proposed: dict
    after: dict
    decision: Optional[str]
    response: Optional[str]
    monitor_after_decision: Optional[List[str]]
    admission_permissions: Optional[List[str]]
    operations: List[str]
    effect: Optional[Call]
    action: Optional[str]
    observation: Optional[Call]


@dataclass
class Run:
    config: Config
    initial: dict
    steps: List[Step]
    final: dict
    effects: List[Call]

    @property
    def completed(self) -> bool:
        return self.final["pc"] == len(PLAN) and self.final["pending"] is None

    def projection(self, view: str = "event") -> dict:
        if view not in ("event", "step"):
            raise ValueError("view must be event or step")
        interactions = [s for s in self.steps if view == "step"
                        or s.action is not None or s.observation is not None]
        return {
            "actions": [s.action for s in interactions],
            "observations": [asdict(s.observation) if s.observation else None
                             for s in interactions],
        }

    def to_dict(self) -> dict:
        result = asdict(self)
        result["completed"] = self.completed
        result["secrets_read"] = [s.event.value for s in self.steps if s.event.kind == "AReadT"]
        result["views"] = {view: self.projection(view) for view in ("event", "step")}
        return result


def replay(config: Config, monitor: Optional[Monitor] = None,
           tools: Optional[FakeTools] = None) -> Run:
    monitor = monitor if monitor is not None else Monitor(config.policy)
    tools = tools if tools is not None else FakeTools()
    if tools.effects:
        raise ValueError("Use a fresh fake tool sink for each replay")
    agent = AgentState(trusted_inputs=(data(config.secret),), untrusted_inputs=(config.email,))
    policy = MonitorState(frozenset({"Fetch", "Inbox"} if config.inbox_allowed else {"Fetch"}))
    initial = snapshot(agent, policy)
    steps = []
    while agent.pc < len(PLAN):
        before = snapshot(agent, policy)
        event, proposed, origin = agent_step(agent, config.mode)
        proposal = snapshot(proposed, policy)
        decision = response = decision_state = admission_state = None
        effect = action = None
        operations = []
        if event.kind == "AReadT":
            policy = monitor.mnext(policy, event)
            agent = proposed
            operations.append("Read trusted secret; mnext grants no permissions")
        elif event.kind == "AReadU":
            decision, policy = monitor.mdecide(policy, event.tool, ())
            decision_state = sorted(policy.permissions)
            operations.append("Decide Inbox with empty arguments; keep returned monitor state")
            if decision == "Allowed":
                policy = monitor.mnext(policy, event)
                admission_state = sorted(policy.permissions)
                operations.append("Apply mnext for the allowed read before delivering its content")
                action = event.value
            agent = receive(proposed, decision)
            response = event.value if decision == "Allowed" else "Done"
            operations.append("Admit email to Mail and context" if decision == "Allowed"
                              else "Store Done in Mail; do not admit email or call mnext")
        elif event.kind == "ACall":
            decision, policy = monitor.mdecide(policy, event.tool, event.args)
            decision_state = sorted(policy.permissions)
            operations.append("Decide Fetch; keep returned monitor state")
            if decision == "Allowed":
                effect = Call(event.tool, event.args)
                tools.dispatch(effect)
                operations.append("Dispatch to fake Fetch sink: attacker receives arguments")
            else:
                operations.append("Deny silently: no dispatch and no attacker observation")
            response = "Done"
            agent = receive(proposed, decision)
            operations.append("Discard injected call result; leave plan counter and memory unchanged")
        else:
            agent = proposed
            operations.append("Assign Summary := Mail; monitor unchanged")
        if config.policy == "late" and before["context"] and "Fetch" in policy.permissions:
            # Deliberate runtime-error extension, NOT the paper's atomic react.
            policy = MonitorState(policy.permissions - {"Fetch"})
            operations.append("LATE EXTENSION: revoke Fetch after one post-admission step; too late for this call")
        steps.append(Step(len(steps) + 1, origin, event, before, proposal,
                          snapshot(agent, policy), decision, response, decision_state,
                          admission_state, operations, effect, action, effect))
    return Run(config, initial, steps, snapshot(agent, policy), list(tools.effects))


def compare(left: Run, right: Run, view: str = "event") -> dict:
    """A leak-pair predicate for completed traces; deliberately not an RS prover."""
    a, b = left.projection(view), right.projection(view)
    same_actions = a["actions"] == b["actions"]
    different_observations = a["observations"] != b["observations"]
    return {"view": view, "same_actions": same_actions,
            "different_observations": different_observations,
            "qualifying_leak_pair": left.completed and right.completed
            and same_actions and different_observations}


def demo_runs() -> List[Run]:
    runs = [replay(Config(mode, policy, secret))
            for policy in ("open", "fenced", "late")
            for mode in ("reference", "injected") for secret in (0, 1)]
    runs += [replay(Config(secret=s, email="Data 7")) for s in (0, 1)]
    runs += [replay(Config(secret=s, inbox_allowed=False)) for s in (0, 1)]
    return runs


def bundle(runs: List[Run]) -> dict:
    return {"schema_version": 1, "paper_commit": PAPER_COMMIT,
            "audience": "Analyst diagnostic trace: includes secrets; not the attacker view",
            "runs": [run.to_dict() for run in runs],
            "pairs": [{"left": i, "right": i + 1,
                       "event": compare(runs[i], runs[i + 1]),
                       "step": compare(runs[i], runs[i + 1], "step")}
                      for i in range(0, len(runs) - 1, 2)]}
