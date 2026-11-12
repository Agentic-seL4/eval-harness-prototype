"""Host-compiled Microkit monitor; Python supplies only workflow and fake effects."""

import ctypes
import hashlib
import re
import shutil
import subprocess
import sys
import tempfile
from contextlib import contextmanager
from pathlib import Path

WORKSPACE = Path(__file__).resolve().parents[3]
PROTOTYPE = WORKSPACE / "explorations/discovery_phase/prototypes/microkit-broker"
SOURCES = ("src/monitor.c", "src/monitor.h", "src/config.h", "include/protocol.h")


class CapParams(ctypes.Structure):
    _fields_ = [("caps0", ctypes.c_uint32), ("grant_on_t", ctypes.c_uint32),
                ("revoke_on_u", ctypes.c_uint32), ("late_fetch", ctypes.c_int)]


class MonitorStep(ctypes.Structure):
    _fields_ = [("decision", ctypes.c_int), ("decided", ctypes.c_uint32),
                ("admitted", ctypes.c_uint32), ("after", ctypes.c_uint32)]


class CMonitor:
    """Per-run parameters and permission mask; the library has no mutable globals."""

    def __init__(self, library, defines, config):
        self.library, self.defines = library, defines
        self.tools = {"Inbox": defines["TOOL_INBOX"], "Fetch": defines["TOOL_FETCH"]}
        policy = defines[f"POLICY_{config.policy.upper()}"]
        self.params = library.cap_params(policy, int(config.inbox_allowed))
        self.caps = self.params.caps0

    def names(self, caps):
        known = sum(1 << tool for tool in self.tools.values())
        if caps & ~known:
            raise ValueError(f"C monitor returned unknown permission bits: {caps:#x}")
        return sorted(name for name, tool in self.tools.items() if caps & (1 << tool))

    def step(self, event, context_before):
        kind = {"AReadT": "STEP_READ_T", "AReadU": "STEP_READ_U",
                "ACall": "STEP_CALL", "ATau": "STEP_TAU"}[event.kind]
        result = self.library.monitor_step(
            ctypes.byref(self.params), self.caps, self.defines[kind],
            self.tools[event.tool] if event.tool else 0, int(context_before),
        )
        # Refuse unexpected ABI/protocol values rather than treating them as a denial.
        valid = (self.defines["R_ALLOWED"], self.defines["R_DENIED"]) if event.kind in ("AReadU", "ACall") else (0,)
        if result.decision not in valid:
            raise ValueError(f"C monitor returned unexpected decision: {result.decision}")
        for caps in (result.decided, result.admitted, result.after):
            self.names(caps)
        return result


@contextmanager
def compiled_monitor():
    """Build an unchanged source snapshot in a temporary directory; never fall back."""
    compiler = shutil.which("clang")
    if compiler is None:
        raise FileNotFoundError("C backend requires clang; no Python fallback is used")
    version = subprocess.run([compiler, "--version"], check=True, capture_output=True,
                             text=True, timeout=30).stdout.strip()
    revision = subprocess.run(["git", "-C", str(PROTOTYPE), "rev-parse", "HEAD"],
                              check=True, capture_output=True, text=True, timeout=30).stdout.strip()
    with tempfile.TemporaryDirectory(prefix="inspect-email-monitor-") as directory:
        root = Path(directory)
        hashes, defines = {}, {}
        for name in SOURCES:
            source = (PROTOTYPE / name).read_bytes()
            target = root / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(source)
            hashes[name] = hashlib.sha256(source).hexdigest()
            defines.update({key: int(value) for key, value in
                            re.findall(r"^#define (\w+) (\d+)\b", source.decode(), re.M)})
        output = root / ("libmonitor.dylib" if sys.platform == "darwin" else "libmonitor.so")
        command = [compiler, "-shared", "-fPIC", "-O2", "-Wall", "-Wextra", "-Werror",
                   "-I", str(root / "include"), "-I", str(root / "src"),
                   str(root / "src/monitor.c"), "-o", str(output)]
        subprocess.run(command, check=True, capture_output=True, text=True, timeout=30)
        library = ctypes.CDLL(str(output))
        library.cap_params.argtypes = [ctypes.c_int, ctypes.c_int]
        library.cap_params.restype = CapParams
        library.monitor_step.argtypes = [ctypes.POINTER(CapParams), ctypes.c_uint32,
                                        ctypes.c_int, ctypes.c_uint64, ctypes.c_int]
        library.monitor_step.restype = MonitorStep
        provenance = {
            "prototype": str(PROTOTYPE.relative_to(WORKSPACE)), "revision": revision,
            "source_sha256": hashes, "compiler": compiler, "compiler_version": version,
            "command": command, "library_sha256": hashlib.sha256(output.read_bytes()).hexdigest(),
            "build_location": "temporary; removed after this sample",
        }
        yield library, defines, provenance


def replay_c(engine, config, monitor, tools=None):
    """Execute the scripted plan using C decisions; never call Python monitor logic."""
    return replay_monitored(engine, config, monitor, tools)


def replay_monitored(engine, config, monitor, tools=None, stepper=None):
    """Trusted executor shared by C runs and the separately labelled controls."""
    stepper = stepper if stepper is not None else engine.agent_step
    tools = tools if tools is not None else engine.FakeTools()
    if tools.effects:
        raise ValueError("Use a fresh fake tool sink for each replay")
    agent = engine.AgentState(trusted_inputs=(engine.data(config.secret),),
                              untrusted_inputs=(config.email,))

    def snapshot(state):
        return engine.snapshot(state, engine.MonitorState(frozenset(monitor.names(monitor.caps))))

    initial, steps = snapshot(agent), []
    while agent.pc < len(engine.PLAN):
        before = snapshot(agent)
        event, proposed, origin = stepper(agent, config.mode)
        proposal = snapshot(proposed)
        result = monitor.step(event, bool(agent.context))
        decision = response = decided = admitted = None
        effect = action = None
        operations = ["C monitor_step computes the decision and permission states"]
        if event.kind in ("AReadU", "ACall"):
            decision = "Allowed" if result.decision == monitor.defines["R_ALLOWED"] else "Denied"
            decided = monitor.names(result.decided)
        if event.kind == "AReadU":
            if decision == "Allowed":
                # Commit the fence before receive makes content available to the agent.
                monitor.caps = result.admitted
                admitted = monitor.names(monitor.caps)
                action = event.value
                operations.append("Commit C admission permissions before delivering email")
            agent = engine.receive(proposed, decision)
            response = event.value if decision == "Allowed" else "Done"
        elif event.kind == "ACall":
            # A late policy can return Allowed and revoke Fetch in result.after.
            # Dispatch follows the decision, before committing that final state.
            if decision == "Allowed":
                effect = engine.Call(event.tool, event.args)
                tools.dispatch(effect)
                operations.append("Dispatch allowed call to the fake sink")
            else:
                operations.append("Deny call; no fake sink dispatch")
            agent = engine.receive(proposed, decision)
            response = "Done"
        else:
            agent = proposed
        # C alone applies late revocation; no second Python policy update occurs.
        monitor.caps = result.after
        steps.append(engine.Step(len(steps) + 1, origin, event, before, proposal,
                                 snapshot(agent), decision, response, decided, admitted,
                                 operations, effect, action, effect))
    return engine.Run(config, initial, steps, snapshot(agent), list(tools.effects))


def compare_traces(reference, actual):
    """Compare every structured field except backend-specific explanatory prose."""
    def semantic_steps(trace):
        return [{key: value for key, value in step.items() if key != "operations"}
                for step in trace["steps"]]
    checks = {key: reference[key] == actual[key]
              for key in ("config", "initial", "final", "effects", "completed", "secrets_read", "views")}
    checks["steps"] = semantic_steps(reference) == semantic_steps(actual)
    return {"reference_backend": "python", "agrees": all(checks.values()), "checks": checks}
