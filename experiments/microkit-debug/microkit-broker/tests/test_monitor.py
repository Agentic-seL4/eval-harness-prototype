"""T6: the C monitor (src/monitor.c) against core.py and the Isabelle definitions.

monitor.c is compiled as a host shared library and called through ctypes. Two
oracles: email-fence/core.py's Monitor and replays, and a literal Python
transcription of capDecide and capObs (Agent_Compose.thy) with the E1L/E1F
parameters (Email_Leak.thy, Email_Fenced.thy).
"""
import ctypes
import itertools
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

PROTOTYPE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROTOTYPE / "scripts"))

import expected as ex  # noqa: E402


def defines(*names):
    values = {}
    for name in names:
        text = (PROTOTYPE / name).read_text()
        for key, value in re.findall(r"^#define (\w+) (\d+)\b", text, re.M):
            values[key] = int(value)
    return values


D = defines("include/protocol.h", "src/config.h", "src/monitor.h")
TOOLS = {D["TOOL_INBOX"]: "Inbox", D["TOOL_FETCH"]: "Fetch"}
IDS = {name: tool for tool, name in TOOLS.items()}
POLICY_IDS = {"open": D["POLICY_OPEN"], "fenced": D["POLICY_FENCED"], "late": D["POLICY_LATE"]}
DECISIONS = {D["R_ALLOWED"]: "Allowed", D["R_DENIED"]: "Denied", 0: None}
STEP_KINDS = {"AReadT": D["STEP_READ_T"], "AReadU": D["STEP_READ_U"],
              "ACall": D["STEP_CALL"], "ATau": D["STEP_TAU"]}
# Tool identifiers to try, including ones that would overflow a naive shift.
TOOL_IDS = [0, 1, 2, 3, 31, 32, 33, 63, 64, 2 ** 63, 2 ** 64 - 1]
STATES = [frozenset(c) for n in range(3) for c in itertools.combinations(sorted(IDS), n)]


def mask(names):
    return sum(1 << IDS[n] for n in names)


def names(bits):
    found = {name for tool, name in TOOLS.items() if bits >> tool & 1}
    assert mask(found) == bits, "unknown bits in {:#x}".format(bits)
    return frozenset(found)


def tool_name(tool):
    return TOOLS.get(tool, "Tool{}".format(tool))


# Literal transcription of the Isabelle definitions, for the email instances.
ISABELLE = {  # policy -> (caps0, grantOn v, revokeOnU); late uses E1L's parameters
    "open": (frozenset({"Fetch", "Inbox"}), frozenset(), frozenset()),
    "late": (frozenset({"Fetch", "Inbox"}), frozenset(), frozenset()),
    "fenced": (frozenset({"Fetch", "Inbox"}), frozenset(), frozenset({"Fetch"})),
}


def cap_decide_isabelle(caps, tool, args):
    contract = True  # "\<lambda>_ _. True"
    return ("Allowed" if tool in caps and contract else "Denied"), caps


def cap_obs_isabelle(policy, caps, label):
    _, grant_on, revoke_on_u = ISABELLE[policy]
    kind = label[0]
    if kind == "AReadT":
        return caps | grant_on
    if kind == "AReadU":
        return caps - revoke_on_u
    return caps


class CapParams(ctypes.Structure):
    _fields_ = [("caps0", ctypes.c_uint32), ("grant_on_t", ctypes.c_uint32),
                ("revoke_on_u", ctypes.c_uint32), ("late_fetch", ctypes.c_int)]


class MonitorStep(ctypes.Structure):
    _fields_ = [("decision", ctypes.c_int), ("decided", ctypes.c_uint32),
                ("admitted", ctypes.c_uint32), ("after", ctypes.c_uint32)]


@unittest.skipUnless(shutil.which("clang"), "clang not installed")
class MonitorTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        library = Path(cls.tmp.name) / ("libmonitor" + (".dylib" if sys.platform == "darwin" else ".so"))
        subprocess.run(["clang", "-shared", "-fPIC", "-O2", "-Wall", "-Wextra", "-Werror",
                        "-I", str(PROTOTYPE / "include"), "-I", str(PROTOTYPE / "src"),
                        str(PROTOTYPE / "src" / "monitor.c"), "-o", str(library)], check=True)
        lib = ctypes.CDLL(str(library))
        lib.cap_params.restype = CapParams
        lib.cap_params.argtypes = [ctypes.c_int, ctypes.c_int]
        lib.cap_decide.restype = ctypes.c_int
        lib.cap_decide.argtypes = [ctypes.c_uint32, ctypes.c_uint64, ctypes.POINTER(ctypes.c_uint32)]
        lib.cap_obs.restype = ctypes.c_uint32
        lib.cap_obs.argtypes = [ctypes.POINTER(CapParams), ctypes.c_uint32, ctypes.c_int]
        lib.monitor_step.restype = MonitorStep
        lib.monitor_step.argtypes = [ctypes.POINTER(CapParams), ctypes.c_uint32, ctypes.c_int,
                                     ctypes.c_uint64, ctypes.c_int]
        cls.lib = lib
        cls.core = ex.core()

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def params(self, policy, inbox_allowed=True):
        return self.lib.cap_params(POLICY_IDS[policy], int(inbox_allowed))

    def test_initial_state(self):
        for policy, inbox_allowed in itertools.product(POLICY_IDS, (True, False)):
            run = self.core.replay(self.core.Config(policy=policy, inbox_allowed=inbox_allowed))
            c_initial = names(self.params(policy, inbox_allowed).caps0)
            self.assertEqual(sorted(c_initial), run.initial["permissions"], (policy, inbox_allowed))
            if inbox_allowed:
                self.assertEqual(c_initial, ISABELLE[policy][0])

    def test_decide_on_every_state_and_tool(self):
        checked = 0
        for policy, caps, tool, args in itertools.product(POLICY_IDS, STATES, TOOL_IDS,
                                                           [(), ("Data 1",)]):
            nxt = ctypes.c_uint32(0xDEAD)
            decision = DECISIONS[self.lib.cap_decide(mask(caps), tool, ctypes.byref(nxt))]
            core_decision, core_next = self.core.Monitor(policy).mdecide(
                self.core.MonitorState(caps), tool_name(tool), args)
            self.assertEqual((decision, names(nxt.value)), (core_decision, core_next.permissions),
                             (policy, sorted(caps), tool))
            self.assertEqual((decision, names(nxt.value)),
                             cap_decide_isabelle(caps, tool_name(tool), args))
            checked += 1
        self.assertEqual(checked, 3 * 4 * len(TOOL_IDS) * 2)

    def test_update_on_every_state_and_label(self):
        Event = self.core.Event
        labels = [("AReadT", None, "Data 1", D["EV_READ_T"]), ("AReadU", "Inbox", "Email", D["EV_READ_U"]),
                  ("AReadU", "Fetch", "Data 7", D["EV_READ_U"]), ("ANew", None, None, D["EV_NEW"])]
        for policy, inbox_allowed, caps, (kind, tool, value, event) in itertools.product(
                POLICY_IDS, (True, False), STATES, labels):
            p = self.params(policy, inbox_allowed)
            got = names(self.lib.cap_obs(ctypes.byref(p), mask(caps), event))
            core_next = self.core.Monitor(policy).mnext(self.core.MonitorState(caps),
                                                        Event(kind, tool=tool, value=value))
            self.assertEqual(got, core_next.permissions, (policy, sorted(caps), kind, tool))
            self.assertEqual(got, cap_obs_isabelle(policy, caps, (kind, tool, value)))

    def test_steps_reproduce_every_replay(self):
        steps_checked = 0
        for name, (policy, mode, secret, email, inbox) in ex.configurations().items():
            run = self.core.replay(self.core.Config(
                mode=mode, policy=policy, secret=secret, email={"malicious": "Email", "benign": "Data 7"}[email],
                inbox_allowed=inbox == "allowed"))
            p = self.params(policy, inbox == "allowed")
            caps = p.caps0
            for step in run.steps:
                where = "{} step {}".format(name, step.number)
                self.assertEqual(sorted(names(caps)), step.before["permissions"], where)
                tool = IDS.get(step.event.tool, 0)
                r = self.lib.monitor_step(ctypes.byref(p), caps, STEP_KINDS[step.event.kind], tool,
                                          int(bool(step.before["context"])))
                self.assertEqual(DECISIONS[r.decision], step.decision, where)
                if step.monitor_after_decision is not None:
                    self.assertEqual(sorted(names(r.decided)), step.monitor_after_decision, where)
                if step.admission_permissions is not None:
                    self.assertEqual(sorted(names(r.admitted)), step.admission_permissions, where)
                self.assertEqual(sorted(names(r.after)), step.after["permissions"], where)
                caps = r.after  # the C monitor carries its own state through the run
                steps_checked += 1
            self.assertEqual(sorted(names(caps)), run.final["permissions"], name)
        trace_records = sum(tag == "TRACE" for n in ex.configurations() for tag, _ in ex.expected(n))
        self.assertEqual(steps_checked, trace_records)

    def test_compiles_for_the_target(self):
        subprocess.run(["clang", "-target", "aarch64-none-elf", "-ffreestanding", "-nostdlib", "-O2",
                        "-Wall", "-Wextra", "-Werror", "-mstrict-align", "-I", str(PROTOTYPE / "include"),
                        "-I", str(PROTOTYPE / "src"), "-c", str(PROTOTYPE / "src" / "monitor.c"),
                        "-o", str(Path(self.tmp.name) / "monitor.o")], check=True)


if __name__ == "__main__":
    unittest.main()
