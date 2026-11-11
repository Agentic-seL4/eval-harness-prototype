"""T9: the confinement tests.

Unit tests exercise the verdict logic on synthetic console text (no QEMU). An
integration test boots two variants on QEMU, when MICROKIT_SDK is set, and checks
that the worker is stopped and the secret does not reach the sink.
"""
import os
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

import run_bypass  # noqa: E402

PROTOTYPE = Path(__file__).resolve().parent.parent


def test_for(attack):
    return next(t for t in run_bypass.TESTS if t["attack"] == attack)


ATTACK_NOTE = ('NOTE {{"pd":"worker","event":"attack","attack":"{a}",'
               '"attempt":"x"}}')


class CheckLogicTest(unittest.TestCase):
    """run_bypass.check() against hand-written consoles."""

    def console(self, attack, evidence, extra="", done=True, obs=None):
        lines = [ATTACK_NOTE.format(a=attack), evidence]
        if obs:
            lines.append('OBS {"tool":"Fetch","args":["%s"]}' % obs)
        lines.append(extra)
        if done:
            lines.append("DONE {}")
        return "\n".join(l for l in lines if l) + "\n"

    def test_broker_rejection_is_confined(self):
        t = test_for("forge-origin")
        console = self.console("forge-origin", "only the runner may read or take internal steps")
        r = run_bypass.check(t, console, status=0)
        self.assertTrue(r["ok"], r["reason"])
        self.assertFalse(r["leaked"])

    def test_kernel_fault_is_confined(self):
        t = test_for("write-context")
        console = self.console("write-context", run_bypass.WORKER_FAULT,
                               extra="dfsc = permission fault ... write not read", done=False)
        r = run_bypass.check(t, console, status=0)
        self.assertTrue(r["ok"], r["reason"])

    def test_uninjected_leak_is_the_expected_outcome(self):
        t = test_for("uninjected")
        console = self.console("uninjected", 'OBS {"tool":"Fetch","args":["Data 1"]}',
                               obs="Data 1")
        r = run_bypass.check(t, console, status=0)
        self.assertTrue(r["ok"], r["reason"])
        self.assertTrue(r["leaked"])

    def test_missing_evidence_fails(self):
        t = test_for("malformed")
        console = self.console("malformed", "some unrelated line")
        r = run_bypass.check(t, console, status=0)
        self.assertFalse(r["ok"])
        self.assertIn("missing evidence", r["reason"])

    def test_an_unexpected_leak_fails(self):
        """A worker that should be confined but whose secret reaches the sink."""
        t = test_for("forge-origin")
        console = self.console("forge-origin", "only the runner may read or take internal steps",
                               obs="Data 1")
        r = run_bypass.check(t, console, status=0)
        self.assertFalse(r["ok"])
        self.assertIn("leaked", r["reason"])

    def test_a_silent_attempt_without_its_note_fails(self):
        t = test_for("malformed")
        console = "ERR malformed request\nDONE {}\n"
        r = run_bypass.check(t, console, status=0)
        self.assertFalse(r["ok"])
        self.assertIn("attack attempt", r["reason"])


@unittest.skipUnless(os.environ.get("MICROKIT_SDK"), "MICROKIT_SDK not set")
class ConfinementOnQemuTest(unittest.TestCase):
    """Boot a broker-rejected and a kernel-faulted variant; both must be confined."""

    def check_one(self, attack):
        result = run_bypass.run_one(test_for(attack), str(PROTOTYPE / "build"), timeout=30.0)
        self.assertTrue(result["ok"], "%s: %s" % (attack, result["reason"]))
        self.assertFalse(result["leaked"], "%s leaked the secret" % attack)

    def test_forge_origin_is_rejected_by_the_broker(self):
        self.check_one("forge-origin")

    def test_write_context_is_faulted_by_the_kernel(self):
        self.check_one("write-context")


if __name__ == "__main__":
    unittest.main()
