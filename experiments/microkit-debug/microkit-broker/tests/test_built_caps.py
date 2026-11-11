"""T10: the check of the capabilities the Microkit tool actually built.

Unit tests run the parser and the policy check on synthetic tables. When
MICROKIT_SDK is set, integration tests run the real tool with --viper-output on the
real system description, and on broken descriptions that the tool accepts. The
static checker (check_topology.py) is deliberately bypassed there: the point is that
the second check catches them on its own.
"""
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

PROTOTYPE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROTOTYPE / "scripts"))

import check_built_caps as cb  # noqa: E402

POLICY = json.loads((PROTOTYPE / "flow-policy.json").read_text())
SYSTEM = (PROTOTYPE / "broker.system").read_text()

WORKER_VPR = """// exported invariants for PD worker in broker.system
define mk_is_ppcall_target(x) (x in Set(0))
define mk_is_notify_target(x) (x in Set(1))
define mk_is_irq_channel(x) (false)
define mk_is_child(x) (false)
define pansel4_has_cap(x) (x in Set(1,2,3,4,11,74))
define pansel4_has_tcb_cap(x) (false)
define mem_context_contains(x) (33558528 <= x && x < 33562624)
define mem_plan_mem_contains(x) (33554432 <= x && x < 33558528)
define mem_readable(x) (mem_context_contains(x) || mem_plan_mem_contains(x))
define mem_writeable(x) (false)
"""


def table(calls=(), notifies=(), irqs=(), extra_slots=(), reads=(), writes=(), **forbidden):
    slots = cb.OWN_SLOTS | {cb.BASE_CALL + n for n in calls} | {cb.BASE_NOTIFY + n for n in notifies} \
        | {cb.BASE_IRQ + n for n in irqs} | set(extra_slots)
    t = dict(mk_is_ppcall_target=set(calls), mk_is_notify_target=set(notifies), mk_is_irq_channel=set(irqs),
             mk_is_child=set(), pansel4_has_cap=slots, mem_readable=set(reads), mem_writeable=set(writes))
    for kind, value in forbidden.items():
        t["pansel4_has_%s_cap" % kind] = value
    return t


def good_tables():
    """The tables the tool builds for broker.system, written out by hand."""
    return {
        "sink": table(notifies=[1], reads=["obs_out"], writes=["obs_out"]),
        "broker": table(calls=[3], notifies=[1], reads=["secret", "inbox", "context"], writes=["context"]),
        "runner": table(calls=[0], notifies=[1], reads=["plan_mem"], writes=["plan_mem"]),
        "worker": table(calls=[0], notifies=[1], reads=["plan_mem", "context"]),
        "net": table(notifies=[1], irqs=[0], reads=["uart1", "inbox", "obs_out"], writes=["uart1", "inbox"]),
    }


class ParseTest(unittest.TestCase):
    def test_parses_sets_regions_and_false(self):
        t = cb.parse_vpr(WORKER_VPR)
        self.assertEqual(t["mk_is_ppcall_target"], {0})
        self.assertEqual(t["pansel4_has_cap"], {1, 2, 3, 4, 11, 74})
        self.assertEqual(t["mk_is_irq_channel"], set())
        self.assertEqual(t["mem_readable"], {"context", "plan_mem"})
        self.assertEqual(t["mem_writeable"], set())

    def test_channel_peers_and_irqs_from_the_description(self):
        peers, irqs = cb.describe_channels(SYSTEM)
        self.assertEqual(peers["worker"], {0: "broker", 1: "runner"})
        self.assertEqual(peers["broker"][3], "sink")
        self.assertEqual(irqs["net"], {0: 40})


class CheckTest(unittest.TestCase):
    def problems(self, tables):
        peers, irqs = cb.describe_channels(SYSTEM)
        return cb.check(tables, POLICY, peers, irqs)

    def test_the_intended_tables_conform(self):
        self.assertEqual(self.problems(good_tables()), [])

    def test_worker_writing_context_is_caught(self):
        t = good_tables()
        t["worker"]["mem_writeable"] = {"context"}
        self.assertIn("worker may not write context", self.problems(t))

    def test_an_unexplained_capability_is_caught(self):
        t = good_tables()
        t["worker"]["pansel4_has_cap"].add(77)
        self.assertIn("worker: unexplained capability in slot 77", self.problems(t))

    def test_untrusted_call_beyond_its_bound_is_caught(self):
        t = good_tables()
        t["net"] = table(calls=[1], notifies=[1], irqs=[0], reads=["uart1", "inbox", "obs_out"],
                         writes=["uart1", "inbox"])
        self.assertIn("untrusted net may not call broker", self.problems(t))

    def test_a_thread_capability_is_caught(self):
        t = good_tables()
        t["worker"]["pansel4_has_tcb_cap"] = {6}
        self.assertIn("worker: holds a tcb capability", self.problems(t))

    def test_a_missing_pd_is_caught(self):
        t = good_tables()
        del t["sink"]
        self.assertIn("sink: no capability table was exported", self.problems(t))


@unittest.skipUnless(os.environ.get("MICROKIT_SDK"), "MICROKIT_SDK not set")
class BuiltSystemTest(unittest.TestCase):
    """The real tool on the real description, and on broken ones it accepts."""

    SEARCH = PROTOTYPE / "build" / "fenced-injected-s1-malicious-allowed"

    @classmethod
    def setUpClass(cls):
        subprocess.run(["make", "-s", "all"], cwd=PROTOTYPE, check=True, capture_output=True)

    def built(self, system_text):
        tool = Path(os.environ["MICROKIT_SDK"]) / "bin" / "microkit"
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            (tmp / "broker.system").write_text(system_text)
            caps = tmp / "capabilities"
            caps.mkdir()
            run = subprocess.run([str(tool), str(tmp / "broker.system"), "--search-path", str(self.SEARCH),
                                  "--board", "qemu_virt_aarch64", "--config", "debug",
                                  "-o", str(tmp / "loader.img"), "-r", str(tmp / "report.txt"),
                                  "--viper-output", str(caps)], capture_output=True, text=True)
            self.assertEqual(run.returncode, 0, "the Microkit tool rejected it:\n" + run.stderr)
            tables = cb.load_tables(caps)
        peers, irqs = cb.describe_channels(system_text)
        return cb.check(tables, POLICY, peers, irqs)

    def mutate(self, old, new):
        self.assertIn(old, SYSTEM)
        return SYSTEM.replace(old, new, 1)

    def test_the_real_system_conforms(self):
        self.assertEqual(self.built(SYSTEM), [])

    def test_worker_mapping_context_writable(self):
        system = self.mutate('<map mr="context"  vaddr="0x2001000" perms="r"',
                             '<map mr="context"  vaddr="0x2001000" perms="rw"')
        self.assertIn("worker may not write context", self.built(system))

    def test_worker_mapping_the_inbox(self):
        line = '<map mr="context"  vaddr="0x2001000" perms="r" setvar_vaddr="context" />'
        system = self.mutate(line, line + '\n        <map mr="inbox" vaddr="0x2003000" perms="r" />')
        self.assertIn("worker may not read inbox", self.built(system))

    def test_worker_with_a_channel_to_the_sink(self):
        channel = ('    <channel>\n        <end pd="worker" id="2" pp="true" />\n'
                   '        <end pd="sink" id="2" />\n    </channel>\n</system>')
        problems = self.built(self.mutate("</system>", channel))
        self.assertIn("worker can call the sink directly", problems)
        self.assertIn("untrusted worker may not call sink", problems)

    def test_net_given_a_call_to_the_broker(self):
        system = self.mutate('<end pd="net"    id="1" />', '<end pd="net"    id="1" pp="true" />')
        self.assertIn("untrusted net may not call broker", self.built(system))


if __name__ == "__main__":
    unittest.main()
