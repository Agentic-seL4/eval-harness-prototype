"""T5: the static topology checker accepts broker.system and rejects broken variants."""
import json
import subprocess
import sys
import tempfile
import unittest
import xml.etree.ElementTree as ET
from pathlib import Path

PROTOTYPE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROTOTYPE / "scripts"))

import check_topology as ct  # noqa: E402

SYSTEM = PROTOTYPE / "broker.system"
POLICY = json.loads((PROTOTYPE / "flow-policy.json").read_text())
HEADER = (PROTOTYPE / "src" / "topology.h").read_text()


def pd(root, name):
    return next(p for p in root.iter("protection_domain") if p.get("name") == name)


def map_of(root, pd_name, region):
    return next(m for m in pd(root, pd_name).findall("map") if m.get("mr") == region)


def add_map(root, pd_name, region, perms, vaddr="0x3000000"):
    attrs = {"mr": region, "vaddr": vaddr}
    if perms is not None:
        attrs["perms"] = perms
    ET.SubElement(pd(root, pd_name), "map", attrs)


def add_channel(root, a, a_id, b, b_id, a_pp=False, a_notify=True, b_notify=True):
    channel = ET.SubElement(root, "channel")
    ET.SubElement(channel, "end", {"pd": a, "id": str(a_id), "pp": str(a_pp).lower(),
                                   "notify": str(a_notify).lower()})
    ET.SubElement(channel, "end", {"pd": b, "id": str(b_id), "notify": str(b_notify).lower()})


def add_pd(root, name, priority, parent=None):
    element = ET.SubElement(parent if parent is not None else root, "protection_domain",
                            {"name": name, "priority": str(priority)})
    ET.SubElement(element, "program_image", {"path": name + ".elf"})
    return element


def run_check(root, header=HEADER, policy=POLICY):
    results = ct.check(ct.System(root), policy, header)
    return {name: problems for name, ok, problems in results if not ok}


# Each mutation breaks the design in one way; the value is the set of checks that must fail.
def worker_reads_inbox(root):
    add_map(root, "worker", "inbox", "r")


def worker_writes_plan_mem(root):
    map_of(root, "worker", "plan_mem").set("perms", "rw")


def default_perms_are_read_write(root):
    del map_of(root, "worker", "context").attrib["perms"]


def executable_mapping(root):
    map_of(root, "worker", "context").set("perms", "rx")


def worker_calls_sink(root):
    add_channel(root, "worker", 2, "sink", 1, a_pp=True, a_notify=False, b_notify=False)


def worker_can_notify_broker(root):
    end = next(e for c in root.findall("channel") for e in c.findall("end")
               if e.get("pd") == "worker" and e.get("id") == "0")
    end.set("notify", "true")


def runner_calls_sink(root):
    add_channel(root, "runner", 2, "sink", 1, a_pp=True, a_notify=False, b_notify=False)


def spy_reads_secret(root):
    add_pd(root, "spy", 10)
    add_map(root, "spy", "secret", "r")


def shared_scratch_region(root):
    ET.SubElement(root, "memory_region", {"name": "scratch", "size": "0x1000"})
    add_map(root, "runner", "scratch", "rw")
    add_map(root, "sink", "scratch", "r")


def broker_below_runner(root):
    pd(root, "broker").set("priority", "90")


def call_cycle(root):
    add_channel(root, "sink", 1, "runner", 2, a_pp=True, a_notify=False, b_notify=False)


def interrupt_added(root):
    ET.SubElement(pd(root, "worker"), "irq", {"irq": "41", "id": "5"})


def net_maps_secret(root):
    add_map(root, "net", "secret", "r")


def net_calls_broker(root):
    end = next(e for c in root.findall("channel") for e in c.findall("end")
               if e.get("pd") == "net" and e.get("id") == "1")
    end.set("pp", "true")


def net_notifies_runner(root):
    add_channel(root, "net", 3, "runner", 2, b_notify=False)


def net_writes_obs_out(root):
    map_of(root, "net", "obs_out").set("perms", "rw")


def interrupt_moved_to_sink(root):
    irq = pd(root, "net").find("irq")
    pd(root, "net").remove(irq)
    pd(root, "sink").append(irq)


def interrupt_shared(root):
    ET.SubElement(pd(root, "worker"), "irq", {"irq": "40", "id": "5"})


def child_pd(root):
    add_pd(root, "helper", 140, parent=pd(root, "broker"))


MUTATIONS = {
    worker_reads_inbox: {"region access", "untrusted authority", "mediation"},
    worker_writes_plan_mem: {"region access", "untrusted authority"},
    default_perms_are_read_write: {"region access", "untrusted authority"},
    executable_mapping: {"region access", "untrusted authority"},
    worker_calls_sink: {"untrusted authority", "sink reachability", "mediation", "channel ids"},
    worker_can_notify_broker: {"untrusted authority"},
    runner_calls_sink: {"sink reachability", "mediation", "channel ids"},
    spy_reads_secret: {"classified", "region access"},
    shared_scratch_region: {"classified", "sink reachability", "mediation"},
    broker_below_runner: {"priorities"},
    call_cycle: {"priorities", "channel ids"},
    interrupt_added: {"interrupts"},
    net_maps_secret: {"region access", "untrusted authority", "mediation"},
    net_calls_broker: {"untrusted authority"},
    net_notifies_runner: {"untrusted authority", "channel ids"},
    net_writes_obs_out: {"region access", "untrusted authority", "mediation"},
    interrupt_moved_to_sink: {"interrupts"},
    interrupt_shared: {"interrupts"},
    child_pd: {"supported", "classified"},
}


class TopologyTest(unittest.TestCase):
    def fresh(self):
        return ET.parse(SYSTEM).getroot()

    def test_design_topology_passes(self):
        self.assertEqual(run_check(self.fresh()), {})

    def test_every_mutation_fails_the_expected_checks(self):
        for mutate, expected in MUTATIONS.items():
            with self.subTest(mutate.__name__):
                root = self.fresh()
                mutate(root)
                failed = run_check(root)
                self.assertTrue(expected <= set(failed), "{}: failed {}".format(mutate.__name__, sorted(failed)))

    def test_messages_name_the_problem(self):
        root = self.fresh()
        worker_reads_inbox(root)
        failed = run_check(root)
        self.assertIn("inbox reaches worker without broker: inbox -> worker", failed["mediation"])
        root = self.fresh()
        shared_scratch_region(root)
        self.assertIn("worker reaches sink without broker: worker -> runner -> scratch -> sink",
                      run_check(root)["mediation"])
        root = self.fresh()
        call_cycle(root)
        self.assertTrue(any("cycle" in p for p in run_check(root)["priorities"]))

    def test_channel_ids_must_match_topology_header(self):
        swapped = HEADER.replace("RUNNER_CH_BROKER 0", "RUNNER_CH_BROKER 9")
        self.assertIn("RUNNER_CH_BROKER is 9 in src/topology.h but 0 in the description",
                      run_check(self.fresh(), header=swapped)["channel ids"])
        missing = HEADER.replace("#define SINK_CH_BROKER 0", "")
        self.assertIn("src/topology.h has no SINK_CH_BROKER", run_check(self.fresh(), header=missing)["channel ids"])

    def test_policy_must_bound_untrusted_pds(self):
        policy = json.loads(json.dumps(POLICY))
        policy["roles"]["runner"] = "untrusted"
        self.assertIn("untrusted PD runner has no authority bound in the policy",
                      run_check(self.fresh(), policy=policy)["untrusted authority"])

    def test_design_shows_the_derived_graph(self):
        graph = ct.mermaid(ct.System(self.fresh()), POLICY)
        self.assertIn("```mermaid\n" + graph + "\n```", (PROTOTYPE / "DESIGN.md").read_text())

    def test_command_line(self):
        script = str(PROTOTYPE / "scripts" / "check_topology.py")
        good = subprocess.run([sys.executable, script], capture_output=True, text=True)
        self.assertEqual(good.returncode, 0, good.stdout + good.stderr)
        self.assertIn("all 9 checks passed", good.stdout)
        root = self.fresh()
        worker_calls_sink(root)
        with tempfile.TemporaryDirectory() as tmp:
            bad_system = Path(tmp) / "bad.system"
            ET.ElementTree(root).write(bad_system)
            bad = subprocess.run([sys.executable, script, "--system", str(bad_system)],
                                 capture_output=True, text=True)
        self.assertEqual(bad.returncode, 1)
        self.assertIn("FAIL  mediation", bad.stdout)
        graph = subprocess.run([sys.executable, script, "--mermaid"], capture_output=True, text=True)
        self.assertTrue(graph.stdout.startswith("flowchart LR"))
        self.assertIn("worker <-->|call| broker", graph.stdout)


if __name__ == "__main__":
    unittest.main()
