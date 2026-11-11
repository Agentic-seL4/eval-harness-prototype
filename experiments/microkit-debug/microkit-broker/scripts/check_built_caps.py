#!/usr/bin/env python3
"""Check the capabilities the Microkit tool actually built against flow-policy.json (T10).

check_topology.py checks the system description before the Microkit tool runs. This
script checks the tool's output instead: with --viper-output, the tool writes one
file per protection domain describing that PD's capability table and memory
permissions as built into the capDL specification (Microkit manual, section 4). It
is a second, independent view: if the tool built something the description did not
say, or our own parser of the description is wrong, this check sees what the system
will really hold.

What it checks, for every PD:

  * every capability slot is explained: the PD's own four (input, endpoint, address
    space, reply) plus one per declared channel end: 10+id to notify, 74+id to
    call, 138+id for an interrupt (libmicrokit's layout, microkit.h);
  * no PD holds a thread, VCPU, I/O-port or SMC capability, or has children;
  * the regions it can read and write are within the policy's readers and writers;
  * trusted PDs hold no interrupt;
  * only the broker can call the sink, and nothing can notify it;

and, for untrusted PDs, that their calls, notifications, interrupts and mappings are
within untrusted_authority.

The .vpr format is not fixed across Microkit versions (manual, section 4); this
parser follows SDK 2.3.1, which the prototype pins.

    check_built_caps.py DIR       check the .vpr files in DIR
"""
import argparse
import json
import re
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

HERE = Path(__file__).resolve().parent
PROTOTYPE = HERE.parent

# libmicrokit's capability layout (SDK 2.3.1, include/microkit.h).
OWN_SLOTS = {1, 2, 3, 4}
BASE_NOTIFY, BASE_CALL, BASE_IRQ = 10, 74, 138
FORBIDDEN = ("tcb", "vcpu", "ioport", "arm_smc")

DEFINE = re.compile(r"^define (\w+)\(x\) \((.*)\)\s*$")
SET = re.compile(r"^x in Set\(([\d,\s]*)\)$")
REGION = re.compile(r"mem_(\w+)_contains\(x\)")


def parse_vpr(text):
    """One PD's exported invariants: sets of channel ids and slots, and region names."""
    table = {}
    for line in text.splitlines():
        m = DEFINE.match(line.strip())
        if not m:
            continue
        name, body = m.groups()
        if name in ("mem_readable", "mem_writeable"):
            table[name] = set(REGION.findall(body))
        elif body == "false":
            table[name] = set()
        else:
            s = SET.match(body)
            if s:
                table[name] = {int(v) for v in s.group(1).split(",") if v.strip()}
    return table


def describe_channels(system_text):
    """From broker.system: for each PD, channel id -> peer PD, and irq channel id -> irq."""
    root = ET.fromstring(system_text)
    peers, irqs = {}, {}
    for pd in root.iter("protection_domain"):
        peers.setdefault(pd.get("name"), {})
        irqs[pd.get("name")] = {int(i.get("id")): int(i.get("irq")) for i in pd.findall("irq")}
    for channel in root.iter("channel"):
        ends = channel.findall("end")
        if len(ends) == 2:
            a, b = ends
            peers.setdefault(a.get("pd"), {})[int(a.get("id"))] = b.get("pd")
            peers.setdefault(b.get("pd"), {})[int(b.get("id"))] = a.get("pd")
    return peers, irqs


def check(tables, policy, peers, irqs):
    """Problems found in the built capability tables; an empty list means they conform."""
    problems = []
    roles = policy["roles"]
    regions = policy["regions"]
    bounds = policy.get("untrusted_authority", {})

    for pd in sorted(roles):
        if pd not in tables:
            problems.append("%s: no capability table was exported" % pd)
    for pd in sorted(tables):
        if pd not in roles:
            problems.append("%s: built, but not classified in the policy" % pd)

    callers_of = {}
    notifiers_of = {}
    for pd, t in sorted(tables.items()):
        calls = t.get("mk_is_ppcall_target", set())
        notifies = t.get("mk_is_notify_target", set())
        irq_ids = t.get("mk_is_irq_channel", set())
        expected = (OWN_SLOTS | {BASE_NOTIFY + n for n in notifies} | {BASE_CALL + n for n in calls}
                    | {BASE_IRQ + n for n in irq_ids})
        held = t.get("pansel4_has_cap", set())
        for slot in sorted(held - expected):
            problems.append("%s: unexplained capability in slot %d" % (pd, slot))
        for slot in sorted(expected - held):
            problems.append("%s: declared channel has no capability in slot %d" % (pd, slot))
        for kind in FORBIDDEN:
            if t.get("pansel4_has_%s_cap" % kind):
                problems.append("%s: holds a %s capability" % (pd, kind))
        if t.get("mk_is_child"):
            problems.append("%s: has child PDs" % pd)

        for region in sorted(t.get("mem_readable", set())):
            if region not in regions:
                problems.append("%s: maps %s, which the policy does not list" % (pd, region))
            elif pd not in regions[region]["readers"]:
                problems.append("%s may not read %s" % (pd, region))
        for region in sorted(t.get("mem_writeable", set())):
            if region in regions and pd not in regions[region]["writers"]:
                problems.append("%s may not write %s" % (pd, region))

        call_peers = {peers.get(pd, {}).get(n, "channel %d" % n) for n in calls}
        notify_peers = {peers.get(pd, {}).get(n, "channel %d" % n) for n in notifies}
        irq_numbers = {irqs.get(pd, {}).get(n, -1) for n in irq_ids}
        for peer in call_peers:
            callers_of.setdefault(peer, set()).add(pd)
        for peer in notify_peers:
            notifiers_of.setdefault(peer, set()).add(pd)

        if roles.get(pd) in ("trusted", "monitor") and irq_ids:
            problems.append("%s: trusted PD holds interrupts %s" % (pd, sorted(irq_numbers)))
        if pd in bounds:
            bound = bounds[pd]
            for peer in sorted(call_peers - set(bound["calls"])):
                problems.append("untrusted %s may not call %s" % (pd, peer))
            for peer in sorted(notify_peers - set(bound["notifies"])):
                problems.append("untrusted %s may not notify %s" % (pd, peer))
            for irq in sorted(irq_numbers - set(bound["irqs"])):
                problems.append("untrusted %s may not receive interrupt %d" % (pd, irq))
            for region in sorted(t.get("mem_readable", set()) - set(bound["maps"])):
                problems.append("untrusted %s may not map %s" % (pd, region))
            for region in sorted(t.get("mem_writeable", set())):
                if bound["maps"].get(region) != "rw":
                    problems.append("untrusted %s may not write %s" % (pd, region))

    sinks = [pd for pd, role in roles.items() if pd == "sink"]
    for sink in sinks:
        for caller in sorted(callers_of.get(sink, set()) - {"broker"}):
            problems.append("%s can call the sink directly" % caller)
        for notifier in sorted(notifiers_of.get(sink, set())):
            problems.append("%s can notify the sink" % notifier)
    return problems


def load_tables(directory):
    return {p.stem: parse_vpr(p.read_text()) for p in sorted(Path(directory).glob("*.vpr"))}


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("directory", help="directory with one .vpr file per PD (microkit --viper-output)")
    parser.add_argument("--system", default=str(PROTOTYPE / "broker.system"))
    parser.add_argument("--policy", default=str(PROTOTYPE / "flow-policy.json"))
    args = parser.parse_args()

    tables = load_tables(args.directory)
    if not tables:
        print("no .vpr files in %s" % args.directory, file=sys.stderr)
        return 2
    policy = json.loads(Path(args.policy).read_text())
    peers, irqs = describe_channels(Path(args.system).read_text())
    problems = check(tables, policy, peers, irqs)
    for pd, t in sorted(tables.items()):
        slots = ",".join(str(s) for s in sorted(t.get("pansel4_has_cap", set())))
        reads = ",".join(sorted(t.get("mem_readable", set()))) or "-"
        writes = ",".join(sorted(t.get("mem_writeable", set()))) or "-"
        print("%-7s slots {%s}  reads {%s}  writes {%s}" % (pd, slots, reads, writes))
    if problems:
        print("\nBuilt capabilities do NOT conform to %s:" % Path(args.policy).name)
        for p in problems:
            print("  - " + p)
        return 1
    print("\nBuilt capabilities conform to %s." % Path(args.policy).name)
    return 0


if __name__ == "__main__":
    sys.exit(main())
