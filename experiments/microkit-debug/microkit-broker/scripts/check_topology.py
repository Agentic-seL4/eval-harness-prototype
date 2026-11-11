#!/usr/bin/env python3
"""Check a Microkit system description against the intended information flow.

Reads broker.system, flow-policy.json and src/topology.h, builds the flow graph
and checks the properties of DESIGN.md section 6. Exit status 1 if any check fails.

The flow graph has a node for every PD and memory region:
  * a mapping with read permission is an edge region -> PD, with write permission
    an edge PD -> region;
  * a protected call carries data both ways: caller -> callee and callee -> caller;
  * a notification is an edge notifier -> notified;
  * an interrupt is an edge from its device ("irq N") to the PD that receives it.
Timing and other covert channels are not modelled (T10).

    check_topology.py                 check, print one line per property
    check_topology.py --mermaid       print the derived flow graph as Mermaid
"""
import argparse
import json
import re
import sys
import xml.etree.ElementTree as ET
from collections import deque
from pathlib import Path

PROTOTYPE = Path(__file__).resolve().parent.parent

# Elements whose authority the graph models; anything else is rejected.
MODELLED = {"system", "memory_region", "protection_domain", "program_image", "map", "channel", "end", "irq"}
DEFAULT_PERMS = "rw"  # Microkit's default for <map>


class System:
    """The parts of a system description that grant authority."""

    def __init__(self, root):
        self.unsupported = []
        self.pds = {}       # name -> priority
        self.regions = {}   # name -> attributes
        self.maps = []      # (pd, region, perms)
        self.channels = []  # ((pd, id, pp, notify), (pd, id, pp, notify))
        self.irqs = []      # (pd, irq number, channel id)
        for element in root.iter():
            if element.tag not in MODELLED:
                self.unsupported.append(element.tag)
        for region in root.findall("memory_region"):
            self.regions[region.get("name")] = dict(region.attrib)
        for pd in root.iter("protection_domain"):
            name = pd.get("name")
            if pd.find("protection_domain") is not None:
                self.unsupported.append("child protection_domain in " + name)
            self.pds[name] = int(pd.get("priority", "0"))
            for m in pd.findall("map"):
                self.maps.append((name, m.get("mr"), m.get("perms", DEFAULT_PERMS)))
            for irq in pd.findall("irq"):
                self.irqs.append((name, int(irq.get("irq")), int(irq.get("id"))))
        for channel in root.findall("channel"):
            ends = []
            for end in channel.findall("end"):
                ends.append((end.get("pd"), int(end.get("id")), end.get("pp", "false") == "true",
                             end.get("notify", "true") == "true"))
            self.channels.append(tuple(ends))

    def edges(self):
        """Directed flow edges (source, target, label)."""
        result = []
        for pd, region, perms in self.maps:
            if "r" in perms:
                result.append((region, pd, "read"))
            if "w" in perms:
                result.append((pd, region, "write"))
        for a, b in self.channels:
            for this, other in ((a, b), (b, a)):
                if this[2]:
                    result.append((this[0], other[0], "call"))
                    result.append((other[0], this[0], "reply"))
                if this[3]:
                    result.append((this[0], other[0], "notify"))
        for pd, number, _ in self.irqs:
            result.append(("irq {}".format(number), pd, "interrupt"))
        return result

    def calls(self):
        return [(this[0], other[0]) for a, b in self.channels for this, other in ((a, b), (b, a)) if this[2]]


def path_avoiding(edges, source, target, avoid):
    """A shortest path from source to target that does not visit avoid, or None."""
    successors = {}
    for s, t, _ in edges:
        successors.setdefault(s, set()).add(t)
    parent = {source: None}
    queue = deque([source])
    while queue:
        node = queue.popleft()
        if node == target:
            path = []
            while node is not None:
                path.append(node)
                node = parent[node]
            return path[::-1]
        for nxt in sorted(successors.get(node, ())):
            if nxt != avoid and nxt not in parent:
                parent[nxt] = node
                queue.append(nxt)
    return None


def topology_ids(header_text):
    """{(pd, peer): id} from '#define PD_CH_PEER id' lines."""
    ids = {}
    for pd, peer, value in re.findall(r"^#define (\w+?)_CH_(\w+)\s+(\d+)", header_text, re.M):
        ids[(pd.lower(), peer.lower())] = int(value)
    return ids


def check(system, policy, header_text):
    """List of (name, ok, problems)."""
    results = []

    def record(name, problems):
        results.append((name, not problems, problems))

    roles = policy["roles"]
    monitor = [pd for pd, role in roles.items() if role == "monitor"]

    record("supported", ["unsupported element: " + u + " (the checker does not model its authority)"
                         for u in system.unsupported])

    problems = ["PD {} has no role in the policy".format(pd) for pd in system.pds if pd not in roles]
    problems += ["region {} is not in the policy".format(r) for r in system.regions if r not in policy["regions"]]
    problems += ["policy PD {} is not in the description".format(pd) for pd in roles if pd not in system.pds]
    if len(monitor) != 1:
        problems.append("the policy must name exactly one monitor PD")
    record("classified", problems)

    problems = []
    for pd, region, perms in system.maps:
        if "x" in perms:
            problems.append("{} maps {} executable ({})".format(pd, region, perms))
        rule = policy["regions"].get(region)
        if rule is None:
            continue
        if "r" in perms and pd not in rule["readers"]:
            problems.append("{} may not read {} (perms {})".format(pd, region, perms))
        if "w" in perms and pd not in rule["writers"]:
            problems.append("{} may not write {} (perms {})".format(pd, region, perms))
    record("region access", problems)

    problems = []
    for pd, allowed in policy.get("untrusted_authority", {}).items():
        for p, region, perms in system.maps:
            if p == pd and not set(perms) <= set(allowed["maps"].get(region, "")):
                problems.append("{} maps {} with perms {}, allowed: {}".format(
                    pd, region, perms, allowed["maps"].get(region, "none")))
        for a, b in system.channels:
            for this, other in ((a, b), (b, a)):
                if this[0] != pd:
                    continue
                if this[2] and other[0] not in allowed["calls"]:
                    problems.append("{} can call {}".format(pd, other[0]))
                if this[3] and other[0] not in allowed["notifies"]:
                    problems.append("{} can notify {}".format(pd, other[0]))
    for pd, role in roles.items():
        if role == "untrusted" and pd not in policy.get("untrusted_authority", {}):
            problems.append("untrusted PD {} has no authority bound in the policy".format(pd))
    record("untrusted authority", problems)

    problems = []
    bounds = policy.get("untrusted_authority", {})
    for pd, number, _ in system.irqs:
        if number not in bounds.get(pd, {}).get("irqs", []):
            problems.append("{} receives interrupt {}, which the policy does not give it".format(pd, number))
    holders = {}
    for pd, number, _ in system.irqs:
        holders.setdefault(number, []).append(pd)
    problems += ["interrupt {} is given to {}".format(n, " and ".join(pds)) for n, pds in holders.items() if len(pds) > 1]
    record("interrupts", problems)

    edges = system.edges()
    problems = []
    for target, allowed in policy.get("only_reached_from", {}).items():
        for s, t, label in edges:
            if t == target and s not in allowed:
                problems.append("{} reaches {} directly ({})".format(s, target, label))
    record("sink reachability", problems)

    problems = []
    if len(monitor) == 1:
        for source, target in policy["mediated"]:
            path = path_avoiding(edges, source, target, monitor[0])
            if path:
                problems.append("{} reaches {} without {}: {}".format(
                    source, target, monitor[0], " -> ".join(path)))
    record("mediation", problems)

    problems = []
    for caller, callee in system.calls():
        if system.pds.get(callee, -1) <= system.pds.get(caller, -1):
            problems.append("{} (priority {}) calls {} (priority {}); the callee must be higher".format(
                caller, system.pds.get(caller), callee, system.pds.get(callee)))
    if path_cycle(system.calls()):
        problems.append("the call graph has a cycle: " + " -> ".join(path_cycle(system.calls())))
    record("priorities", problems)

    ids = topology_ids(header_text)
    problems = []
    seen = set()
    used = {}
    for a, b in system.channels:
        for end in (a, b):
            used.setdefault(end[0], []).append(end[1])
    for pd, _, ident in system.irqs:
        used.setdefault(pd, []).append(ident)
    for pd, idents in used.items():
        duplicates = sorted({i for i in idents if idents.count(i) > 1})
        if duplicates:
            problems.append("{} uses channel id {} twice".format(pd, ", ".join(map(str, duplicates))))
    for a, b in system.channels:
        for this, other in ((a, b), (b, a)):
            key = (this[0], other[0])
            seen.add(key)
            if key not in ids:
                problems.append("src/topology.h has no {}_CH_{}".format(this[0].upper(), other[0].upper()))
            elif ids[key] != this[1]:
                problems.append("{}_CH_{} is {} in src/topology.h but {} in the description".format(
                    this[0].upper(), other[0].upper(), ids[key], this[1]))
    for key in ids:
        if key not in seen:
            problems.append("{}_CH_{} in src/topology.h has no channel".format(key[0].upper(), key[1].upper()))
    record("channel ids", problems)
    return results


def path_cycle(calls):
    """A cycle in the call graph as a list of PDs, or None."""
    graph = {}
    for a, b in calls:
        graph.setdefault(a, []).append(b)
    state = {}

    def visit(node, stack):
        state[node] = "active"
        stack.append(node)
        for nxt in graph.get(node, ()):
            if state.get(nxt) == "active":
                return stack[stack.index(nxt):] + [nxt]
            if nxt not in state:
                found = visit(nxt, stack)
                if found:
                    return found
        stack.pop()
        state[node] = "done"
        return None

    for node in sorted(graph):
        if node not in state:
            found = visit(node, [])
            if found:
                return found
    return None


def mermaid(system, policy):
    """The derived flow graph, coloured by the policy's roles."""
    lines = ["flowchart LR"]
    for region in system.regions:
        lines.append("    {0}[({0})]".format(region))
    for _, number, _ in system.irqs:
        lines.append("    irq{0}{{{{irq {0}}}}}".format(number))
    for pd, priority in system.pds.items():
        lines.append("    {0}[{0} · prio {1}]".format(pd, priority))
    merged = {}
    for s, t, label in system.edges():
        if label == "reply":
            continue  # shown as a two-way call
        merged.setdefault((s.replace(" ", ""), t), []).append(label)
    for (s, t), labels in merged.items():
        if "call" in labels:
            lines.append("    {} <-->|call| {}".format(s, t))
        rest = [label for label in labels if label != "call"]
        if rest:
            lines.append("    {} -->|{}| {}".format(s, " + ".join(rest), t))
    styles = {"trusted": "fill:#E7EEF5,stroke:#24405C", "monitor": "fill:#FDF3E2,stroke:#A5690C,stroke-width:3px",
              "untrusted": "fill:#FAE9E7,stroke:#A83226,stroke-dasharray:5 3"}
    for pd, role in policy["roles"].items():
        if pd in system.pds and role in styles:
            lines.append("    style {} {}".format(pd, styles[role]))
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--system", type=Path, default=PROTOTYPE / "broker.system")
    parser.add_argument("--policy", type=Path, default=PROTOTYPE / "flow-policy.json")
    parser.add_argument("--topology", type=Path, default=PROTOTYPE / "src" / "topology.h")
    parser.add_argument("--mermaid", action="store_true", help="print the flow graph instead of checking")
    args = parser.parse_args()
    system = System(ET.parse(args.system).getroot())
    policy = json.loads(args.policy.read_text())
    if args.mermaid:
        print(mermaid(system, policy))
        return
    results = check(system, policy, args.topology.read_text())
    for name, ok, problems in results:
        print("{}  {}".format("PASS" if ok else "FAIL", name))
        for problem in problems:
            print("      " + problem)
    failed = [name for name, ok, _ in results if not ok]
    if failed:
        print("{}: {} of {} checks failed".format(args.system.name, len(failed), len(results)), file=sys.stderr)
        sys.exit(1)
    print("{}: all {} checks passed".format(args.system.name, len(results)))


if __name__ == "__main__":
    main()
