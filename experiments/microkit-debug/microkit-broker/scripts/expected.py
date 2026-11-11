#!/usr/bin/env python3
"""Expected trace records for each configuration, computed by the email-fence replay.

The Microkit system prints one record per line: a tag, a space and a JSON object
(PROTOCOL.md, section 5). This script renders the same records from
../../email-fence/core.py, so the run matrix (T8) can compare them with QEMU's
serial output. It also parses serial output and maps fixture text to the formal
values of Email_Setting.thy.

    expected.py --list                     configuration names
    expected.py fenced-injected-s1-malicious-allowed
    expected.py --fixtures NAME            with fixture text instead of formal values
"""
import argparse
import importlib.util
import json
import re
import sys
from dataclasses import asdict
from functools import lru_cache
from pathlib import Path

HERE = Path(__file__).resolve().parent
PROTOTYPE = HERE.parent
FIXTURES = PROTOTYPE / "fixtures"
CORE = PROTOTYPE.parent / "email-fence" / "core.py"

sys.path.insert(0, str(HERE))
from make_prefill import fixture_text  # noqa: E402

TAGS = ("CONFIG", "TRACE", "OBS", "MEM", "DONE", "NOTE", "ERR")
LINE = re.compile(r"^(%s) (\{.*\})\s*$" % "|".join(TAGS))
# Tags whose records the comparison uses; NOTE and ERR are diagnostics.
COMPARED = ("CONFIG", "TRACE", "OBS", "MEM", "DONE")

POLICIES = ("open", "fenced", "late")
MODES = ("reference", "injected")


@lru_cache(maxsize=1)
def core():
    """Load the unchanged email-fence engine under a private module name."""
    if not CORE.is_file():
        raise RuntimeError("needs the sibling prototype email-fence/core.py")
    name = "_microkit_broker_email_fence_core"
    spec = importlib.util.spec_from_file_location(name, CORE)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module  # dataclasses look the module up by name
    spec.loader.exec_module(module)
    return module


def config_name(policy, mode, secret, email="malicious", inbox="allowed"):
    return "{}-{}-s{}-{}-{}".format(policy, mode, secret, email, inbox)


def configurations():
    """The 16 runs of email-fence's demo: the 12-run matrix plus four extras."""
    runs = [(p, m, s, "malicious", "allowed") for p in POLICIES for m in MODES for s in (0, 1)]
    runs += [("fenced", "injected", s, "benign", "allowed") for s in (0, 1)]
    runs += [("fenced", "injected", s, "malicious", "denied") for s in (0, 1)]
    return {config_name(*run): run for run in runs}


@lru_cache(maxsize=1)
def manifest():
    """Fixture text (as decoded from JSON escapes) -> formal value, and back."""
    data = json.loads((FIXTURES / "fixtures.json").read_text())
    to_formal, to_text = {}, {}
    for group in ("secret", "email"):
        for entry in data[group].values():
            text = fixture_text(FIXTURES / entry["file"]).decode("latin-1")
            to_formal[text] = entry["formal"]
            to_text[entry["formal"]] = text
    return to_formal, to_text


def map_values(obj, table):
    """Replace every string value (not key) found in table."""
    if isinstance(obj, dict):
        return {k: map_values(v, table) for k, v in obj.items()}
    if isinstance(obj, list):
        return [map_values(v, table) for v in obj]
    if isinstance(obj, str):
        return table.get(obj, obj)
    return obj


def expected(name):
    """Records the system should print for one configuration, with formal values."""
    policy, mode, secret, email, inbox = configurations()[name]
    engine = core()
    formal_email = {"malicious": "Email", "benign": "Data 7"}[email]
    run = engine.replay(engine.Config(mode=mode, policy=policy, secret=secret, email=formal_email,
                                      inbox_allowed=inbox == "allowed"))
    records = [("CONFIG", {"pd": "broker", "policy": policy,
                           "initial_perms": run.initial["permissions"]}),
               ("CONFIG", {"pd": "worker", "mode": mode, "attack": "none"})]
    for step in run.steps:
        event = step.event
        effect = None
        if step.effect is not None:
            effect = {"tool": step.effect.tool, "args": list(step.effect.args)}
            # The sink prints its observation during the broker's transaction,
            # before the broker prints that step's TRACE record.
            records.append(("OBS", dict(effect)))
        records.append(("TRACE", {
            "step": step.number,
            "caller": "runner" if step.origin == "plan" else "worker",
            "event": event.kind,
            "tool": event.tool,
            "args": list(event.args) if event.kind == "ACall" else None,
            "value": event.value if event.kind in ("AReadT", "AReadU") else None,
            "decision": step.decision,
            "perms_before": step.before["permissions"],
            "perms_decided": step.monitor_after_decision,
            "perms_admitted": step.admission_permissions,
            "perms_after": step.after["permissions"],
            "context_len": len(step.after["context"]),
            "effect": effect,
        }))
    records.append(("MEM", {"pc": run.final["pc"], "memory": dict(run.final["memory"])}))
    records.append(("DONE", {}))
    return records


def format_record(tag, obj):
    """One line: ASCII JSON, compact separators, keys in the order given."""
    return "{} {}".format(tag, json.dumps(obj, ensure_ascii=True, separators=(",", ":")))


def parse_records(text):
    """Records in serial output. Lines with a known tag but invalid JSON become BAD."""
    records = []
    for line in text.splitlines():
        line = line.rstrip("\r")
        match = LINE.match(line)
        if match:
            try:
                records.append((match.group(1), json.loads(match.group(2))))
            except json.JSONDecodeError:
                records.append(("BAD", line))
        elif line.split(" ", 1)[0] in TAGS:
            records.append(("BAD", line))
    return records


def to_formal(records):
    """Map fixture text in parsed records to formal values (Email, Data 7, ...)."""
    table, _ = manifest()
    return [(tag, map_values(obj, table)) for tag, obj in records]


def compare(expected_records, actual_records):
    """Differences between expected records and parsed serial output (PROTOCOL.md §5).

    Fixture text in the output is mapped to formal values first. Each compared tag's
    records are checked in order (CONFIG regardless of order); any ERR or BAD record
    is a difference. An empty list means the run matches.
    """
    actual = to_formal(actual_records)
    problems = []
    for tag, obj in actual:
        if tag == "BAD":
            problems.append("malformed line: " + obj)
        elif tag == "ERR":
            problems.append("ERR " + json.dumps(obj))
    for tag in COMPARED:
        want = [obj for t, obj in expected_records if t == tag]
        got = [obj for t, obj in actual if t == tag]
        if tag == "CONFIG":
            want = sorted(want, key=lambda o: o.get("pd", ""))
            got = sorted(got, key=lambda o: o.get("pd", ""))
        if len(want) != len(got):
            problems.append("{}: expected {} records, got {}".format(tag, len(want), len(got)))
        for number, (w, g) in enumerate(zip(want, got), 1):
            for key in sorted(set(w) | set(g)):
                if w.get(key) != g.get(key):
                    problems.append("{} #{} {}: expected {!r}, got {!r}".format(
                        tag, number, key, w.get(key), g.get(key)))
    return problems


def to_fixture_text(records):
    """Map formal values to the fixture text the system actually prints."""
    _, table = manifest()
    return [(tag, map_values(obj, table)) for tag, obj in records]


def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("names", nargs="*", help="configuration names (see --list)")
    parser.add_argument("--list", action="store_true", help="list configuration names")
    parser.add_argument("--fixtures", action="store_true",
                        help="print fixture text, exactly as the system prints it")
    args = parser.parse_args()
    known = configurations()
    if args.list or not args.names:
        print("\n".join(known))
        return
    for name in args.names:
        if name not in known:
            parser.error("unknown configuration {!r}; see --list".format(name))
        records = expected(name)
        if args.fixtures:
            records = to_fixture_text(records)
        if len(args.names) > 1:
            print("# " + name)
        for tag, obj in records:
            print(format_record(tag, obj))


if __name__ == "__main__":
    main()
