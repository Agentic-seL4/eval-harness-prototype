"""Finite distinguishing-pair checks over saved original-matrix Inspect logs."""

import argparse
import hashlib
import json
import sys
from collections import defaultdict
from pathlib import Path

from inspect_ai.log import read_eval_log

from cases import configurations, expected_outcome
from email_task import email_engine
from scoring import assess_execution


def event_projection(trace):
    """Rebuild the original Run.projection('event') from structured steps."""
    selected = [s for s in trace["steps"] if s["action"] is not None or s["observation"] is not None]
    return {"actions": [s["action"] for s in selected],
            "observations": [s["observation"] for s in selected]}


class RecordedRun:
    """Minimal adapter to use the prototype's existing compare predicate."""
    def __init__(self, trace):
        self.completed = trace["completed"]
        self.view = event_projection(trace)

    def projection(self, view):
        if view != "event":
            raise ValueError("This analysis declares only the event observer")
        return self.view


def pair_report(log):
    cases = configurations()
    known_ids = set(cases)
    logged_samples = log.samples or []
    unexpected = sorted(str(s.id) for s in logged_samples if s.id not in known_ids)
    samples = defaultdict(list)
    for sample in logged_samples:
        samples[sample.id].append(sample)
    groups = defaultdict(dict)
    for name, config in cases.items():
        # Keep every setting except the secret fixed within a pair.
        group = name.replace(f"-s{config['secret']}-", "-")
        groups[group][config["secret"]] = name
    pairs = []
    for group, ids in groups.items():
        item = {"case": group, "sample_ids": [ids[0], ids[1]], "status": "invalid",
                "expected_qualifying_pair": bool(expected_outcome(cases[ids[0]])["effects"]),
                "comparison": None, "conformant": False, "reasons": []}
        records, traces, conformant = [], [], []
        for secret in (0, 1):
            name = ids[secret]
            if len(samples[name]) != 1:
                item["reasons"].append(f"{name}: expected exactly one sample")
                continue
            sample = samples[name][0]
            record = sample.store.get("execution")
            assessment = assess_execution(record, cases[name])
            if sample.error is not None or not assessment["valid"]:
                item["reasons"].append(f"{name}: execution error or invalid record")
                continue
            trace = record["analyst_trace"]
            if (trace["config"] != cases[name] or trace["completed"] is not True
                    or trace["final"]["pc"] != 3 or trace["final"]["pending"] is not None):
                item["reasons"].append(f"{name}: mismatched configuration or incomplete execution")
                continue
            try:
                projection = event_projection(trace)
                saved_projection = trace["views"]["event"]
            except (KeyError, TypeError):
                item["reasons"].append(f"{name}: missing attacker projection")
                continue
            if (projection != saved_projection
                    or not assessment["checks"]["dispatch_records"]
                    or not assessment["checks"]["observation_records"]
                    or not assessment["checks"]["attacker_view"]):
                item["reasons"].append(f"{name}: inconsistent attacker projection or sink records")
                continue
            if (record.get("backend") not in ("python", "c")
                    or not isinstance(record.get("source"), dict)
                    or record["source"].get("sha256") != email_engine().source_sha256):
                item["reasons"].append(f"{name}: missing or unsupported source provenance")
                continue
            records.append(record)
            traces.append(trace)
            conformant.append(assessment["conformance"])
        if item["reasons"]:
            pairs.append(item)
            continue
        if (records[0]["backend"] != records[1]["backend"]
                or records[0]["source"] != records[1]["source"]
                or records[0].get("native_monitor", {}).get("source_sha256")
                != records[1].get("native_monitor", {}).get("source_sha256")):
            item["reasons"].append("Pair mixes backends or source snapshots")
            pairs.append(item)
            continue
        comparison = email_engine().compare(RecordedRun(traces[0]), RecordedRun(traces[1]), "event")
        item.update(status="valid", comparison=comparison, conformant=all(conformant))
        # Conformance regressions remain visible, even when the actual pair can
        # still be compared. A new observed disclosure must not be hidden.
        pairs.append(item)
    valid = [p for p in pairs if p["status"] == "valid"]
    summary = {
        "valid_pairs": len(valid), "invalid_pairs": len(pairs) - len(valid),
        "qualifying_pairs": sum(p["comparison"]["qualifying_leak_pair"] for p in valid),
        "unexpected_pair_results": sum(p["comparison"]["qualifying_leak_pair"]
                                       != p["expected_qualifying_pair"] for p in valid),
        "nonconformant_pairs": sum(not p["conformant"] for p in valid),
        "unexpected_sample_ids": unexpected,
    }
    passed = (len(valid) == 8 and not summary["unexpected_pair_results"]
              and not summary["nonconformant_pairs"] and not unexpected)
    return {"scope": "Finite distinguishing-pair check, event observer; not a Relative Security proof",
            "passed": passed, "summary": summary, "pairs": pairs}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("log", type=Path, help="One complete original 16-case matrix .eval log")
    parser.add_argument("--output", type=Path, help="Save comparison booleans, not private diagnostic traces")
    args = parser.parse_args(argv)
    try:
        report = pair_report(read_eval_log(str(args.log)))
        report["source_log"] = str(args.log.resolve())
        report["source_log_sha256"] = hashlib.sha256(args.log.read_bytes()).hexdigest()
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        print(json.dumps({"passed": report["passed"], **report["summary"]}, indent=2))
        return 0 if report["passed"] else 1
    except (OSError, ValueError, KeyError, TypeError) as error:
        print(f"Pair analysis failed: {type(error).__name__}: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
