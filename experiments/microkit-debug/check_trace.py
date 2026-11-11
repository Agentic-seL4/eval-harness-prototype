#!/usr/bin/env python3
"""Check a saved serial log using the copied prototype's reference comparator."""
import argparse
import hashlib
import json
from pathlib import Path
import sys

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "microkit-broker" / "scripts"))
import expected  # noqa: E402


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("case", choices=sorted(expected.configurations()))
    parser.add_argument("log", type=Path, help="serial log; relative to the current directory")
    parser.add_argument("--report", type=Path, help="save a JSON result (overwrites this file)")
    args = parser.parse_args()
    if args.report and args.report.resolve() == args.log.resolve():
        parser.error("report must not overwrite the input log")
    try:
        data = args.log.read_bytes()
        records = expected.parse_records(data.decode("utf-8"))
        problems = expected.compare(expected.expected(args.case), records)
        result = {
            "case": args.case,
            "log": str(args.log.resolve()),
            "log_sha256": hashlib.sha256(data).hexdigest(),
            "passed": not problems,
            "problems": problems,
            "compared_tags": list(expected.COMPARED),
            "scope": "Saved serial records only; no build, execution-status or timing check.",
        }
        if args.report:
            args.report.write_text(json.dumps(result, indent=2) + "\n")
    except (OSError, UnicodeError, RuntimeError) as error:
        print("ERROR: {}".format(error), file=sys.stderr)
        return 2
    print("{}: {}".format("FAIL" if problems else "PASS", args.case))
    for problem in problems:
        print("  " + problem)
    if not problems:
        print("All compared records match the Python reference.")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
