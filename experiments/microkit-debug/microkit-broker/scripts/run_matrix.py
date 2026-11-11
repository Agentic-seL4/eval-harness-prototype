#!/usr/bin/env python3
"""Build and boot every configuration on QEMU and compare it with email-fence/core.py (T8).

For each of the 16 configurations (expected.py --list) this builds an image in
its own build directory, boots it until DONE, keeps the serial log and compares
the trace records with core.py's replay. It then pairs the runs that differ only
in the secret and asks whether the attacker's view (the sink's OBS records) tells
secret 0 from secret 1.

Scope: two secrets and one fixed attacker input per pair. Equal views show only
that these runs do not distinguish the secrets; this is not a relative-security
verdict, which quantifies over all inputs and model behaviours.

With --input tcp (T8b) the email is not built in: each run connects to QEMU's
second UART as the attacker, sends the email once the broker reports that the
runner is waiting for it, and records what comes back on the socket. The console
must still match core.py exactly, and the socket must carry exactly the expected
OBS lines and nothing else.

    run_matrix.py                    all 16 configurations, 4 at a time
    run_matrix.py --input tcp        the same, with the email sent over TCP
    run_matrix.py --only NAME ...    selected configurations
    run_matrix.py --jobs 1           one at a time
"""
import argparse
import concurrent.futures
import datetime
import json
import os
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
PROTOTYPE = HERE.parent
sys.path.insert(0, str(HERE))

import expected as ex  # noqa: E402
import run_qemu  # noqa: E402

# The paper's verdicts for the email example: only injected open and late runs leak.
LEAKING = {("open", "injected", "malicious", "allowed"), ("late", "injected", "malicious", "allowed")}


def observations(records):
    return [obj for tag, obj in records if tag == "OBS"]


WAITING = "inbox not ready"  # the broker's NOTE when the runner waits for the email


def run_one(name, build_root, timeout, input_mode="file"):
    """Build and boot one configuration; return its result record."""
    policy, mode, secret, email, inbox = ex.configurations()[name]
    build_dir = Path(build_root) / (name + ("-tcp" if input_mode == "tcp" else ""))
    started = time.monotonic()
    result = dict(name=name, policy=policy, mode=mode, secret=secret, email=email, inbox=inbox,
                  input=input_mode, expected_observations=observations(ex.expected(name)), observations=None)
    make = subprocess.run(["make", "-s", "BUILD_DIR=" + str(build_dir), "POLICY=" + policy, "MODE=" + mode,
                           "SECRET={}".format(secret), "EMAIL=" + email, "INBOX=" + inbox,
                           "INPUT=" + input_mode],
                          cwd=PROTOTYPE, capture_output=True, text=True)
    if make.returncode != 0:
        result.update(ok=False, problems=["build failed: " + (make.stderr or make.stdout)[-500:]],
                      seconds=round(time.monotonic() - started, 1))
        return result
    if input_mode == "tcp":
        fixture = ex.FIXTURES / "email-{}.txt".format(email)
        status, output, socket_text = run_qemu.run_with_socket(
            build_dir / "loader.img", fixture.read_bytes().rstrip(b"\r\n") + b"\n",
            until="DONE {}", timeout=timeout, send_after=WAITING)
        (build_dir / "attacker.log").write_text(socket_text)
    else:
        status, output = run_qemu.run(build_dir / "loader.img", until="DONE {}", timeout=timeout, echo=False)
    (build_dir / "serial.log").write_text(output)
    records = ex.parse_records(output)
    problems = ex.compare(ex.expected(name), records)
    if status != 0:
        problems.insert(0, "no DONE within {} s".format(timeout) if status == 1 else "QEMU stopped early")
    seen = observations(ex.to_formal(records))
    if input_mode == "tcp":
        if WAITING not in output:
            problems.append("the runner never waited for the email (wait path not exercised)")
        # The attacker's view is the socket: exactly the expected OBS lines, nothing else.
        socket_records = ex.to_formal(ex.parse_records(socket_text))
        stray = [line for line in socket_text.splitlines() if not line.startswith("OBS ")]
        if stray:
            problems.append("socket carried more than OBS lines: {!r}".format(stray[:3]))
        seen = observations(socket_records)
        if seen != result["expected_observations"]:
            problems.append("socket OBS: expected {}, got {}".format(result["expected_observations"], seen))
    result.update(ok=not problems, problems=problems, observations=seen,
                  seconds=round(time.monotonic() - started, 1))
    return result


def verdicts(results):
    """Pair the secret-0 and secret-1 runs of each setting and compare the attacker's views."""
    pairs = {}
    for r in results:
        pairs.setdefault((r["policy"], r["mode"], r["email"], r["inbox"]), {})[r["secret"]] = r
    rows = []
    for key, pair in pairs.items():
        if set(pair) != {0, 1}:
            continue
        observed = pair[0]["observations"] != pair[1]["observations"]
        predicted = pair[0]["expected_observations"] != pair[1]["expected_observations"]
        rows.append(dict(policy=key[0], mode=key[1], email=key[2], inbox=key[3],
                         seen=[pair[0]["observations"], pair[1]["observations"]],
                         distinguishes=observed, core_predicts=predicted,
                         paper_expects=key in LEAKING,
                         ok=observed == predicted == (key in LEAKING)))
    return rows


def describe(observed):
    if observed is None:
        return "(no run)"
    if not observed:
        return "nothing"
    return "; ".join("{} {}".format(o["tool"], json.dumps(o["args"])) for o in observed)


def report(results, rows, versions):
    matched = sum(r["ok"] for r in results)
    tcp = any(r.get("input") == "tcp" for r in results)
    source = ("Input: the email sent over TCP to the second UART; the attacker's view is the socket."
              if tcp else "Input: the email built into the inbox; the attacker's view is the sink's `OBS` records.")
    lines = ["# Run matrix" + (" (email over TCP)" if tcp else ""), "",
             "Generated {} by `scripts/run_matrix.py`. {}.".format(
                 datetime.datetime.now().strftime("%d %B %Y %H:%M"), versions), "", source, "",
             "**{} of {} configurations print exactly what `core.py` predicts.**".format(matched, len(results)), "",
             "| Configuration | Matches `core.py` | Attacker sees | Time |",
             "|---|---|---|---|"]
    for r in results:
        lines.append("| `{}` | {} | {} | {} s |".format(r["name"], "yes" if r["ok"] else "**no**",
                                                       describe(r["observations"]), r["seconds"]))
    lines += ["", "## Can the attacker tell secret 0 from secret 1?", "",
              "Each row pairs two runs that differ only in the secret. The attacker's view is the",
              "sink's `OBS` records. Scope: these two secrets and this one email, not a relative-",
              "security verdict.", "",
              "| Policy | Model | Email | Inbox | Secret 0: attacker sees | Secret 1: attacker sees | Tells them apart | `core.py` | Paper |",
              "|---|---|---|---|---|---|---|---|---|"]
    for row in rows:
        lines.append("| {} | {} | {} | {} | {} | {} | {} | {} | {} |".format(
            row["policy"], row["mode"], row["email"], row["inbox"], describe(row["seen"][0]),
            describe(row["seen"][1]), "**yes**" if row["distinguishes"] else "no",
            "yes" if row["core_predicts"] else "no", "leaks" if row["paper_expects"] else "no leak"))
    failures = [r for r in results if not r["ok"]]
    if failures:
        lines += ["", "## Differences", ""]
        for r in failures:
            lines.append("- `{}`".format(r["name"]))
            lines += ["  - " + p for p in r["problems"][:20]]
    return "\n".join(lines) + "\n"


def versions():
    sdk = os.environ.get("MICROKIT_SDK", "")
    sdk_version = Path(sdk, "VERSION").read_text().strip() if sdk and Path(sdk, "VERSION").is_file() else "?"
    qemu = subprocess.run(["qemu-system-aarch64", "--version"], capture_output=True, text=True).stdout.split("\n")[0]
    return "Microkit SDK {}, {}".format(sdk_version, qemu.replace("QEMU emulator version", "QEMU"))


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--only", nargs="+", metavar="NAME", help="configurations to run (see expected.py --list)")
    parser.add_argument("--jobs", type=int, default=4)
    parser.add_argument("--input", choices=("file", "tcp"), default="file")
    parser.add_argument("--timeout", type=float, default=30.0)
    parser.add_argument("--build-root", type=Path, default=PROTOTYPE / "build")
    parser.add_argument("--report", type=Path, default=PROTOTYPE / "build" / "matrix")
    args = parser.parse_args()
    if not os.environ.get("MICROKIT_SDK"):
        parser.error("set MICROKIT_SDK to the Microkit SDK 2.3.1 directory")
    names = args.only or list(ex.configurations())
    unknown = [n for n in names if n not in ex.configurations()]
    if unknown:
        parser.error("unknown configuration(s): " + ", ".join(unknown))

    with concurrent.futures.ThreadPoolExecutor(max_workers=args.jobs) as pool:
        results = list(pool.map(lambda n: run_one(n, args.build_root, args.timeout, args.input), names))
    rows = verdicts(results)
    text = report(results, rows, versions())
    if args.input == "tcp" and args.report == PROTOTYPE / "build" / "matrix":
        args.report = PROTOTYPE / "build" / "matrix-tcp"
    args.report.mkdir(parents=True, exist_ok=True)
    (args.report / "report.md").write_text(text)
    (args.report / "report.json").write_text(json.dumps(dict(results=results, verdicts=rows), indent=2) + "\n")
    print(text)
    print("Serial logs in {}/<name>/serial.log; report in {}".format(args.build_root, args.report / "report.md"))
    ok = all(r["ok"] for r in results) and all(row["ok"] for row in rows)
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
