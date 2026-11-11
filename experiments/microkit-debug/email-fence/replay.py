#!/usr/bin/env python3
"""Run the email-fence teaching experiment using only the Python standard library."""
import argparse
import json
from pathlib import Path

from core import Config, PAPER_COMMIT, bundle, compare, demo_runs, replay


def natural(text):
    try:
        value = int(text)
    except ValueError:
        raise argparse.ArgumentTypeError("secret must be a nonnegative integer")
    if value < 0:
        raise argparse.ArgumentTypeError("secret must be a nonnegative integer")
    return value


def label(run):
    c = run.config
    extra = " / benign" if c.email != "Email" else " / inbox denied" if not c.inbox_allowed else ""
    return "{} / {}{}".format(c.policy, c.mode, extra)


def effects(run):
    return "; ".join("{} [{}]".format(c.tool, ", ".join(c.args)) for c in run.effects) or "nothing"


def save_json(path, payload):
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    print("Wrote diagnostic JSON:", target)


def save_html(path, payload):
    template = Path(__file__).with_name("viewer.html").read_text(encoding="utf-8")
    # Keep embedded JSON inert even if future fixtures contain HTML delimiters.
    encoded = json.dumps(payload).replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026")
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(template.replace("__TRACE_DATA__", encoded), encoding="utf-8")
    print("Wrote offline viewer:", target)


def show_run(run, interactive=False):
    print("{}; secret = Data {}".format(label(run), run.config.secret))
    print("ANALYST VIEW: memory and diagnostics below include secrets.")
    print("Initial permissions:", ", ".join(run.initial["permissions"]))
    for step in run.steps:
        if interactive:
            try:
                answer = input("Enter: next recorded step; q: stop viewing > ").strip().lower()
            except EOFError:
                return
            if answer == "q":
                return
        print("\n{}. {} [{}]".format(step.number, step.event.description(), step.origin))
        print("   pc {} -> {}; oracle {} -> {}".format(
            step.before["pc"], step.after["pc"], step.before["oracle"], step.after["oracle"]))
        print("   permissions {} -> {}".format(step.before["permissions"], step.after["permissions"]))
        print("   memory:", step.after["memory"])
        print("   context:", list(step.after["context"]))
        if step.proposed["pending"]:
            print("   pending read (inside transaction):", step.proposed["pending"])
        print("   pending after transaction:", step.after["pending"])
        if step.decision:
            print("   decision: {}; response: {}".format(step.decision, step.response))
        for operation in step.operations:
            print("   -", operation)
        observation = step.observation
        print("   attacker sees:", "{} {}".format(observation.tool, list(observation.args))
              if observation else "nothing at this step")
    print("\nCompleted:", run.completed, "| Summary:", run.final["memory"]["Summary"])
    print("Event view (null = no action/observation, not the string 'null'):")
    print(json.dumps(run.projection(), indent=2))


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command")
    demo = commands.add_parser("demo", help="compare paired runs and optionally export an offline viewer")
    demo.add_argument("--json", metavar="PATH", help="write full analyst traces")
    demo.add_argument("--html", metavar="PATH", help="write a self-contained interactive HTML viewer")
    single = commands.add_parser("run", help="explain one execution")
    single.add_argument("--mode", choices=("reference", "injected"), default="injected")
    single.add_argument("--policy", choices=("open", "fenced", "late"), default="fenced")
    single.add_argument("--secret", type=natural, default=0)
    single.add_argument("--email", choices=("malicious", "benign"), default="malicious")
    single.add_argument("--deny-inbox", action="store_true")
    single.add_argument("--step", action="store_true", help="press Enter to view each recorded atomic step")
    single.add_argument("--json", metavar="PATH")
    args = parser.parse_args(argv)
    if args.command == "run":
        run = replay(Config(args.mode, args.policy, args.secret,
                            "Email" if args.email == "malicious" else "Data 7", not args.deny_inbox))
        if args.json:
            save_json(args.json, bundle([run]))
        show_run(run, args.step)
        return 0
    runs = demo_runs()
    print("EMAIL-FENCE REPLAY | paper {}".format(PAPER_COMMIT[:7]))
    print("Same public input; vary only the secret in each row. All tools are fake.\n")
    print("{:<35} {:<18} {:<18} {}".format("Scenario", "Attacker: secret 0", "Attacker: secret 1", "Completes"))
    for i in range(0, len(runs), 2):
        a, b = runs[i:i + 2]
        print("{:<35} {:<18} {:<18} {}".format(label(a), effects(a), effects(b), a.completed and b.completed))
    print("\nPaired event-view checks (equal actions AND different observations):")
    for i in range(0, len(runs), 2):
        a, b = runs[i:i + 2]
        result = compare(a, b)
        print("  {}: {}".format(label(a), "leak pair" if result["qualifying_leak_pair"] else "no leak pair in this comparison"))
    print("\nThe reference plan never calls Fetch. Open and late injections add a disclosure.")
    print("Fenced runs still finish this assignment task; they do not perform real summarisation.")
    print("Late is a deliberately broken implementation extension, not the atomic formal policy.")
    print("These finite checks are not an RS proof. Full traces are private analyst diagnostics.")
    payload = bundle(runs)
    if getattr(args, "json", None):
        save_json(args.json, payload)
    if getattr(args, "html", None):
        save_html(args.html, payload)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
