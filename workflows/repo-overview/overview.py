#!/usr/bin/env python3
"""Collect Git evidence; acknowledge reviewed snapshots separately."""

import argparse
import datetime as dt
import fcntl
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import uuid


HERE = Path(__file__).resolve().parent
DEFAULT_ROOT = HERE.parents[2]


def git(repo, *args, check=True):
    env = dict(os.environ, GIT_TERMINAL_PROMPT="0", GIT_OPTIONAL_LOCKS="0")
    result = subprocess.run(
        ["git", "-C", str(repo), *args], capture_output=True, text=True,
        errors="replace", env=env, timeout=180,
    )
    if check and result.returncode:
        raise RuntimeError(result.stderr.strip() or "Git command failed")
    return result


def read_json(path, default=None):
    return json.loads(path.read_text()) if path.exists() else default


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True).encode()).hexdigest()


def write_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=".overview-", dir=path.parent)
    try:
        with os.fdopen(fd, "w") as handle:
            json.dump(value, handle, indent=2, ensure_ascii=True)
            handle.write("\n")
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def discover(root, excluded):
    repos = []
    skipped = []
    for current, dirs, files in os.walk(root, followlinks=False):
        directory = Path(current)
        relative = directory.relative_to(root).as_posix()
        if directory != root and (directory.name in excluded or relative in excluded):
            skipped.append(relative)
            dirs[:] = []
            continue
        if directory != root and (".git" in dirs or ".git" in files):
            repos.append(directory)
        dirs[:] = sorted(d for d in dirs if d != ".git" and not (directory / d).is_symlink())
    return sorted(repos), sorted(skipped)


def has_commit(repo, sha):
    return git(repo, "cat-file", "-e", sha + "^{commit}", check=False).returncode == 0


def ancestor(repo, before, after):
    result = git(repo, "merge-base", "--is-ancestor", before, after, check=False)
    if result.returncode not in (0, 1):
        raise RuntimeError(result.stderr.strip())
    return result.returncode == 0


def branch_refs(repo):
    output = git(repo, "for-each-ref", "--format=%(refname)%09%(objectname)%09%(symref)",
                 "refs/heads", "refs/remotes").stdout
    refs = {}
    for line in output.splitlines():
        name, sha, symbolic = line.split("\t")
        if not symbolic:
            refs[name] = sha
    if git(repo, "symbolic-ref", "-q", "HEAD", check=False).returncode != 0:
        tip = git(repo, "rev-parse", "--verify", "HEAD", check=False)
        if tip.returncode == 0:
            refs["HEAD (detached)"] = tip.stdout.strip()
    return refs


def changed_files(repo, base, tip):
    if base is None:
        base = git(repo, "hash-object", "-t", "tree", "/dev/null").stdout.strip()
    raw = git(repo, "diff", "--no-ext-diff", "--no-textconv", "--no-renames",
              "--name-status", "-z", base, tip, "--").stdout.rstrip("\0")
    fields = raw.split("\0") if raw else []
    paths = [{"status": fields[i], "path": fields[i + 1]} for i in range(0, len(fields), 2)]
    stat = git(repo, "diff", "--no-ext-diff", "--no-textconv", "--shortstat", base, tip, "--").stdout.strip()
    return paths, stat


def comparison_base(repo, tip, earlier):
    candidates = []
    for old in set(earlier.values()):
        if has_commit(repo, old):
            result = git(repo, "merge-base", tip, old, check=False)
            if result.returncode == 0:
                sha = result.stdout.strip()
                distance = int(git(repo, "rev-list", "--count", sha + ".." + tip).stdout)
                candidates.append((distance, sha))
    return min(candidates)[1] if candidates else None


def collect_repo(repo, root, previous, offline, since):
    entry = {"path": repo.relative_to(root).as_posix(), "fetch": {}, "errors": []}
    remotes = git(repo, "remote").stdout.splitlines()
    for remote in remotes:
        if offline:
            entry["fetch"][remote] = {"status": "offline: freshness unknown"}
            continue
        try:
            result = git(repo, "fetch", "--prune", "--no-tags", "--no-recurse-submodules",
                         "--", remote, "+refs/heads/*:refs/remotes/" + remote + "/*", check=False)
            entry["fetch"][remote] = {"status": "ok" if result.returncode == 0 else "failed"}
            if result.returncode:
                entry["errors"].append("Fetch failed for " + remote + ": " + result.stderr.strip())
        except (RuntimeError, subprocess.TimeoutExpired) as error:
            entry["fetch"][remote] = {"status": "failed"}
            entry["errors"].append("Fetch failed for " + remote + ": " + str(error))
    entry["local_changes"] = bool(git(repo, "status", "--porcelain", "--untracked-files=all").stdout)
    entry["shallow_history"] = git(repo, "rev-parse", "--is-shallow-repository").stdout.strip() == "true"
    entry["remote_freshness"] = "unknown" if offline or entry["errors"] else "fetched" if remotes else "no remotes"
    refs = branch_refs(repo)
    old_refs = previous.get("refs", {}) if previous else {}
    entry["refs"] = refs
    entry["initial_review"] = previous is None
    entry["initial_since"] = since if previous is None else None
    entry["previous_report"] = previous.get("report") if previous else None
    valid_old = sorted({sha for sha in old_refs.values() if has_commit(repo, sha)})
    entry["missing_previous_objects"] = sorted(set(old_refs.values()) - set(valid_old))
    entry["branches"] = []
    commits = {}
    for name, tip in sorted(refs.items()):
        old = old_refs.get(name)
        branch = {"ref": name, "before": old, "after": tip}
        if old == tip:
            branch["status"] = "unchanged"
        elif old is None:
            branch["status"] = "initial" if previous is None else "new"
        elif old not in valid_old:
            branch["status"] = "previous object unavailable"
        else:
            branch["status"] = "advanced" if ancestor(repo, old, tip) else "rewritten"
        log_args = ["log", "--format=%H%x09%ct%x09%s", tip]
        if previous is None:
            log_args.append("--since-as-filter=" + since)
        if valid_old:
            log_args.extend(["--not", *valid_old])
        log_args.append("--")
        branch_commits = []
        for line in git(repo, *log_args).stdout.splitlines():
            sha, timestamp, subject = line.split("\t", 2)
            item = commits.setdefault(sha, {"sha": sha, "timestamp": int(timestamp), "subject": subject, "refs": []})
            item["refs"].append(name)
            branch_commits.append(sha)
        branch["new_commits"] = branch_commits
        base = old if old in valid_old else None
        available = branch["status"] != "previous object unavailable"
        if previous is None:
            # This is an orientation diff; commit-level reading is authoritative.
            if branch_commits:
                parent = git(repo, "rev-parse", branch_commits[-1] + "^", check=False)
                base = parent.stdout.strip() if parent.returncode == 0 else None
            else:
                base = tip
        elif old is None:
            base = comparison_base(repo, tip, old_refs)
        branch["diff_base"] = base
        branch["diff_available"] = available
        if available and branch["status"] != "unchanged":
            branch["files"], branch["diff_stat"] = changed_files(repo, base, tip)
        else:
            branch["files"], branch["diff_stat"] = [], ""
        entry["branches"].append(branch)
    for name, old in sorted(old_refs.items()):
        if name not in refs:
            entry["branches"].append({"ref": name, "before": old, "after": None, "status": "deleted"})
    entry["commits"] = sorted(commits.values(), key=lambda item: (-item["timestamp"], item["sha"]))
    return entry


def collect(args):
    root = args.root.resolve()
    workflow = root / "research/workflows/repo-overview"
    config = read_json(workflow / "config.json")
    if not config:
        raise ValueError("Missing workflow config.json")
    state = read_json(workflow / "state.json", {"version": 1, "repositories": {}})
    now = dt.datetime.now(dt.timezone.utc)
    since = (now - dt.timedelta(days=config["initial_days"])).isoformat()
    repos, skipped = discover(root, set(config["exclude_repositories"]))
    packet = {"version": 1, "root": str(root), "collected_at": now.isoformat(),
              "state_digest": digest(state), "offline": args.offline,
              "excluded": skipped, "repositories": [], "missing_repositories": []}
    for repo in repos:
        relative = repo.relative_to(root).as_posix()
        print("Collecting " + relative, file=sys.stderr, flush=True)
        try:
            entry = collect_repo(repo, root, state["repositories"].get(relative), args.offline, since)
        except (RuntimeError, subprocess.TimeoutExpired) as error:
            entry = {"path": relative, "errors": [str(error)]}
        packet["repositories"].append(entry)
    found = {entry["path"] for entry in packet["repositories"]}
    packet["missing_repositories"] = sorted(set(state["repositories"]) - found - set(skipped))
    failed = any(entry["errors"] for entry in packet["repositories"])
    if not any(entry.get("commits") for entry in packet["repositories"]):
        # Return coverage and failures without creating an updates directory.
        # Keep checkpoints unchanged: collection alone is not a review.
        packet["status"] = "collection_incomplete" if failed else "no_new_commits"
        packet["packet_path"] = None
        for entry in packet["repositories"]:
            for branch in entry.get("branches", []):
                branch.pop("files", None)
                branch.pop("diff_stat", None)
        print(json.dumps(packet, ensure_ascii=True))
        return 1 if failed else 0
    run = now.strftime("%Y-%m-%dT%H%M%SZ") + "-" + uuid.uuid4().hex[:6]
    output = root / "research/updates" / run / "packet.json"
    write_json(output, packet)
    print(output)
    return 1 if failed else 0


def complete(args):
    root = args.root.resolve()
    packet_path = args.packet.resolve()
    report = args.report.resolve()
    if not report.is_file() or not report.read_text().strip():
        raise ValueError("Save a non-empty review report before completing")
    report_relative = report.relative_to(root).as_posix()
    packet = read_json(packet_path)
    if packet["root"] != str(root):
        raise ValueError("Packet belongs to a different project root")
    entries = {entry["path"]: entry for entry in packet["repositories"]}
    selected = set(args.repo)
    if selected - entries.keys():
        raise ValueError("Selected repository is absent from packet")
    for name in selected:
        if entries[name]["errors"] or "refs" not in entries[name]:
            raise ValueError("Cannot complete failed collection: " + name)
    workflow = root / "research/workflows/repo-overview"
    with (workflow / ".state.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        state_path = workflow / "state.json"
        state = read_json(state_path, {"version": 1, "repositories": {}})
        if digest(state) != packet["state_digest"]:
            raise ValueError("Checkpoint changed since collection; collect again")
        for name in selected:
            state["repositories"][name] = {
                "refs": entries[name]["refs"], "report": report_relative,
                "collected_at": packet["collected_at"], "remote_freshness": entries[name]["remote_freshness"],
            }
        write_json(state_path, state)
    print("Completed: " + ", ".join(sorted(selected)))
    return 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=DEFAULT_ROOT)
    commands = parser.add_subparsers(dest="command", required=True)
    collect_parser = commands.add_parser("collect", help="Fetch branches and write evidence")
    collect_parser.add_argument("--offline", action="store_true")
    complete_parser = commands.add_parser("complete", help="Acknowledge a saved review")
    complete_parser.add_argument("--packet", type=Path, required=True)
    complete_parser.add_argument("--report", type=Path, required=True)
    complete_parser.add_argument("--repo", action="append", required=True)
    args = parser.parse_args()
    try:
        return collect(args) if args.command == "collect" else complete(args)
    except (ValueError, OSError, RuntimeError, subprocess.TimeoutExpired) as error:
        print("Error: " + str(error), file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
