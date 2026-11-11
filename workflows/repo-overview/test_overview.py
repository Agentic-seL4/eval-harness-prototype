#!/usr/bin/env python3
"""Behaviour checks using isolated Git repositories; no network access."""

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


SCRIPT = Path(__file__).with_name("overview.py")


class WorkflowTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="repo-overview-test-")
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.root = self.base / "project"
        self.workflow = self.root / "research/workflows/repo-overview"
        self.workflow.mkdir(parents=True)
        (self.workflow / "config.json").write_text(json.dumps({
            "exclude_repositories": ["agentdojo", "sandbox_escape_bench", "sandbox-escape_bench"],
            "initial_days": 7,
        }))
        self.env = dict(os.environ, GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL="/dev/null",
                        GIT_AUTHOR_NAME="Test", GIT_AUTHOR_EMAIL="test@example.invalid",
                        GIT_COMMITTER_NAME="Test", GIT_COMMITTER_EMAIL="test@example.invalid")
        self.remote = self.base / "remote.git"
        self.seed = self.base / "seed"
        self.repo = self.root / "notes"
        self.run_cmd("git", "init", "--bare", "--initial-branch=main", str(self.remote))
        self.run_cmd("git", "init", "--initial-branch=main", str(self.seed))
        old_history = self._testMethodName == "test_empty_initial_collection_creates_no_updates_directory"
        self.commit("base.txt", "base", old_date=old_history)
        self.base_sha = self.git(self.seed, "rev-parse", "HEAD").stdout.strip()
        self.git(self.seed, "remote", "add", "origin", str(self.remote))
        self.git(self.seed, "checkout", "-b", "topic")
        self.commit("policy.txt", "topic policy", old_date=old_history)
        self.topic_sha = self.git(self.seed, "rev-parse", "HEAD").stdout.strip()
        self.git(self.seed, "checkout", "main")
        self.git(self.seed, "push", "origin", "--all")
        self.run_cmd("git", "clone", "--single-branch", "--branch", "main", str(self.remote), str(self.repo))

    def run_cmd(self, *args, check=True, env=None):
        result = subprocess.run(args, capture_output=True, text=True, env=env or self.env)
        if check:
            self.assertEqual(result.returncode, 0, result.stderr)
        return result

    def git(self, repo, *args, **kwargs):
        return self.run_cmd("git", "-C", str(repo), *args, **kwargs)

    def commit(self, path, content, old_date=False):
        (self.seed / path).write_text(content)
        self.git(self.seed, "add", "--", path)
        env = self.env
        if old_date:
            env = dict(env, GIT_AUTHOR_DATE="2001-01-01T12:00:00Z", GIT_COMMITTER_DATE="2001-01-01T12:00:00Z")
        self.git(self.seed, "commit", "-m", content, env=env)

    def collect(self, offline=False, success=True):
        args = [sys.executable, str(SCRIPT), "--root", str(self.root), "collect"]
        if offline:
            args.append("--offline")
        result = self.run_cmd(*args, check=success)
        if not success:
            self.assertNotEqual(result.returncode, 0)
        if result.stdout.startswith("{"):
            return None, json.loads(result.stdout)
        path = Path(result.stdout.strip())
        return path, json.loads(path.read_text())

    def finish(self, packet_path, success=True, report=True):
        report_path = packet_path.with_name("overview.md")
        if report:
            report_path.write_text("Reviewed notes and all branch changes in this test.\n")
        result = self.run_cmd(sys.executable, str(SCRIPT), "--root", str(self.root), "complete",
                              "--packet", str(packet_path), "--report", str(report_path),
                              "--repo", "notes", check=success)
        if not success:
            self.assertNotEqual(result.returncode, 0)
        return result

    def test_fetches_non_main_in_narrow_clone_and_preserves_worktree(self):
        (self.repo / "base.txt").write_text("local work")
        path, packet = self.collect()
        entry = packet["repositories"][0]
        self.assertEqual(entry["refs"]["refs/remotes/origin/topic"], self.topic_sha)
        self.assertTrue(entry["local_changes"])
        self.assertEqual((self.repo / "base.txt").read_text(), "local work")
        self.assertEqual(self.git(self.repo, "branch", "--show-current").stdout.strip(), "main")
        self.assertNotIn("refs/remotes/origin/HEAD", entry["refs"])
        self.assertFalse((self.workflow / "state.json").exists())
        self.finish(path)
        before = set((self.root / "research/updates").rglob("*"))
        state = (self.workflow / "state.json").read_bytes()
        second_path, second = self.collect()
        self.assertIsNone(second_path)
        self.assertEqual(second["status"], "no_new_commits")
        self.assertEqual(set((self.root / "research/updates").rglob("*")), before)
        self.assertEqual((self.workflow / "state.json").read_bytes(), state)
        self.assertEqual(second["repositories"][0]["commits"], [])
        self.assertTrue(all(b["status"] == "unchanged" for b in second["repositories"][0]["branches"]))

    def test_new_old_dated_branch_and_shared_commits(self):
        first, _ = self.collect()
        self.finish(first)
        self.git(self.seed, "checkout", "-b", "old-feature")
        self.commit("runtime.txt", "old dated runtime change", old_date=True)
        sha = self.git(self.seed, "rev-parse", "HEAD").stdout.strip()
        self.git(self.seed, "branch", "same-change")
        self.git(self.seed, "push", "origin", "--all")
        _, packet = self.collect()
        entry = packet["repositories"][0]
        self.assertEqual([c["sha"] for c in entry["commits"]], [sha])
        self.assertEqual(len(entry["commits"][0]["refs"]), 2)
        branches = {b["ref"]: b for b in entry["branches"]}
        self.assertEqual(branches["refs/remotes/origin/old-feature"]["status"], "new")
        self.assertEqual(branches["refs/remotes/origin/old-feature"]["diff_base"], self.base_sha)

    def test_rewrite_deletion_and_merge_deduplication(self):
        first, _ = self.collect()
        self.finish(first)
        self.git(self.seed, "merge", "--ff-only", "topic")
        self.git(self.seed, "branch", "rewritten", self.base_sha)
        self.git(self.seed, "push", "origin", "main", "rewritten")
        second, packet = self.collect()
        self.assertIsNone(second)
        self.assertEqual(packet["repositories"][0]["commits"], [])
        self.git(self.seed, "push", "--force", "origin", self.base_sha + ":topic")
        # Permit deletion of the bare test remote's default branch.
        self.git(self.remote, "config", "receive.denyDeleteCurrent", "ignore")
        self.git(self.seed, "push", "origin", "--delete", "main")
        _, packet = self.collect()
        branches = {b["ref"]: b for b in packet["repositories"][0]["branches"]}
        self.assertEqual(branches["refs/remotes/origin/topic"]["status"], "rewritten")
        self.assertEqual(branches["refs/remotes/origin/main"]["status"], "deleted")

    def test_failures_and_missing_reports_do_not_advance_state(self):
        first, _ = self.collect()
        self.finish(first, success=False, report=False)
        self.assertFalse((self.workflow / "state.json").exists())
        self.finish(first)
        saved = (self.workflow / "state.json").read_bytes()
        self.git(self.repo, "remote", "set-url", "origin", str(self.base / "absent.git"))
        failed, packet = self.collect(success=False)
        self.assertIsNone(failed)
        self.assertEqual(packet["status"], "collection_incomplete")
        self.assertTrue(packet["repositories"][0]["errors"])
        self.assertEqual((self.workflow / "state.json").read_bytes(), saved)
        # If a cached/local new commit exists, retain an evidence packet, but
        # still refuse to acknowledge the repository whose fetch failed.
        (self.repo / "new.txt").write_text("unreviewed")
        self.git(self.repo, "add", "new.txt")
        self.git(self.repo, "commit", "-m", "new local work")
        failed, _ = self.collect(success=False)
        self.assertIsNotNone(failed)
        self.finish(failed, success=False)
        self.assertEqual((self.workflow / "state.json").read_bytes(), saved)

    def test_empty_initial_collection_creates_no_updates_directory(self):
        # A new checkout with no commits in its initial window needs no files.
        packet_path, result = self.collect()
        self.assertIsNone(packet_path)
        self.assertEqual(result["status"], "no_new_commits")
        self.assertFalse((self.root / "research/updates").exists())
        self.assertFalse((self.workflow / "state.json").exists())

    def test_stale_packet_rejected_and_snapshot_not_current_head_saved(self):
        first, packet = self.collect()
        second, _ = self.collect()
        self.git(self.repo, "branch", "unreviewed")
        self.finish(first)
        state = json.loads((self.workflow / "state.json").read_text())
        self.assertEqual(state["repositories"]["notes"]["refs"], packet["repositories"][0]["refs"])
        self.finish(second, success=False)

    def test_discovery_exclusions_nested_repos_and_worktrees(self):
        for name in ["agentdojo", "sandbox_escape_bench", "sandbox-escape_bench", "new/repository"]:
            path = self.root / name
            path.mkdir(parents=True)
            self.run_cmd("git", "init", "--initial-branch=main", str(path))
        self.git(self.repo, "worktree", "add", "-b", "worktree-branch", str(self.root / "worktree"))
        _, packet = self.collect(offline=True)
        self.assertEqual({r["path"] for r in packet["repositories"]}, {"notes", "new/repository", "worktree"})
        self.assertEqual(set(packet["excluded"]), {"agentdojo", "sandbox_escape_bench", "sandbox-escape_bench"})
        entry = next(r for r in packet["repositories"] if r["path"] == "notes")
        self.assertEqual(entry["remote_freshness"], "unknown")

    def test_all_configured_remotes_and_detached_head(self):
        self.git(self.repo, "remote", "add", "upstream", str(self.remote))
        self.git(self.repo, "checkout", "--detach")
        _, packet = self.collect()
        entry = packet["repositories"][0]
        self.assertEqual(set(entry["fetch"]), {"origin", "upstream"})
        self.assertEqual(entry["refs"]["refs/remotes/upstream/topic"], self.topic_sha)
        self.assertEqual(entry["refs"]["HEAD (detached)"], self.base_sha)

    def test_initial_window_walks_past_old_dated_tip(self):
        self.git(self.seed, "checkout", "topic")
        self.commit("old.txt", "old dated tip", old_date=True)
        old_tip = self.git(self.seed, "rev-parse", "HEAD").stdout.strip()
        self.git(self.seed, "push", "origin", "topic")
        _, packet = self.collect()
        entry = packet["repositories"][0]
        branch = next(b for b in entry["branches"] if b["ref"] == "refs/remotes/origin/topic")
        self.assertIn(self.topic_sha, branch["new_commits"])
        self.assertNotIn(old_tip, branch["new_commits"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
