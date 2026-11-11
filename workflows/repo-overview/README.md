# Repository overview

Agreed on 2026-10-23: review project repositories for WP2, including non-main
branches. Exclude AgentDojo and SandboxEscapeBench from the overview. Include new
repositories automatically. Keep routine proof detail brief.

## Implementation plan

All four steps implemented and checked on 2026-10-23.

1. Collect changes from every configured remote branch and local branch without
   switching branches. Fetch explicit branch refspecs, including for narrow clones.
2. Save branch tips, commit evidence and changed paths in a dated packet. Compare
   against the last completed review; identify new, deleted and rewritten branches.
3. Use the project skill to inspect relevant diffs and write a concise WP2 report.
4. Advance checkpoints only for explicitly completed repositories after saving
   the report. Test branch handling and failure recovery with temporary repositories.

## Run

From the project root, ask Codex:

> Use $project-repo-overview to update the repositories and review changes since
> the last completed overview, including non-main branches.

The [project skill](../../../.agents/skills/project-repo-overview/SKILL.md) defines
the review procedure.
The Python helper uses Python 3.9+ and Git 2.37+ on macOS/Linux; no package
installation is needed. Its commands are:

```sh
# Optional: update clean working branches with the existing pull script.
bash pull-clean-repos.sh

# Fetch all remote branches and collect evidence; does not alter working files.
python3 research/workflows/repo-overview/overview.py collect

# Use cached refs when offline; the packet records that freshness is unknown.
python3 research/workflows/repo-overview/overview.py collect --offline

# After writing a report, acknowledge only repositories fully covered by it.
python3 research/workflows/repo-overview/overview.py complete \
  --packet research/updates/RUN/packet.json \
  --report research/updates/RUN/overview.md \
  --repo notes --repo prompt-injection-RS

python3 research/workflows/repo-overview/test_overview.py
```

`collect` creates a packet and prints its path only if at least one included
repository has new commits under the comparison rules below. Such runs have a
unique UTC directory under `research/updates/`. With no new commits it prints a
JSON status (`no_new_commits`, or `collection_incomplete` on failure), with branch
coverage and errors, and creates no update files or directories. Report this
status in the chat; do not create a report, update the index or run `complete`.
Local branches catching up, branch deletions, rewinds and new refs pointing only
to previously reviewed commits do not by themselves create files. Offline status
does not establish remote freshness; failed collections still exit non-zero.

`state.json` stores the last reviewed branch tips, with a
reference to the report. Do not edit state manually during a run. `complete`
rejects empty reports, failed collections and stale packets, and writes state
atomically. Collecting alone never advances state, including no-new-commit runs.
Consequently branch-only changes can be reported again until a later commit-bearing
review records them. A new repository with no commits in its initial window stays
without a checkpoint until a review is needed. Existing reports are preserved.

## Coverage and interpretation

- Discovery walks below the project root, including nested repositories and Git
  worktrees. It skips `.git`, symlink directories and excluded repository trees.
  Edit `config.json` to change exclusions or the initial window.
- Fetch every configured remote with an explicit all-heads refspec and pruning.
  No branch checkout, merge, reset, build or proof command is needed. Fetch failures
  remain visible and prevent that repository's checkpoint from advancing.
- Track local and remote branches, and detached HEAD when present. Remote `HEAD`
  aliases are omitted. Local changes are reported but not included in commit diffs.
- Existing branches compare against their own saved tips. A repository's commit
  list is deduplicated across branches and excludes commits reachable from any
  previously reviewed tip. Branch diffs can therefore overlap an earlier report.
- A newly discovered repository gets orientation plus commits from the previous
  seven days. Older history is explicitly outside that first review. Its first
  checkpoint establishes a baseline at the collected tips.
- A new branch in an existing repository includes all commits not reachable from
  earlier reviewed tips, regardless of date. Its file comparison uses a common
  ancestor with the previous tips where available. An unrelated branch is compared
  with an empty tree. This can be a large review; defer it rather than silently
  advancing the checkpoint.
- Rewritten branches show a tree diff and newly reachable commits. If an earlier
  object is missing, the comparison is marked unavailable; review the current
  branch explicitly before acknowledging a fresh baseline.
- Offline runs may checkpoint cached, reviewed refs, but must label remote
  freshness unknown. Missing repositories remain in state and are reported.
- Shallow clones are labelled in the packet; their history may be incomplete.
  State that limitation in the report and defer a checkpoint if needed evidence
  is missing. The collector does not automatically deepen clones.
- This reviews fetched branches of configured remotes. Unconfigured forks, remote
  pull-request refs and uncommitted work are outside coverage.

## Report

Aim for a short briefing: relevant WP2 changes and implications; other changes;
up to three suggested readings; coverage and limitations. Cite branch names,
commit IDs and file locations. Distinguish proposals, implemented changes,
source-reported results and independent checks. Record inspected and unread areas.

Summarise routine Isabelle/HOL proof maintenance in a line. Give plain-language
attention to changed assumptions, definitions, counterexamples and interfaces
that affect runtime enforcement or evaluation. Do not claim proofs were checked.

The collector supplies evidence, not an automatic research summary. The skill
performs the reading and writes the report. Update `research/index.md` with each
saved report; update older research conclusions only when the evidence warrants it.

## Validation, 2026-10-23

- `python3 research/workflows/repo-overview/test_overview.py`: eight tests passed
  with Python 3.14.7 and Git 2.39.5. Covers narrow clones, all remotes, branch
  rewrites/deletions, old commit dates, deduplication, dirty worktrees, discovery,
  offline mode, failed fetches and checkpoint protection.
- Skill validator: passed using `uv --cache-dir /tmp/repo-overview-uv-cache run
  --no-project --with pyyaml python
  /Users/mt0062/.codex/skills/.system/skill-creator/scripts/quick_validate.py
  .agents/skills/project-repo-overview`. PyYAML was needed only by this validator.
- `python3 research/workflows/repo-overview/overview.py collect`: live fetch
  succeeded for five repositories, including the newly added
  `prototype-agentic-monitoring`. Both excluded repositories were omitted.
  [Evidence packet](../../updates/2026-10-23T120540Z-8d08de/packet.json).
  The first sandboxed attempt could not resolve GitHub; the authorised retry
  succeeded. The later date-filter refinement was checked in the isolated tests.
- No research report or review checkpoint was created. Working branches were not
  pulled or switched. These are workflow checks, not verification of source claims.

Initial collector SHA-256 (before the output-rule change below):
`bf699456d7f2d040771ebcb640f914a59217418e123f5f139cb50eb4e7d46a99`.

### Output-rule update, 23 October 2026

Update files now require new commits. Re-ran
`python3 research/workflows/repo-overview/test_overview.py`: nine tests passed,
including no-file collections and continued packet creation for new commits.
The skill validator passed with the cached PyYAML dependency. An offline collection
against this project returned `no_new_commits`; the update directory's entries and
modification times, and the checkpoint bytes, were unchanged. This offline check
does not establish current remote freshness.
