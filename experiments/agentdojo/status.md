# Container status

2026-10-28. Source revision: `089ed468cf3ed0322acc66b0211f26d9d90dbf60`. Container setup complete; model runs await the user's next instruction.

## Build and runtime

- Started the existing Colima VM with `colima start --activate=false`. The active Docker context was not changed.
- Exported selected files from the pinned Git revision using `python3 research/experiments/agentdojo/prepare_build.py`.
- Built with `docker --context colima compose -f research/experiments/agentdojo/compose.yaml build`: exit 0. uv installed 163 packages from the lockfile and built AgentDojo.
- Started with the same Compose prefix and `up -d`: exit 0. Container `agentdojo-examples-agentdojo-1` is left running, idle.
- Image: `agentic-sel4/agentdojo:089ed468`, ID `sha256:a7d3fbf8bdd42917deef457ff1cf951df3ead2fe96c41bced7ea69a5485a1b7a`, ARM64, 1,536,991,002 bytes.
- Python 3.12.15; runtime UID 1000. Runtime networking disabled; no API keys supplied. Results-mount write succeeded.
- Initial build preparation was slow with the workspace-wide context. Retried successfully with a small pinned-source export. Buildx is absent; the classic Docker builder succeeded.

## Checks

All commands use the Compose prefix above followed by `exec -T agentdojo`.

| Command | Result |
|---|---|
| `python -m agentdojo.scripts.benchmark --help` | Exit 0; CLI and suite imports load. |
| `python -m pytest tests/test_functions_runtime/test_functions_runtime.py -q -p no:cacheprovider` | Exit 0; 10 passed in 0.15 s. |
| `python -m agentdojo.scripts.check_suites -s banking --benchmark-version v1.2.2` | Exit 0, but printed injection-detection failures for all 16 user tasks; all 9 injection-task references passed. |
| `python -` with the [setup check](check_setup.py) on standard input | 16 user-task and 9 injection-task reference predicates passed; actual direct-attack placement reached the bill text for user task 0 / injection task 7. Non-root runtime and results mount verified. |

Raw outputs are stored locally under `results/` and ignored by Git. The setup check was first run as inline Python, then saved for repeatable use. See the [guide](README.md) for full commands.

## Upstream issue and limits

`agentdojo/src/agentdojo/task_suite/task_suite.py:is_task_injectable` accepts only string tool content, while `GroundTruthPipeline` emits lists of content blocks. Thus the general injection detector sees no text. The actual `BaseAttack.get_injection_candidates` path handles content blocks; it succeeded in the separate setup check.

No upstream files were changed. No model calls, attack-success measurements or defence evaluations were performed. Reference checks exercise predefined scripts and predicates; they do not establish model behaviour or complete scoring correctness. Base image tags are not digest-pinned.
