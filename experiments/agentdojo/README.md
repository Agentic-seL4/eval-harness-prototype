# AgentDojo container: first step

Scope: build the harness and check it without model calls. Later examples require a separate continuation. No API credentials are configured. Runtime networking is disabled; model runs will require a deliberate configuration change.

The whole Python harness, tools and simulated state run inside one container. This packages AgentDojo; it does not create a container-escape benchmark.

Source: workspace `agentdojo/`, revision `089ed468cf3ed0322acc66b0211f26d9d90dbf60`. Dependencies come from its lockfile, including the development group for pytest. Python and uv image tags are specified; base images are not digest-pinned, so this is not a fully immutable build. See [status](status.md) for actual execution evidence.

## Build and start

Commands run from the workspace root. This machine uses Colima. For another Docker backend, omit `--context colima`.

```bash
colima start --activate=false
python3 research/experiments/agentdojo/prepare_build.py
docker --context colima compose -f research/experiments/agentdojo/compose.yaml config --quiet
docker --context colima compose -f research/experiments/agentdojo/compose.yaml build
docker --context colima compose -f research/experiments/agentdojo/compose.yaml up -d
```

The preparation script exports selected tracked files from the pinned Git revision into an ignored `.build-context/`. It excludes uncommitted changes, credentials, existing runs and the checkout's Git directory. The runtime has a read-only filesystem, a temporary directory and a writable `/results` mount. It runs as a non-root user, without a Docker socket or published ports.

## Check without a model

```bash
docker --context colima compose -f research/experiments/agentdojo/compose.yaml exec -T agentdojo python -m agentdojo.scripts.benchmark --help
docker --context colima compose -f research/experiments/agentdojo/compose.yaml exec -T agentdojo python -m pytest tests/test_functions_runtime/test_functions_runtime.py -q -p no:cacheprovider
docker --context colima compose -f research/experiments/agentdojo/compose.yaml exec -T agentdojo python -m agentdojo.scripts.check_suites -s banking --benchmark-version v1.2.2
```

The upstream suite checker currently reports all user tasks as non-injectable despite exit code 0. Its `is_task_injectable()` filters out structured content blocks. This is recorded in [status](status.md); upstream code is unchanged. Run the separate setup check to validate reference predicates and actual direct-attack placement:

```bash
docker --context colima compose -f research/experiments/agentdojo/compose.yaml exec -T agentdojo python - < research/experiments/agentdojo/check_setup.py
```

This skips only the faulty general injection check, then independently verifies the planned bill injection through the actual attack class. It checks neither a model response nor all possible injection paths. These checks do not establish agent robustness or reproduce paper results.

## Inspect or stop

```bash
docker --context colima compose -f research/experiments/agentdojo/compose.yaml ps
docker --context colima compose -f research/experiments/agentdojo/compose.yaml exec agentdojo bash
docker --context colima compose -f research/experiments/agentdojo/compose.yaml down
```

Stopping the Compose service leaves the image and saved results available. Do not run model examples until the next step is agreed.

References: [architecture note](../../notes/agentdojo-architecture.md), [upstream dependencies](../../../agentdojo/pyproject.toml), [uv Docker guide](https://docs.astral.sh/uv/guides/integration/docker/).
