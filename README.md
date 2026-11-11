# Evaluation harnesses and prototypes

This repository develops and compares harnesses for evaluating AI agents, alongside related runtime and monitoring prototypes. It supports WP2 of Agentic-seL4: exploring how trusted runtimes can constrain untrusted agents while allowing them to complete useful tasks.

The work covers tool access, isolation, policy enforcement and prompt-injection scenarios. Experiments consider both security outcomes and legitimate task completion. seL4 and Microkit are candidate foundations alongside Linux, containers and other approaches.

## Repository contents

- [experiments/](experiments/): evaluation harnesses, runtime prototypes and their setup and run instructions.
- [notes/](notes/): architecture studies, feasibility assessments and research discussions.
- [papers/](papers/): paper reading notes and comparisons.
- [updates/](updates/): reviews of related repository changes.
- [workflows/](workflows/): supporting research workflows.

See the [research index](index.md) for current progress and the [project context](project-context.md) for background. Each experiment has its own instructions and evidence; these are research prototypes with results limited to the cases tested.
