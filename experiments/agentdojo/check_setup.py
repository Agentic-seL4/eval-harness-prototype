"""Check reference tasks and attack placement without a model or upstream edits."""

import os
import platform

from agentdojo.task_suite import get_suite
from agentdojo.agent_pipeline.ground_truth_pipeline import GroundTruthPipeline
from agentdojo.attacks.baseline_attacks import DirectAttack

suite = get_suite("v1.2.2", "banking")
passed, (users, injections) = suite.check(check_injectable=False)
assert passed, (users, injections)
print(f"Reference predicates: {len(users)} user tasks and {len(injections)} injection tasks passed.")
user = suite.get_user_task_by_id("user_task_0")
goal = suite.get_injection_task_by_id("injection_task_7")
payload = DirectAttack(suite, GroundTruthPipeline(user)).attack(user, goal)
assert "injection_bill_text" in payload, payload.keys()
assert goal.GOAL in payload["injection_bill_text"]
print("Direct attack placement: user_task_0 / injection_task_7 reaches injection_bill_text.")
assert os.geteuid() != 0
print(f"Runtime: Python {platform.python_version()}, {platform.machine()}, uid={os.geteuid()}.")
with open("/results/mount-check.txt", "w") as output:
    output.write("Container can write to the results mount.\n")
print("Results mount: write passed.")
