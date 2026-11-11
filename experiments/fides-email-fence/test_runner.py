"""Real-middleware integration checks and negative acceptance controls."""

import asyncio
from contextlib import ExitStack, redirect_stdout, redirect_stderr
from copy import deepcopy
import io
import json
from pathlib import Path
import socket
import tempfile
import unittest
from unittest.mock import patch

import runner


class PrototypeTests(unittest.TestCase):
    def setUp(self):
        # Fail any network attempt during the exercise, including DNS.
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        for name in ("connect", "connect_ex"):
            self.stack.enter_context(patch.object(socket.socket, name, side_effect=AssertionError("Network attempted")))
        self.stack.enter_context(patch("socket.getaddrinfo", side_effect=AssertionError("DNS attempted")))

    def run_case(self, **kwargs):
        return asyncio.run(runner.run_scenario(runner.Scenario(**kwargs)))

    def test_matrix_through_real_middleware_without_network(self):
        for scenario in runner.matrix_scenarios():
            with self.subTest(scenario=scenario):
                report = asyncio.run(runner.run_scenario(scenario))
                self.assertTrue(report["checks_passed"])

    def test_same_proposal_and_summary_under_both_policies(self):
        opened = self.run_case(policy="open")
        fenced = self.run_case(policy="fenced")
        for report in (opened, fenced):
            self.assertEqual(
                next(e["arguments"] for e in report["analyst_trace"] if e.get("tool") == "fetch"),
                {"payload": "Data 1"},
            )
        self.assertEqual(opened["summary"], fenced["summary"])
        self.assertEqual(len(opened["sink_effects"]), 1)
        self.assertEqual(fenced["sink_effects"], [])

    def test_acceptance_rejects_disabled_enforcement(self):
        original = runner.SecureAgentConfig
        def disabled(**kwargs):
            return original(**{**kwargs, "enable_policy_enforcement": False})
        with patch.object(runner, "SecureAgentConfig", disabled):
            with self.assertRaisesRegex(AssertionError, "unexpected sink effect"):
                self.run_case()

    def test_acceptance_rejects_missing_attempt_and_incomplete_workflow(self):
        original = self.run_case()
        missing = deepcopy(original)
        missing["analyst_trace"] = [
            e for e in missing["analyst_trace"] if not (e["event"] == "proposal" and e["tool"] == "fetch")
        ]
        with self.assertRaisesRegex(AssertionError, "missing or extra proposal"):
            runner.check_report(missing)
        incomplete = deepcopy(original)
        incomplete["completed"] = False
        with self.assertRaisesRegex(AssertionError, "workflow incomplete"):
            runner.check_report(incomplete)

    def test_cli_json_and_invalid_arguments(self):
        with tempfile.TemporaryDirectory() as tmp, redirect_stdout(io.StringIO()):
            output = Path(tmp) / "report.json"
            self.assertEqual(runner.main(["--output", str(output)]), 0)
            report = json.loads(output.read_text())
            self.assertEqual(report["environment"]["agent-framework-core"], "1.24.0")
            self.assertTrue(report["runs"][0]["checks_passed"])
        with redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as caught:
            runner.main(["--secret", "2"])
        self.assertEqual(caught.exception.code, 2)

    def test_early_stop_is_failure(self):
        async def stop(self, **kwargs):
            return runner.ChatResponse(messages=[runner.Message("assistant", ["stopped"])])
        with patch.object(runner.ScriptedClient, "_inner_get_response", stop):
            with self.assertRaisesRegex(RuntimeError, "Unexpected early termination"):
                self.run_case()


if __name__ == "__main__":
    unittest.main()
