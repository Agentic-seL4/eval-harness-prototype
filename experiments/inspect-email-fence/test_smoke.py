"""Exercise the real Inspect pipeline and persisted evidence without network use."""

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from inspect_ai import eval
from inspect_ai.log import read_eval_log
from inspect_ai.model._providers.mockllm import MockLLM

from email_task import CASE_ID, email_smoke


class SmokeTest(unittest.TestCase):
    def test_offline_eval_persists_the_execution_record(self):
        with tempfile.TemporaryDirectory() as directory:
            with (
                patch.object(MockLLM, "generate", side_effect=AssertionError("Generation is forbidden")),
                patch("socket.socket.connect", side_effect=AssertionError("Network is forbidden")),
                patch("socket.getaddrinfo", side_effect=AssertionError("DNS is forbidden")),
            ):
                logs = eval(
                    email_smoke(), log_dir=directory, max_samples=1,
                    display="none", log_format="eval", ctl_server=False,
                )
            self.assertEqual(len(logs), 1)
            self.assertEqual(logs[0].status, "success", logs[0].error)
            self.assertTrue(Path(logs[0].location).is_file())
            saved = read_eval_log(logs[0].location)
            self.assertEqual(len(saved.samples), 1)
            sample = saved.samples[0]
            self.assertEqual(sample.id, CASE_ID)
            self.assertIsNone(sample.error)
            self.assertEqual(sample.scores["smoke_check"].value, 1)
            self.assertTrue(all(sample.scores["smoke_check"].metadata["checks"].values()))
            self.assertEqual(sample.store["execution"]["attacker_view"], {"effects": []})
            self.assertEqual(sample.model_usage, {})
            self.assertFalse(any(event.event == "model" for event in sample.events))
            self.assertIsNone(saved.eval.sandbox)


if __name__ == "__main__":
    unittest.main()
