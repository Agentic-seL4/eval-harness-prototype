"""Exercise the actual C executor, its ordering, failure paths and Inspect logs."""

import copy
import hashlib
import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from inspect_ai.log import read_eval_log

from c_backend import CMonitor, PROTOTYPE, SOURCES, compare_traces, compiled_monitor, replay_c
from cases import configurations
from email_task import email_engine, email_matrix
from test_matrix import offline_eval


def trace(run):
    return json.loads(json.dumps(run.to_dict()))


class CExecutorTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.build = compiled_monitor()
        cls.library, cls.defines, cls.provenance = cls.build.__enter__()
        cls.addClassCleanup(cls.build.__exit__, None, None, None)
        cls.engine = email_engine()

    def monitor(self, config):
        return CMonitor(self.library, self.defines, config)

    def test_all_16_traces_match_without_python_monitor_or_replay(self):
        for name, values in configurations().items():
            with self.subTest(case=name):
                config = self.engine.Config(**values)
                reference = trace(self.engine.replay(config))
                with (
                    patch.object(self.engine, "replay", side_effect=AssertionError("Python replay forbidden")),
                    patch.object(self.engine.Monitor, "mdecide", side_effect=AssertionError("Python decision forbidden")),
                    patch.object(self.engine.Monitor, "mnext", side_effect=AssertionError("Python update forbidden")),
                ):
                    actual = trace(replay_c(self.engine, config, self.monitor(config)))
                self.assertTrue(compare_traces(reference, actual)["agrees"])

    def test_fence_is_committed_before_email_delivery(self):
        config = self.engine.Config(policy="fenced", secret=1)
        monitor = self.monitor(config)
        original_receive = self.engine.receive
        deliveries = []

        def receive(proposed, decision):
            if proposed.pending is not None:
                deliveries.append(monitor.names(monitor.caps))
                self.assertEqual(monitor.names(monitor.caps), ["Inbox"])
                self.assertEqual(proposed.context, ())
            return original_receive(proposed, decision)

        with patch.object(self.engine, "receive", side_effect=receive):
            run = replay_c(self.engine, config, monitor)
        self.assertEqual(deliveries, [["Inbox"]])
        self.assertEqual(run.effects, [])
        self.assertTrue(run.completed)

    def test_late_dispatch_precedes_final_revocation(self):
        config = self.engine.Config(policy="late", secret=1)
        monitor = self.monitor(config)
        sink = self.engine.FakeTools()
        dispatch = sink.dispatch

        def observe(call):
            self.assertIn("Fetch", monitor.names(monitor.caps))
            dispatch(call)

        with patch.object(sink, "dispatch", side_effect=observe) as calls:
            run = replay_c(self.engine, config, monitor, sink)
        self.assertEqual(calls.call_count, 1)
        self.assertEqual(run.effects, [self.engine.Call("Fetch", ("Data 1",))])
        self.assertEqual(monitor.names(monitor.caps), ["Inbox"])
        self.assertEqual(run.steps[2].before["permissions"], ["Fetch", "Inbox"])
        self.assertEqual(run.steps[2].after["permissions"], ["Inbox"])

    def test_executor_obeys_changed_native_decision_and_comparison_detects_it(self):
        config = self.engine.Config(policy="open", secret=1)
        monitor = self.monitor(config)
        native_step = monitor.step

        def altered_step(event, context_before):
            result = native_step(event, context_before)
            if event.kind == "ACall":
                result.decision = self.defines["R_DENIED"]
            return result

        with patch.object(monitor, "step", side_effect=altered_step):
            actual = trace(replay_c(self.engine, config, monitor))
        self.assertEqual(actual["effects"], [])
        comparison = compare_traces(trace(self.engine.replay(config)), actual)
        self.assertFalse(comparison["agrees"])
        self.assertFalse(comparison["checks"]["effects"])
        self.assertFalse(comparison["checks"]["steps"])

    def test_comparison_excludes_only_explanatory_operations(self):
        run = trace(self.engine.replay(self.engine.Config(secret=1)))
        changed = copy.deepcopy(run)
        changed["steps"][1]["operations"] = ["Different backend explanation"]
        self.assertTrue(compare_traces(run, changed)["agrees"])
        changed["steps"][1]["admission_permissions"] = ["Fetch", "Inbox"]
        self.assertFalse(compare_traces(run, changed)["agrees"])

    def test_provenance_hashes_identify_the_compiled_sources(self):
        self.assertIn("clang", self.provenance["compiler_version"].lower())
        self.assertEqual(len(self.provenance["revision"]), 40)
        self.assertEqual(self.provenance["source_sha256"], {
            name: hashlib.sha256((PROTOTYPE / name).read_bytes()).hexdigest() for name in SOURCES
        })
        output = Path(self.provenance["command"][-1])
        self.assertEqual(hashlib.sha256(output.read_bytes()).hexdigest(), self.provenance["library_sha256"])


class CIntegrationTest(unittest.TestCase):
    def test_c_matrix_persists_scores_comparison_and_build_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            result = offline_eval(directory, backend="c")
            saved = read_eval_log(result.location)
            self.assertEqual(result.status, "success", result.error)
            self.assertEqual(len(saved.samples), 16)
            for sample in saved.samples:
                with self.subTest(case=sample.id):
                    self.assertIsNone(sample.error)
                    for scorer in ("conformance", "completion", "backend_agreement"):
                        self.assertEqual(sample.scores[scorer].value, 1)
                    record = sample.store["execution"]
                    self.assertEqual(record["backend"], "c")
                    self.assertTrue(all(record["comparison"]["checks"].values()))
                    build = record["native_monitor"]
                    self.assertEqual(set(build["source_sha256"]), set(SOURCES))
                    self.assertFalse(Path(build["command"][-1]).exists(), "Temporary build was not removed")
                    self.assertEqual(sample.model_usage, {})
                    self.assertFalse(any(e.event == "model" for e in sample.events))
            scores = {s.name: s for s in saved.results.scores}
            self.assertEqual(scores["backend_agreement"].metrics["accuracy"].value, 1)
            self.assertEqual({k: v.value for k, v in scores["disclosure"].metrics.items()},
                             {"disclosed": 4, "not_disclosed": 12, "unknown": 0})

    def test_missing_compiler_is_a_sample_error_without_fallback(self):
        with tempfile.TemporaryDirectory() as directory:
            with (
                patch("c_backend.shutil.which", return_value=None),
                patch.object(email_engine(), "replay", side_effect=AssertionError("Fallback forbidden")),
            ):
                result = offline_eval(directory, backend="c", limit=1)
            sample = read_eval_log(result.location).samples[0]
            self.assertIsNotNone(sample.error)
            self.assertFalse(sample.scores)
            self.assertEqual(sample.store["execution"], {
                "backend": "c", "status": "error", "error_type": "FileNotFoundError",
            })

    def test_compiler_failure_propagates(self):
        run = subprocess.run

        def fail_build(command, **kwargs):
            if "-shared" in command:
                raise subprocess.CalledProcessError(1, command, stderr="Deliberate compiler failure")
            return run(command, **kwargs)

        with patch("c_backend.subprocess.run", side_effect=fail_build):
            with self.assertRaises(subprocess.CalledProcessError):
                with compiled_monitor():
                    self.fail("A failed compiler must not yield a library")

    def test_unknown_backend_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "backend must be"):
            email_matrix(backend="other")


if __name__ == "__main__":
    unittest.main()
