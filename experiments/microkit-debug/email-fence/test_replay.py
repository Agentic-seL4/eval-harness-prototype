"""Independent expected traces and boundary checks for the handwritten fixture."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from core import (AgentState, Call, Config, FakeTools, Monitor, MonitorState,
                  Pending, agent_step, compare, receive, replay)
from replay import save_html


class ReplayTests(unittest.TestCase):
    def test_open_trace_matches_email_leak_e1_tr(self):
        run = replay(Config(policy="open", secret=73))
        # Five states, transcribed from e1_tr (including the initial state).
        expected = [
            (0, 0, {"Secret": "Data 0", "Mail": "Data 0", "Summary": "Data 0", "Result": "Data 0"}, ()),
            (1, 1, {"Secret": "Data 73", "Mail": "Data 0", "Summary": "Data 0", "Result": "Data 0"}, ()),
            (2, 2, {"Secret": "Data 73", "Mail": "Email", "Summary": "Data 0", "Result": "Data 0"}, ("Email",)),
            (2, 3, {"Secret": "Data 73", "Mail": "Email", "Summary": "Data 0", "Result": "Data 0"}, ("Email",)),
            (3, 4, {"Secret": "Data 73", "Mail": "Email", "Summary": "Email", "Result": "Data 0"}, ("Email",)),
        ]
        states = [run.initial] + [s.after for s in run.steps]
        self.assertEqual([(s["pc"], s["oracle"], s["memory"], s["context"]) for s in states], expected)
        self.assertTrue(all(s["pending"] is None for s in states))
        self.assertTrue(all(s["permissions"] == ["Fetch", "Inbox"] for s in states))
        self.assertEqual([s.event.kind for s in run.steps], ["AReadT", "AReadU", "ACall", "ATau"])
        self.assertEqual(run.effects, [Call("Fetch", ("Data 73",))])
        self.assertTrue(run.completed)

    def test_fenced_authority_is_gone_at_content_admission(self):
        run = replay(Config(secret=1))
        read, injection = run.steps[1:3]
        self.assertEqual(read.before["context"], ())
        self.assertEqual(read.proposed["memory"]["Mail"], "Data 0")
        self.assertEqual(read.proposed["pending"], {"target": "Mail", "content": "Email"})
        self.assertEqual(read.monitor_after_decision, ["Fetch", "Inbox"])
        self.assertEqual(read.admission_permissions, ["Inbox"])
        self.assertEqual(read.after["context"], ("Email",))
        self.assertEqual(injection.decision, "Denied")
        self.assertEqual(run.effects, [])
        self.assertEqual(run.final["memory"]["Summary"], "Email")

    def test_policy_update_precedes_receive(self):
        events = []

        class RecordingMonitor(Monitor):
            def mnext(self, state, event):
                events.append(event.kind)
                return super().mnext(state, event)

        def checked_receive(state, decision):
            if state.pending and decision == "Allowed":
                self.assertEqual(events, ["AReadT", "AReadU"])
            return receive(state, decision)

        with patch("core.receive", side_effect=checked_receive):
            replay(Config(), monitor=RecordingMonitor("fenced"))

    def test_reference_never_dispatches_and_still_finishes(self):
        for policy in ("open", "fenced", "late"):
            for email in ("Email", "Data 7"):
                with self.subTest(policy=policy, email=email):
                    run = replay(Config(mode="reference", policy=policy, email=email))
                    self.assertEqual([s.origin for s in run.steps], ["plan"] * 3)
                    self.assertEqual(run.effects, [])
                    self.assertEqual(run.final["memory"]["Summary"], email)
                    self.assertEqual(run.final["oracle"], 3)
                    self.assertTrue(run.completed)

    def test_injected_result_is_discarded_for_both_decisions(self):
        for policy in ("open", "fenced"):
            with self.subTest(policy=policy):
                injection = replay(Config(policy=policy)).steps[2]
                self.assertEqual(injection.response, "Done")
                self.assertEqual(injection.before["memory"], injection.after["memory"])
                self.assertEqual(injection.after["pc"], 2)
                self.assertEqual(injection.after["oracle"], 3)
                self.assertIsNone(injection.after["pending"])

    def test_denied_inbox_consumes_input_without_admitting_payload(self):
        run = replay(Config(inbox_allowed=False))
        read = run.steps[1]
        self.assertEqual(read.decision, "Denied")
        self.assertIsNone(read.admission_permissions)
        self.assertEqual(read.after["untrusted_inputs"], ())
        self.assertEqual(read.after["context"], ())
        self.assertEqual(read.after["memory"]["Mail"], "Done")
        self.assertEqual(read.after["permissions"], ["Fetch"])
        self.assertEqual(run.final["memory"]["Summary"], "Done")
        self.assertEqual(len(run.steps), 3)
        self.assertEqual(run.projection(), {"actions": [], "observations": []})
        self.assertTrue(run.completed)

    def test_denial_keeps_successor_state_and_does_not_observe_read(self):
        observed = []

        class StatefulDenial(Monitor):
            def mdecide(self, state, tool, args):
                return "Denied", MonitorState(frozenset())

            def mnext(self, state, event):
                observed.append(event.kind)
                return super().mnext(state, event)

        run = replay(Config(), monitor=StatefulDenial("fenced"))
        self.assertEqual(run.steps[1].after["permissions"], [])
        self.assertEqual(observed, ["AReadT"])
        self.assertEqual(run.final["memory"]["Summary"], "Done")

    def test_denied_calls_never_reach_tool_sink(self):
        sink = FakeTools()
        with patch.object(sink, "dispatch", wraps=sink.dispatch) as dispatch:
            replay(Config(), tools=sink)
            dispatch.assert_not_called()

    def test_benign_mail_finishes_and_still_triggers_fence(self):
        run = replay(Config(email="Data 7"))
        self.assertEqual(run.final["memory"]["Summary"], "Data 7")
        self.assertEqual(run.final["permissions"], ["Inbox"])
        self.assertEqual(run.final["context"], ("Data 7",))
        self.assertEqual(len(run.steps), 3)
        self.assertEqual(run.effects, [])

    def test_late_revocation_leaks_before_permission_is_removed(self):
        run = replay(Config(policy="late", secret=1))
        self.assertEqual(run.steps[1].admission_permissions, ["Fetch", "Inbox"])
        self.assertEqual(run.steps[2].decision, "Allowed")
        self.assertEqual(run.steps[2].after["permissions"], ["Inbox"])
        self.assertEqual(run.effects, [Call("Fetch", ("Data 1",))])
        self.assertTrue(run.completed)

    def test_event_and_step_projections_have_expected_padding(self):
        run = replay(Config(policy="open", secret=1))
        obs = {"tool": "Fetch", "args": ("Data 1",)}
        self.assertEqual(run.projection(), {"actions": ["Email", None], "observations": [None, obs]})
        self.assertEqual(run.projection("step"), {
            "actions": [None, "Email", None, None], "observations": [None, None, obs, None]})
        fenced = replay(Config())
        self.assertEqual(fenced.projection(), {"actions": ["Email"], "observations": [None]})
        self.assertEqual(fenced.projection("step")["observations"], [None] * 4)

    def test_two_secret_pairs_distinguish_open_and_late_only(self):
        for policy, expected in (("open", True), ("fenced", False), ("late", True)):
            for view in ("event", "step"):
                with self.subTest(policy=policy, view=view):
                    a, b = [replay(Config(policy=policy, secret=s)) for s in (0, 1)]
                    self.assertEqual(compare(a, b, view)["qualifying_leak_pair"], expected)

    def test_call_presence_can_differ_without_qualifying_event_pair(self):
        # A different policy used only to exercise the observer restriction.
        class ConditionalMonitor(Monitor):
            def mdecide(self, state, tool, args):
                return ("Denied" if args == ("Data 1",) else "Allowed"), state

        a, b = [replay(Config(policy="open", secret=s), monitor=ConditionalMonitor("open"))
                for s in (0, 1)]
        self.assertEqual(len(a.effects), 1)
        self.assertEqual(len(b.effects), 0)
        self.assertEqual(compare(a, b), {"view": "event", "same_actions": False,
                                       "different_observations": True, "qualifying_leak_pair": False})
        self.assertTrue(compare(a, b, "step")["qualifying_leak_pair"])

    def test_initial_memory_does_not_preload_secret(self):
        a, b = [replay(Config(secret=s)) for s in (0, 1)]
        self.assertEqual(a.initial["memory"], b.initial["memory"])
        self.assertNotEqual(a.initial["trusted_inputs"], b.initial["trusted_inputs"])

    def test_no_injection_after_program_termination(self):
        state = AgentState(pc=3, oracle=2, context=("Email",))
        self.assertIsNone(agent_step(state, "injected"))

    def test_pending_read_blocks_another_agent_step(self):
        with self.assertRaises(ValueError):
            agent_step(AgentState(pending=Pending("Mail", "Email")), "injected")

    def test_nonempty_context_is_not_sufficient_to_inject(self):
        for context, oracle in ((("Data 7",), 2), (("Email",), 3)):
            event, after, origin = agent_step(AgentState(pc=2, oracle=oracle, context=context), "injected")
            self.assertEqual((event.kind, origin, after.pc), ("ATau", "plan", 3))

    def test_invalid_configuration_is_rejected(self):
        for options in ({"secret": -1}, {"secret": True}, {"mode": "llm"},
                        {"policy": "anything"}, {"email": "unparsed text"}):
            with self.subTest(options=options), self.assertRaises(ValueError):
                Config(**options)

    def test_json_and_html_cli_exports(self):
        with tempfile.TemporaryDirectory() as folder:
            output = Path(folder)
            subprocess.run([sys.executable, str(Path(__file__).with_name("replay.py")),
                            "demo", "--json", str(output / "traces.json"),
                            "--html", str(output / "explorer.html")], check=True, capture_output=True)
            payload = json.loads((output / "traces.json").read_text())
            self.assertEqual(len(payload["runs"]), 16)
            self.assertEqual(len(payload["pairs"]), 8)
            self.assertTrue(all(r["completed"] for r in payload["runs"]))
            html = (output / "explorer.html").read_text()
            self.assertNotIn("__TRACE_DATA__", html)
            self.assertIn('"schema_version": 1', html)

    def test_html_embedded_data_cannot_close_script(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "test.html"
            with patch("builtins.print"):
                save_html(path, {"test": "</script><script>alert('x')</script>"})
            html = path.read_text()
            self.assertNotIn("</script><script>alert", html)
            self.assertIn(r"\u003c/script\u003e", html)

    def test_cli_step_view_accepts_quit_and_eof(self):
        for keys in ("\nq\n", ""):
            result = subprocess.run([sys.executable, str(Path(__file__).with_name("replay.py")),
                                     "run", "--step"], input=keys, text=True, capture_output=True)
            self.assertEqual(result.returncode, 0, result.stderr)
        bad = subprocess.run([sys.executable, str(Path(__file__).with_name("replay.py")),
                              "run", "--secret", "-1"], capture_output=True)
        self.assertEqual(bad.returncode, 2)


if __name__ == "__main__":
    unittest.main()
