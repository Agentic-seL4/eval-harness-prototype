"""T8: the run matrix's verdict logic, on synthetic results (no QEMU needed)."""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

import expected as ex  # noqa: E402
import run_matrix  # noqa: E402


def results(observe=None):
    """One result per configuration, observing what core.py predicts unless overridden."""
    out = []
    for name, (policy, mode, secret, email, inbox) in ex.configurations().items():
        predicted = run_matrix.observations(ex.expected(name))
        seen = observe(name, predicted) if observe else predicted
        out.append(dict(name=name, policy=policy, mode=mode, secret=secret, email=email, inbox=inbox,
                        expected_observations=predicted, observations=seen, ok=True, problems=[], seconds=0))
    return out


class VerdictTest(unittest.TestCase):
    def test_predicted_views_give_the_paper_verdicts(self):
        rows = run_matrix.verdicts(results())
        self.assertEqual(len(rows), 8)
        self.assertTrue(all(row["ok"] for row in rows))
        self.assertEqual({(r["policy"], r["mode"]) for r in rows if r["distinguishes"]},
                         {("open", "injected"), ("late", "injected")})

    def test_a_leak_under_the_fence_is_flagged(self):
        def leak(name, predicted):
            return [{"tool": "Fetch", "args": ["Data " + name.split("-s")[1][0]]}] if name.startswith("fenced-injected") else predicted
        row = next(r for r in run_matrix.verdicts(results(leak))
                   if (r["policy"], r["mode"], r["email"], r["inbox"]) == ("fenced", "injected", "malicious", "allowed"))
        self.assertTrue(row["distinguishes"])
        self.assertFalse(row["ok"])

    def test_a_missing_leak_is_flagged(self):
        def silent(name, predicted):
            return [] if name.startswith("open-injected") else predicted
        row = next(r for r in run_matrix.verdicts(results(silent)) if (r["policy"], r["mode"]) == ("open", "injected"))
        self.assertFalse(row["distinguishes"])
        self.assertFalse(row["ok"])

    def test_report_mentions_scope_and_differences(self):
        rs = results()
        rs[0].update(ok=False, problems=["TRACE #1 value: expected 'Data 0', got 'Data 9'"])
        text = run_matrix.report(rs, run_matrix.verdicts(rs), "test")
        self.assertIn("15 of 16 configurations", text)
        self.assertIn("not a relative-\nsecurity verdict", text)
        self.assertIn("TRACE #1 value", text)


if __name__ == "__main__":
    unittest.main()
