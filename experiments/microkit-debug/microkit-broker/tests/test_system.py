"""Build and boot configurations on QEMU (T4 onwards).

Skipped unless MICROKIT_SDK is set and clang, ld.lld and qemu-system-aarch64 are
installed. Each configuration is built in a temporary directory.
"""
import concurrent.futures
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

PROTOTYPE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROTOTYPE / "scripts"))

import expected as ex  # noqa: E402
import make_prefill as mp  # noqa: E402
import run_matrix  # noqa: E402
import run_qemu  # noqa: E402

TOOLS = ("clang", "ld.lld", "qemu-system-aarch64", "make")
HAVE_TOOLCHAIN = bool(os.environ.get("MICROKIT_SDK")) and all(shutil.which(t) for t in TOOLS)
START_ORDER = ["sink", "broker", "runner", "worker", "net"]  # descending priority


def build_and_boot(build_dir, until, **config):
    variables = ["{}={}".format(k.upper(), v) for k, v in config.items()]
    subprocess.run(["make", "-s", "BUILD_DIR=" + str(build_dir)] + variables, cwd=PROTOTYPE,
                   check=True, stdout=subprocess.DEVNULL)
    status, output = run_qemu.run(build_dir / "loader.img", until=until, timeout=20, echo=False)
    return status, output


@unittest.skipUnless(HAVE_TOOLCHAIN, "needs MICROKIT_SDK and the Microkit toolchain")
class SkeletonTest(unittest.TestCase):
    CONFIGS = [
        dict(policy="fenced", mode="injected", secret=1, email="malicious", inbox="allowed"),
        dict(policy="open", mode="reference", secret=0, email="benign", inbox="denied"),
        dict(policy="late", mode="injected", secret=0, email="malicious", inbox="allowed"),
    ]

    def test_every_pd_starts_and_reports_its_configuration(self):
        for config in self.CONFIGS:
            with self.subTest(**config), tempfile.TemporaryDirectory() as tmp:
                status, output = build_and_boot(Path(tmp) / "b", "DONE {}", **config)
                self.assertEqual(status, 0, output[-2000:])
                records = ex.parse_records(output)
                self.assertNotIn("BAD", [t for t, _ in records], output)
                self.assertEqual([o for t, o in records if t == "ERR"], [])

                starts = [o for t, o in records if t == "NOTE" and o.get("event") == "start"]
                # net has the lowest priority, so it may start after DONE; then the run is cut short.
                self.assertEqual([o["pd"] for o in starts], START_ORDER[:len(starts)])
                self.assertGreaterEqual(len(starts), 4)
                broker, runner, worker = starts[1], starts[2], starts[3]

                configs = {o["pd"]: o for t, o in records if t == "CONFIG"}
                perms = ["Fetch", "Inbox"] if config["inbox"] == "allowed" else ["Fetch"]
                self.assertEqual(configs["broker"], {"pd": "broker", "policy": config["policy"],
                                                     "initial_perms": perms})
                self.assertEqual(configs["worker"],
                                 {"pd": "worker", "mode": config["mode"], "attack": "none"})

                # Prefilled regions as the broker sees them.
                secret = mp.fixture_text(ex.FIXTURES / "secret-{}.txt".format(config["secret"]))
                email = mp.fixture_text(ex.FIXTURES / "email-{}.txt".format(config["email"]))
                self.assertEqual((broker["secret_len"], broker["inbox_seq"], broker["inbox_len"],
                                  broker["context_count"]), (len(secret), 1, len(email), 0))

                # The worker reads the runner's initialised plan memory.
                self.assertEqual(runner["pc"], 0)
                self.assertEqual((worker["pc"], worker["secret"], worker["context_count"]),
                                 (0, "Data 0", 0))


@unittest.skipUnless(HAVE_TOOLCHAIN, "needs MICROKIT_SDK and the Microkit toolchain")
class EmailRunTest(unittest.TestCase):
    """T7/T8: complete runs print exactly what core.py predicts."""

    def test_all_sixteen_configurations_match_and_leak_as_the_paper_says(self):
        with tempfile.TemporaryDirectory() as tmp:
            with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
                results = list(pool.map(lambda n: run_matrix.run_one(n, tmp, 30), ex.configurations()))
        for r in results:
            self.assertEqual(r["problems"], [], r["name"])
        rows = run_matrix.verdicts(results)
        self.assertEqual(len(rows), 8)
        leaking = {(row["policy"], row["mode"]) for row in rows if row["distinguishes"]}
        self.assertEqual(leaking, {("open", "injected"), ("late", "injected")})
        self.assertTrue(all(row["ok"] for row in rows))

    def test_all_sixteen_configurations_with_the_email_over_tcp(self):
        # T8b: the attacker sends the email over TCP once the runner waits for it;
        # the console must match core.py and the socket must carry exactly the OBS lines.
        with tempfile.TemporaryDirectory() as tmp:
            with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
                results = list(pool.map(lambda n: run_matrix.run_one(n, tmp, 30, "tcp"), ex.configurations()))
        for r in results:
            self.assertEqual(r["problems"], [], r["name"])
        rows = run_matrix.verdicts(results)
        self.assertTrue(all(row["ok"] for row in rows))

    def test_comparison_notices_a_wrong_policy(self):
        # Guard against a comparison that always passes: a fenced run is not an open one.
        with tempfile.TemporaryDirectory() as tmp:
            _, output = build_and_boot(Path(tmp) / "b", "DONE {}", policy="fenced", mode="injected",
                                       secret=1, email="malicious", inbox="allowed")
        problems = ex.compare(ex.expected("open-injected-s1-malicious-allowed"), ex.parse_records(output))
        self.assertIn("OBS: expected 1 records, got 0", problems)
        self.assertIn("TRACE #3 decision: expected 'Allowed', got 'Denied'", problems)


class DesignCopyTest(unittest.TestCase):
    def test_design_shows_the_real_system_description(self):
        def system_element(text):
            return re.search(r"<system>.*?</system>", text, re.S).group(0)
        design = (PROTOTYPE / "DESIGN.md").read_text()
        actual = (PROTOTYPE / "broker.system").read_text()
        self.assertEqual(system_element(design), system_element(actual))


if __name__ == "__main__":
    unittest.main()
