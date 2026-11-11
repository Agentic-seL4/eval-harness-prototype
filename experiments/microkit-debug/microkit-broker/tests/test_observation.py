"""T10: what each output channel carries, in the debug and release configurations.

The debug console is not mediated by capabilities: in a debug build every PD,
including the untrusted worker, can print to it. Here only the analyst reads it.
In a release build it carries nothing at all, while the attacker's socket (the net
PD's UART) still carries exactly the OBS lines. Needs MICROKIT_SDK.
"""
import os
import subprocess
import sys
import unittest
from pathlib import Path

PROTOTYPE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROTOTYPE / "scripts"))

import expected as ex  # noqa: E402
import run_qemu  # noqa: E402

EMAIL = (PROTOTYPE / "fixtures" / "email-malicious.txt").read_bytes().rstrip(b"\n") + b"\n"
LEAK = 'OBS {"tool":"Fetch","args":["Data 1"]}'


def build(**variables):
    args = ["make", "-s"] + ["%s=%s" % kv for kv in variables.items()] + ["all"]
    subprocess.run(args, cwd=PROTOTYPE, check=True, capture_output=True)
    name = "{POLICY}-injected-s1-malicious-allowed{tcp}{cfg}".format(
        POLICY=variables.get("POLICY", "fenced"),
        tcp="-tcp" if variables.get("INPUT") == "tcp" else "",
        cfg="-release" if variables.get("MICROKIT_CONFIG") == "release" else "")
    return PROTOTYPE / "build" / name / "loader.img"


@unittest.skipUnless(os.environ.get("MICROKIT_SDK"), "MICROKIT_SDK not set")
class ObservationTest(unittest.TestCase):
    def test_debug_console_carries_output_from_the_untrusted_worker(self):
        image = build(POLICY="fenced")
        status, console = run_qemu.run(str(image), until="DONE {}", timeout=30, echo=False)
        self.assertEqual(status, 0)
        worker_lines = [o for t, o in ex.parse_records(console) if t == "NOTE" and o.get("pd") == "worker"]
        self.assertTrue(worker_lines, "expected the worker's own NOTE lines on the debug console")

    def test_release_console_is_silent_and_the_attacker_sees_only_obs(self):
        image = build(POLICY="open", INPUT="tcp", MICROKIT_CONFIG="release")
        status, console, socket_text = run_qemu.run_with_socket(
            str(image), EMAIL, until=None, timeout=30, until_attacker='"]}')
        self.assertEqual(status, 0, "the attacker never received the OBS line")
        self.assertEqual(console, "", "a release build should print nothing on the console")
        self.assertEqual(socket_text.strip(), LEAK)


if __name__ == "__main__":
    unittest.main()
