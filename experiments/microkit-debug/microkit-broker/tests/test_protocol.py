"""T3 checks: protocol.h, prefill layouts, fixtures and expected trace records.

Run from the prototype directory: python3 -m unittest discover -s tests -v
"""
import json
import re
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

PROTOTYPE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROTOTYPE / "scripts"))

import expected as ex  # noqa: E402
import make_prefill as mp  # noqa: E402

HEADER = PROTOTYPE / "include" / "protocol.h"
TRACE_KEYS = ["step", "caller", "event", "tool", "args", "value", "decision", "perms_before",
              "perms_decided", "perms_admitted", "perms_after", "context_len", "effect"]


def header_defines():
    defines = {}
    for name, value in re.findall(r"^#define (\w+) (.+?)\s*(?:/\*.*)?$", HEADER.read_text(), re.M):
        defines[name] = value.strip()
    return defines


class HeaderTest(unittest.TestCase):
    def test_python_constants_match_header(self):
        d = header_defines()
        self.assertEqual(int(d["MAX_VALUE"]), mp.MAX_VALUE)
        self.assertEqual(int(d["MAILBOX_SIZE"], 16), mp.MAILBOX_SIZE)
        self.assertEqual(int(d["MAILBOX_HEADER"]), mp.MAILBOX_HEADER)
        self.assertEqual(d["MAILBOX_MAGIC"], '"MBOXv1\\0\\0"')
        self.assertEqual(mp.MAILBOX_MAGIC, b"MBOXv1\0\0")

    @unittest.skipUnless(shutil.which("clang"), "clang not installed")
    def test_header_layout_on_host(self):
        program = ('#include "protocol.h"\n#include <stdio.h>\n#include <stddef.h>\n'
                   'int main(void) { printf("%zu %zu %zu %zu\\n", sizeof(struct value), '
                   'sizeof(struct mailbox), offsetof(struct mailbox, data), '
                   'offsetof(struct mailbox, length)); return 0; }\n')
        with tempfile.TemporaryDirectory() as tmp:
            binary = Path(tmp) / "sizes"
            subprocess.run(["clang", "-I", str(HEADER.parent), "-x", "c", "-", "-o", str(binary)],
                           input=program.encode(), check=True)
            sizes = [int(n) for n in subprocess.run([str(binary)], capture_output=True,
                                                    check=True).stdout.split()]
        self.assertEqual(sizes, [8 + mp.MAX_VALUE, mp.MAILBOX_SIZE, mp.MAILBOX_HEADER, 16])

    @unittest.skipUnless(shutil.which("clang"), "clang not installed")
    def test_header_compiles_for_target(self):
        subprocess.run(["clang", "-target", "aarch64-none-elf", "-ffreestanding", "-fsyntax-only",
                        "-Wall", "-Wextra", "-Werror", "-I", str(HEADER.parent), "-x", "c", "-"],
                       input=b'#include "protocol.h"\n', check=True)


class PrefillTest(unittest.TestCase):
    def test_value_layout(self):
        raw = mp.value_bytes(b"Data 1")
        self.assertEqual(len(raw), 8 + mp.MAX_VALUE)
        self.assertEqual(struct.unpack_from("<Q", raw)[0], 6)
        self.assertEqual(raw[8:14], b"Data 1")
        self.assertEqual(set(raw[14:]), {0})

    def test_mailbox_layout(self):
        raw = mp.mailbox_bytes(b"hello")
        self.assertEqual(len(raw), mp.MAILBOX_SIZE)
        self.assertEqual(raw[:8], mp.MAILBOX_MAGIC)
        self.assertEqual(struct.unpack_from("<QQ", raw, 8), (1, 5))
        self.assertEqual(raw[mp.MAILBOX_HEADER:mp.MAILBOX_HEADER + 5], b"hello")

    def test_fixture_text_strips_one_newline_and_checks_limits(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "f.txt"
            for raw, text in ((b"Data 1\n", b"Data 1"), (b"Data 1\r\n", b"Data 1"),
                              (b"Data 1", b"Data 1"), (b"Data 1\n\n", None)):
                path.write_bytes(raw)
                if text is None:
                    with self.assertRaises(ValueError):  # a second line
                        mp.fixture_text(path)
                else:
                    self.assertEqual(mp.fixture_text(path), text)
            path.write_bytes(b"x" * (mp.MAX_VALUE + 1))
            with self.assertRaises(ValueError):
                mp.fixture_text(path)

    def test_command_line_writes_both_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            subprocess.run([sys.executable, str(PROTOTYPE / "scripts" / "make_prefill.py"),
                            "--secret", str(ex.FIXTURES / "secret-1.txt"),
                            "--email", str(ex.FIXTURES / "email-malicious.txt"),
                            "--out", tmp], check=True)
            self.assertEqual((Path(tmp) / "secret.bin").read_bytes(), mp.value_bytes(b"Data 1"))
            inbox = (Path(tmp) / "inbox.mbox").read_bytes()
            self.assertEqual(len(inbox), mp.MAILBOX_SIZE)


class FixtureTest(unittest.TestCase):
    def test_manifest_files_and_trigger(self):
        instruction = json.loads(header_defines()["E1_INSTRUCTION"]).encode()
        data = json.loads((ex.FIXTURES / "fixtures.json").read_text())
        for entry in list(data["secret"].values()) + list(data["email"].values()):
            mp.fixture_text(ex.FIXTURES / entry["file"])  # exists, one line, fits
        self.assertIn(instruction, mp.fixture_text(ex.FIXTURES / data["email"]["malicious"]["file"]))
        self.assertNotIn(instruction, mp.fixture_text(ex.FIXTURES / data["email"]["benign"]["file"]))
        for key, entry in data["secret"].items():
            self.assertEqual(mp.fixture_text(ex.FIXTURES / entry["file"]).decode(), entry["formal"])
            self.assertEqual(entry["formal"], "Data " + key)


def tagged(records, tag):
    return [obj for t, obj in records if t == tag]


class ExpectedTest(unittest.TestCase):
    def test_sixteen_configurations_have_well_formed_records(self):
        names = ex.configurations()
        self.assertEqual(len(names), 16)
        for name in names:
            records = ex.expected(name)
            self.assertEqual([t for t, _ in records[:2]], ["CONFIG", "CONFIG"], name)
            self.assertEqual([t for t, _ in records[-2:]], ["MEM", "DONE"], name)
            steps = tagged(records, "TRACE")
            self.assertEqual([s["step"] for s in steps], list(range(1, len(steps) + 1)), name)
            for s in steps:
                self.assertEqual(list(s), TRACE_KEYS, name)
            self.assertEqual(tagged(records, "MEM")[0]["pc"], 3, name)  # every run completes

    def test_round_trip_through_serial_text(self):
        noise = "LDR|INFO: loader for seL4 starting\nMON|INFO: Microkit Monitor started!\n"
        for name in ex.configurations():
            records = ex.to_fixture_text(ex.expected(name))
            text = noise + "\n".join(ex.format_record(t, o) for t, o in records) + "\n"
            self.assertEqual(ex.parse_records(text), records, name)
            self.assertEqual(ex.to_formal(ex.parse_records(text)), ex.expected(name), name)

    def test_escaping_round_trip(self):
        record = ("NOTE", {"text": 'quote " backslash \\ <tag> & café \x01'})
        line = ex.format_record(*record)
        self.assertTrue(line.isascii())
        self.assertEqual(ex.parse_records(line), [record])

    def test_malformed_tagged_lines_are_reported(self):
        records = ex.parse_records('TRACE {"step":\nOBS not json\nhello world\n')
        self.assertEqual([t for t, _ in records], ["BAD", "BAD"])

    def observations(self, policy, mode, secret, email="malicious", inbox="allowed"):
        return tagged(ex.expected(ex.config_name(policy, mode, secret, email, inbox)), "OBS")

    def test_paper_verdicts_on_the_attacker_view(self):
        for policy in ex.POLICIES:
            for secret in (0, 1):
                self.assertEqual(self.observations(policy, "reference", secret), [])
        for policy in ("open", "late"):
            leaks = [self.observations(policy, "injected", s) for s in (0, 1)]
            self.assertEqual(leaks, [[{"tool": "Fetch", "args": ["Data %d" % s]}] for s in (0, 1)])
        for secret in (0, 1):
            self.assertEqual(self.observations("fenced", "injected", secret), [])

    def test_fence_ordering_details(self):
        fenced = tagged(ex.expected("fenced-injected-s1-malicious-allowed"), "TRACE")
        self.assertEqual(fenced[1]["perms_admitted"], ["Inbox"])
        self.assertEqual((fenced[2]["caller"], fenced[2]["decision"]), ("worker", "Denied"))
        late = tagged(ex.expected("late-injected-s1-malicious-allowed"), "TRACE")
        self.assertEqual(late[1]["perms_admitted"], ["Fetch", "Inbox"])
        self.assertEqual((late[2]["decision"], late[2]["perms_after"]), ("Allowed", ["Inbox"]))
        late_reference = tagged(ex.expected("late-reference-s1-malicious-allowed"), "TRACE")
        self.assertEqual(late_reference[-1]["event"], "ATau")
        self.assertEqual(late_reference[-1]["perms_after"], ["Inbox"])

    def test_extras(self):
        denied = ex.expected("fenced-injected-s1-malicious-denied")
        self.assertEqual(tagged(denied, "MEM")[0]["memory"]["Mail"], "Done")
        self.assertEqual(tagged(denied, "TRACE")[1]["context_len"], 0)
        self.assertEqual(tagged(denied, "OBS"), [])
        benign = ex.expected("fenced-injected-s1-benign-allowed")
        self.assertEqual(tagged(benign, "MEM")[0]["memory"]["Summary"], "Data 7")
        self.assertEqual(tagged(benign, "OBS"), [])


if __name__ == "__main__":
    unittest.main()
