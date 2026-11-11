#!/usr/bin/env python3
"""Write the prefill files for the secret and inbox memory regions.

Layouts follow include/protocol.h: the secret is a `struct value`, the inbox a
`struct mailbox` holding one complete message (seq 1). One trailing newline is
stripped from each fixture, so the files can be edited normally.
"""
import argparse
import struct
from pathlib import Path

# Mirrors include/protocol.h; tests/test_protocol.py checks that they agree.
MAX_VALUE = 256
MAILBOX_MAGIC = b"MBOXv1\0\0"
MAILBOX_SIZE = 0x1000
MAILBOX_HEADER = 24
MAILBOX_CAPACITY = MAILBOX_SIZE - MAILBOX_HEADER


def fixture_text(path):
    """Return a fixture's bytes without one trailing newline."""
    data = Path(path).read_bytes()
    if data.endswith(b"\r\n"):
        data = data[:-2]
    elif data.endswith(b"\n"):
        data = data[:-1]
    if len(data) > MAX_VALUE:
        raise ValueError("{}: {} bytes, more than MAX_VALUE ({})".format(path, len(data), MAX_VALUE))
    if b"\n" in data:
        raise ValueError("{}: one line only (an email is one line)".format(path))
    return data


def value_bytes(data):
    """A struct value: 64-bit length, then MAX_VALUE bytes."""
    if len(data) > MAX_VALUE:
        raise ValueError("value longer than MAX_VALUE")
    return struct.pack("<Q", len(data)) + data.ljust(MAX_VALUE, b"\0")


def mailbox_bytes(data, seq=1):
    """A struct mailbox holding one complete message (seq 0 and no data: empty)."""
    if len(data) > MAX_VALUE:
        raise ValueError("message longer than MAX_VALUE")
    header = MAILBOX_MAGIC + struct.pack("<QQ", seq, len(data))
    return header + data.ljust(MAILBOX_CAPACITY, b"\0")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--secret", type=Path, help="secret fixture -> OUT/secret.bin")
    parser.add_argument("--email", type=Path, help="email fixture -> OUT/inbox.mbox")
    parser.add_argument("--empty-inbox", action="store_true",
                        help="OUT/inbox.mbox with no message: the email arrives at run time (T8b)")
    parser.add_argument("--out", type=Path, required=True, help="output directory")
    args = parser.parse_args()
    if not (args.secret or args.email or args.empty_inbox):
        parser.error("give --secret, --email or --empty-inbox")
    if args.email and args.empty_inbox:
        parser.error("--email and --empty-inbox exclude each other")
    args.out.mkdir(parents=True, exist_ok=True)
    if args.secret:
        (args.out / "secret.bin").write_bytes(value_bytes(fixture_text(args.secret)))
    if args.email:
        (args.out / "inbox.mbox").write_bytes(mailbox_bytes(fixture_text(args.email)))
    if args.empty_inbox:
        (args.out / "inbox.mbox").write_bytes(mailbox_bytes(b"", seq=0))


if __name__ == "__main__":
    main()
