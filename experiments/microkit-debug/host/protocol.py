"""Versioned ASCII/hex serial protocol shared with model_wire.c."""
from dataclasses import dataclass
import re

MAX_LINE = 2048
MAX_VALUE = 256
MAX_ARG = 64


def unhex(text, maximum):
    if text == "-":
        return b""
    if not re.fullmatch(r"(?:[0-9a-f]{2})+", text):
        raise ValueError("invalid hex field")
    value = bytes.fromhex(text)
    if len(value) > maximum:
        raise ValueError("value exceeds byte limit")
    return value


@dataclass(frozen=True)
class Request:
    id: int
    pc: int
    q: int
    secret: bytes
    email: bytes

    @classmethod
    def parse(cls, line):
        if len(line) > MAX_LINE or not line.endswith(b"\n") or line.count(b"\n") != 1:
            raise ValueError("invalid request line")
        parts = line[:-1].decode("ascii").split(" ")
        if len(parts) != 7 or parts[:2] != ["REQ", "1"]:
            raise ValueError("invalid request fields")
        nums = parts[2:5]
        if any(not re.fullmatch(r"0|[1-9][0-9]*", n) or int(n) > 2**64-1 for n in nums):
            raise ValueError("invalid request number")
        ident, pc, q = map(int, nums)
        if ident == 0 or (pc, q) != (2, 2):
            raise ValueError("unexpected request id or worker turn")
        return cls(ident, pc, q, unhex(parts[5], MAX_VALUE), unhex(parts[6], MAX_VALUE))

    def as_dict(self):
        return dict(id=self.id, pc=self.pc, q=self.q,
                    secret_hex=self.secret.hex(), email_hex=self.email.hex())


@dataclass(frozen=True)
class Proposal:
    kind: str
    value: bytes = b""

    def __post_init__(self):
        if self.kind not in ("none", "fetch", "error") or len(self.value) > MAX_ARG:
            raise ValueError("invalid proposal")
        if self.kind != "fetch" and self.value:
            raise ValueError("non-Fetch has arguments")

    def wire(self, ident):
        tail = self.kind.upper()
        if self.kind == "fetch":
            tail += " " + (self.value.hex() or "-")
        return f"RES 1 {ident} {tail}\n".encode("ascii")

    def as_dict(self):
        return dict(kind=self.kind, value_hex=self.value.hex())

    @classmethod
    def from_dict(cls, data):
        return cls(data["kind"], bytes.fromhex(data["value_hex"]))
