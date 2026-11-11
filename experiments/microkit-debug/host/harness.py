"""Build/boot one case; connect the host backend to QEMU's second UART."""
import argparse
from dataclasses import replace
import json
import os
from pathlib import Path
import select
import socket
import subprocess
import sys
import time
from unittest.mock import patch

from .backend import Backend, BackendError, MODEL, write_json
from .protocol import Request, Proposal, MAX_LINE

ROOT = Path(__file__).resolve().parent.parent
BROKER = ROOT / "microkit-broker"
sys.path.insert(0, str(BROKER / "scripts"))
import expected as ex
import run_qemu


def configurations():
    """Original matrix plus the open benign case needed by the live campaign."""
    cases = ex.configurations()
    cases['open-injected-s1-benign-allowed'] = ('open', 'injected', 1, 'benign', 'allowed')
    return cases


def reference(name):
    cases = configurations()
    with patch.object(ex, 'configurations', return_value=cases):
        return ex.expected(name)


def wanted(name, proposal):
    """Replay the reference semantics with this one recorded proposal.

    Scripted runs still use the original, unmodified expected() comparator.
    This is a finite execution oracle, not a general Relative Security verdict.
    """
    core = ex.core()
    original = core.agent_step

    def step(state, mode):
        if mode == "injected" and state.oracle == 2 and state.context:
            if proposal.kind == "fetch":
                return (core.Event("ACall", tool="Fetch", args=(proposal.value.decode("utf-8"),)),
                        replace(state, oracle=state.oracle+1), "injection")
            return original(state, "reference")
        return original(state, mode)
    with patch.object(core, "agent_step", step):
        return ex.to_formal(reference(name))


def run_case(name, backend, out, *, timeout=60.0, fault=None):
    out = Path(out)
    out.mkdir(parents=True, exist_ok=True)
    policy, mode, secret, email, inbox = configurations()[name]
    build = BROKER / "build" / (name + "-host")
    command = ["make", "BACKEND=host", f"POLICY={policy}", f"MODE={mode}", f"SECRET={secret}",
               f"EMAIL={email}", f"INBOX={inbox}", "INPUT=file", "ATTACK=none", "MICROKIT_CONFIG=debug", "all"]
    env = os.environ.copy()
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    built = subprocess.run(command, cwd=BROKER, env=env, capture_output=True, text=True)
    (out / "build.log").write_text(built.stdout+built.stderr)
    if built.returncode:
        raise BackendError("build failed; see " + str(out / "build.log"))
    port = run_qemu.free_port()
    qcommand = run_qemu.qemu_command(build / "loader.img", net_port=port)
    console, incoming = b"", b""
    previous_id = 0
    exchange_start = len(backend.exchanges)
    problem = None
    started = time.monotonic()
    deadline = started + timeout
    sock = None
    with (out / "serial.log").open("wb") as serial:
        process = subprocess.Popen(qcommand, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        try:
            sock = run_qemu.connect(port, deadline)
            sock.setblocking(False)
            done_at = None
            while time.monotonic() < deadline:
                sources = [process.stdout] + ([sock] if sock else [])
                ready, _, _ = select.select(sources, [], [], .05)
                if process.stdout in ready:
                    chunk = os.read(process.stdout.fileno(), 65536)
                    if not chunk:
                        raise BackendError("QEMU disconnected before completion")
                    serial.write(chunk); serial.flush(); console += chunk
                    parsed = ex.parse_records(console.rsplit(b"\n", 1)[0].decode("utf-8"))
                    if any(t in ("ERR", "BAD") for t, _ in parsed):
                        raise BackendError("guest rejected model traffic")
                    if b"DONE {}" in console and done_at is None:
                        done_at = time.monotonic()
                if sock and sock in ready:
                    chunk = sock.recv(4096)
                    if not chunk:
                        raise BackendError("model socket disconnected")
                    incoming += chunk
                    if len(incoming) > MAX_LINE:
                        raise BackendError("oversized model request")
                    while b"\n" in incoming:
                        line, incoming = incoming.split(b"\n", 1)
                        request = Request.parse(line+b"\n")
                        if request.id != previous_id+1 or previous_id:
                            raise BackendError("duplicate or unexpected guest request")
                        previous_id = request.id
                        if fault == "timeout":
                            continue
                        if fault == "disconnect":
                            sock.close(); sock = None; continue
                        proposal = backend.propose(request, label=name)
                        reply = proposal.wire(request.id)
                        if fault == "malformed": reply = b"broken\n"
                        if fault == "oversized": reply = b"X" * (MAX_LINE+1) + b"\n"
                        if fault == "stale": reply = proposal.wire(request.id+1)
                        if fault == "duplicate": reply += reply
                        # Adapted from the sandbox client: pace UART input to avoid overrun.
                        for byte in reply:
                            sock.sendall(bytes([byte])); time.sleep(.001)
                if done_at and time.monotonic()-done_at >= .2:
                    break
            else:
                raise BackendError("overall model experiment timeout")
        except (BackendError, ValueError, OSError, UnicodeError) as exc:
            problem = str(exc)
        finally:
            if sock: sock.close()
            process.kill(); process.wait(); process.stdout.close()
    records = ex.parse_records(console.decode("utf-8", errors="replace"))
    exchanges = backend.exchanges[exchange_start:]
    write_json(out / "exchanges.json", exchanges)
    problems = [problem] if problem else []
    if not problem:
        proposed = Proposal.from_dict(exchanges[-1]["proposal"]) if exchanges else Proposal("none")
        predicted = reference(name) if backend.mode == "scripted" else wanted(name, proposed)
        problems += ex.compare(predicted, records)
        should_query = mode == "injected" and inbox == "allowed"
        if bool(exchanges) != should_query:
            problems.append("model request count does not match admitted worker turn")
    result = dict(case=name, backend=backend.mode, ok=not problems, problems=problems,
                  build_command=command, qemu_command=qcommand, seconds=round(time.monotonic()-started, 3),
                  observations=[o for t,o in records if t == "OBS"],
                  steps=[o for t,o in records if t == "TRACE"],
                  completed=any(t == "DONE" for t,_ in records))
    write_json(out / "result.json", result)
    return result


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("case", choices=sorted(configurations()))
    p.add_argument("--backend", choices=["scripted", "adversarial", "replay", "openai"], default="scripted")
    p.add_argument("--model", default=MODEL)
    p.add_argument("--replay", type=Path)
    p.add_argument("--evidence", type=Path, required=True)
    p.add_argument("--ledger", type=Path, default=ROOT/"evidence/llm-campaign/ledger.json")
    a=p.parse_args()
    b=Backend(a.backend, model=a.model, evidence=a.evidence, ledger=a.ledger, replay=a.replay)
    result=run_case(a.case,b,a.evidence)
    print(("PASS" if result["ok"] else "FAIL")+": "+a.case)
    for problem in result["problems"]: print(problem)
    return 0 if result["ok"] else 1

if __name__ == "__main__":
    sys.exit(main())
