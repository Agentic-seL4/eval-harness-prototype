#!/usr/bin/env python3
"""Boot a Microkit image on QEMU virt (AArch64) and stop it when done.

A Microkit system never exits, so this runner stops QEMU once the expected text
appears on the console or the timeout expires. Exit status: 0 if the text was seen,
1 on timeout, 2 if QEMU stopped first.

QEMU always gets a second serial port (the second PL011 UART, driven by the net
PD). By default it is unconnected. With --net-port it listens on 127.0.0.1:PORT:
the attacker's connection. Connect with `nc 127.0.0.1 PORT`, or let this script
connect and send a file with --send; what comes back on the socket is printed
with the prefix "attacker< ".
"""
import argparse
import os
import select
import socket
import subprocess
import sys
import time
from pathlib import Path


def qemu_command(image, smp=1, net_port=None):
    # From the Microkit 2.3.1 manual, section "QEMU virt (AArch64)".
    second = "null" if net_port is None else "tcp:127.0.0.1:{},server=on,wait=off".format(net_port)
    command = ["qemu-system-aarch64", "-machine", "virt,virtualization=on",
               "-cpu", "cortex-a53", "-nographic", "-serial", "mon:stdio", "-serial", second,
               "-device", "loader,file={},addr=0x70000000,cpu-num=0".format(image),
               "-m", "size=2G"]
    return command + (["-smp", str(smp)] if smp > 1 else [])


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def connect(port, deadline):
    while time.monotonic() < deadline:
        try:
            return socket.create_connection(("127.0.0.1", port), timeout=1)
        except OSError:
            time.sleep(0.05)
    raise TimeoutError("QEMU did not accept a connection on port {}".format(port))


def _show_attacker(chunk):
    for line in chunk.decode(errors="replace").splitlines():
        sys.stdout.write("attacker< " + line + "\n")
    sys.stdout.flush()


def _run(image, until, timeout, smp, echo, net_port, send, send_after, until_attacker=None):
    process = subprocess.Popen(qemu_command(image, smp, net_port), stdin=subprocess.DEVNULL,
                               stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    console, received = b"", b""
    status = 1
    deadline = time.monotonic() + timeout
    attacker = None
    try:
        if send is not None:
            attacker = connect(net_port, deadline)
            attacker.setblocking(False)
        while time.monotonic() < deadline:
            if attacker is not None and send and (send_after is None or send_after.encode() in console):
                attacker.sendall(send)
                send = b""
            sources = [process.stdout] + ([attacker] if attacker is not None else [])
            ready, _, _ = select.select(sources, [], [], 0.2)
            if attacker is not None and attacker in ready:
                chunk = attacker.recv(4096)
                received += chunk
                if echo and chunk:
                    _show_attacker(chunk)
                # A release build prints nothing on the console; stop on the socket instead.
                if until_attacker is not None and until_attacker.encode() in received:
                    status = 0
                    break
            if process.stdout not in ready:
                continue
            chunk = os.read(process.stdout.fileno(), 4096)
            if not chunk:
                status = 2
                break
            console += chunk
            if echo:
                sys.stdout.write(chunk.decode(errors="replace"))
                sys.stdout.flush()
            if until is not None and until.encode() in console:
                status = 0
                # Let the rest of the same burst arrive, on both channels. The net PD
                # has the lowest priority, so the attacker's reply may come after DONE.
                time.sleep(0.3)
                for source in sources:
                    while select.select([source], [], [], 0)[0]:
                        chunk = os.read(source.fileno(), 4096) if source is process.stdout else source.recv(4096)
                        if not chunk:
                            break
                        if source is process.stdout:
                            console += chunk
                            if echo:
                                sys.stdout.write(chunk.decode(errors="replace"))
                        else:
                            received += chunk
                            if echo:
                                _show_attacker(chunk)
                break
    finally:
        if attacker is not None:
            attacker.close()
        process.kill()
        process.wait()
        process.stdout.close()
    return status, console.decode(errors="replace"), received.decode(errors="replace")


def run(image, until=None, timeout=30.0, smp=1, echo=True):
    """Boot with the second UART unconnected. Returns (status, console output)."""
    status, console, _ = _run(image, until, timeout, smp, echo, None, None, None)
    return status, console


def run_with_socket(image, send, until=None, timeout=30.0, send_after=None, echo=False, port=None,
                    until_attacker=None):
    """Boot with the second UART on a TCP socket; connect, send `send` (bytes) once
    `send_after` appears on the console, and collect what comes back. Stops when
    `until` appears on the console or `until_attacker` on the socket.
    Returns (status, console output, socket output)."""
    return _run(image, until, timeout, 1, echo, port or free_port(), send, send_after, until_attacker)


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("image", type=Path)
    parser.add_argument("--until", help="stop once this text appears on the console")
    parser.add_argument("--timeout", type=float, default=30.0)
    parser.add_argument("--smp", type=int, default=1)
    parser.add_argument("--log", type=Path, help="also write the console output here")
    parser.add_argument("--net-port", type=int, help="second UART listens on 127.0.0.1:PORT")
    parser.add_argument("--send", type=Path, help="with --net-port: connect, send this file, show replies")
    parser.add_argument("--until-attacker", help="with --send: stop once this text arrives on the socket")
    args = parser.parse_args()
    if not args.image.is_file():
        parser.error("no such image: {}".format(args.image))
    if args.send and not args.net_port:
        parser.error("--send needs --net-port")
    send = None
    if args.send:
        send = args.send.read_bytes()
        if not send.endswith(b"\n"):
            send += b"\n"
    elif args.net_port:
        print("run_qemu: the attacker's port is 127.0.0.1:{}; connect with: nc 127.0.0.1 {}".format(
            args.net_port, args.net_port), file=sys.stderr)
    status, console, _ = _run(args.image, args.until, args.timeout, args.smp, True, args.net_port, send, None,
                              args.until_attacker)
    if args.log:
        args.log.write_text(console)
    if status == 1 and args.until:
        print("\nrun_qemu: timed out after {}s without {!r}".format(args.timeout, args.until), file=sys.stderr)
    elif status == 2:
        print("\nrun_qemu: QEMU stopped before the expected output", file=sys.stderr)
    sys.exit(status if (args.until or args.until_attacker) else 0)


if __name__ == "__main__":
    main()
