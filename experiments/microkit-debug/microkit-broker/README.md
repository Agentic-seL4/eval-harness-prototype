# Microkit broker

**In progress:** paper 1's email example (Leaky / Fenced Summariser) as an seL4 Microkit
system on QEMU. A broker PD holds the monitor; a scripted worker PD plays the
injected model; the sink's output is what the attacker sees.

The email example runs end to end on QEMU (T7): the runner executes the plan, the
worker obeys the email, the broker decides and the sink records what the attacker
sees. Under the open policy the secret leaks; under the fenced policy it does not.
All 16 configurations of the email-fence demo print exactly what `core.py` predicts
(T8, `make matrix`), also when the attacker sends the email over TCP (T8b,
`make matrix INPUT=tcp`). See the [plan and task list](PLAN.md), the
[information-flow design](DESIGN.md), the [protocol and trace format](PROTOCOL.md)
and the [work log](LOG.md).

- The secret is a text file, placed at build time into a read-only region that only
  the broker maps. The email is either built in the same way, or sent at run time
  over TCP to QEMU's second UART, driven by the untrusted `net` PD.
- Expected traces come from the [email-fence replay](../email-fence/).
- Design background: [note 05](../../notes/05_microkit-mapping/).
- Write-up for the team: [note 06](../../notes/06_microkit-prototype/report.pdf).

## Set up and check the toolchain

Tested on macOS on Apple silicon; Linux needs the equivalent packages (untested). Four
steps, about ten minutes, mostly downloads. Nothing is installed inside the repository.

**1. Apple's command-line tools and two Homebrew packages.** If you don't have
[Homebrew](https://brew.sh), install it first.

```bash
xcode-select --install      # Apple clang, make and python3; skip if already installed
brew install qemu lld       # the QEMU emulator and the LLVM linker
```

Apple's `clang` compiles everything; only the linker and QEMU are missing from a stock
Mac. The scripts need Python 3.9 or newer, which Apple's `python3` provides.

**2. Download the Microkit SDK.** It is not on Homebrew: it is a download from the
seL4 project's [Microkit 2.3.1 release](https://github.com/seL4/microkit/releases/tag/2.3.1).
On Apple silicon use `microkit-sdk-2.3.1-macos-aarch64.tar.gz` (73 MB); on another
host, the tarball for your system. Unpack it anywhere outside the repository, for
example in `~/tools`:

```bash
mkdir -p ~/tools && cd ~/tools
curl -LO https://github.com/seL4/microkit/releases/download/2.3.1/microkit-sdk-2.3.1-macos-aarch64.tar.gz
shasum -a 256 microkit-sdk-2.3.1-macos-aarch64.tar.gz
# should print 359c2172f789267e55f651106c8a7e87b2f2b94b5284b111daf09f3181a09475
tar xf microkit-sdk-2.3.1-macos-aarch64.tar.gz      # creates ~/tools/microkit-sdk-2.3.1/
```

**3. Tell the build where the SDK is.** `MICROKIT_SDK` must name the unpacked folder,
the one containing `VERSION`, `bin/` and `board/`. Use your own path; there is no
default:

```bash
export MICROKIT_SDK="$HOME/tools/microkit-sdk-2.3.1"
```

This lasts only for the current terminal. To keep it, add the same line to
`~/.zshrc` and open a new terminal. Elsewhere in this README and in
[DEMO.md](DEMO.md), `/path/to/microkit-sdk-2.3.1` stands for this folder.

**4. Check the setup.** From this directory:

```bash
scripts/check-env.sh
```

It prints the tool versions, builds the SDK's `hello` example for
`qemu_virt_aarch64` (debug) with `clang` and `ld.lld`, boots it on QEMU, and ends with
`== environment OK`, in a few seconds. Output goes to the ignored `build/`
directory. Then `make test` (about 20 seconds) runs everything, including every
configuration on QEMU.

**If something goes wrong**

| Message | Cause and fix |
|---|---|
| `cd: /path/to/microkit-sdk-2.3.1: No such file or directory` | `MICROKIT_SDK` still holds the example path, or a folder that doesn't exist. Set it to your unpacked SDK (step 3). |
| `Set MICROKIT_SDK to the unpacked Microkit SDK 2.3.1 directory` | Not set in this terminal (step 3). |
| `missing: ld.lld` or `missing: qemu-system-aarch64` | Step 1. |
| `warning: expected Microkit SDK 2.3.1, found …` | A different SDK version. The prototype is pinned to 2.3.1. |
| macOS refuses to run `bin/microkit` ("cannot be opened") | The download was quarantined, as can happen when it comes through a browser. Clear the flag: `xattr -dr com.apple.quarantine "$MICROKIT_SDK"`. |
| The TCP demo can't listen on port 4444 inside Claude Code | Claude Code's sandbox blocks local listening; set `sandbox.network.allowLocalBinding: true`. |

`scripts/run_qemu.py IMAGE --until TEXT` boots any Microkit image and stops QEMU
when `TEXT` appears or the timeout expires.

## Build and boot

```bash
export MICROKIT_SDK=/path/to/microkit-sdk-2.3.1   # your unpacked SDK (step 3 above)
make                       # POLICY=fenced MODE=injected SECRET=1 EMAIL=malicious INBOX=allowed
make run                   # boot until the plan finishes (DONE)
make POLICY=open run       # the same email with the open policy: watch for OBS
make matrix                # all 16 configurations against core.py (about 5 s); report in build/matrix/
make matrix INPUT=tcp      # the same with the email sent over TCP; report in build/matrix-tcp/
make demo                  # a narrated walk-through for a live demo (see DEMO.md)
make preflight             # before a live demo: check, build and run everything DEMO.md uses (~15 s)
make bypass                # confinement tests (T9): misbehaving workers, each stopped
make check-topology        # broker.system against flow-policy.json (every build runs it)
make MICROKIT_CONFIG=release INPUT=tcp POLICY=open all   # a release build: silent console (DESIGN.md §12)
make test                  # host tests; also runs all 16 configurations on QEMU if MICROKIT_SDK is set
```

For a live presentation, [DEMO.md](DEMO.md) is a presenter's guide: the leak, the
fence, the same over a live TCP connection, and the confinement tests, each one
command. `make bypass` boots a worker per attempt (undeclared channel, read-only and
unmapped memory, forged caller, malformed request, and an un-injected leak) and shows
what stops each; see [DESIGN.md](DESIGN.md) section 11.

Each configuration builds in `build/<policy>-<mode>-s<secret>-<email>-<inbox>/`
(with `-tcp` appended for TCP input).

## Send the email yourself, over TCP

```bash
make INPUT=tcp POLICY=open run      # terminal 1: the analyst's console; waits for the email
nc 127.0.0.1 4444                   # terminal 2: the attacker; type or paste the email, press Enter
```

Paste the line from `fixtures/email-malicious.txt`. Terminal 1 shows the whole trace.
Terminal 2 receives only what the attacker sees: `OBS {"tool":"Fetch","args":["Data 1"]}`
under the open policy, nothing under the fenced one. Keep `nc` open until the reply
arrives: QEMU drops the connection once the client stops sending, so a piped one-shot
`nc` misses the reply. `make INPUT=tcp SEND=1 run` sends the fixture email for you
and prints the reply as `attacker< …`. `PORT=…` changes the port.
`make compile_flags.txt` writes include paths for clangd (ignored by Git).

## Files so far

| Path | Contents |
|---|---|
| `broker.system`, `Makefile` | The Microkit system description and the build |
| `flow-policy.json`, `scripts/check_topology.py` | The intended information flow, and the static checker that compares the description with it ([DESIGN.md §6](DESIGN.md)) |
| `scripts/check_built_caps.py` | Checks the capability tables the Microkit tool built against the same policy, after every build ([DESIGN.md §12](DESIGN.md)) |
| `src/` | The five PDs (`net.c` drives the second UART); the monitor (`monitor.c`, tested on the host against `core.py`); the trace writer, channel identifiers and helpers |
| `include/protocol.h` | Opcodes, replies, tools, limits and shared-memory layouts for the PDs |
| `fixtures/` | The secrets and emails as one-line text files, and their formal values |
| `scripts/make_prefill.py` | Writes the `secret` and `inbox` region contents from the fixtures |
| `scripts/expected.py` | Expected trace records per configuration, computed by `email-fence/core.py`; the comparison |
| `scripts/run_matrix.py` | Builds and boots all configurations, compares them, and reports whether the attacker can tell the secrets apart |
| `scripts/run_bypass.py`, `DEMO.md` | The confinement tests (T9) and the live-demo guide |
| `scripts/demo.py` | `make demo`: a narrated leak / fence / confinement walk-through |
| `scripts/run_qemu.py`, `scripts/check-env.sh` | Boot an image on QEMU, optionally with the attacker's TCP port; check the toolchain |
| `tests/` | `make test`: protocol, topology and monitor checks, and boots on QEMU when `MICROKIT_SDK` is set (needs the sibling `email-fence/`) |

`python3 scripts/expected.py --fixtures fenced-injected-s1-malicious-allowed` shows what
the system must print for one configuration; `--list` names all 16.
