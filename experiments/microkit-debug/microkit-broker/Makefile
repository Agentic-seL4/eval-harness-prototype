# Microkit broker: build and boot one configuration (PROTOCOL.md section 6).
#
#   make [POLICY=fenced] [MODE=injected] [SECRET=1] [EMAIL=malicious] [INBOX=allowed] [INPUT=file]
#   make run        build, then boot on QEMU until the run finishes (UNTIL)
#   make INPUT=tcp run          the email arrives over TCP: connect with nc 127.0.0.1 $(PORT)
#   make INPUT=tcp SEND=1 run   ... or let the script send the fixture email
#   make matrix     build and boot all 16 configurations; compare with core.py (INPUT=tcp too)
#   make check-topology   check broker.system against flow-policy.json (also run by every build)
#   make test       host-side tests
#   make compile_flags.txt   include paths for clangd
#
# Needs MICROKIT_SDK (the unpacked Microkit SDK 2.3.1), clang, ld.lld,
# qemu-system-aarch64 and python3.

BACKEND ?= builtin
BACKEND_ID_builtin := 0
BACKEND_ID_host := 1
POLICY ?= fenced
MODE ?= injected
SECRET ?= 1
EMAIL ?= malicious
INBOX ?= allowed
INPUT ?= file
ATTACK ?= none
PORT ?= 4444

MICROKIT_BOARD := qemu_virt_aarch64
MICROKIT_CONFIG ?= debug
UNTIL ?= DONE {}
TIMEOUT ?= $(if $(filter tcp,$(INPUT)),$(if $(SEND),30,300),30)

# Map each value to the constants in src/config.h; an unknown value stops the build.
POLICY_ID_open := POLICY_OPEN
POLICY_ID_fenced := POLICY_FENCED
POLICY_ID_late := POLICY_LATE
MODE_ID_reference := MODE_REFERENCE
MODE_ID_injected := MODE_INJECTED
INBOX_ID_allowed := 1
INBOX_ID_denied := 0
# Confinement-test workers (T9); 'none' is the honest worker.
ATTACK_ID_none := ATTACK_NONE
ATTACK_ID_uninjected := ATTACK_UNINJECTED
ATTACK_ID_lib-channel := ATTACK_LIB_CHANNEL
ATTACK_ID_raw-sink := ATTACK_RAW_SINK
ATTACK_ID_forge-origin := ATTACK_FORGE_ORIGIN
ATTACK_ID_write-context := ATTACK_WRITE_CONTEXT
ATTACK_ID_unmapped := ATTACK_UNMAPPED
ATTACK_ID_malformed := ATTACK_MALFORMED
check_value = $(if $(filter $(2),$(3)),,$(error $(1) must be one of: $(3)))
$(call check_value,BACKEND,$(BACKEND),builtin host)
ifeq ($(BACKEND),host)
ifneq ($(INPUT),file)
$(error BACKEND=host requires INPUT=file)
endif
ifneq ($(ATTACK),none)
$(error BACKEND=host requires ATTACK=none)
endif
endif
$(call check_value,POLICY,$(POLICY),open fenced late)
$(call check_value,MODE,$(MODE),reference injected)
$(call check_value,SECRET,$(SECRET),0 1)
$(call check_value,EMAIL,$(EMAIL),malicious benign)
$(call check_value,INBOX,$(INBOX),allowed denied)
$(call check_value,INPUT,$(INPUT),file tcp)
$(call check_value,MICROKIT_CONFIG,$(MICROKIT_CONFIG),debug release)
$(call check_value,ATTACK,$(ATTACK),none uninjected lib-channel raw-sink forge-origin write-context unmapped malformed)

NAME := $(POLICY)-$(MODE)-s$(SECRET)-$(EMAIL)-$(INBOX)$(if $(filter tcp,$(INPUT)),-tcp,)$(if $(filter-out none,$(ATTACK)),-$(ATTACK),)$(if $(filter-out debug,$(MICROKIT_CONFIG)),-$(MICROKIT_CONFIG),)
BUILD_DIR ?= build/$(NAME)$(if $(filter host,$(BACKEND)),-host,)
SYSTEM := $(if $(filter host,$(BACKEND)),model.system,broker.system)
FLOW_POLICY := $(if $(filter host,$(BACKEND)),model-flow-policy.json,flow-policy.json)
TOPOLOGY := $(if $(filter host,$(BACKEND)),src/model_topology.h,src/topology.h)
IMAGE := $(BUILD_DIR)/loader.img

BOARD_DIR = $(MICROKIT_SDK)/board/$(MICROKIT_BOARD)/$(MICROKIT_CONFIG)
MICROKIT_TOOL = $(MICROKIT_SDK)/bin/microkit
CC := clang -target aarch64-none-elf
LD := ld.lld
PYTHON ?= python3

CFLAGS = -nostdlib -ffreestanding -g -O0 -fno-inline -fno-omit-frame-pointer -Wall -Wextra -Werror -mstrict-align \
         -Iinclude -Isrc -I$(BOARD_DIR)/include -DCFG_HOST_BACKEND=$(BACKEND_ID_$(BACKEND))
DEFS_broker := -DCFG_POLICY=$(POLICY_ID_$(POLICY)) -DCFG_INBOX_ALLOWED=$(INBOX_ID_$(INBOX))
DEFS_worker := -DCFG_MODE=$(MODE_ID_$(MODE)) -DCFG_ATTACK=$(ATTACK_ID_$(ATTACK))

PDS := sink broker runner worker net
COMMON := trace util mr
HEADERS := include/protocol.h $(wildcard src/*.h)

.PHONY: all run matrix bypass demo preflight test check-topology clean require-sdk
.SECONDARY:
all: $(IMAGE)

require-sdk:
	@test -n "$(MICROKIT_SDK)" || { echo "Set MICROKIT_SDK to the Microkit SDK 2.3.1 directory" >&2; exit 1; }
	@test -x "$(MICROKIT_TOOL)" || { echo "No Microkit tool at $(MICROKIT_TOOL)" >&2; exit 1; }

$(BUILD_DIR):
	mkdir -p $@

# Defines differ between configurations, so every configuration has its own objects.
ifeq ($(BACKEND),host)
$(BUILD_DIR)/net.o: src/model_link.c $(HEADERS) Makefile | require-sdk $(BUILD_DIR)
	$(CC) -c $(CFLAGS) $< -o $@
$(BUILD_DIR)/worker.elf: $(BUILD_DIR)/model_wire.o
endif

$(BUILD_DIR)/%.o: src/%.c $(HEADERS) Makefile | require-sdk $(BUILD_DIR)
	$(CC) -c $(CFLAGS) $(DEFS_$*) $< -o $@

$(BUILD_DIR)/%.elf: $(BUILD_DIR)/%.o $(addprefix $(BUILD_DIR)/,$(addsuffix .o,$(COMMON)))
	$(LD) -L$(BOARD_DIR)/lib $^ -lmicrokit -Tmicrokit.ld -o $@

# Broker uses a distinct code address for source debugging.
$(BUILD_DIR)/broker.elf: $(BUILD_DIR)/broker.o $(addprefix $(BUILD_DIR)/,$(addsuffix .o,$(COMMON))) $(BUILD_DIR)/monitor.o debug-broker.ld
	$(LD) -L$(BOARD_DIR)/lib $(filter %.o,$^) -lmicrokit -Tdebug-broker.ld -o $@

# Keep runner and worker code distinct from broker and other PDs for debugging.
$(BUILD_DIR)/runner.elf: $(BUILD_DIR)/runner.o $(addprefix $(BUILD_DIR)/,$(addsuffix .o,$(COMMON))) debug-runner.ld
	$(LD) -L$(BOARD_DIR)/lib $(filter %.o,$^) -lmicrokit -Tdebug-runner.ld -o $@

$(BUILD_DIR)/worker.elf: $(BUILD_DIR)/worker.o $(addprefix $(BUILD_DIR)/,$(addsuffix .o,$(COMMON))) debug-worker.ld
	$(LD) -L$(BOARD_DIR)/lib $(filter %.o,$^) -lmicrokit -Tdebug-worker.ld -o $@

$(BUILD_DIR)/secret.bin: fixtures/secret-$(SECRET).txt scripts/make_prefill.py | $(BUILD_DIR)
	$(PYTHON) scripts/make_prefill.py --secret $< --out $(BUILD_DIR)

# File input: the email is in the inbox from the start. TCP input: an empty mailbox
# that the net PD fills when the attacker sends a line.
ifeq ($(INPUT),tcp)
$(BUILD_DIR)/inbox.mbox: scripts/make_prefill.py | $(BUILD_DIR)
	$(PYTHON) scripts/make_prefill.py --empty-inbox --out $(BUILD_DIR)
else
$(BUILD_DIR)/inbox.mbox: fixtures/email-$(EMAIL).txt scripts/make_prefill.py | $(BUILD_DIR)
	$(PYTHON) scripts/make_prefill.py --email $< --out $(BUILD_DIR)
endif

# Checked twice: the description before the Microkit tool runs (check_topology.py),
# and the capability tables the tool actually built (check_built_caps.py, T10).
# An image that fails the second check is deleted.
$(IMAGE): $(SYSTEM) $(FLOW_POLICY) $(TOPOLOGY) scripts/check_topology.py \
        scripts/check_built_caps.py \
        $(addprefix $(BUILD_DIR)/,$(addsuffix .elf,$(PDS))) \
        $(BUILD_DIR)/secret.bin $(BUILD_DIR)/inbox.mbox | require-sdk
	$(PYTHON) scripts/check_topology.py --system $(SYSTEM) --policy $(FLOW_POLICY) --topology $(TOPOLOGY) > $(BUILD_DIR)/topology.txt || { cat $(BUILD_DIR)/topology.txt; exit 1; }
	rm -rf $(BUILD_DIR)/capabilities && mkdir -p $(BUILD_DIR)/capabilities
	$(MICROKIT_TOOL) $(SYSTEM) --search-path $(BUILD_DIR) --board $(MICROKIT_BOARD) \
	    --config $(MICROKIT_CONFIG) -o $@ -r $(BUILD_DIR)/report.txt \
	    --viper-output $(BUILD_DIR)/capabilities
	$(PYTHON) scripts/check_built_caps.py $(BUILD_DIR)/capabilities --system $(SYSTEM) --policy $(FLOW_POLICY) > $(BUILD_DIR)/capabilities.txt \
	    || { cat $(BUILD_DIR)/capabilities.txt; rm -f $@; exit 1; }

NET_ARGS = $(if $(filter tcp,$(INPUT)),--net-port $(PORT) $(if $(SEND),--send fixtures/email-$(EMAIL).txt),)

run: $(IMAGE)
ifeq ($(BACKEND),host)
	@echo "Use the host harness: uv run python -m host.harness (from the experiment root)."; exit 2
else
	$(PYTHON) scripts/run_qemu.py $(IMAGE) --until '$(UNTIL)' --timeout $(TIMEOUT) \
	    --log $(BUILD_DIR)/serial.log $(NET_ARGS)

endif

matrix: | require-sdk
	$(PYTHON) scripts/run_matrix.py --input $(INPUT)

# Confinement tests (T9): workers that misbehave on purpose; each is stopped.
bypass: | require-sdk
	$(PYTHON) scripts/run_bypass.py

# A narrated walk-through for a live demo (leak, fence, confinement).
demo: | require-sdk
	$(PYTHON) scripts/demo.py

# Before a live demo: check, build and run everything DEMO.md uses once.
preflight: | require-sdk
	scripts/preflight.sh $(PORT)

test:
	$(PYTHON) -m unittest discover -s tests -v

check-topology:
	$(PYTHON) scripts/check_topology.py

compile_flags.txt: Makefile | require-sdk
	printf '%s\n' --target=aarch64-none-elf -ffreestanding -Iinclude -Isrc \
	    -I$(BOARD_DIR)/include -DCFG_POLICY=POLICY_FENCED -DCFG_INBOX_ALLOWED=1 \
	    -DCFG_MODE=MODE_INJECTED > $@

clean:
	rm -rf build
