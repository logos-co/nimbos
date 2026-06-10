# Copyright (c) 2026 Status Research & Development GmbH. Licensed under
# either of:
# - Apache License, version 2.0
# - MIT license
# at your option. This file may not be copied, modified, or distributed except
# according to those terms.

SHELL := bash # the shell used internally by "make"

# used inside the included makefiles
BUILD_SYSTEM_DIR := vendor/nimbus-build-system

# we set its default value before LOG_LEVEL is used in "variables.mk"
LOG_LEVEL := DEBUG

# used by Make targets that launch a beacon node
RUNTIME_LOG_LEVEL := INFO

LINK_PCRE := 0

# we don't want an error here, so we can handle things later, in the ".DEFAULT" target
-include $(BUILD_SYSTEM_DIR)/makefiles/variables.mk

NODE_ID := 0
BASE_PORT := 9000
BASE_REST_PORT := 5052
BASE_METRICS_PORT := 8008
# WARNING: Use lazy assignment to allow CI to override.
EXECUTOR_NUMBER ?= 0

CPU_LIMIT := 0
BUILD_END_MSG := "\\x1B[92mBuild completed successfully:\\x1B[39m"

TEST_MODULES_FLAGS := -d:chronicles_log_level=TRACE -d:chronicles_sinks=json[file]

ifeq ($(CPU_LIMIT), 0)
	CPU_LIMIT_CMD :=
else
	CPU_LIMIT_CMD := cpulimit --limit=$(CPU_LIMIT) --foreground --
endif

# TODO: move this to nimbus-build-system
ifeq ($(shell uname), Darwin)
	# Scary warnings in large volume: https://github.com/status-im/nimbus-eth2/issues/3076
	SILENCE_WARNINGS := 2>&1 | grep -v "failed to insert symbol" | grep -v "could not find object file symbol for symbol" || true
else
	SILENCE_WARNINGS :=
endif

TOOLS_CORE := \
	version

# The TOOLS/TOOLS_CORE decomposition is a workaround so logos_chain_node can
# build on its own, and if/when that becomes a non-issue, it can be recombined
# to a single TOOLS list.
TOOLS := $(TOOLS_CORE) logos_chain_node
.PHONY: $(TOOLS)

TOOLS_DIRS := \
	logos_chain
TOOLS_CSV := $(subst $(SPACE),$(COMMA),$(TOOLS))

.PHONY: \
	all \
	deps \
	update \
	test \
	clean \
	libbacktrace \
	dist-amd64 \
	dist-arm64 \
	dist-arm \
	dist-win64 \
	dist-macos-arm64 \
	dist

# TODO: Add the installer packages here
PLATFORM_SPECIFIC_TARGETS :=

# MSYS_NO_PATHCONV=1: On Windows MSYS2, 1st path gets mangled without this flag!
GIT_SUBMODULE_ENV := MSYS_NO_PATHCONV=1

ifeq ($(NIM_PARAMS),)
# "variables.mk" was not included, so we update the submodules.
#
# The `git reset ...` will try to fix a `make update` that was interrupted
# with Ctrl+C after deleting the working copy and before getting a chance to
# restore it in $(BUILD_SYSTEM_DIR).

# Some vendor submodules use Git LFS; require it up front for clearer errors.
ifeq (, $(shell which git-lfs))
ifeq ($(shell uname), Darwin)
$(error Git LFS not installed. Run 'brew install git-lfs' to set up)
else
$(error Git LFS not installed)
endif
endif

GIT_SUBMODULE_UPDATE := $(GIT_SUBMODULE_ENV) git submodule update --init --recursive
.DEFAULT:
	+@ echo -e "Git submodules not found. Running '$(GIT_SUBMODULE_UPDATE)'.\n"; \
		$(GIT_SUBMODULE_UPDATE) && \
		$(GIT_SUBMODULE_ENV) git submodule foreach --quiet 'git reset --quiet --hard' && \
		echo
# Now that the included *.mk files appeared, and are newer than this file, Make will restart itself:
# https://www.gnu.org/software/make/manual/make.html#Remaking-Makefiles
#
# After restarting, it will execute its original goal, so we don't have to start a child Make here
# with "$(MAKE) $(MAKECMDGOALS)". Isn't hidden control flow great?

else # "variables.mk" was included. Business as usual until the end of this file.

# default target, because it's the first one that doesn't start with '.'
# Also build logos-bindings (C bindings library + header) in CI.
all: | $(TOOLS) $(PLATFORM_SPECIFIC_TARGETS) logos-bindings

# must be included after the default target
-include $(BUILD_SYSTEM_DIR)/makefiles/targets.mk

DEPOSITS_DELAY := 0

#- "--define:release" cannot be added to "config.nims"
#- disable Nim's default parallelisation because it starts too many processes for too little gain
#- https://github.com/status-im/nim-libp2p#use-identify-metrics
NIM_PARAMS := -d:release --parallelBuild:1 -d:libp2p_agents_metrics -d:KnownLibP2PAgents=nimbus,lighthouse,lodestar,prysm,teku,grandine -d:libp2p_quic_support $(NIM_PARAMS)

ifeq ($(USE_LIBBACKTRACE), 0)
NIM_PARAMS += -d:disable_libbacktrace
endif

deps: | deps-common nat-libs build/generate_makefile
ifneq ($(USE_LIBBACKTRACE), 0)
deps: | libbacktrace
endif

#- deletes binaries that might need to be rebuilt after a Git pull
update: | update-common
	rm -f build/generate_makefile
	rm -fr nimcache/

# nim-libbacktrace
libbacktrace:
	+ "$(MAKE)" -C vendor/nim-libbacktrace --no-print-directory BUILD_CXX_LIB=0

UNIT_TEST_BASE_PORT := 29960
REST_TEST_BASE_PORT := 30990
MINIMAL_TESTNET_BASE_PORT := 25001
MAINNET_TESTNET_BASE_PORT := 26501

SIGNER_TYPE := nimbus

XML_TEST_BINARIES := \
	all_tests

# test suite
.PHONY: $(XML_TEST_BINARIES) force_build_alone_all_tests

ifneq (,$(filter test,$(MAKECMDGOALS)))
FORCE_BUILD_ALONE_ALL_TESTS_DEPS := $(XML_TEST_BINARIES_CORE) $(TEST_BINARIES)
else
FORCE_BUILD_ALONE_ALL_TESTS_DEPS :=
endif
force_build_alone_all_tests: | $(FORCE_BUILD_ALONE_ALL_TESTS_DEPS)

all_tests: | build deps force_build_alone_all_tests
	+ echo -e $(BUILD_MSG) "build/$@" && \
		MAKE="$(MAKE)" V="$(V)" $(ENV_SCRIPT) scripts/compile_nim_program.sh \
			$@ \
			"tests/$@.nim" \
			$(NIM_PARAMS) $(TEST_MODULES_FLAGS) && \
		echo -e $(BUILD_END_MSG) "build/$@"

# This parameter passing scheme is ugly, but short.
test: | $(XML_TEST_BINARIES) $(TEST_BINARIES)
	for TEST_BINARY in $(XML_TEST_BINARIES); do \
		PARAMS="--xml:build/$${TEST_BINARY}.xml --console"; \
		echo -e "\nRunning $${TEST_BINARY} $${PARAMS}\n"; \
		NIMBUS_TEST_KEYMANAGER_BASE_PORT=$$(( $(UNIT_TEST_BASE_PORT) + EXECUTOR_NUMBER * 6 + 0 )) \
		NIMBUS_TEST_SIGNING_NODE_BASE_PORT=$$(( $(UNIT_TEST_BASE_PORT) + EXECUTOR_NUMBER * 6 + 4 )) \
			build/$${TEST_BINARY} $${PARAMS} || { \
				echo -e "\n$${TEST_BINARY} $${PARAMS} failed; Last 5000 lines from the log:"; \
				tail -n5000 "$${TEST_BINARY}.log"; exit 1; \
			}; \
		done; \
		rm -rf 0000-*.json t_slashprot_migration.* *.log block_sim_db
	for TEST_BINARY in $(TEST_BINARIES); do \
		PARAMS=""; \
		REDIRECT=""; \
		if [[ "$${TEST_BINARY}" == "block_sim" ]]; then PARAMS="--validators=10000 --slots=192"; \
		fi; \
		echo -e "\nRunning $${TEST_BINARY} $${PARAMS}\n"; \
		if [[ "$${REDIRECT}" != "" ]]; then \
			build/$${TEST_BINARY} $${PARAMS} > "$${REDIRECT}" && echo "OK" || { \
				echo -e "\n$${TEST_BINARY} $${PARAMS} failed; Last 5000 lines from the log:"; \
				tail -n5000 "$${TEST_BINARY}.log"; exit 1; \
			}; \
		else \
			build/$${TEST_BINARY} $${PARAMS} || { \
				echo -e "\n$${TEST_BINARY} $${PARAMS} failed; Last 5000 lines from the log:"; \
				tail -n5000 "$${TEST_BINARY}.log"; exit 1; \
			}; \
		fi; \
		done; \
		rm -rf 0000-*.json t_slashprot_migration.* *.log block_sim_db

# It's OK to only build this once. `make update` deletes the binary, forcing a rebuild.
ifneq ($(USE_LIBBACKTRACE), 0)
build/generate_makefile: | libbacktrace
endif
build/generate_makefile: tools/generate_makefile.nim | deps-common
	+ echo -e $(BUILD_MSG) "$@" && \
	$(ENV_SCRIPT) $(NIMC) c -o:$@ $(NIM_PARAMS) tools/generate_makefile.nim $(SILENCE_WARNINGS) && \
	echo -e $(BUILD_END_MSG) "$@"

# GCC's LTO parallelisation is able to detect a GNU Make jobserver and get its
# maximum number of processes from there, but only if we use the "+" prefix.
# Without it, it will default to the number of CPU cores, which can be a
# problem on low-memory systems.
# It also requires Make to pass open file descriptors to the GCC process,
# which is not possible if we let Nim handle this, so we generate and use a
# makefile instead.
$(filter-out $(TOOLS_CORE_CUSTOMCOMPILE),$(TOOLS)): | build deps
	+ for D in $(TOOLS_DIRS); do [ -e "$${D}/$@.nim" ] && TOOL_DIR="$${D}" && break; done && \
		echo -e $(BUILD_MSG) "build/$@" && \
		MAKE="$(MAKE)" V="$(V)" $(ENV_SCRIPT) scripts/compile_nim_program.sh $@ "$${TOOL_DIR}/$@.nim" $(NIM_PARAMS) && \
		echo -e $(BUILD_END_MSG) "build/$@"

ifneq (,$(filter all,$(MAKECMDGOALS)))
FORCE_BUILD_ALONE_TOOLS_DEPS := $(TOOLS_CORE)
else ifeq (,$(MAKECMDGOALS))
FORCE_BUILD_ALONE_TOOLS_DEPS := $(TOOLS_CORE)
else
FORCE_BUILD_ALONE_TOOLS_DEPS :=
endif
.PHONY: force_build_alone_tools
force_build_alone_tools: | $(FORCE_BUILD_ALONE_TOOLS_DEPS)

# https://www.gnu.org/software/make/manual/html_node/Multiple-Rules.html#Multiple-Rules
# Already defined as a reult
logos_chain_node: force_build_alone_tools

###
### Other
###

.PHONY: logos-lib logos-headers logos-bindings

# Build C static library from logos_c_bindings.nim into the c_bindings folder
logos-lib: | build deps
	+ $(ENV_SCRIPT) $(NIMC) c $(NIM_PARAMS) \
		--verbosity:2 \
		--app:staticlib \
		--out:logos_chain/c_bindings/liblogos_blockchain.a \
		logos_chain/c_bindings/logos_c_bindings.nim

# Generate C header for the bindings into the c_bindings folder
# Depends on logos-lib so the two `nim c` invocations on logos_c_bindings.nim
# don't race on the shared nimcache/<cfg>/logos_c_bindings/ directory under `make -j`.
logos-headers: logos-lib | build deps
	+ $(ENV_SCRIPT) $(NIMC) c $(NIM_PARAMS) \
		--verbosity:2 \
		--compileOnly \
		--header:logos_chain/c_bindings/logos_c_bindings.h \
		logos_chain/c_bindings/logos_c_bindings.nim

# Convenience target: build both the static lib and the C header
logos-bindings: logos-lib logos-headers

ntu: | build deps
	mkdir -p vendor/.nimble/bin/
	+ $(ENV_SCRIPT) $(NIMC) -d:danger -o:vendor/.nimble/bin/ntu c vendor/nim-testutils/ntu.nim

clean: | clean-common
	rm -rf build/{$(TOOLS_CSV),all_tests,test_*,proto_array,fork_choice,*.a,*.so,*_node,*ssz*,nimbus_*,beacon_node*,block_sim,transition*,generate_makefile,nimbus-wix/obj}
ifneq ($(USE_LIBBACKTRACE), 0)
	+ "$(MAKE)" -C vendor/nim-libbacktrace clean $(HANDLE_OUTPUT)
endif

book:
	"$(MAKE)" -C docs book

dist-amd64:
	+ MAKE="$(MAKE)" \
		scripts/make_dist.sh amd64

dist-amd64-opt:
	+ MAKE="$(MAKE)" \
		scripts/make_dist.sh amd64-opt

dist-arm64:
	+ MAKE="$(MAKE)" \
		scripts/make_dist.sh arm64

dist-arm:
	+ MAKE="$(MAKE)" \
		scripts/make_dist.sh arm

dist-win64:
	+ MAKE="$(MAKE)" \
		scripts/make_dist.sh win64

dist-macos-arm64:
	+ MAKE="$(MAKE)" \
		scripts/make_dist.sh macos-arm64

dist:
	+ $(MAKE) dist-amd64
	+ $(MAKE) dist-amd64-opt
	+ $(MAKE) dist-arm64
	+ $(MAKE) dist-arm
	+ $(MAKE) dist-win64
	+ $(MAKE) dist-macos-arm64

#- Build and run benchmarks using an external repo (which can be used easily on
#  older commits, before this Make target was added).
#- It's up to the user to create a benchmarking environment that minimises the
#  results spread. We're showing a 95% CI bar to help visualise that.
benchmarks:
	+ vendor/nimbus-benchmarking/run_nbc_benchmarks.sh --output-type d3

endif # "variables.mk" was not included
