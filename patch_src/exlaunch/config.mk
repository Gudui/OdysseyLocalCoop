# Odyssey Local Co-op release build configuration.

LOAD_KIND := Module
PROGRAM_ID := 0100000000010000
ELF_EXTRACT :=
PYTHON := python3
NPDM_JSON := qlaunch.json
WINDOWS_PWD := $(shell command -v cygpath >/dev/null 2>&1 && cygpath -m "$(PWD)")
C_FLAGS := -g0 -ffile-prefix-map=$(PWD)=/workspace/exlaunch -fdebug-prefix-map=$(PWD)=/workspace/exlaunch -fmacro-prefix-map=$(PWD)=/workspace/exlaunch
ifneq ($(strip $(WINDOWS_PWD)),)
C_FLAGS += -ffile-prefix-map=$(WINDOWS_PWD)=/workspace/exlaunch -fdebug-prefix-map=$(WINDOWS_PWD)=/workspace/exlaunch -fmacro-prefix-map=$(WINDOWS_PWD)=/workspace/exlaunch
endif
CXX_FLAGS :=
