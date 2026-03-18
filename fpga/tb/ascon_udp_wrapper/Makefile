# Cocotb Makefile for ASCON UDP Wrapper Test
# Usage: make

# Simulator
SIM = verilator
TOPLEVEL_LANG = verilog

# Source files
VERILOG_SOURCES = \
    $(PWD)/ascon-verilog/rtl/ascon_core.sv \
    $(PWD)/ascon_udp_wrapper.sv

# Top-level module
TOPLEVEL = ascon_udp_wrapper

# Python test module (test_wrapper.py -> module name = test_wrapper)
MODULE = test_wrapper

# Verilator extra args
EXTRA_ARGS += --trace
EXTRA_ARGS += --timing
EXTRA_ARGS += -I$(PWD)/ascon-verilog/rtl
EXTRA_ARGS += -Wno-fatal

include $(shell cocotb-config --makefiles)/Makefile.sim
