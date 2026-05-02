# Cocotb Makefile for ASCON UDP Decrypt Wrapper Test
# Location: fpga/tb/ascon_udp_decrypt/ (or wherever you put it)
# Usage: make

SIM = verilator
TOPLEVEL_LANG = verilog

VERILOG_SOURCES = \
    $(PWD)/ascon-verilog/rtl/ascon_core.sv \
    $(PWD)/ascon_udp_decrypt.sv

TOPLEVEL = ascon_udp_decrypt
MODULE = test_decrypt_wrapper

EXTRA_ARGS += --trace
EXTRA_ARGS += --timing
EXTRA_ARGS += -I$(PWD)/ascon-verilog/rtl
EXTRA_ARGS += -Wno-fatal

include $(shell cocotb-config --makefiles)/Makefile.sim
