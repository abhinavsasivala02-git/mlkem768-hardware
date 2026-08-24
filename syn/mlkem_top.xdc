#=============================================================================
# ML-KEM-768 (FIPS 203) — Constraint file
#
# Target : ML-KEM-768 (K=3, ETA1=2, ETA2=2, DU=10, DV=4)
# Tool   : Xilinx Vivado (XDC)
# Top    : mlkem_top
#
# Clock  : 100 MHz (10.0 ns)
# Reset  : rst_n  — asynchronous, active-low
# I/F    : AXI4-Lite slave (8-bit address, 32-bit data) + irq_done
#
# Adjust CLK_PERIOD/IO delays to match your design target before use.
#=============================================================================

#--- 1. Clock ----------------------------------------------------------------
create_clock -name clk -period 10.000 -waveform {0.000 5.000} [get_ports clk]

# Optional: define the clock to the AXI interface explicitly (same physical clk)
# set_clock_groups -asynchronous -group [get_clocks clk]

# Clock uncertainty / jitter margin (clock network + PLL jitter)
set_clock_uncertainty 0.100 [get_clocks clk]

#--- 2. Asynchronous reset ---------------------------------------------------
# rst_n is sampled asynchronously (in the `always @(posedge clk or negedge rst_n)`
# reset blocks), so it must not be timed as a synchronous path.
set_false_path -from [get_ports rst_n]

#--- 3. Input delays (data arrives after the AXI host's clock edge) ----------
# Reference the external AXI4-Lite master's clock. If the host runs on the same
# `clk`, remove the `-clock` and use a relative input delay instead.
set_input_delay  -clock clk -max 2.000 [get_ports -filter {DIR == IN}]
set_input_delay  -clock clk -min 0.000 [get_ports -filter {DIR == IN}]

# Tighter/explicit AXI input delays (optional, overrides the blanket above):
# set_input_delay  -clock clk -max 1.500 [get_ports s_axi_*]
# set_input_delay  -clock clk -min 0.000 [get_ports s_axi_*]

#--- 4. Output delays --------------------------------------------------------
set_output_delay -clock clk -max 3.000 [get_ports -filter {DIR == OUT}]
set_output_delay -clock clk -min 0.000 [get_ports -filter {DIR == OUT}]

#--- 5. AXI4-Lite handshake paths (max/min cycle relaxations) ----------------
# AW/W/AR channels are typically not on the critical timing path; allow 2 cycles.
set_multicycle_path 2 -setup -from [get_ports s_axi_awvalid]
set_multicycle_path 2 -setup -from [get_ports s_axi_wvalid]
set_multicycle_path 2 -setup -from [get_ports s_axi_arvalid]

# Present the response/data one cycle after the request for the read channel.
set_multicycle_path 1 -setup -to [get_ports s_axi_rvalid]
set_multicycle_path 1 -hold  -to [get_ports s_axi_rvalid]

#--- 6. Clock-to-output on the interrupt (can be relaxed) --------------------
set_max_delay -datapath_only 10.000 -from [get_clocks clk] -to [get_ports irq_done]

#--- 7. Memory / datapath notes ----------------------------------------------
# The EK/DK/CT buffers are implemented as distributed registers
# (reg [7:0] ek_mem [0:...], etc.) in mlkem_top.v. For large ASIC/FPGA area
# savings, target them to block RAM with a `--shreg`/RAM inference (not required
# for functionality; the registers are synchronous single-port).
#
# The 1600-bit Keccak state and the polynomial RAMs are inferred as registers,
# and the NTT twiddle ROM (ntt_rom.v) is inferred as a distributed ROM.

#--- 8. Place & route (optional) ---------------------------------------------
# set_property PACKAGE_PIN <pin> [get_ports clk]      ;# map top-level ports
# set_property IOSTANDARD LVCMOS33 [get_ports {clk rst_n s_axi_* irq_done}]

#--- End of constraints -------------------------------------------------------
