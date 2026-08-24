##############################################################################
# ML-KEM-768 (FIPS 203) — Synopsys Design Constraints (SDC)
#
# Target : ML-KEM-768 (K=3, ETA1=2, ETA2=2, DU=10, DV=4)
# Tool   : Cadence Genus / Synopsys (read_sdc <this file>)
# Top    : mlkem_top
#
# Clock  : 100 MHz (10.0 ns)
# Reset  : rst_n  — asynchronous, active-low
# I/F    : AXI4-Lite slave (8-bit address, 32-bit data) + irq_done
#
# Adjust the period/delays to your process target. A matching Genus script
# (syn/syn_mlkem.tcl) drives this design; this SDC is equivalent to the inline
# constraints there and is kept standalone for reuse.
##############################################################################

#--- 1. Clock ----------------------------------------------------------------
create_clock -name clk -period 10.0 -waveform {0.0 5.0} [get_ports clk]
set_clock_uncertainty 0.20 [get_clocks clk]

# Single synchronous domain: AXI interface is clocked by the same `clk`.
set_clock_groups -asynchronous -group {clk}

#--- 2. Asynchronous reset ---------------------------------------------------
set_false_path -from [get_ports rst_n]

#--- 3. Input delays ---------------------------------------------------------
set_input_delay  -clock clk -max 1.5 [all_inputs]
set_input_delay  -clock clk -min 0.0 [all_inputs]

#--- 4. Output delays --------------------------------------------------------
set_output_delay -clock clk -max 2.0 [all_outputs]
set_output_delay -clock clk -min 0.0 [all_outputs]

#--- 5. AXI4-Lite multicycle relaxations ------------------------------------
set_multicycle_path 2 -setup -from [get_ports {s_axi_awvalid s_axi_wvalid s_axi_arvalid}]
set_multicycle_path 1 -setup -to   [get_ports {s_axi_rvalid s_axi_bvalid}]

#--- 6. Interrupt (can be relaxed, datapath-only) ---------------------------
set_max_delay -datapath_only 10.0 -to [get_ports irq_done]

#--- 7. Synthesis-relevant attributes ----------------------------------------
# The EK/DK/CT buffers are registers; allow them to be mapped to RAM/FF.
set_dont_touch [get_cells -hier -filter {NAME =~ */ek_mem/*}]
set_dont_touch [get_cells -hier -filter {NAME =~ */dk_mem/*}]
set_dont_touch [get_cells -hier -filter {NAME =~ */ct_mem/*}]

set_max_fanout 32 [all_inputs]

#--- End of SDC --------------------------------------------------------------
