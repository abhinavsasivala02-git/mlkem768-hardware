##############################################################################
# mlkem.sdc — timing constraints for mlkem_top (ML-KEM-768, FIPS 203)
#
# Plain SDC, readable by both flows:
#   Vivado : read_xdc syn/mlkem.sdc     (see syn/run_vivado_synth.tcl)
#   Genus  : read_sdc syn/mlkem.sdc     (see syn/run_genus.tcl)
#
# Only SDC commands accepted by both tools are used. Anything tool-specific
# (set_db, config_timing_analysis, report options) belongs in the run script.
#
# mlkem_top ports: clk, rst_n, s_axi_* (AXI4-Lite slave), irq_done.
# Single clock domain — mlkem_core, the K-PKE blocks, the Keccak engines and
# the AXI interface are all clocked by `clk`. `rst_n` is an asynchronous
# active-low reset.
##############################################################################

#-----------------------------------------------------------------------------
# 1. Clock
#-----------------------------------------------------------------------------
# 10.0 ns = 100 MHz. Change this value to retarget the frequency, or set
# CLK_PERIOD_NS before reading this file (run_vivado_synth.tcl does that from
# its command line) to sweep the period without editing constraints.
if {![info exists CLK_PERIOD_NS]} {
    set CLK_PERIOD_NS 10.0
}

create_clock -name clk -period $CLK_PERIOD_NS [get_ports clk]

# Pre-CTS allowance for skew and jitter; replace with measured numbers after
# the clock tree is built.
set_clock_uncertainty [expr {$CLK_PERIOD_NS * 0.05}] [get_clocks clk]

#-----------------------------------------------------------------------------
# 2. I/O timing — AXI4-Lite
#-----------------------------------------------------------------------------
# Budget 30% of the period at each boundary so the block still closes when
# dropped into a larger SoC. Ports are listed explicitly rather than via
# all_inputs/all_outputs so that `clk` is never given an input delay and the
# constraints read identically in Vivado and Genus.
set IN_DELAY  [expr {$CLK_PERIOD_NS * 0.30}]
set OUT_DELAY [expr {$CLK_PERIOD_NS * 0.30}]

set axi_inputs [get_ports {                     \
    s_axi_awaddr[*]  s_axi_awvalid              \
    s_axi_wdata[*]   s_axi_wstrb[*] s_axi_wvalid \
    s_axi_bready                                \
    s_axi_araddr[*]  s_axi_arvalid              \
    s_axi_rready                                \
}]

set axi_outputs [get_ports {                    \
    s_axi_awready    s_axi_wready               \
    s_axi_bresp[*]   s_axi_bvalid               \
    s_axi_arready                               \
    s_axi_rdata[*]   s_axi_rresp[*] s_axi_rvalid \
}]

set_input_delay  -clock clk $IN_DELAY  $axi_inputs
set_output_delay -clock clk $OUT_DELAY $axi_outputs

# irq_done is a level-sensitive interrupt sampled by a CPU, not a timed
# handshake, but it still leaves the block synchronously.
set_output_delay -clock clk $OUT_DELAY [get_ports irq_done]

#-----------------------------------------------------------------------------
# 3. Reset
#-----------------------------------------------------------------------------
# rst_n is asserted and released asynchronously by external logic, so it is
# not a timed path. Synchronize its release outside this block if a clean
# recovery/removal check is required.
set_false_path -from [get_ports rst_n]

#-----------------------------------------------------------------------------
# 4. Notes on the expected critical path
#-----------------------------------------------------------------------------
# The worst path should land in one of:
#   keccak_round / keccak_f1600 : one full Keccak-f[1600] round per cycle —
#                                 theta - rho - pi - chi - iota across the
#                                 1600-bit state. Widest logic cone by far.
#   ntt_butterfly               : multiply + Montgomery reduce + add/sub
#   poly_basemul                : two multiplies plus a reduction
#
# If timing fails, pipeline keccak_round first (e.g. split after theta), or
# process half a round per cycle. That costs 2x cycles on every hash but the
# hash engines are not the throughput bottleneck for KeyGen/Encaps/Decaps.
