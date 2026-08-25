##############################################################################
# Cadence Genus Synthesis Script — ML-KEM-768 (FIPS 203)
#
# Target : ML-KEM-768 (K=3, ETA1=2, ETA2=2, DU=10, DV=4)
# Top    : mlkem_top
# Clock  : 100 MHz (10.0 ns)
# Reset  : rst_n (asynchronous, active-low)
#
# Usage  : cd syn && genus -f syn_mlkem.tcl      (run from the syn/ directory)
#
# NOTE   : The .xdc (Vivado) is intentionally not used here; this is the ASIC/
#          Genus flow only. Timing constraints are defined inline below for
#          robustness; a post-synthesis SDC is written to ./netlists.
##############################################################################

set DESIGN       mlkem_top
set RTL_DIR      ../rtl
set WORK_DIR     ./work
set REPORT_DIR   ./reports
set NETLIST_DIR  ./netlists

# --- Target library — update for your PDK -----------------------------------
set LIB_PATH     /path/to/pdk/libs
set LIB_NAME     typical.lib          ;# replace with actual cell library

# --- Clock / timing ---------------------------------------------------------
set CLK_NAME   clk
set CLK_PERIOD 10.0                   ;# 100 MHz
set IN_DELAY   1.5
set OUT_DELAY  2.0

file mkdir $WORK_DIR $REPORT_DIR $NETLIST_DIR

# --- Read RTL (hierarchy order; mlkem_hash_engine replaces the legacy
#     keccak_absorb_squeeze, which is intentionally omitted) ------------------
read_hdl -v2001 -include $RTL_DIR/pkg \
    $RTL_DIR/pkg/ntt_rom.v \
    $RTL_DIR/mem/poly_ram.v \
    $RTL_DIR/math/barrett_reduce.v \
    $RTL_DIR/math/montgomery_reduce.v \
    $RTL_DIR/math/modular_arith.v \
    $RTL_DIR/math/ntt_butterfly.v \
    $RTL_DIR/math/ntt.v \
    $RTL_DIR/math/intt.v \
    $RTL_DIR/math/poly_arith.v \
    $RTL_DIR/math/poly_basemul.v \
    $RTL_DIR/sample/sample_ntt.v \
    $RTL_DIR/sample/sample_cbd.v \
    $RTL_DIR/encode/byte_decode.v \
    $RTL_DIR/encode/byte_encode.v \
    $RTL_DIR/encode/compress.v \
    $RTL_DIR/encode/decompress.v \
    $RTL_DIR/keccak/keccak_round.v \
    $RTL_DIR/keccak/keccak_f1600.v \
    $RTL_DIR/keccak/mlkem_hash_engine.v \
    $RTL_DIR/keccak/shake128.v \
    $RTL_DIR/keccak/shake256.v \
    $RTL_DIR/keccak/sha3_256.v \
    $RTL_DIR/keccak/sha3_512.v \
    $RTL_DIR/kpke/kpke_keygen.v \
    $RTL_DIR/kpke/kpke_encrypt.v \
    $RTL_DIR/kpke/kpke_decrypt.v \
    $RTL_DIR/mlkem/mlkem_keygen.v \
    $RTL_DIR/mlkem/mlkem_encaps.v \
    $RTL_DIR/mlkem/mlkem_decaps.v \
    $RTL_DIR/mlkem/mlkem_axi_lite_if.v \
    $RTL_DIR/mlkem/mlkem_core.v \
    $RTL_DIR/mlkem/mlkem_top.v

# --- Elaborate ---------------------------------------------------------------
elaborate $DESIGN -parameters {K=3 ETA1=2 ETA2=2 DU=10 DV=4}
check_design -all
uniquify

# --- Read library ------------------------------------------------------------
read_libs $LIB_PATH/$LIB_NAME

# --- Timing constraints --------------------------------------------------------
create_clock -name $CLK_NAME -period $CLK_PERIOD -waveform {0.0 5.0} [get_ports clk]
set_clock_uncertainty 0.20 [get_clocks $CLK_NAME]
set_propagated_clocks  true

set_input_delay  $IN_DELAY  -clock $CLK_NAME [all_inputs]
set_output_delay $OUT_DELAY -clock $CLK_NAME [all_outputs]

# Async active-low reset — do not time through it
set_false_path -from [get_ports rst_n]

# AXI4-Lite valid/ready handshakes are not on the critical path
set_multicycle_path 2 -setup -from [get_ports {s_axi_awvalid s_axi_wvalid s_axi_arvalid}]
set_multicycle_path 1 -setup -to   [get_ports {s_axi_rvalid s_axi_bvalid}]

# Interrupt can be relaxed (datapath-only)
set_max_delay -datapath_only $CLK_PERIOD -to [get_ports irq_done]

# --- Synthesis (three-stage) ---------------------------------------------------
set_db syn_generic_effort  medium
set_db syn_map_effort      medium
set_db syn_opt_effort      high

syn_generic
syn_map
syn_opt

# --- Reports -------------------------------------------------------------------
report_timing    -max_paths 10 > $REPORT_DIR/timing.rpt
report_area                    > $REPORT_DIR/area.rpt
report_power                   > $REPORT_DIR/power.rpt
report_clock_gating            > $REPORT_DIR/clock_gating.rpt
report_qor                     > $REPORT_DIR/qor.rpt

puts "=== QoR Summary ==="
report_qor

# --- Write outputs --------------------------------------------------------------
write_hdl > $NETLIST_DIR/${DESIGN}_netlist.v
write_sdf > $NETLIST_DIR/${DESIGN}.sdf
write_sdc > $NETLIST_DIR/${DESIGN}.sdc

puts "=== Synthesis Complete ==="
puts "Netlist : $NETLIST_DIR/${DESIGN}_netlist.v"
puts "Reports : $REPORT_DIR/"
