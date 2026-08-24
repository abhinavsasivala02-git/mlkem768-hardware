##############################################################################
# Cadence Genus Synthesis Script — ML-KEM (FIPS 203)
# Target: ML-KEM-768 (K=3, ETA1=2, ETA2=2, DU=10, DV=4)
#
# Usage:
#   genus -f syn_mlkem.tcl
##############################################################################

#--- 1. Setup -----------------------------------------------------------------
set DESIGN       mlkem_top
set RTL_DIR      ../rtl
set WORK_DIR     ./work
set REPORT_DIR   ./reports
set NETLIST_DIR  ./netlists

# Target library — update path for your PDK
set LIB_PATH     /path/to/pdk/libs
set LIB_NAME     typical.lib   ;# Replace with actual cell library

file mkdir $WORK_DIR $REPORT_DIR $NETLIST_DIR

#--- 2. Constraints -----------------------------------------------------------
set CLK_NAME     clk
set CLK_PERIOD   10.0          ;# 100 MHz  (adjust to target frequency)
set IN_DELAY     1.5
set OUT_DELAY    2.0

#--- 3. Read RTL --------------------------------------------------------------
# Read all RTL files in dependency order
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
    $RTL_DIR/keccak/keccak_round.v \
    $RTL_DIR/keccak/keccak_f1600.v \
    $RTL_DIR/keccak/keccak_absorb_squeeze.v \
    $RTL_DIR/keccak/shake128.v \
    $RTL_DIR/keccak/shake256.v \
    $RTL_DIR/keccak/sha3_256.v \
    $RTL_DIR/keccak/sha3_512.v \
    $RTL_DIR/encode/byte_decode.v \
    $RTL_DIR/encode/byte_encode.v \
    $RTL_DIR/encode/compress.v \
    $RTL_DIR/encode/decompress.v \
    $RTL_DIR/sample/sample_ntt.v \
    $RTL_DIR/sample/sample_cbd.v \
    $RTL_DIR/kpke/kpke_keygen.v \
    $RTL_DIR/kpke/kpke_encrypt.v \
    $RTL_DIR/kpke/kpke_decrypt.v \
    $RTL_DIR/mlkem/mlkem_keygen.v \
    $RTL_DIR/mlkem/mlkem_encaps.v \
    $RTL_DIR/mlkem/mlkem_decaps.v \
    $RTL_DIR/mlkem/mlkem_axi_lite_if.v \
    $RTL_DIR/mlkem/mlkem_core.v \
    $RTL_DIR/mlkem/mlkem_top.v

#--- 4. Elaborate -------------------------------------------------------------
elaborate $DESIGN -parameters {K=3 ETA1=2 ETA2=2 DU=10 DV=4}

check_design -all
uniquify

#--- 5. Read Library ----------------------------------------------------------
read_libs $LIB_PATH/$LIB_NAME

#--- 6. timing constraints -----------------------------------------------------------
create_clock -name $CLK_NAME -period $CLK_PERIOD [get_ports clk]

# AXI clock alias (same clock, different name in AXI IF module)
set_clock_uncertainty 0.2 [get_clocks $CLK_NAME]
set_propagated_clocks true

set_input_delay  $IN_DELAY  -clock $CLK_NAME [all_inputs]
set_output_delay $OUT_DELAY -clock $CLK_NAME [all_outputs]

# Async active-low reset — don't analyze timing through reset
set_false_path -from [get_ports rst_n]

# AXI ready/valid paths — relax if needed
set_multicycle_path 2 -setup -to [get_ports s_axi_*]

#--- 7. Synthesis (three-stage) -----------------------------------------------
set_db syn_generic_effort  medium
set_db syn_map_effort      medium
set_db syn_opt_effort      high

syn_generic
syn_map
syn_opt

#--- 8. Reports ---------------------------------------------------------------
report_timing  -max_paths 10  > $REPORT_DIR/timing.rpt
report_area               > $REPORT_DIR/area.rpt
report_power              > $REPORT_DIR/power.rpt
report_clock_gating       > $REPORT_DIR/clock_gating.rpt
report_qor                > $REPORT_DIR/qor.rpt

puts "=== QoR Summary ==="
report_qor

#--- 9. Write Netlists --------------------------------------------------------
write_hdl > $NETLIST_DIR/${DESIGN}_netlist.v
write_sdf > $NETLIST_DIR/${DESIGN}.sdf
write_sdc > $NETLIST_DIR/${DESIGN}.sdc

puts "=== Synthesis Complete ==="
puts "Netlist : $NETLIST_DIR/${DESIGN}_netlist.v"
puts "Reports : $REPORT_DIR/"
