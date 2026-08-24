#=============================================================================
# Cadence Genus Synthesis Script for ML-KEM (FIPS 203)
# Target: ASIC Synthesis
# Top Module: mlkem_top
#
# Usage:  genus -f run_genus.tcl
#    or:  genus (then) source run_genus.tcl
#=============================================================================

#-----------------------------------------------------------------------------
# 1. DESIGN CONFIGURATION — EDIT THESE FOR YOUR ENVIRONMENT
#-----------------------------------------------------------------------------
set DESIGN_NAME   "mlkem_top"
set RTL_DIR       "../rtl"
set CLK_NAME      "clk"
set CLK_PERIOD_NS 10.0            ;# Target clock period (adjust for speed)
set RST_NAME      "rst_n"

# *** TECHNOLOGY LIBRARY — UPDATE THESE PATHS ***
# Point to your foundry .lib / .lef files
# Example for a generic 45nm library:
#   set LIB_PATH "/path/to/your/stdcell_library"
#   set LIBERTY_FILE "${LIB_PATH}/your_lib_tt_1p0v_25c.lib"
#   set LEF_FILE     "${LIB_PATH}/your_lib.lef"
#
# Uncomment and update the lines below with your actual library paths:
# set LIB_PATH     "/home/cadtools/pdk/lib"
# set LIBERTY_FILE  "${LIB_PATH}/slow.lib"
# set LEF_FILE      "${LIB_PATH}/tech.lef"

#-----------------------------------------------------------------------------
# 2. GENUS SETUP
#-----------------------------------------------------------------------------
# Suppress non-critical info messages to keep the log clean
set_db / .information_level 7

# Create a working directory for Genus outputs
set_db / .init_hdl_search_path ${RTL_DIR}

#-----------------------------------------------------------------------------
# 3. READ TECHNOLOGY LIBRARY
#-----------------------------------------------------------------------------
# *** UNCOMMENT the lines below after setting your library paths above ***
# read_libs ${LIBERTY_FILE}
# read_physical -lef ${LEF_FILE}

# If you have no library yet and just want to check elaboration,
# Genus will run in "generic" mode (no timing, but syntax/connectivity checks)
puts "============================================================"
puts " NOTE: If no library is loaded, Genus runs in generic mode."
puts " Update LIB_PATH/LIBERTY_FILE/LEF_FILE for real synthesis."
puts "============================================================"

#-----------------------------------------------------------------------------
# 4. READ RTL FILES — Dependency-ordered (leaf modules first)
#-----------------------------------------------------------------------------
# Verilog-2001 mode, with include path for mlkem_params.vh
set_db / .hdl_verilog_read_version 2001

# --- Leaf arithmetic modules ---
read_hdl -v2001 ${RTL_DIR}/barrett_reduce.v
read_hdl -v2001 ${RTL_DIR}/montgomery_reduce.v
read_hdl -v2001 ${RTL_DIR}/modular_arith.v

# --- NTT subsystem ---
read_hdl -v2001 ${RTL_DIR}/ntt_rom.v
read_hdl -v2001 ${RTL_DIR}/ntt_butterfly.v
read_hdl -v2001 ${RTL_DIR}/poly_ram.v
read_hdl -v2001 ${RTL_DIR}/ntt.v
read_hdl -v2001 ${RTL_DIR}/intt.v

# --- Polynomial operations ---
read_hdl -v2001 ${RTL_DIR}/poly_basemul.v
read_hdl -v2001 ${RTL_DIR}/poly_arith.v

# --- Keccak / SHA3 / SHAKE ---
read_hdl -v2001 ${RTL_DIR}/keccak_round.v
read_hdl -v2001 ${RTL_DIR}/keccak_f1600.v
read_hdl -v2001 ${RTL_DIR}/keccak_absorb_squeeze.v
read_hdl -v2001 ${RTL_DIR}/sha3_256.v
read_hdl -v2001 ${RTL_DIR}/sha3_512.v
read_hdl -v2001 ${RTL_DIR}/shake128.v
read_hdl -v2001 ${RTL_DIR}/shake256.v

# --- Sampling ---
read_hdl -v2001 ${RTL_DIR}/sample_ntt.v
read_hdl -v2001 ${RTL_DIR}/sample_cbd.v

# --- Compress / Decompress ---
read_hdl -v2001 ${RTL_DIR}/compress.v
read_hdl -v2001 ${RTL_DIR}/decompress.v

# --- Byte encode / decode ---
read_hdl -v2001 ${RTL_DIR}/byte_encode.v
read_hdl -v2001 ${RTL_DIR}/byte_decode.v

# --- K-PKE inner schemes ---
read_hdl -v2001 ${RTL_DIR}/kpke_keygen.v
read_hdl -v2001 ${RTL_DIR}/kpke_encrypt.v
read_hdl -v2001 ${RTL_DIR}/kpke_decrypt.v

# --- ML-KEM outer schemes ---
read_hdl -v2001 ${RTL_DIR}/mlkem_keygen.v
read_hdl -v2001 ${RTL_DIR}/mlkem_encaps.v
read_hdl -v2001 ${RTL_DIR}/mlkem_decaps.v

# --- Top-level ---
read_hdl -v2001 ${RTL_DIR}/mlkem_core.v
read_hdl -v2001 ${RTL_DIR}/mlkem_axi_lite_if.v
read_hdl -v2001 ${RTL_DIR}/mlkem_top.v

#-----------------------------------------------------------------------------
# 5. ELABORATE DESIGN
#-----------------------------------------------------------------------------
elaborate ${DESIGN_NAME}

# Check elaboration
check_design -unresolved

puts "============================================================"
puts " Elaboration complete. Check messages above for errors."
puts "============================================================"

#-----------------------------------------------------------------------------
# 6. TIMING CONSTRAINTS (SDC)
#-----------------------------------------------------------------------------
# Clock definition
set CLK_PORT [get_ports ${CLK_NAME}]
create_clock -name sys_clk -period ${CLK_PERIOD_NS} ${CLK_PORT}
set_clock_uncertainty 0.2 [get_clocks sys_clk]
set_clock_transition  0.1 [get_clocks sys_clk]

# Reset is asynchronous — mark as false path
set_false_path -from [get_ports ${RST_NAME}]

# Input/output delays (adjust as needed for your system)
set ALL_INPUTS  [remove_from_collection [all_inputs] [get_ports "${CLK_NAME} ${RST_NAME}"]]
set ALL_OUTPUTS [all_outputs]

set_input_delay  -clock sys_clk [expr ${CLK_PERIOD_NS} * 0.3] ${ALL_INPUTS}
set_output_delay -clock sys_clk [expr ${CLK_PERIOD_NS} * 0.3] ${ALL_OUTPUTS}

# Drive strength and load
set_input_transition 0.2 ${ALL_INPUTS}
set_load 0.05 ${ALL_OUTPUTS}

# Max fanout constraint
set_max_fanout 20 ${DESIGN_NAME}

# Max transition
set_max_transition 0.5 ${DESIGN_NAME}

#-----------------------------------------------------------------------------
# 7. SYNTHESIS
#-----------------------------------------------------------------------------
# Set synthesis effort
set_db / .syn_generic_effort  high
set_db / .syn_map_effort      high
set_db / .syn_opt_effort      high

# --- Generic synthesis (technology-independent optimization) ---
syn_generic
puts ">>> syn_generic complete"

# --- Map to technology library ---
syn_map
puts ">>> syn_map complete"

# --- Post-map optimization ---
syn_opt
puts ">>> syn_opt complete"

puts "============================================================"
puts " Synthesis complete!"
puts "============================================================"

#-----------------------------------------------------------------------------
# 8. REPORTS
#-----------------------------------------------------------------------------
# Create reports directory
file mkdir ../reports

# Timing report
report_timing -max_paths 20 > ../reports/timing_report.rpt
puts ">>> Timing report written to ../reports/timing_report.rpt"

# Area report
report_area > ../reports/area_report.rpt
puts ">>> Area report written to ../reports/area_report.rpt"

# Power report
report_power > ../reports/power_report.rpt
puts ">>> Power report written to ../reports/power_report.rpt"

# Design rule violations
report_design_rule_violations > ../reports/drv_report.rpt

# Gate count summary
report_gates > ../reports/gates_report.rpt

# QoR summary
report_qor > ../reports/qor_report.rpt

#-----------------------------------------------------------------------------
# 9. WRITE OUTPUTS
#-----------------------------------------------------------------------------
file mkdir ../output

# Gate-level netlist (Verilog)
write_hdl -mapped > ../output/${DESIGN_NAME}_netlist.v
puts ">>> Netlist written to ../output/${DESIGN_NAME}_netlist.v"

# Timing constraints (SDC)
write_sdc > ../output/${DESIGN_NAME}.sdc
puts ">>> SDC written to ../output/${DESIGN_NAME}.sdc"

# Design database (for Innovus place-and-route)
write_design -innovus -basename ../output/${DESIGN_NAME}
puts ">>> Innovus design files written to ../output/"

puts ""
puts "============================================================"
puts " ALL DONE — ML-KEM synthesis finished successfully"
puts "============================================================"
puts " Reports:  ../reports/"
puts " Outputs:  ../output/"
puts "============================================================"

# Uncomment to exit Genus automatically:
# exit
