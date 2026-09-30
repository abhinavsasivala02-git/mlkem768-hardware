##############################################################################
# run_vivado_synth.tcl — out-of-context synthesis of mlkem_top (ML-KEM-768)
#
# Usage (from MLKEM_work/):
#   vivado -mode batch -source syn/run_vivado_synth.tcl
#
# Optional overrides:
#   vivado -mode batch -source syn/run_vivado_synth.tcl -tclargs <part> <period_ns>
#
# Outputs (syn/reports/):
#   utilization.rpt   LUT / FF / BRAM / DSP / LUTRAM counts
#   timing_summary.rpt  WNS / WHS / TNS, all clocks
#   timing_paths.rpt  10 worst setup paths, full detail
#   clocks.rpt        clock definitions as seen by the tool
#   synth.dcp         checkpoint, for opening the design interactively
##############################################################################

set PART   [expr {$argc > 0 ? [lindex $argv 0] : "xc7a200tfbg484-2"}]
set PERIOD [expr {$argc > 1 ? [lindex $argv 1] : 10.0}]
set TOP    mlkem_top

set here    [file normalize [file dirname [info script]]]
set root    [file dirname $here]
set rtl     $root/rtl
# One directory per (part, period) so runs can be compared side by side.
set repdir  $here/reports/${PART}_[format %g $PERIOD]ns
file mkdir $repdir

puts "### part=$PART  period=${PERIOD}ns  top=$TOP"

#-----------------------------------------------------------------------------
# Read RTL. Collect every source rather than listing them: Vivado resolves
# module dependencies itself, and the list cannot drift out of date.
#-----------------------------------------------------------------------------
set srcs [lsort [glob -nocomplain $rtl/*/*.v]]
# *_copy.v are placeholders, never part of the design
set srcs [lsearch -all -inline -not $srcs *_copy.v]
puts "### reading [llength $srcs] verilog sources"
read_verilog $srcs

# mlkem_params.vh lives in rtl/pkg and is `include`d by several modules
set_property include_dirs [list $rtl/pkg] [current_fileset]

# mlkem.sdc picks this up instead of its own default.
set CLK_PERIOD_NS $PERIOD
read_xdc $here/mlkem.sdc

#-----------------------------------------------------------------------------
# Synthesize out-of-context: no I/O buffers, so the report reflects the block
# as it would be integrated, not a standalone chip.
#-----------------------------------------------------------------------------
synth_design -top $TOP -part $PART -mode out_of_context \
             -generic K=3 -generic ETA1=2 -generic ETA2=2 \
             -generic DU=10 -generic DV=4

write_checkpoint -force $repdir/synth.dcp

#-----------------------------------------------------------------------------
# Reports
#-----------------------------------------------------------------------------
report_utilization      -file $repdir/utilization.rpt
report_timing_summary   -file $repdir/timing_summary.rpt
report_timing -sort_by group -max_paths 10 -path_type full_clock_expanded \
                        -file $repdir/timing_paths.rpt
report_clocks           -file $repdir/clocks.rpt

#-----------------------------------------------------------------------------
# Console summary — the two numbers that matter
#-----------------------------------------------------------------------------
set wns [get_property SLACK [get_timing_paths -delay_type max]]
set whs [get_property SLACK [get_timing_paths -delay_type min]]
set luts [get_property CELL_COUNT [get_cells -hier -filter {PRIMITIVE_GROUP == LUT}]]

puts "============================================================"
puts " mlkem_top synthesis summary"
puts "   part          : $PART"
puts "   clock period  : ${PERIOD} ns"
puts "   WNS (setup)   : $wns ns"
puts "   WHS (hold)    : $whs ns"
if {$wns >= 0} {
    puts "   Fmax (approx) : [format %.1f [expr {1000.0 / ($PERIOD - $wns)}]] MHz"
} else {
    puts "   TIMING FAILED : tighten pipelining or relax the period"
}
puts "   reports       : $repdir"
puts "============================================================"
