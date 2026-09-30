##############################################################################
# run_vivado_impl.tcl — place & route mlkem_top and report SIGN-OFF timing
#
# Synthesis-only timing is not closure: post-synthesis there is no routing, so
# net delays are ~0 and virtually every path reports a hold violation.  Hold is
# resolved by the router.  Only post-route numbers mean anything.
#
# Usage (from MLKEM_work/, after run_vivado_synth.tcl for the same part/period):
#   vivado -mode batch -source syn/run_vivado_impl.tcl \
#          -tclargs xc7z020clg484-1 38.0
#
# Outputs into syn/reports/<part>_<period>ns/impl/:
#   timing_summary_routed.rpt   WNS / WHS / TNS / THS after routing
#   utilization_routed.rpt      final placed utilization
#   route_status.rpt            any unrouted nets
#   impl.dcp                    routed checkpoint
##############################################################################

set PART   [expr {$argc > 0 ? [lindex $argv 0] : "xc7z020clg484-1"}]
set PERIOD [expr {$argc > 1 ? [lindex $argv 1] : 38.0}]

set here   [file normalize [file dirname [info script]]]
set rundir $here/reports/${PART}_[format %g $PERIOD]ns
set impl   $rundir/impl
file mkdir $impl

if {![file exists $rundir/synth.dcp]} {
    error "no synth.dcp in $rundir - run run_vivado_synth.tcl for this part/period first"
}

puts "### implementing $PART at ${PERIOD} ns"
open_checkpoint $rundir/synth.dcp

# Out-of-context: no physical pins, so do not try to place I/O buffers.
set_property HD.PARTPIN_RANGE {} [current_design] -quiet

opt_design
place_design
phys_opt_design
route_design

write_checkpoint -force $impl/impl.dcp

report_timing_summary -file $impl/timing_summary_routed.rpt
report_utilization    -file $impl/utilization_routed.rpt
report_route_status   -file $impl/route_status.rpt
report_timing -sort_by group -max_paths 10 -path_type full_clock_expanded \
                      -file $impl/timing_paths_routed.rpt

set wns [get_property SLACK [get_timing_paths -delay_type max]]
set whs [get_property SLACK [get_timing_paths -delay_type min]]

puts "============================================================"
puts " POST-ROUTE sign-off — $PART @ ${PERIOD} ns"
puts "   WNS (setup) : $wns ns"
puts "   WHS (hold)  : $whs ns"
if {$wns >= 0 && $whs >= 0} {
    puts "   RESULT      : TIMING CLOSED at [format %.2f [expr {1000.0/$PERIOD}]] MHz"
} else {
    puts "   RESULT      : NOT CLOSED"
}
puts "============================================================"
