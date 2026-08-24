# ============================================================================
# Vivado 2023.2 batch simulation: kpke round-trip KeyGen -> Encrypt -> Decrypt
# Run:  vivado -mode batch -source run_rt_roundtrip.tcl
# Uses exec to call xvlog/xelab/xsim (vivado.bat already sets PATH).
# ============================================================================

set proj_dir "vivado_rt"
set top      "tb_roundtrip"

set rtl_root [file normalize "rtl"]
set tb_file  [file normalize "tb/tb_roundtrip.v"]

file delete -force $proj_dir
file mkdir $proj_dir

# Recursively collect *.v under rtl, excluding placeholder copies
proc collect_rtl {dir out} {
    foreach f [glob -nocomplain -types f [file join $dir *.v]] {
        if {[string match {*_copy.v} $f]} { continue }
        lappend out $f
    }
    foreach d [glob -nocomplain -types d [file join $dir *]] {
        set out [collect_rtl $d $out]
    }
    return $out
}

set sources [collect_rtl $rtl_root [list]]
puts "=== RTL sources: [llength $sources] files ==="
foreach s $sources { puts "  $s" }

set rtl_abs [file dirname $rtl_root]

# ---------------------------------------------------------------- xvlog
puts "=== xvlog ==="
if {[catch {
    exec cmd /c xvlog --incr -i [file join $rtl_abs rtl pkg] {*}$sources $tb_file
} msg]} {
    puts "XVLOG ERROR: $msg"
    exit 1
}

# ---------------------------------------------------------------- xelab
puts "=== xelab ==="
if {[catch {
    exec cmd /c xelab --debug typical $top -s work.$top -timescale 1ns/1ps
} msg]} {
    puts "XELAB ERROR: $msg"
    exit 1
}

# ---------------------------------------------------------------- xsim
puts "=== xsim run -all ==="
if {[catch {
    exec cmd /c xsim work.$top -runall
} msg]} {
    puts "XSIM ERROR: $msg"
    exit 1
}

puts "=== SIMULATION COMPLETE ==="