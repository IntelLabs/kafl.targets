#!/bin/sh

cat /proc/cpuinfo |/vmcall hcat

/vmcall is_nyx
echo "CPU is Nyx: $?" |/vmcall hcat

/vmcall hget -x vmcall
/vmcall hget test.bin

ls -l |/vmcall hcat

/vmcall habort "return from loader.sh"
