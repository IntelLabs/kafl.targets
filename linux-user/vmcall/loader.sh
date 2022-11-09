#!/bin/sh

cat /proc/cpuinfo |/vmcall hcat

/vmcall is_nyx
echo "CPU is Nyx: $?" |/vmcall hcat

mkdir /fuzz
/vmcall hget -o /fuzz test.bin
/vmcall hget -x -o /fuzz vmcall

/vmcall hcat /fuzz/test.bin

ls -l | /vmcall hcat
ls -l /fuzz | /vmcall hcat

/vmcall habort "return from loader.sh"
