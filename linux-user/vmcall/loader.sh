#!/bin/sh

cat /proc/cpuinfo |/vmcall hcat

/vmcall is_nyx
echo "CPU is Nyx: $?" |/vmcall hcat

/vmcall hget -x -o /bin vmcall

mkdir /fuzz
vmcall hget -o /fuzz test.bin
vmcall hget -x -o /fuzz foo

vmcall hcat /fuzz/test.bin

vmcall hpush /fuzz/foo
vmcall hpush -o "test_XXXXXX" /fuzz/foo

ls -l | vmcall hcat
ls -l /fuzz | vmcall hcat

/vmcall habort "return from loader.sh"
