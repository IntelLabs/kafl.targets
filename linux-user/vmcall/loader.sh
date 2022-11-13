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
vmcall hpush -a /fuzz/foo
vmcall hpush -a /fuzz/foo
vmcall hpush -o "test_XXXXXX" /fuzz/foo

vmcall hrange 0,100-500
vmcall hrange 0,101100-202500 1,200000-23423432

vmcall hcheck
vmcall hlock

ls -l | vmcall hcat
ls -l /fuzz | vmcall hcat

/vmcall habort "return from loader.sh"
