#!/bin/sh

vmcall hcat /proc/cpuinfo

mkdir /test
vmcall hget -o /test test_2K.bin
vmcall hget -o /test test_4K.bin
vmcall hget -o /test test_4.1K.bin
vmcall hget -o /test test_3.9K.bin
vmcall hget -o /test test_1M.bin
vmcall hget -o /test test_2M.bin
vmcall hget -x -o /test foo
vmcall hget -x -o /test enoexist # fail

vmcall hcat /test/foo

vmcall hpush /test/foo
vmcall hpush -a /test/foo
vmcall hpush -a /test/foo
vmcall hpush -o "test_XXXXXX" /test/foo

vmcall hpush /test/test_2K.bin
vmcall hpush /test/test_4K.bin
vmcall hpush /test/test_4.1K.bin
vmcall hpush /test/test_3.9K.bin
vmcall hpush /test/test_1M.bin
vmcall hpush /test/test_2M.bin

vmcall hpush /test/enoexit # fail

vmcall hpush /proc/cpuinfo
vmcall hpush -o "vmcall.map" /proc/self/maps

vmcall hrange 0,1100-1500
vmcall hrange 0,101100-202500 1,200000-23423432

vmcall hlock

ls -l | vmcall hcat
ls -l /test | vmcall hcat

# return to loader.sh, which will upload agent.log
