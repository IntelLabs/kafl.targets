#!/bin/sh

vmcall hcat /proc/cpuinfo

mkdir /test
vmcall hget -o /test test.bin
vmcall hget -x -o /test foo
vmcall hget -x -o /test enoexist # fail

vmcall hcat /test/test.bin

vmcall hpush /test/foo
vmcall hpush -a /test/foo
vmcall hpush -a /test/foo
vmcall hpush -o "test_XXXXXX" /test/foo

vmcall hrange 0,1100-1500
vmcall hrange 0,101100-202500 1,200000-23423432

vmcall hlock

ls -l | vmcall hcat
ls -l /test | vmcall hcat

vmcall habort "return from agent.sh"
