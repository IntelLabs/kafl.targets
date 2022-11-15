#!/bin/sh

# sysctl setup
echo 0 > /proc/sys/kernel/randomize_va_space
echo /dev/null > /proc/sys/kernel/core_pattern

grep . /proc/sys/kernel/randomize_va_space /proc/sys/kernel/core_pattern | tee -a /tmp/sysctl.conf
grep . /sys/devices/system/cpu/vulnerabilities/* | tee -a /tmp/sysctl.conf

vmcall hpush /tmp/sysctl.conf

# launch target
vmcall hget -x -o /fuzz forkserver.so

export LD_BIND_NOW=1
export ASAN_OPTIONS=detect_leaks=0:allocator_may_return_null=1:exitcode=101

mkdir -p /tmp
#LD_PRELOAD="/lib/x86_64-linux-gnu/libasan.so.5:/fuzz/forkserver.so" /fuzz/unlzma /tmp/payload.lzma
LD_PRELOAD="/fuzz/forkserver.so" /fuzz/bison -g -u /tmp/payload
