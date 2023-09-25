#!/bin/sh

# sysctl setup
echo 0 > /proc/sys/kernel/randomize_va_space
echo /dev/null > /proc/sys/kernel/core_pattern

# upload guest info
mkdir /tmp
grep . /proc/sys/kernel/randomize_va_space /proc/sys/kernel/core_pattern | tee -a /tmp/sysctl.conf
grep . /sys/devices/system/cpu/vulnerabilities/* | tee -a /tmp/sysctl.conf
vmcall hpush /tmp/sysctl.conf
vmcall hpush /proc/cpuinfo

# run the test
TEST=test_addr_translation
echo "running $TEST"|vmcall hcat
vmcall hget -x -o /fuzz $TEST
/fuzz/$TEST|vmcall hcat
