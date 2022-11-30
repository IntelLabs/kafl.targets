#!/bin/sh

# sysctl setup
echo 0 > /proc/sys/kernel/randomize_va_space
echo /dev/null > /proc/sys/kernel/core_pattern

grep . /proc/sys/kernel/randomize_va_space /proc/sys/kernel/core_pattern | tee -a /tmp/sysctl.conf
grep . /sys/devices/system/cpu/vulnerabilities/* | tee -a /tmp/sysctl.conf

vmcall hpush /tmp/sysctl.conf

function get_lower_range() {
	grep -i "$1" /proc/kallsyms|head -1|cut -d \  -f 1
}

function get_upper_range() {
	grep -i "$1" /proc/kallsyms|tail -1|cut -d \  -f 1
}

# trace all kernel code
IP0_START=$(get_lower_range "t\ _stext")
IP0_END=$(get_upper_range "t\ _etext")
IP1_START=$(get_lower_range "t\ _sinittext")
IP1_END=$(get_upper_range "t\ _einittext")

vmcall hrange 0,$IP0_START-$IP0_END 1,$IP1_START-$IP1_END

# launch target
vmcall hget -x -o /fuzz execserver
#vmcall hget -x -o /fuzz syz-stress
vmcall hget -x -o /fuzz syz-executor

export LD_BIND_NOW=1
export ASAN_OPTIONS=detect_leaks=0:allocator_may_return_null=1:exitcode=101

mkdir -p /tmp
cd /fuzz
#/fuzz/execserver vmcall hcat /proc/cpuinfo
#/fuzz/execserver ./syz-stress -procs 1 -output -syscalls ioctl,open,openat 2>&1 |vmcall hcat
/fuzz/execserver -n 10 ./syz-stress -procs 1 -syscalls ioctl,open,openat 2>&1 |vmcall hcat
