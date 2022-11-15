#!/bin/sh

FS="ext4"

function get_lower_range() {
	grep -i "$1" /proc/kallsyms|head -1|cut -d \  -f 1
}

function get_upper_range() {
	grep -i "$1" /proc/kallsyms|tail -1|cut -d \  -f 1
}

# trace only FS code
IP0_START=$(get_lower_range "t\ _ext4\|t\ mount\|t ioctl")
IP0_END=$(get_upper_range "t\ _ext4\|t\ mount\|t ioctl")
vmcall hrange 0,$IP0_START-$IP0_END

## trace all kernel code
#IP0_START=$(get_lower_range "t\ _stext")
#IP0_END=$(get_upper_range "t\ _etext")
#IP1_START=$(get_lower_range "t\ _sinittext")
#IP1_END=$(get_upper_range "t\ _einittext")
#
#vmcall hrange 0,$IP0_START-$IP0_END 1,$IP1_START-$IP1_END

# clean pipes
dmesg -c > /fuzz/boot.log
vmcall hpush /fuzz/boot.log
vmcall hpush /proc/kallsyms
vmcall hpush /proc/cpuinfo
vmcall hpush /proc/filesystems
vmcall hpush /proc/modules

if grep -q $FS /proc/filesystems; then
	/fuzz/fs_fuzzer $FS
else
	echo "No such fs: $FS"
fi
