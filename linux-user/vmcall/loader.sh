#!/bin/sh

cat /proc/cpuinfo |/vmcall hcat

/vmcall hget -x test.bin

/vmcall habort "return from loader.sh"
