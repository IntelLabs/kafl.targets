#!/bin/sh

cat /proc/cpuinfo |/vmcall hcat

/vmcall habort "return from loader.sh"
