#!/bin/sh

cat /proc/cpuinfo |/vmcall

/vmcall habort "return from loader.sh"
