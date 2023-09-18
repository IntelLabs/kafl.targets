#!/bin/sh

echo "Hello from agent.sh" | vmcall hcat

echo "Checking host config.." | vmcall hcat
vmcall check|vmcall hcat

echo "Downloading dvkm.ko" | vmcall hcat
vmcall hget -x -o /fuzz dvkm.ko
cd /fuzz

echo "Downloading fuzz_dvkm" | vmcall hcat
vmcall hget -x -o /fuzz fuzz_dvkm

echo "Inserting dvkm.ko" | vmcall hcat
insmod dvkm.ko

echo "Uploading maps" | vmcall hcat
vmcall hpush -o "modules" /proc/modules

echo "Fuzz dvkm.ko" | vmcall hcat
fuzz_dvkm

# return to loader.sh, which will upload agent.log
