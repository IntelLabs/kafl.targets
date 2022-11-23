#!/bin/sh

echo "Hello from agent.sh" |vmcall hcat

echo "Checking host config.." |vmcall hcat
vmcall check|vmcall hcat

echo "CPU Info:" |vmcall hcat /proc/cpuinfo

vmcall hpush /proc/cpuinfo
vmcall hpush -o "vmcall.map" /proc/self/maps

# return to loader.sh, which will upload agent.log
