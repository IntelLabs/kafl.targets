#!/bin/bash
#
# kAFL helper script to build and launch Zephyr components
#
# Copyright 2019-2020 Intel Corporation
# SPDX-License-Identifier: MIT
#
set -e

SCRIPT_ROOT="$(dirname "$(realpath "$0")")"

KAFL_OPTS="-p $(nproc) --grimoire --redqueen -t 1 -ts 0.05"

# recent Zephyr uses qemu -icount and fails to boot with -enable-kvm
#ZEPHYR_VERSION="v2.4.0"
ZEPHYR_VERSION="v2.3.0"

# default toolchain setup
SDK_URL="https://github.com/zephyrproject-rtos/sdk-ng/releases/download/v0.11.3/zephyr-sdk-0.11.3-setup.run"
export ZEPHYR_TOOLCHAIN_VARIANT=zephyr
export ZEPHYR_SDK_INSTALL_DIR=$HOME/zephyr-sdk/

function fail {
	echo
	echo -e "$1"
	echo
	exit 1
}

get_env() {
	KAFL_ROOT=$(west path kafl 2>/dev/null)
	# may fail on missing / disabled zephyr install
	ZEPHYR_BASE=$(west path zephyr 2>/dev/null) || true
}

function fetch_zephyr() {
	get_env
	test -d "$ZEPHYR_BASE" && (echo "ZEPHYR_BASE is already set. Skipping install."; return)
	echo -e "\nAttempting to fetch Zephyr and dependencies using sudo apt, west update, and pip3.\n\n\tHit Enter to continue or ctrl-c to abort."
	read
	echo "[*] Fetching dependencies.. (sudo apt)"
	# https://docs.zephyrproject.org/latest/getting_started/installation_linux.html
	sudo apt-get update
	sudo apt-get upgrade
	sudo apt-get install --no-install-recommends \
		git cmake ninja-build gperf ccache dfu-util \
		device-tree-compiler wget python3-pip python3-setuptools \
		python3-wheel python3-yaml xz-utils file make gcc gcc-multilib

	# missing deps on Ubuntu?
	sudo apt-get install python3-pyelftools

	echo "[*] Fetching Zephyr repos.. (west update -k)"
	# Zephyr also uses West. Need to add it as an `import` :-/
	ln -sf $SCRIPT_ROOT/zephyr.yml $KAFL_ROOT/.submanifests/zephyr.yml

	# fetch Zephyr project using west and add any python dependencies
	west update -k
	get_env
	test -d "$ZEPHYR_BASE" || fail "Failed to add Zephyr to west workspace. Exit."

	echo "[*] Fetching Zephyr python deps.. (pip3 install)"
	pip3 install -r $ZEPHYR_BASE/scripts/requirements.txt
}

function fetch_sdk() {
	test -d "$ZEPHYR_SDK_INSTALL_DIR" && (echo "ZEPHYR_SDK_INSTALL_DIR is already set. Skipping install."; return)

	# Download Zephyr SDK. Not pretty.
	get_env
	INSTALLER=$ZEPHYR_BASE/$(basename $SDK_URL)

	echo -e "\nAttempting to fetch and execute Zephyr SDK installer from\n$SDK_URL\n\n\tHit Enter to continue or ctrl-c to abort."
	read
	wget -c -O $INSTALLER $SDK_URL
	bash $INSTALLER
}

function fetch_deps() {
	# fetch Zephyr and SDK if not available
	test -d "$ZEPHYR_BASE" || (echo "Could not find Zephyr in current west workspace."; fetch_zephyr)
	test -d "$ZEPHYR_SDK_INSTALL_DIR" || (echo "Could not find Zephyr SDK."; fetch_sdk)
}

function check_deps() {
	test -d "$ZEPHYR_BASE" || fail "Could not find Zephyr install. Exit."
	test -d "$ZEPHYR_SDK_INSTALL_DIR"  || fail "Could not find Zephyr SDK. Exit."

	echo -e "# Detected Zephyr environment:"
	echo "ZEPHYR_BASE=$ZEPHYR_BASE"
	echo "ZEPHYR_SDK_INSTALL_DIR=$ZEPHYR_SDK_INSTALL_DIR"
	echo "ZEPHYR_TOOLCHAIN_VARIANT=$ZEPHYR_TOOLCHAIN_VARIANT"
	export ZEPHYR_BASE
}

function build_app() {

	if [[ -z "$ZEPHYR_BASE" ]]; then
		printf "\tError: Zephyr SDK is not active, skipping Zephyr targets!\n"
		exit
	fi

	# select target app / variant
	APP=$1; shift

	pushd $SCRIPT_ROOT
	test -d build && rm -rf build
   	mkdir build || fail "Could not create build/ directory. Exit."
	cd build
	#cmake -GNinja -DBOARD=qemu_x86_64 -DKAFL_${APP}=y ..
	cmake -GNinja -DBOARD=qemu_x86 -DKAFL_${APP}=y ..
	ninja
	popd
}

function fuzz() {
	pushd $KAFL_ROOT

	BIN=${SCRIPT_ROOT}/build/zephyr/zephyr.elf
	MAP=${SCRIPT_ROOT}/build/zephyr/zephyr.map
	test -f $BIN -a -f $MAP || fail "Could not find Zephyr target .elf and .map files. Need to build first?"

	range=$(grep -A 1 ^text "$MAP" |xargs |cut -d\  -f 2,3)
	ip_start=$(echo $range|sed 's/ .*//')
	ip_end=$(echo -e "obase=16\nibase=16\n$(echo $range|sed s/x//g|sed 's/\ /+/'|tr a-z A-Z)"|bc)

	echo "IP filter range: $ip_start-0x$ip_end"

	python3 kafl_fuzz.py \
		-ip0 ${ip_start}-0x${ip_end} \
		--kernel ${BIN} \
		--memory 32 \
		--work-dir /dev/shm/kafl_zephyr \
		--seed-dir $SCRIPT_ROOT/seeds/ \
		--purge $KAFL_OPTS $*
}

function cov()
{
	pushd $KAFL_ROOT
	TEMPDIR=$(mktemp -d -p /dev/shm)
	WORKDIR=$1; shift

	BIN=${SCRIPT_ROOT}/build/zephyr/zephyr.elf
	MAP=${SCRIPT_ROOT}/build/zephyr/zephyr.map
	test -f $BIN -a -f $MAP || fail "Could not find Zephyr target .elf and .map files. Need to build first?"

	range=$(grep -A 1 ^text "$MAP" |xargs |cut -d\  -f 2,3)
	ip_start=$(echo $range|sed 's/ .*//')
	ip_end=$(echo -e "obase=16\nibase=16\n$(echo $range|sed s/x//g|sed 's/\ /+/'|tr a-z A-Z)"|bc)

	echo
	echo "Using temp workdir >>$TEMPDIR<<.."
	echo "IP filter range: $ip_start-0x$ip_end"
	echo
	sleep 1


	# Note: -ip0 and other VM settings should match those used during fuzzing
	python3 kafl_cov.py \
		-v -ip0 ${ip_start}-0x${ip_end} \
		--kernel ${BIN} \
		--memory 32 \
		--work-dir $TEMPDIR \
		--input $WORKDIR $*
	popd
}

function gdb()
{
	pushd $KAFL_ROOT
	TEMPDIR=$(mktemp -d -p /dev/shm)
	PAYLOAD=$1; shift

	BIN=${SCRIPT_ROOT}/build/zephyr/zephyr.elf
	MAP=${SCRIPT_ROOT}/build/zephyr/zephyr.map
	test -f $BIN -a -f $MAP || fail "Could not find Zephyr target .elf and .map files. Need to build first?"

	echo
	echo "Using temp workdir >>$TEMPDIR<<.."
	sleep 1


	# Note: -ip0 and other VM settings should match those used during fuzzing
	kafl_debug.py --action gdb --purge -v \
		--kernel ${BIN} \
		--memory 32 \
		--work-dir $TEMPDIR \
		--input $PAYLOAD $*
	popd
}

function noise()
{
	pushd $KAFL_ROOT
	TEMPDIR=$(mktemp -d -p /dev/shm)
	PAYLOAD=$1; shift

	BIN=${SCRIPT_ROOT}/build/zephyr/zephyr.elf
	MAP=${SCRIPT_ROOT}/build/zephyr/zephyr.map
	test -f $BIN -a -f $MAP || fail "Could not find Zephyr target .elf and .map files. Need to build first?"

	range=$(grep -A 1 ^text "$MAP" |xargs |cut -d\  -f 2,3)
	ip_start=$(echo $range|sed 's/ .*//')
	ip_end=$(echo -e "obase=16\nibase=16\n$(echo $range|sed s/x//g|sed 's/\ /+/'|tr a-z A-Z)"|bc)

	echo
	echo "Using temp workdir >>$TEMPDIR<<.."
	echo "IP filter range: $ip_start-0x$ip_end"
	echo
	sleep 1


	# Note: -ip0 and other VM settings should match those used during fuzzing
	kafl_debug.py --action noise --purge \
		-v -ip0 ${ip_start}-0x${ip_end} \
		--kernel ${BIN} \
		--memory 32 \
		-n 0 \
		--work-dir $TEMPDIR \
		--input $PAYLOAD $*
	popd
}

function usage() {
	echo
	echo "Build and run the Zephyr RTOS samples."
	echo
	echo "Usage: $0 <cmd> <args>"
	echo
	echo Available commands:
	echo -e "\tzephyr                - install Zephyr SDK, or display detected setup"
	echo -e "\tbuild <TEST|JSON|FS>  - build the test, json or fs fuzzing sample"
	echo -e "\tfuzz [args]           - fuzz the currently build sample with optional kAFL args"
	echo -e "\tnoise <input>         - execute input many times and monitor coverage"
	echo -e "\tdebug <input>         - execute input in debug mode (qemu gdbstub)"
	echo -e "\tcov <dir>             - process corpus of existing workdir and collect coverage info"
	echo
	exit
}


CMD=$1; shift || usage

get_env

case $CMD in
	"zephyr")
		fetch_zephyr
		fetch_sdk
		# re-scan + report
		get_env
		check_deps
		;;
	"fuzz")
		fuzz $*
		;;
	"cov")
		test -d "$1" || usage
		cov $*
		;;
	"noise")
		test -f "$1" || usage
		noise $*
		;;
	"debug")
		test -f "$1" || usage
		gdb $*
		;;
	"build")
		test -n "$1" || usage
		check_deps
		build_app $1
		;;
	*)
		usage
		;;
esac
