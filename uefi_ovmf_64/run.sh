#!/bin/bash
#
# kAFL helper script to build and launch UEFI components
#
# Copyright 2019-2020 Intel Corporation
# SPDX-License-Identifier: MIT
#

set -e

EDK2_REPO="https://github.com/IntelLabs/kafl.edk2.git"
EDK2_BRANCH="kafl/edk2-2c17d676e4"

function usage() {
  cat >&2 << HERE

Build and fuzz the UEFI OVMF sample.

This script assumes KAFL at $KAFL_ROOT and EDK2 cloned to $EDK2_ROOT.
Build settings in Conf/target.txt will be overridden with '$BUILD_OPTS'.

Usage: $0 <target>

Targets:
  fuzz           - fuzz sample agent in kAFL
  noise <file>   - process <file> in trace mode to collect coverage info
  cov <dir>      - process <dir> in trace mode to collect coverage info
  edk2           - download edk2 branch + build deps
  dxe_null       - build kAFL Dxe NULL Fuzzing platform
  ovmf           - Build genuine OVMF platform, for post DXE fuzzing
  app            - Build application the harness
HERE
  exit
}

function fail {
  echo -e "\nError: $@\n" >&2
  exit 1
}

function install_edk2()
{
  # requirements on top of kAFL base install
  sudo apt-get install nasm iasl g++ g++-multilib

  # download + apply patch unless install folder already exists
  if [ -d $EDK2_ROOT ]; then
    echo "[*] Folder exists, assume it is already patched.."
    pushd $EDK2_ROOT
  else
    git clone "$EDK2_REPO" "$EDK2_ROOT"
    pushd "$EDK2_ROOT"
    git checkout "$EDK2_BRANCH"
    git submodule update --init --recursive
    patch -p1 < $SCRIPT_ROOT/edk2_kafl.patch || exit
    patch -p1 < $SCRIPT_ROOT/edk2_kafl_ovmf.patch || exit
  fi
  make -C BaseTools -j $(nproc)
  export EDK_TOOLS_PATH=$PWD/BaseTools
  . edksetup.sh BaseTools
  popd
}

function build_ovmf()
{
  [ -d $EDK2_ROOT/BaseTools ] || fail "Please set correct \$EDK2_ROOT"
  pushd $EDK2_ROOT
  export EDK_TOOLS_PATH=$PWD/BaseTools
  . edksetup.sh BaseTools

  which build || fail "Could not find 'build' util. Abort."

  build $BUILD_OPTS -p OvmfPkg/OvmfPkg${OVMF_DSC_ARCH}.dsc

  echo "Build done, copy target files.."
  cp -v Build/Ovmf${ARCH}/${BUILD}_${TOOL}/FV/OVMF.fd $TARGET_BIN
  cp -v Build/Ovmf${ARCH}/${BUILD}_${TOOL}/FV/OVMF_CODE.fd $SCRIPT_ROOT
  cp -v Build/Ovmf${ARCH}/${BUILD}_${TOOL}/FV/OVMF_VARS.fd $SCRIPT_ROOT
  popd
}

function build_platform()
{
  echo
  echo Building package $1, output platform name $2, extra build opts $3
  echo
  sleep 1

  [ -d $EDK2_ROOT/BaseTools ] || fail "Please set correct \$EDK2_ROOT"
  pushd $EDK2_ROOT
  export PACKAGES_PATH=$SCRIPT_ROOT
  export EDK_TOOLS_PATH=$PWD/BaseTools
  . edksetup.sh BaseTools

  which build || fail "Could not find 'build' util. Abort."

  # Already built with my OVMF platform
  # @see in kAFLDxeHarnessPkg/App/kAFLApp.inf
  build $BUILD_OPTS $3 -p "$1/kAFLDxePlatform${OVMF_DSC_ARCH}.dsc"

  echo "Build done, copy target files.."
  # Copy new platform
  cp -v "Build/$2/${BUILD}_${TOOL}/FV/OVMF.fd" $TARGET_BIN
  cp -v "Build/$2/${BUILD}_${TOOL}/FV/OVMF_CODE.fd" $SCRIPT_ROOT
  cp -v "Build/$2/${BUILD}_${TOOL}/FV/OVMF_VARS.fd" $SCRIPT_ROOT

  # Copy harness
  cp -v "Build/$2/${BUILD}_${TOOL}/X64/kAFLApp.efi" $SCRIPT_ROOT/fake_hda/harness.efi

  popd
}

function build_null()
{
  EXTRA=""
  build_platform kAFLDxePlatformNullPkg kAFLNull "$EXTRA"
}

function build_app()
{
  [ -d $EDK2_ROOT/BaseTools ] || ( echo "Please set correct EDK2_ROOT"; exit )
  pushd $EDK2_ROOT
  export PACKAGES_PATH=$SCRIPT_ROOT
  export EDK_TOOLS_PATH=$PWD/BaseTools
  . edksetup.sh BaseTools

  which build || exit

  build $BUILD_OPTS -p ${APP}Pkg/$APP.dsc

  echo "Build done, copy target files.."
  # XXX Should distinguish OVMF target architecture from harness architecture
  cp -v Build/${APP}Pkg/${BUILD}_${TOOL}/X64/$APP.efi $SCRIPT_ROOT/fake_hda/harness.efi
  popd
}

function fuzz()
{
  # Note: -ip0 depends on your UEFI build and provided machine memory!
  # To debug qemu, append -D -d to qemu extra and you'll have qemu logs
  kafl fuzz --purge \
    --bios $TARGET_BIN \
    $TARGET_RANGE \
    --qemu-extra="-hda fat:rw:$SCRIPT_ROOT/fake_hda" \
    --work-dir /dev/shm/kafl_uefi \
    $KAFL_OPTS $*
}

function noise()
{
  pushd $KAFL_ROOT/fuzzer
  TEMPDIR=$(mktemp -d -p /dev/shm)
  WORKDIR=$1; shift
  echo
  echo "Using temp workdir >>$TEMPDIR<<.."
  echo
  sleep 1

  # Note: VM configuration and trace settings should match those used during fuzzing
  kafl debug --action noise --purge \
    --bios $TARGET_BIN \
    $TARGET_RANGE \
    --qemu-extra="-hda fat:rw:$SCRIPT_ROOT/fake_hda" \
    --work-dir $TEMPDIR \
    --input $WORKDIR $*
  popd
}

function cov()
{
  WORKDIR=$1
  echo
  echo "Using temp workdir >>$TEMPDIR<<.."
  echo
  sleep 1

  # Note: VM configuration and trace settings should match those used during fuzzing
  kafl cov --resume \
    --bios $TARGET_BIN \
    $TARGET_RANGE \
    --qemu-extra="-hda fat:rw:$SCRIPT_ROOT/fake_hda" \
    --work-dir $WORKDIR \
    --input $WORKDIR
  popd
}


##
## Main
##

# check basic env setup
test -z ${KAFL_ROOT-} && fail "Could not find \$KAFL_ROOT. Missing 'make env'?"
[ -d $KAFL_ROOT/fuzzer ] || fail "Please set correct KAFL_ROOT"

# disable possibly pre-configured edk2 workspace
unset EDK_TOOLS_PATH
unset WORKSPACE
unset CONF_PATH
unset PACKAGES_PATH

# edk2 overrides the kAFL WORKSPACE so we base everything in SCRIPT_ROOT
SCRIPT_ROOT="$(cd `dirname $0` && pwd)"
EDK2_ROOT=$SCRIPT_ROOT/edk2.git

##
## Fuzzer / Target Configuration
##

KAFL_CONFIG_FILE="$SCRIPT_ROOT/kafl.yaml"
KAFL_OPTS="--redqueen --grimoire -p 8"
TARGET_BIN=$SCRIPT_ROOT/bios.bin
TARGET_RANGE="-ip0 0x2000000-0x2F00000 -ip1 0xF000000-0xFF00000"

#BUILD=RELEASE
BUILD=DEBUG
#BUILD=NOOPT

# Architecture selection
#ARCH=IA32
ARCH=X64
#ARCH=3264
TOOL=GCC5

APP=TestBMP
APP=TestDecompress

BUILD_OPTS=""
OVMF_DSC_ARCH=""

if test $ARCH = "X64"
then
  BUILD_OPTS="-a X64"
  OVMF_DSC_ARCH="X64"
elif test $ARCH = "IA32"
then
  BUILD_OPTS="-a IA32"
  OVMF_DSC_ARCH="Ia32"
elif test $ARCH = "3264"
then
  BUILD_OPTS="-a IA32 -a X64"
  OVMF_DSC_ARCH="Ia32X64"
else
  fail "Bad target architecture configuration"
fi

BUILD_OPTS="${BUILD_OPTS} \
    -t ${TOOL} \
    -b ${BUILD} \
    -n $(nproc)"


CMD=$1; shift || usage

case $CMD in
  "fuzz")
    fuzz $*
    ;;
  "noise")
    test -f "$1" || usage
    noise $*
    ;;
  "cov")
    test -d "$1" || usage
    cov $1
    ;;
  "edk2")
    install_edk2
    ;;
  "dxe_null")
    build_null
    ;;
  "ovmf")
    build_ovmf
    ;;
  "app")
    build_app
    ;;
  *)
    usage
    ;;
esac
