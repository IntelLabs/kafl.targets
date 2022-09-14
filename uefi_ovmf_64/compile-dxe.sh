#!/bin/bash
#
# kAFL helper script to build and launch UEFI components
#
# Copyright 2019-2020 Intel Corporation
# SPDX-License-Identifier: MIT
#

set -e

unset EDK_TOOLS_PATH
unset WORKSPACE
unset CONF_PATH
unset PACKAGES_PATH

TARGET_ROOT="$(dirname ${PWD}/${0})"
[ -n "$KAFL_ROOT" ] || KAFL_ROOT=${PWD}
[ -n "$EDK2_ROOT" ] || EDK2_ROOT=$KAFL_ROOT/edk2.git

[ -d $KAFL_ROOT/fuzzer ] || ( echo "Please set correct KAFL_ROOT" ; false )

# Release selection

#BUILD=RELEASE
#BUILD=DEBUG
BUILD=NOOPT

# Architecture selection

#ARCH=IA32
ARCH=X64
#ARCH=3264
TOOL=GCC5

#APP=TestDecompress
#APP=TestBMP
APP=TestToy

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
  echo "Bad target architecture configuration"
  exit 1
fi

BUILD_OPTS="${BUILD_OPTS} \
  -t ${TOOL} \
  -b ${BUILD} \
  -n $(nproc)"

KAFL_OPTS="--redqueen --grimoire -v --debug -p 8"

function install_edk2()
{
  # requirements on top of kAFL base install
  sudo apt-get install nasm iasl g++ g++-multilib

  # download + apply patch unless install folder already exists
  if [ -d $KAFL_ROOT/edk2.git ]; then
    echo "[*] Folder exists, assume it is already patched.."
    pushd $KAFL_ROOT/edk2.git
  else
    git clone https://github.com/tianocore/edk2 $KAFL_ROOT/edk2.git
    pushd $KAFL_ROOT/edk2.git
    git checkout -b edk2-stable201905
    git submodule update --init --recursive
    patch -p1 < $TARGET_ROOT/edk2_kafl.patch || exit
    patch -p1 < $TARGET_ROOT/edk2_kafl_ovmf.patch || exit
  fi
  make -C BaseTools -j $(nproc)
  export EDK_TOOLS_PATH=$PWD/BaseTools
  . edksetup.sh BaseTools
  popd
}

function build_platform()
{
  echo
  echo Building package $1, output platform name $2, extra build opts $3
  echo
  sleep 1

  [ -d $EDK2_ROOT/BaseTools ] || ( echo "Please set correct EDK2_ROOT"; exit )
  pushd $EDK2_ROOT
  export PACKAGES_PATH=$TARGET_ROOT
  export EDK_TOOLS_PATH=$PWD/BaseTools
  . edksetup.sh BaseTools

  which build || exit

  # Already built with my OVMF platform
  # @see in kAFLDxeHarnessPkg/App/kAFLApp.inf
  build $BUILD_OPTS $3 -p "$1/kAFLDxePlatform${OVMF_DSC_ARCH}.dsc"

  echo "Build done, copy target files.."
  # Copy new platform
  cp -v "Build/$2/${BUILD}_${TOOL}/FV/OVMF.fd" $TARGET_ROOT/bios.bin
  cp -v "Build/$2/${BUILD}_${TOOL}/FV/OVMF_CODE.fd" $TARGET_ROOT
  cp -v "Build/$2/${BUILD}_${TOOL}/FV/OVMF_VARS.fd" $TARGET_ROOT

  # Copy harness
  cp -v "Build/$2/${BUILD}_${TOOL}/X64/kAFLApp.efi" $TARGET_ROOT/fake_hda/harness.efi

  popd
}

function build_null()
{
  EXTRA=""
  build_platform kAFLDxePlatformNullPkg kAFLNull "$EXTRA"
}

function run()
{
  pushd $KAFL_ROOT/fuzzer
  # Note: -ip0 depends on your UEFI build and provided machine memory!
  #  --seed-dir $TARGET_ROOT/seeds/ \
  # To debug qemu, append -D -d to qemu extra and you'll have qemu logs
  ./kafl_fuzz.py -ip0 0xE000000-0xEF00000 -ip1 0xF000000-0xFF00000 --purge \
    --qemu-extra="-hda fat:rw:$TARGET_ROOT/fake_hda" \
    --bios $TARGET_ROOT/bios.bin \
    --memory 256 \
    --work-dir /dev/shm/kafl_uefi \
    $KAFL_OPTS $*
  popd
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

  # Note: -ip0 and other VM settings should match those used during fuzzing
  ./kafl_debug.py --action noise -ip0 0x2000000-0x2F00000 -ip1 0xF000000-0xFF00000 --purge \
    --bios $TARGET_ROOT/bios.bin \
    --qemu-extra="-hda fat:rw:$TARGET_ROOT/fake_hda" \
    --memory 256 \
    --work-dir $TEMPDIR \
    --input $WORKDIR $*
  popd
}

function cov()
{
  pushd $KAFL_ROOT/fuzzer
  TEMPDIR=$(mktemp -d -p /dev/shm)
  WORKDIR=$1
  echo
  echo "Using temp workdir >>$TEMPDIR<<.."
  echo
  sleep 1

  # Note: -ip0 and other VM settings should match those used during fuzzing
  echo ./kafl_cov.py -v -ip0 0xE000000-0xEF00000 -ip1 0xF000000-0xFF00000 --purge \
    --bios $TARGET_ROOT/bios.bin \
    --qemu-extra "-hda fat:rw:$TARGET_ROOT/fake_hda" \
    --memory 256 \
    --work-dir $TEMPDIR \
    --input $WORKDIR
  ./kafl_cov.py -v -ip0 0xE000000-0xEF00000 -ip1 0xF000000-0xFF00000 --purge \
    --bios $TARGET_ROOT/bios.bin \
    --qemu-extra="-hda fat:rw:$TARGET_ROOT/fake_hda" \
    --memory 256 \
    --work-dir $TEMPDIR \
    --input $WORKDIR
  popd
}

function build_app()
{
  [ -d $EDK2_ROOT/BaseTools ] || ( echo "Please set correct EDK2_ROOT"; exit )
  pushd $EDK2_ROOT
  export PACKAGES_PATH=$TARGET_ROOT
  export EDK_TOOLS_PATH=$PWD/BaseTools
  . edksetup.sh BaseTools

  which build || exit

  build $BUILD_OPTS -p ${APP}Pkg/$APP.dsc

  echo "Build done, copy target files.."
  # XXX Should distinguish OVMF target architecture from harness architecture
  cp -v Build/${APP}Pkg/${BUILD}_${TOOL}/X64/$APP.efi $TARGET_ROOT/fake_hda/kAFLApp.efi
  popd
}

function build_ovmf()
{
  [ -d $EDK2_ROOT/BaseTools ] || ( echo "Please set correct EDK2_ROOT"; exit )
  pushd $EDK2_ROOT
  export EDK_TOOLS_PATH=$PWD/BaseTools
  . edksetup.sh BaseTools

  which build || exit

  build $BUILD_OPTS -p OvmfPkg/OvmfPkg${OVMF_DSC_ARCH}.dsc

  echo "Build done, copy target files.."
  # [ $ARCH == "IA32" ] && ARCH="Ia32"
  cp -v Build/Ovmf${ARCH}/${BUILD}_${TOOL}/FV/OVMF.fd $TARGET_ROOT/bios.bin
  cp -v Build/Ovmf${ARCH}/${BUILD}_${TOOL}/FV/OVMF_CODE.fd $TARGET_ROOT
  cp -v Build/Ovmf${ARCH}/${BUILD}_${TOOL}/FV/OVMF_VARS.fd $TARGET_ROOT
  popd
}

function usage() {
  echo
  echo "Build and run the UEFI OVMF sample."
  echo
  echo "This script assumes KAFL at $KAFL_ROOT and EDK2 cloned to $EDK2_ROOT."
  echo "Build settings in Conf/target.txt will be overridden with '$BUILD_OPTS'."
  echo
  echo "Usage: $0 <target>"
  echo
  echo Targets:
  echo "  run                          - run sample agent in kAFL"
  echo "  noise <file>                 - process <file> in trace mode to collect coverage info"
  echo "  cov <dir>                    - process <dir> in trace mode to collect coverage info"
  echo "  edk2                         - download edk2 branch + build deps"
  echo "  dxe_null                     - build kAFL Dxe NULL Fuzzing platform"
  echo "  ovmf                         - Build genuine OVMF platform, for post"
  echo "                                     DXE fuzzing"
  echo "  app                          - Build application the harness"
  exit
}


CMD=$1; shift || usage

case $CMD in
  "run")
    run $*
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
