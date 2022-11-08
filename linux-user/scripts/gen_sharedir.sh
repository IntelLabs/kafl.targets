#!/bin/bash

# 
# Copyright (C)  2022  Intel Corporation. 
#
# This software and the related documents are Intel copyrighted materials, and
# your use of them is governed by the express license under which they were
# provided to you ("License"). Unless the License provides otherwise, you may
# not use, modify, copy, publish, distribute, disclose or transmit this software
# or the related documents without Intel's prior written permission. This
# software and the related documents are provided as is, with no express or
# implied warranties, other than those that are expressly stated in the License.
#
# SPDX-License-Identifier: MIT
#
# Generate a base sharedir for use with kAFL
# First argument is the target sharedir directory to be created + populated
#

set -e
set -u

HTOOLS_ROOT=$PACKER_ROOT/packer/linux_x86_64-userspace/
SHAREDIR=$BKC_ROOT/bkc/kafl/userspace/sharedir_template

fatal() {
	echo
	echo -e "\nError: $@\n" >&2
	echo -e "Usage:\n\t$(basename $0) <path/to/sharedir>\n" >&2
    exit 1
}

test $# -ne 1 || fatal "Need exactly one argument."
TARGET=$(realpath "$1")

test -d "$TARGET" && fatal "Refuse to overwrite output directory $TARGET."
test -d "$HTOOLS_ROOT" || fatal "Invalid directory: \$HTOOLS_ROOT=$HTOOLS_ROOT."
test -d "$SHAREDIR" || fatal "Invalid directory: \$SHAREDIR=$SHAREDIR."
mkdir -p "$TARGET" || fatal "Could not create output directory $TARGET."

echo "[*] Building kAFL / htools..."
make -C $HTOOLS_ROOT bin64 || fatal "Failed to build kAFL htools?"

echo "[*] Populating sharedir..."
cp -v $SHAREDIR/* $TARGET/ || fatal "Failed copying sharedir template files!"
cp -v $HTOOLS_ROOT/bin64/* $TARGET/ || fatal "Failed copying htools"

echo "[*] Done. Customize sharedir startup via $TARGET/init.sh"
