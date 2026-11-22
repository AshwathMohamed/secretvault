#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
# setup_vm.sh - installs everything needed to build the module (Ubuntu 22.04/24.04).
# Run it as a normal user, it uses sudo itself.
set -e   # stop at the first error
sudo apt update
# build-essential, flex, bison, bc, libelf, libssl, dwarves = tools the kernel build system needs
# linux-headers-$(uname -r) = headers of the kernel that is RUNNING right now (the module must match it)
sudo apt install -y build-essential libncurses-dev flex bison libssl-dev libelf-dev bc dwarves \
     git gdb python3 linux-headers-$(uname -r)
echo "Done. Take a VMware snapshot named 'clean-base' now."
