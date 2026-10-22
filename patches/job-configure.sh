#!/bin/bash
# unixnu defconfig/fetch/tree of the main configuration (the GPU job needs the tree for its sources, not the images).
set -euxo pipefail
W=$GITHUB_WORKSPACE
cd "$W/UniXNU"
./unixnu defconfig droidvm_defconfig -D ../UniXNU-droidvm
./unixnu fetch
./unixnu tree
