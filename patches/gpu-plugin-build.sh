#!/bin/bash
# Build the Adreno Metal plugin (NativeAdrenoMetal.bundle + probe daemon) on a macOS runner. No Apple-derived inputs are used.
set -euxo pipefail
W=$GITHUB_WORKSPACE
cd "$W/UniXNU"
./unixnu defconfig droidvm_defconfig -D ../UniXNU-droidvm
./unixnu fetch
./unixnu tree
TREE=$PWD/out/droidvm/tree
bash "$W/patches/gpu-plugin-tree.sh" "$TREE"
