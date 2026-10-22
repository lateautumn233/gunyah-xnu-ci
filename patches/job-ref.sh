#!/bin/bash
# Reference candidate: a kernel without the storage/display drivers (the storage audit of the real kernel needs it). Output: refout/.
set -euxo pipefail
W=$GITHUB_WORKSPACE
cd "$W/UniXNU"
J=$(sysctl -n hw.ncpu)
python3 "$W/patches/make-reference-device.py" ../UniXNU-droidvm ../UniXNU-droidvm-ref
./unixnu defconfig droidvm_defconfig -D ../UniXNU-droidvm-ref --out "$PWD/out-ref"
./unixnu fetch
./unixnu tree --out "$PWD/out-ref"
bash "$W/patches/seed-github-cache.sh" out-ref/droidvm/tree
./unixnu ipsw fetch
mkdir -p out-ref && ln -sfn "$PWD/out/ipsw" out-ref/ipsw
./unixnu build kernel -j "$J" --out "$PWD/out-ref"
mkdir -p "$W/refout"
cp out-ref/droidvm/kernel/kernel.macho out-ref/droidvm/kernel/kernel.json "$W/refout/"
