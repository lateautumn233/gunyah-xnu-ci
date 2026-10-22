#!/bin/bash
# First half of the assemble job: configuration with the seed's UUID, fetch, tree, seed bundle and reference kernel in place.
# (The build cache of the kernel is restored between this and job-assemble-build.sh.)
#   $1 seed-bundle.tgz  $2 refout directory
set -euxo pipefail
W=$GITHUB_WORKSPACE
SEED=$(cd "$(dirname "$1")" && pwd)/$(basename "$1")
REF=$(cd "$2" && pwd)
cd "$W/UniXNU"
DEV="$W/UniXNU-droidvm"
# the seed's volume UUID goes into the device configuration (the seed may come from a cache, so the bundle carries no defconfig)
mkdir -p "$W/in/uuid"
tar xzf "$SEED" -C "$W/in/uuid" UniXNU/out/droidvm/tree/build/droidvm-data-fixture/seed.json
UUID=$(python3 -c "import json;print(json.load(open('$W/in/uuid/UniXNU/out/droidvm/tree/build/droidvm-data-fixture/seed.json'))['volume_uuid'].upper())")
sed -i '' "s/^CONFIG_XNU_OWNER_DATA_VOLUME_UUID=.*/CONFIG_XNU_OWNER_DATA_VOLUME_UUID=\"$UUID\"/" "$DEV/configs/droidvm_defconfig"
grep OWNER_DATA_VOLUME_UUID "$DEV/configs/droidvm_defconfig"
./unixnu defconfig droidvm_defconfig -D ../UniXNU-droidvm
./unixnu fetch
./unixnu ipsw fetch
./unixnu tree
TREE="$PWD/out/droidvm/tree"
bash "$W/patches/seed-github-cache.sh" "$TREE"
tar xzf "$SEED" -C "$W"
mkdir -p "$TREE/build/reference-candidate"
cp "$REF/kernel.macho" "$REF/kernel.json" "$TREE/build/reference-candidate/"

