#!/bin/bash
# Full DroidVM image build on a macOS runner: reference kernel, owner-root policies, Data seed, kernel, package, payload, boot disk.
set -euxo pipefail
W=$GITHUB_WORKSPACE
cd "$W/UniXNU"
J=$(sysctl -n hw.ncpu)
DEV="$W/UniXNU-droidvm"
TV="$DEV/.cache/firmware/target-volumes"

# 1. reference candidate: a kernel without the storage/display drivers (the storage audit needs it)
python3 "$W/patches/make-reference-device.py" ../UniXNU-droidvm ../UniXNU-droidvm-ref
./unixnu defconfig droidvm_defconfig -D ../UniXNU-droidvm-ref --out "$PWD/out-ref"
./unixnu fetch
./unixnu tree --out "$PWD/out-ref"
bash "$W/patches/seed-github-cache.sh" out-ref/droidvm/tree
./unixnu ipsw fetch
mkdir -p out-ref && ln -sfn "$PWD/out/ipsw" out-ref/ipsw
./unixnu build kernel -j "$J" --out "$PWD/out-ref"

# 2. main tree, reference candidate in place
./unixnu defconfig droidvm_defconfig -D ../UniXNU-droidvm
./unixnu tree
TREE="$PWD/out/droidvm/tree"
bash "$W/patches/seed-github-cache.sh" "$TREE"
mkdir -p "$TREE/build/reference-candidate"
cp out-ref/droidvm/kernel/kernel.macho out-ref/droidvm/kernel/kernel.json "$TREE/build/reference-candidate/"

# 3. owner root: original OS/SystemOS, VerifiedRoot host library + keys, signed policies
./unixnu ipsw fetch OS Cryptex1,SystemOS
mkdir -p "$TV/os-mount"
for f in 044-76040-038.dmg 044-76034-038.dmg; do cp "$(ls out/ipsw/*/$f)" "$TV/$f"; done
python3 "$TREE/kits/VerifiedRoot/tests/check.py" --output "$TREE/build/verified-root-host" --openssl-prefix "$(brew --prefix openssl@3)"
hdiutil attach -readonly -noverify -noautofsck -nobrowse -mountpoint "$TV/os-mount" "$TV/044-76040-038.dmg"
python3 "$TREE/scripts/build-owner-os-policy.py"
python3 "$TREE/scripts/build-owner-systemos-policy.py"

# 4. Data seed (volatile 2 GiB); its APFS volume UUID goes into the kernel configuration
python3 "$TREE/scripts/prepare-owner-data-fixture.py" --output "$TREE/build/droidvm-data-fixture"
FIX="$TREE/build/droidvm-data-fixture"
UUID=$(python3 -c "import json;print(json.load(open('$FIX/seed.json'))['volume_uuid'].upper())")
mkdir -p "$TREE/build/droidvm-data"
python3 - "$TREE" "$FIX/owner-data-32.cdr" "$TREE/build/droidvm-data/data-32.dbr" <<'PY'
import sys
from pathlib import Path
sys.path.insert(0, sys.argv[1] + '/drivers/DarwinBoot/Test')
import packed_ramdisk
print(packed_ramdisk.pack(Path(sys.argv[2]), Path(sys.argv[3])))
PY
python3 "$TREE/scripts/seed-data-grow.py" --gib 2 --volatile "$TREE/build/droidvm-data/data-32.dbr" "$TREE/build/droidvm-data/data-2g.dbr"
# 4b. Adreno Metal plugin (Turnip + metal2vulkan bridge), staged into the seed without --publish: widgets/wallpaper render through it only after
# the owner has seen it work; GPU=0 skips the whole step.
DATA_RAMDISK="$TREE/build/droidvm-data/data-2g.dbr"
if [ "${GPU:-1}" = 1 ]; then
  bash "$W/patches/gpu-plugin-tree.sh" "$TREE"
  python3 "$TREE/scripts/add-gpu-plugin-data.py" --clients WidgetRenderer_Default,PosterBoard,iconservicesagent \
    "$TREE/build/droidvm-data/data-2g.dbr" "$TREE/build/droidvm-data/data-2g-gpu.dbr"
  DATA_RAMDISK="$TREE/build/droidvm-data/data-2g-gpu.dbr"
fi
sed -i '' "s/^CONFIG_XNU_OWNER_DATA_VOLUME_UUID=.*/CONFIG_XNU_OWNER_DATA_VOLUME_UUID=\"$UUID\"/" "$DEV/configs/droidvm_defconfig"
grep OWNER_DATA_VOLUME_UUID "$DEV/configs/droidvm_defconfig"
./unixnu defconfig droidvm_defconfig -D ../UniXNU-droidvm

# 5. kernel
./unixnu build kernel -j "$J"

# 6. original static+system trust caches (needs the whole IPSW)
IPSW_URL=$(python3 -c "import tomllib;print(tomllib.load(open('$DEV/board.toml','rb'))['ipsw']['url'])")
mkdir -p "$TREE/refer"
curl -fL --retry 5 -o "$TREE/refer/iPad_Pro_HFR_17.7.11_21H461_Restore.ipsw" "$IPSW_URL"
python3 - "$TREE" <<'PY'
import hashlib, plistlib, sys, zipfile
from pathlib import Path
tree = Path(sys.argv[1])
with zipfile.ZipFile(tree / 'refer/iPad_Pro_HFR_17.7.11_21H461_Restore.ipsw') as z:
    m = plistlib.loads(z.read('BuildManifest.plist'))
    ident = [i for i in m['BuildIdentities'] if i['Info']['DeviceClass'] == 'j120ap'][0]
    raw = z.read(ident['Manifest']['StaticTrustCache']['Info']['Path'])
def der(d, at):
    tag, size = d[at:at + 2]; at += 2
    if size & 128:
        n = size & 127; size = int.from_bytes(d[at:at + n], 'big'); at += n
    return tag, d[at:at + size], at + size
tag, seq, _ = der(raw, 0); fields, c = [], 0
while c < len(seq):
    k, v, c = der(seq, c); fields.append((k, v))
assert fields[0][1] == b'IM4P', fields[0]
out = tree / '.cache/firmware/target-volumes/static-trustcache.bin'
out.write_bytes(fields[3][1])
print('static trust cache', hashlib.sha256(fields[3][1]).hexdigest())
PY
python3 "$TREE/scripts/build-original-system-trust.py"

TRUST_ARGS=(--trust-cache "$TREE/build/original-static-system-trust/original-static-system.bundle")
if [ "${GPU:-1}" = 1 ]; then
  python3 "$TREE/scripts/make-owner-trust-bundle.py"
  TRUST_ARGS=(--owner-trust-cache "$TREE/build/adreno-metal-plugin/owner-trust.bundle")
fi

# 7. package (UniXNU.efi), DarwinBoot.efi, payload, boot disk
./unixnu build package -j "$J"
EDK2=$(ls -d out/feeds/mu_basecore-* | head -1)
CLANG_BIN="$(brew --prefix llvm)/bin/" bash "$DEV/scripts/build-darwinboot-efi.sh" "$TREE" "$EDK2" DEBUG
./unixnu build payload \
  "${TRUST_ARGS[@]}" \
  --data-ramdisk "$DATA_RAMDISK" --skip-setup --unique-chip-id 47554e5941480001
bash "$DEV/scripts/make-droidvm-disk.sh" out/droidvm/payload/payload.img out/droidvm/package/Build/Out/AARCH64-DEBUG out/droidvm/droidvm-disk.img
ls -la out/droidvm out/droidvm/payload
