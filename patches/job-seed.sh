#!/bin/bash
# Owner root (original OS/SystemOS, VerifiedRoot host library + keys, signed policies), the Data seed (volatile 2 GiB), the original static+system
# trust caches and the wallpaper overlay. Output: seed-bundle.tgz with every tree input the kernel/payload job needs, plus the device defconfig
# that carries the seed's volume UUID.
set -euxo pipefail
W=$GITHUB_WORKSPACE
cd "$W/UniXNU"
DEV="$W/UniXNU-droidvm"
TV="$DEV/.cache/firmware/target-volumes"
./unixnu defconfig droidvm_defconfig -D ../UniXNU-droidvm
./unixnu fetch
./unixnu ipsw fetch
./unixnu tree
TREE="$PWD/out/droidvm/tree"
bash "$W/patches/seed-github-cache.sh" "$TREE"

# the whole IPSW (static+system trust caches) downloads while the rest builds
IPSW_URL=$(python3 -c "import tomllib;print(tomllib.load(open('$DEV/board.toml','rb'))['ipsw']['url'])")
mkdir -p "$TREE/refer"
curl -fL --retry 5 -o "$TREE/refer/iPad_Pro_HFR_17.7.11_21H461_Restore.ipsw" "$IPSW_URL" &
IPSW_PID=$!

# owner root
./unixnu ipsw fetch OS Cryptex1,SystemOS
mkdir -p "$TV/os-mount"
for f in 044-76040-038.dmg 044-76034-038.dmg; do cp "$(ls out/ipsw/*/$f)" "$TV/$f"; done
python3 "$TREE/kits/VerifiedRoot/tests/check.py" --output "$TREE/build/verified-root-host" --openssl-prefix "$(brew --prefix openssl@3)"
hdiutil attach -readonly -noverify -noautofsck -nobrowse -mountpoint "$TV/os-mount" "$TV/044-76040-038.dmg"
python3 "$TREE/scripts/build-owner-os-policy.py"
python3 "$TREE/scripts/build-owner-systemos-policy.py"
python3 "$TREE/scripts/make-wallpaper-overlay.py" "$TV/os-mount" "$TREE/build/wallpaper-overlay"

# Data seed; its APFS volume UUID goes into the kernel configuration
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
# diskutil sometimes lists the attached seed's APFS container late (seen once with the IPSW download running): retry
for attempt in 1 2 3 4; do
  rm -f "$TREE/build/droidvm-data/data-2g.dbr"
  python3 "$TREE/scripts/seed-data-grow.py" --gib 2 --volatile "$TREE/build/droidvm-data/data-32.dbr" "$TREE/build/droidvm-data/data-2g.dbr" && break
  [ "$attempt" = 4 ] && exit 1
  sleep 15
done
sed -i '' "s/^CONFIG_XNU_OWNER_DATA_VOLUME_UUID=.*/CONFIG_XNU_OWNER_DATA_VOLUME_UUID=\"$UUID\"/" "$DEV/configs/droidvm_defconfig"
grep OWNER_DATA_VOLUME_UUID "$DEV/configs/droidvm_defconfig"

# original static+system trust caches
wait "$IPSW_PID"
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

# bundle (paths relative to the workspace; the kernel/payload job unpacks it into a fresh tree)
T=UniXNU/out/droidvm/tree/build
cd "$W"
mkdir -p bundle
tar czf bundle/seed-bundle.tgz UniXNU-droidvm/configs/droidvm_defconfig \
  $(for d in verified-root-os verified-root-systemos verified-root-host droidvm-data droidvm-data-fixture/seed.json original-static-system-trust wallpaper-overlay; do echo "$T/$d"; done)
ls -la bundle
