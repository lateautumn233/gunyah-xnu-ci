#!/bin/bash
# Second half of the assemble job: kernel, package, DarwinBoot, GPU addon, payload and boot disk.
#   $1 gpu-plugin directory (adreno-metal-plugin, optional)
set -euxo pipefail
W=$GITHUB_WORKSPACE
GPU_DIR=${1:+$(cd "$1" && pwd)}   # absolute: the script changes directory
cd "$W/UniXNU"
J=$(sysctl -n hw.ncpu)
DEV="$W/UniXNU-droidvm"
TREE="$PWD/out/droidvm/tree"
./unixnu build kernel -j "$J"
./unixnu build package -j "$J"
EDK2=$(ls -d out/feeds/mu_basecore-* | head -1)
CLANG_BIN="$(brew --prefix llvm)/bin/" bash "$DEV/scripts/build-darwinboot-efi.sh" "$TREE" "$EDK2" DEBUG

# GPU: the plugin's owner trust module goes around the original trust caches; the plugin itself travels as a payload addon (the Data seed
# stays untouched, so its persistent store survives a plugin rebuild). No --publish yet: widgets and wallpaper render through the plugin
# only after the owner has seen it work.
TRUST_ARGS=(--trust-cache "$TREE/build/original-static-system-trust/original-static-system.bundle")
ADDON_ARGS=()
if [ -n "$GPU_DIR" ] && [ -d "$GPU_DIR" ]; then
  mkdir -p "$TREE/build"
  rm -rf "$TREE/build/adreno-metal-plugin"
  cp -R "$GPU_DIR" "$TREE/build/adreno-metal-plugin"
  python3 "$TREE/scripts/make-owner-trust-bundle.py"
  TRUST_ARGS=(--owner-trust-cache "$TREE/build/adreno-metal-plugin/owner-trust.bundle")
  python3 "$TREE/scripts/make-gpu-addon.py" --clients WidgetRenderer_Default,PosterBoard,iconservicesagent \
    --wallpaper "$TREE/build/wallpaper-overlay" "$TREE/build/droidvm-data/gpu.addon"
  ADDON_ARGS=(--gpu-addon "$TREE/build/droidvm-data/gpu.addon")
fi
./unixnu build payload "${TRUST_ARGS[@]}" \
  --data-ramdisk "$TREE/build/droidvm-data/data-2g.dbr" ${ADDON_ARGS[@]+"${ADDON_ARGS[@]}"} --skip-setup --unique-chip-id 47554e5941480001
bash "$DEV/scripts/make-droidvm-disk.sh" out/droidvm/payload/payload.img out/droidvm/package/Build/Out/AARCH64-DEBUG out/droidvm/droidvm-disk.img
ls -la out/droidvm out/droidvm/payload
