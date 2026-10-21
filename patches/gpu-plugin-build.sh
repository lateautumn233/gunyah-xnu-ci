#!/bin/bash
# Build the Adreno Metal plugin (NativeAdrenoMetal.bundle + probe daemon) on a macOS runner. No Apple-derived inputs are used.
set -euxo pipefail
W=$GITHUB_WORKSPACE
cd "$W/UniXNU"
./unixnu defconfig droidvm_defconfig -D ../UniXNU-droidvm
./unixnu fetch
./unixnu tree
TREE=$PWD/out/droidvm/tree
bash "$W/patches/gpu-setup.sh" "$TREE"
cd "$TREE"
export PATH="$HOME/.cargo/bin:$PATH"
rustup toolchain install 1.98.0 --profile minimal -t aarch64-apple-ios -t aarch64-apple-darwin
python3 scripts/build-turnip-darwin.py --target host
python3 scripts/check-turnip-darwin-host.py || true      # builds plugin_smoke + the host IOKit shim the replay recorder needs
python3 scripts/gen-turnip-replay.py
python3 scripts/build-turnip-darwin.py --target ios
python3 scripts/build-adreno-metal-plugin.py
ls -laR build/adreno-metal-plugin | head -40
cat build/adreno-metal-plugin/trust.json
