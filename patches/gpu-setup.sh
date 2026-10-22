#!/bin/bash
# Prepare the undocumented prerequisites of UniXNU's Adreno Metal plugin build (scripts/build-adreno-metal-plugin.py) from public, pinned inputs:
# .cache/mesa-work (pinned Mesa + the recorded patches as an uncommitted diff), .cache/mesa-venv, .cache/mesa-tools/bin,
# .cache/gpu-reference/metal2vulkan (pinned; build-native-metal-bridge.py applies its own patches).
set -euxo pipefail
TREE=$(cd "$1" && pwd)
cd "$TREE"
mkdir -p .cache/mesa-tools/bin .cache/gpu-reference
HERE=$(cd "$(dirname "$0")" && pwd)
pins() { python3 "$HERE/gpu_pins.py" "$1" "$TREE"; }
MESA_COMMIT=$(pins mesa-commit)
M2V_COMMIT=$(pins m2v-commit)

if [ ! -d .cache/mesa-work/.git ]; then
  git clone --filter=blob:none --no-checkout https://gitlab.freedesktop.org/mesa/mesa.git .cache/mesa-work \
    || git clone --filter=blob:none --no-checkout https://chromium.googlesource.com/external/gitlab.freedesktop.org/mesa/mesa .cache/mesa-work
  (
    cd .cache/mesa-work
    git sparse-checkout init --cone
    DIRS=$(pins mesa-dirs); [ -n "$DIRS" ]
    git sparse-checkout set $DIRS
    git checkout --detach "$MESA_COMMIT"
    PATCHES=$(pins mesa-patches); [ -n "$PATCHES" ]
    for patch in $PATCHES; do git apply "$TREE/$patch"; done
    git rev-parse HEAD; git status --short | head -20
  )
fi

if [ ! -x .cache/mesa-venv/bin/meson ]; then
  python3 -m venv .cache/mesa-venv
  .cache/mesa-venv/bin/pip install --quiet meson mako pyyaml packaging ply
fi
for tool in bison flex; do ln -sf "$(command -v brew >/dev/null && brew --prefix "$tool" || echo /usr)/bin/$tool" ".cache/mesa-tools/bin/$tool"; done
.cache/mesa-tools/bin/bison --version | head -1

if [ ! -d .cache/gpu-reference/metal2vulkan/.git ]; then
  git clone --filter=blob:none --no-checkout https://github.com/steelbrain/metal2vulkan.git .cache/gpu-reference/metal2vulkan
  git -C .cache/gpu-reference/metal2vulkan checkout --detach "$M2V_COMMIT"
fi
