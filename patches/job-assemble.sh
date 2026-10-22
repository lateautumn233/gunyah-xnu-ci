#!/bin/bash
# Kernel, package, DarwinBoot, GPU addon, payload and boot disk from the seed bundle, the reference kernel and (optionally) the GPU plugin.
#   $1 seed-bundle.tgz  $2 refout directory  $3 gpu-plugin directory (adreno-metal-plugin, optional)
set -euxo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
bash "$HERE/job-assemble-prepare.sh" "$1" "$2"
bash "$HERE/job-assemble-build.sh" "${3:-}"
