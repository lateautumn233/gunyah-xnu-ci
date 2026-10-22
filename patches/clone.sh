#!/bin/bash
# Clone the UniXNU fork and its device repository ($1, $2: branches), authenticate its GitHub API fetches, and print the two commits
# (also to $GITHUB_OUTPUT as unixnu_sha/device_sha) that the cache keys are built from.
set -euxo pipefail
W=$(cd "$(dirname "$0")/.." && pwd)
cd "$W"
git clone --recurse-submodules --branch "$1" https://github.com/lateautumn233/UniXNU.git
git clone --branch "$2" https://github.com/lateautumn233/UniXNU-droidvm.git
python3 "$W/patches/github-auth.py" UniXNU/scripts/prepare-xnu-source.py
echo "unixnu_sha=$(git -C UniXNU rev-parse HEAD)" >> "${GITHUB_OUTPUT:-/dev/null}"
echo "device_sha=$(git -C UniXNU-droidvm rev-parse HEAD)" >> "${GITHUB_OUTPUT:-/dev/null}"
