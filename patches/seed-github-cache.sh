#!/bin/bash
# Pre-seed prepare-xnu-source.py's API caches with authenticated gh calls (anonymous urllib is rate limited).
set -euo pipefail
dir="$1/.cache/sources"; mkdir -p "$dir"
api() { gh api "repos/apple-oss-distributions/xnu/contents/$1?ref=$2"; }
api iokit/DriverKit xnu-10063.121.3 > "$dir/xnu-driverkit-10063.121.3.json"
api iokit/DriverKit/crypto xnu-10063.121.3 > "$dir/xnu-driverkit-crypto-10063.121.3.json"
api EXTERNAL_HEADERS/TrustCache xnu-8796.101.5 > "$dir/xnu-trustcache-8796.101.5.json"
ls -la "$dir"
