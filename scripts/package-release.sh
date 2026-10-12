#!/usr/bin/env bash
set -euo pipefail

binary=${1:-target/aarch64-linux-android/release/nulltrace}
release_dir=dist/nulltrace-aarch64-linux-android
archive=dist/nulltrace-aarch64-linux-android.tar.gz

test -x "$binary"
mkdir -p "$release_dir/data"
cp "$binary" "$release_dir/nulltrace"
cp data/gov_domains.csv data/gov_zones.csv data/brands.csv data/gov_prefixes.csv data/hosting_prefixes.csv data/SOURCES.md "$release_dir/data/"
cp README.md "$release_dir/"
(cd dist && tar -czf "$(basename "$archive")" "$(basename "$release_dir")")
sha256sum "$archive" > "$archive.sha256"
echo "$archive"
