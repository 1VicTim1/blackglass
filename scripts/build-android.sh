#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "usage: $0 /path/to/android-ndk" >&2
  exit 2
fi

ndk_root=$1
linker="$ndk_root/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android24-clang"
archiver="$ndk_root/toolchains/llvm/prebuilt/linux-x86_64/bin/llvm-ar"
if [[ ! -x "$linker" ]]; then
  echo "Android NDK linker not found: $linker" >&2
  exit 1
fi
if [[ ! -x "$archiver" ]]; then
  echo "Android NDK archiver not found: $archiver" >&2
  exit 1
fi

rustup target add aarch64-linux-android
CC_aarch64_linux_android="$linker" \
AR_aarch64_linux_android="$archiver" \
CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER="$linker" \
  cargo build --release --target aarch64-linux-android
file target/aarch64-linux-android/release/nulltrace
