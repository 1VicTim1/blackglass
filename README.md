# NULLTRACE

Offline-first forensic terminal for URLs and local files. The interface combines Metasploit-style execution markers, a SOC evidence layout, and a truecolor cyberpunk palette. Counters and events are backed by actual checks.

## Run

```bash
nulltrace 'https://example.com'
nulltrace ./suspicious-file.jpg
```

The offline report completes first. Press Enter to open the network consent dialog, then Enter again to authorize DNS enrichment. Press Escape to cancel the dialog and `q` to exit.

The data directory should sit beside the binary. Its government-domain list is a small sourced seed, not a complete official registry. No government CIDR is asserted without a cited source.

Image scans parse PNG/JPEG/WebP dimensions, JPEG frame and quantization structure, and selected EXIF camera/software/date/GPS fields. Video scans use local `ffprobe` when installed (`pkg install ffmpeg` in Termux); otherwise the video probe is shown as skipped rather than successful. Metadata and encoder tags are evidence, not proof of editing.

## Build

```bash
cargo test
cargo build --release
./scripts/build-android.sh /path/to/android-ndk
./scripts/package-release.sh
```

The Android build targets API 24 and runs in current ARM64 Termux installations.
