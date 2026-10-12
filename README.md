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

Offline identity checks detect brand lookalikes (including `rnicrosoft`), common Unicode confusables, typos, brand tokens on foreign hosts, and special IP scopes. `data/brands.csv` is a curated, incomplete reference catalog: matching a suffix is attribution, not proof of ownership or safety. Findings include the matched brand, evidence and reference domains.

All local files receive filename and active-content inspection: bidirectional/invisible controls, deceptive double extensions, MZ/PE/ELF headers and shebangs. Files are never executed. PE/ELF and executable extensions alone are low-weight signals; filename deception and signature mismatch are stronger signals. Names display control characters as `<U+XXXX>`.

MP4/MOV/M4V containers have a bounded built-in ISO BMFF parser for brands, box offsets/sizes, duration, track dimensions, sample codecs and edit lists. This works without ffprobe; optional ffprobe adds stream detail (`pkg install ffmpeg` in Termux). Cropping and re-encoding cannot be established from container metadata alone. Local reports have no DNS tasks or network consent prompt. A zero heuristic score does not establish safety; coverage and unavailable checks appear in the report.
