# NULLTRACE

Offline-first forensic terminal for URLs, email addresses and local files. The interface combines Metasploit-style execution markers, a SOC evidence layout, and a truecolor cyberpunk palette. Counters and events are backed by actual checks.

## Run

```bash
nulltrace 'https://example.com'
nulltrace '122aaa121@gmail.com'
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

Email addresses are accepted directly, for example `nulltrace 122aaa121@gmail.com`. Offline checks validate and normalize the address, inspect its local part and reuse domain impersonation rules. After explicit online consent, NULLTRACE queries MX, SPF and DMARC through Cloudflare DNS-over-HTTPS. These records describe the domain and cannot prove that an individual mailbox exists; NULLTRACE does not send mail or perform hidden SMTP recipient probes. Quoted local parts and SMTPUTF8 local parts are intentionally outside the first parser version.

RFC 5322/MIME `.eml` files receive a dedicated offline report: decoded headers and Received hops, From/Reply-To/Return-Path alignment, reported SPF/DKIM/DMARC results, text and HTML parts, link destinations and attachments. Attachments are decoded without execution and receive a size, MIME/signature comparison and SHA-256. Authentication-Results is displayed as untrusted evidence unless the receiving boundary is independently established. After explicit consent, NULLTRACE queries the visible sender domain's MX/SPF/DMARC records and traces up to five extracted HTTP(S) links without downloading response bodies. Parsing is bounded to 32 MiB and 128 MIME parts.

URL online enrichment resolves addresses, checks the embedded and local `data/hosting_prefixes.csv` CIDR catalog, queries RIPE Stat for prefix/ASN/holder and approximate GeoLite location, inspects the verified TLS certificate, and traces up to 10 HTTP redirects without downloading response bodies. HTTPS downgrade and redirects to another registrable domain become explained findings.

The packaged CIDR snapshot is generated from the official Cloudflare, AWS and Google Cloud feeds. Regenerate it with `python3 scripts/update-network-data.py`; review and commit the resulting dated CSV. Provider attribution does not increase risk by itself.

Optional MaxMind/DB-IP databases can be placed in `data/` beside the binary or in `NULLTRACE_DATA_DIR`. Recognized names are `GeoLite2-ASN.mmdb`, `GeoLite2-City.mmdb`, `GeoIP2-ASN.mmdb`, `GeoIP2-City.mmdb`, `DBIP-ASN-LITE.mmdb`, and `DBIP-CITY-LITE.mmdb`. Local results and RIPE results are shown with separate source labels; GeoIP describes an approximate network location, not a person's physical location.

All local files receive filename and active-content inspection: bidirectional/invisible controls, deceptive double extensions, MZ/PE/ELF headers and shebangs. Files are never executed. PE/ELF and executable extensions alone are low-weight signals; filename deception and signature mismatch are stronger signals. Names display control characters as `<U+XXXX>`.

MP4/MOV/M4V containers have a bounded built-in ISO BMFF parser for brands, box offsets/sizes, duration, track dimensions, sample codecs and edit lists. This works without ffprobe; optional ffprobe adds stream detail (`pkg install ffmpeg` in Termux). Cropping and re-encoding cannot be established from container metadata alone. Local reports have no DNS tasks or network consent prompt. A zero heuristic score does not establish safety; coverage and unavailable checks appear in the report.
