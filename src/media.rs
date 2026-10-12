use anyhow::{Context, Result, anyhow};
use serde_json::Value;
use std::{
    fs::File,
    io::{Cursor, Read},
    path::Path,
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant},
};

pub struct ProbeResult {
    pub observations: Vec<(String, String)>,
    pub skipped: Option<String>,
}

pub fn inspect_image(path: &Path) -> Result<Vec<(String, String)>> {
    let file = File::open(path)?;
    let mut bytes = Vec::new();
    file.take(32 * 1024 * 1024).read_to_end(&mut bytes)?;
    let mut observations = if bytes.starts_with(b"\x89PNG\r\n\x1a\n") {
        inspect_png(&bytes)?
    } else if bytes.starts_with(&[0xff, 0xd8]) {
        inspect_jpeg(&bytes)?
    } else if bytes.starts_with(b"RIFF") && bytes.get(8..12) == Some(b"WEBP") {
        inspect_webp(&bytes)?
    } else {
        return Err(anyhow!("unsupported image structure"));
    };
    if let Ok(exif) = exif::Reader::new().read_from_container(&mut Cursor::new(&bytes)) {
        for field in exif.fields() {
            let label = match field.tag {
                exif::Tag::Make => Some("EXIF Make"),
                exif::Tag::Model => Some("EXIF Model"),
                exif::Tag::Software => Some("EXIF Software"),
                exif::Tag::DateTime => Some("EXIF Date/Time"),
                exif::Tag::DateTimeOriginal => Some("EXIF Original date/time"),
                exif::Tag::GPSLatitude => Some("EXIF GPS latitude"),
                exif::Tag::GPSLongitude => Some("EXIF GPS longitude"),
                _ => None,
            };
            if let Some(label) = label {
                observations.push((
                    label.into(),
                    match &field.value {
                        exif::Value::Ascii(values) => values
                            .iter()
                            .map(|v| {
                                String::from_utf8_lossy(v)
                                    .trim_matches(char::from(0))
                                    .trim()
                                    .to_string()
                            })
                            .filter(|v| !v.is_empty())
                            .collect::<Vec<_>>()
                            .join("; "),
                        _ => field.display_value().with_unit(&exif).to_string(),
                    },
                ));
            }
        }
    }
    Ok(observations)
}

fn inspect_png(bytes: &[u8]) -> Result<Vec<(String, String)>> {
    if bytes.len() < 24 || &bytes[12..16] != b"IHDR" {
        return Err(anyhow!("invalid PNG IHDR"));
    }
    let w = u32::from_be_bytes(bytes[16..20].try_into()?);
    let h = u32::from_be_bytes(bytes[20..24].try_into()?);
    Ok(vec![
        ("Image dimensions".into(), format!("{w}×{h}")),
        ("Image encoding".into(), "PNG lossless".into()),
    ])
}

fn inspect_jpeg(bytes: &[u8]) -> Result<Vec<(String, String)>> {
    let mut out = Vec::new();
    let mut pos = 2usize;
    let mut qtables = 0usize;
    let mut exif = false;
    while pos + 3 < bytes.len() {
        if bytes[pos] != 0xff {
            pos += 1;
            continue;
        }
        while pos < bytes.len() && bytes[pos] == 0xff {
            pos += 1;
        }
        if pos >= bytes.len() {
            break;
        }
        let marker = bytes[pos];
        pos += 1;
        if matches!(marker, 0xd8 | 0xd9) {
            continue;
        }
        if marker == 0xda {
            break;
        }
        if pos + 2 > bytes.len() {
            break;
        }
        let len = u16::from_be_bytes([bytes[pos], bytes[pos + 1]]) as usize;
        if len < 2 || pos + len > bytes.len() {
            break;
        }
        let data = &bytes[pos + 2..pos + len];
        match marker {
            0xdb => qtables += 1,
            0xe1 if data.starts_with(b"Exif\0\0") => exif = true,
            0xc0 | 0xc2 if data.len() >= 6 => {
                let h = u16::from_be_bytes([data[1], data[2]]);
                let w = u16::from_be_bytes([data[3], data[4]]);
                out.push(("Image dimensions".into(), format!("{w}×{h}")));
                out.push((
                    "JPEG encoding".into(),
                    if marker == 0xc2 {
                        "progressive DCT".into()
                    } else {
                        "baseline DCT".into()
                    },
                ));
            }
            _ => {}
        }
        pos += len;
    }
    out.push(("JPEG quantization tables".into(), qtables.to_string()));
    out.push((
        "EXIF block".into(),
        if exif { "present" } else { "not present" }.into(),
    ));
    Ok(out)
}

fn inspect_webp(bytes: &[u8]) -> Result<Vec<(String, String)>> {
    if bytes.len() >= 30 && &bytes[12..16] == b"VP8X" {
        let w = 1 + u32::from_le_bytes([bytes[24], bytes[25], bytes[26], 0]);
        let h = 1 + u32::from_le_bytes([bytes[27], bytes[28], bytes[29], 0]);
        Ok(vec![
            ("Image dimensions".into(), format!("{w}×{h}")),
            ("Image encoding".into(), "WebP VP8X".into()),
        ])
    } else {
        Ok(vec![("Image encoding".into(), "WebP".into())])
    }
}

pub fn probe_video(path: &Path, timeout: Duration) -> Result<ProbeResult> {
    let mut child = match Command::new("ffprobe")
        .args([
            "-v",
            "error",
            "-of",
            "json",
            "-show_format",
            "-show_streams",
        ])
        .arg("-i")
        .arg(path.canonicalize()?)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
    {
        Ok(v) => v,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Ok(ProbeResult {
                observations: vec![],
                skipped: Some("ffprobe is not installed".into()),
            });
        }
        Err(e) => return Err(e.into()),
    };
    let stdout = child.stdout.take().context("ffprobe stdout missing")?;
    let stderr = child.stderr.take().context("ffprobe stderr missing")?;
    let stdout_reader = thread::spawn(move || read_probe_output(stdout));
    let stderr_reader = thread::spawn(move || read_probe_output(stderr));
    let start = Instant::now();
    loop {
        if child.try_wait()?.is_some() {
            break;
        }
        if start.elapsed() >= timeout {
            let _ = child.kill();
            let _ = child.wait();
            let _ = stdout_reader.join();
            let _ = stderr_reader.join();
            return Err(anyhow!("ffprobe timed out after {}s", timeout.as_secs()));
        }
        thread::sleep(Duration::from_millis(25));
    }
    let status = child.wait()?;
    let stdout = stdout_reader
        .join()
        .map_err(|_| anyhow!("ffprobe output reader failed"))??;
    let _stderr = stderr_reader
        .join()
        .map_err(|_| anyhow!("ffprobe error reader failed"))??;
    if !status.success() {
        return Err(anyhow!("ffprobe rejected the media file"));
    }
    let observations = parse_ffprobe_json(&stdout)?;
    Ok(ProbeResult {
        observations,
        skipped: None,
    })
}

fn read_probe_output(mut reader: impl Read) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    let mut buf = [0u8; 8192];
    let mut over_limit = false;
    loop {
        let n = reader.read(&mut buf)?;
        if n == 0 {
            break;
        }
        if out.len() + n <= 4 * 1024 * 1024 {
            out.extend_from_slice(&buf[..n]);
        } else {
            over_limit = true;
        }
    }
    if over_limit {
        return Err(anyhow!("ffprobe output exceeds 4 MiB limit"));
    }
    Ok(out)
}

pub fn parse_ffprobe_json(bytes: &[u8]) -> Result<Vec<(String, String)>> {
    let root: Value = serde_json::from_slice(bytes).context("invalid ffprobe JSON")?;
    let mut observations = Vec::new();
    if let Some(format) = root
        .pointer("/format/format_long_name")
        .and_then(Value::as_str)
    {
        observations.push(("Container".into(), format.into()));
    }
    if let Some(duration) = root.pointer("/format/duration").and_then(Value::as_str) {
        observations.push(("Duration".into(), format!("{duration}s")));
    }
    if let Some(encoder) = root.pointer("/format/tags/encoder").and_then(Value::as_str) {
        observations.push(("Encoder".into(), encoder.into()));
    }
    if let Some(created) = root
        .pointer("/format/tags/creation_time")
        .and_then(Value::as_str)
    {
        observations.push(("Container creation time".into(), created.into()));
    }
    if let Some(streams) = root.get("streams").and_then(Value::as_array) {
        for (sidx, stream) in streams.iter().enumerate() {
            let kind = stream
                .get("codec_type")
                .and_then(Value::as_str)
                .unwrap_or("stream");
            let codec = stream
                .get("codec_long_name")
                .or_else(|| stream.get("codec_name"))
                .and_then(Value::as_str)
                .unwrap_or("unknown");
            observations.push((format!("Stream {sidx}"), format!("{kind}: {codec}")));
            if kind == "video" {
                if let (Some(w), Some(h)) = (
                    stream.get("width").and_then(Value::as_u64),
                    stream.get("height").and_then(Value::as_u64),
                ) {
                    observations.push(("Video dimensions".into(), format!("{w}×{h}")));
                }
                if let Some(fps) = stream.get("avg_frame_rate").and_then(Value::as_str) {
                    observations.push(("Average frame rate".into(), fps.into()));
                }
            }
        }
    }
    Ok(observations)
}

/// Bounded ISO BMFF parsing; media payload is skipped with seek, never loaded.
pub fn inspect_mp4(path: &Path) -> Result<Vec<(String, String)>> {
    let mut f = File::open(path)?;
    let size = f.metadata()?.len();
    let mut out = vec![(
        "Container parser".into(),
        "built-in ISO BMFF; no external helper".into(),
    )];
    let mut budget = 10000usize;
    parse_boxes(&mut f, 0, size, 0, &mut budget, &mut out)?;
    if !out.iter().any(|(k, _)| k == "Major brand") {
        return Err(anyhow!("not an ISO BMFF container with ftyp"));
    }
    out.push((
        "Forensic limits".into(),
        "Container metadata cannot prove cropping or re-encoding without a reference original"
            .into(),
    ));
    Ok(out)
}
fn parse_boxes(
    f: &mut File,
    mut pos: u64,
    end: u64,
    depth: usize,
    budget: &mut usize,
    out: &mut Vec<(String, String)>,
) -> Result<()> {
    use std::io::{Seek, SeekFrom};
    if depth > 12 {
        return Err(anyhow!("MP4 nesting exceeds limit"));
    }
    while pos < end {
        if *budget == 0 {
            return Err(anyhow!("MP4 box count exceeds limit"));
        }
        *budget -= 1;
        if end - pos < 8 {
            return Err(anyhow!("truncated MP4 box header"));
        }
        f.seek(SeekFrom::Start(pos))?;
        let mut header = [0u8; 8];
        f.read_exact(&mut header)?;
        let mut size = u32::from_be_bytes(header[..4].try_into()?) as u64;
        let kind: [u8; 4] = header[4..].try_into()?;
        let mut header_len = 8u64;
        if size == 1 {
            let mut n = [0u8; 8];
            f.read_exact(&mut n)?;
            size = u64::from_be_bytes(n);
            header_len = 16;
        } else if size == 0 {
            size = end - pos;
        }
        if size < header_len || size > end - pos {
            return Err(anyhow!("MP4 box extends beyond container boundary"));
        }
        let start = pos + header_len;
        let next = pos + size;
        if depth == 0 {
            out.push((
                "Container box".into(),
                format!(
                    "{} offset={pos} size={size}",
                    String::from_utf8_lossy(&kind)
                ),
            ));
        }
        if matches!(
            &kind,
            b"moov" | b"trak" | b"mdia" | b"minf" | b"stbl" | b"edts" | b"udta"
        ) {
            parse_boxes(f, start, next, depth + 1, budget, out)?;
        } else {
            let len = ((size - header_len).min(256)) as usize;
            let mut data = vec![0u8; len];
            f.seek(SeekFrom::Start(start))?;
            f.read_exact(&mut data)?;
            match &kind {
                b"ftyp" if data.len() >= 8 => {
                    out.push((
                        "Major brand".into(),
                        String::from_utf8_lossy(&data[..4]).into_owned(),
                    ));
                    out.push((
                        "Compatible brands".into(),
                        data[8..]
                            .as_chunks::<4>()
                            .0
                            .iter()
                            .map(|s| String::from_utf8_lossy(s))
                            .collect::<Vec<_>>()
                            .join(" / "),
                    ));
                }
                b"mvhd" | b"mdhd" if !data.is_empty() => {
                    let offsets = match data[0] {
                        0 => Some((12usize, 16usize, 4usize)),
                        1 => Some((20, 24, 8)),
                        _ => None,
                    };
                    if let Some((scale_offset, duration_offset, width)) = offsets
                        && data.len() >= duration_offset + width
                    {
                        let scale =
                            u32::from_be_bytes(data[scale_offset..scale_offset + 4].try_into()?);
                        let duration = if width == 4 {
                            u32::from_be_bytes(
                                data[duration_offset..duration_offset + 4].try_into()?,
                            ) as u64
                        } else {
                            u64::from_be_bytes(
                                data[duration_offset..duration_offset + 8].try_into()?,
                            )
                        };
                        if scale > 0
                            && duration != u64::MAX
                            && !(width == 4 && duration == u32::MAX as u64)
                        {
                            out.push((
                                if kind == *b"mvhd" {
                                    "Duration"
                                } else {
                                    "Track duration"
                                }
                                .into(),
                                format!("{:.3}s", duration as f64 / scale as f64),
                            ));
                        }
                        out.push(("Time scale".into(), format!("{scale} ticks/s")));
                    }
                }
                b"tkhd" if !data.is_empty() => {
                    let offset = match data[0] {
                        0 => Some(76),
                        1 => Some(88),
                        _ => None,
                    };
                    if let Some(offset) = offset
                        && data.len() >= offset + 8
                    {
                        let w = u32::from_be_bytes(data[offset..offset + 4].try_into()?) >> 16;
                        let h = u32::from_be_bytes(data[offset + 4..offset + 8].try_into()?) >> 16;
                        if w > 0 && h > 0 {
                            out.push(("Track dimensions".into(), format!("{w}×{h}")));
                        }
                    }
                }
                b"hdlr" if data.len() >= 12 => out.push((
                    "Track handler".into(),
                    String::from_utf8_lossy(&data[8..12]).into_owned(),
                )),
                b"stsd" if data.len() >= 16 => out.push((
                    "Sample codec".into(),
                    String::from_utf8_lossy(&data[12..16]).into_owned(),
                )),
                b"elst" if data.len() >= 8 => out.push((
                    "Edit list".into(),
                    format!(
                        "{} entries; may represent timing offsets, not proof of trimming",
                        u32::from_be_bytes(data[4..8].try_into()?)
                    ),
                )),
                _ => {}
            }
        }
        pos = next;
    }
    Ok(())
}
