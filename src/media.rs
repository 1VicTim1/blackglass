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
                exif::Tag::DateTime | exif::Tag::DateTimeOriginal => Some("EXIF Date/Time"),
                exif::Tag::GPSLatitude => Some("EXIF GPS latitude"),
                exif::Tag::GPSLongitude => Some("EXIF GPS longitude"),
                _ => None,
            };
            if let Some(label) = label {
                observations.push((
                    label.into(),
                    field.display_value().with_unit(&exif).to_string(),
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
        .arg(path)
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
    let start = Instant::now();
    loop {
        if child.try_wait()?.is_some() {
            break;
        }
        if start.elapsed() >= timeout {
            let _ = child.kill();
            let _ = child.wait();
            return Err(anyhow!("ffprobe timed out after {}s", timeout.as_secs()));
        }
        thread::sleep(Duration::from_millis(25));
    }
    let output = child.wait_with_output()?;
    if !output.status.success() {
        return Err(anyhow!("ffprobe rejected the media file"));
    }
    let observations = parse_ffprobe_json(&output.stdout)?;
    Ok(ProbeResult {
        observations,
        skipped: None,
    })
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
