use nulltrace::scan::{ScanSession, StepStatus};
use std::fs;

#[test]
fn png_dimensions_are_reported_in_live_scan() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("pixel.png");
    let png: [u8; 24] = [
        137, 80, 78, 71, 13, 10, 26, 10, 0, 0, 0, 13, b'I', b'H', b'D', b'R', 0, 0, 0, 1, 0, 0, 0,
        1,
    ];
    fs::write(&path, png).unwrap();
    let mut session = ScanSession::new(path.to_str().unwrap()).unwrap();
    assert!(
        session
            .steps()
            .iter()
            .any(|step| step.id == "image_structure")
    );
    while session.run_next_offline() {}
    assert!(
        session
            .observations()
            .iter()
            .any(|o| o.label == "Image dimensions" && o.value == "1×1")
    );
}

#[test]
fn jpeg_quantization_and_frame_type_are_reported() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("sample.jpg");
    let mut jpeg = vec![0xff, 0xd8, 0xff, 0xdb, 0x00, 0x43, 0x00];
    jpeg.extend([16u8; 64]);
    jpeg.extend([
        0xff, 0xc0, 0x00, 0x0b, 0x08, 0x00, 0x10, 0x00, 0x20, 0x01, 0x01, 0x11, 0x00, 0xff, 0xd9,
    ]);
    fs::write(&path, jpeg).unwrap();
    let mut session = ScanSession::new(path.to_str().unwrap()).unwrap();
    while session.run_next_offline() {}
    assert!(
        session
            .observations()
            .iter()
            .any(|o| o.label == "JPEG encoding" && o.value.contains("baseline"))
    );
    assert!(
        session
            .observations()
            .iter()
            .any(|o| o.label == "JPEG quantization tables")
    );
    assert!(
        session
            .observations()
            .iter()
            .any(|o| o.label == "Image dimensions" && o.value == "32×16")
    );
}

#[test]
fn video_plan_has_probe_and_missing_helper_is_not_a_failure() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("clip.mp4");
    fs::write(&path, b"\0\0\0\x18ftypisom\0\0\0\0isomiso2").unwrap();
    let session = ScanSession::new(path.to_str().unwrap()).unwrap();
    let probe = session
        .steps()
        .iter()
        .find(|step| step.id == "video_probe")
        .unwrap();
    assert!(matches!(probe.status, StepStatus::Queued));
}

#[test]
fn exif_camera_make_is_extracted_from_jpeg() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("camera.jpg");
    let mut tiff = vec![b'I', b'I', 42, 0, 8, 0, 0, 0, 1, 0];
    tiff.extend([0x0f, 0x01, 2, 0, 6, 0, 0, 0, 26, 0, 0, 0]);
    tiff.extend([0, 0, 0, 0]);
    tiff.extend(b"Canon\0");
    let mut payload = b"Exif\0\0".to_vec();
    payload.extend(tiff);
    let length = (payload.len() + 2) as u16;
    let mut jpeg = vec![0xff, 0xd8, 0xff, 0xe1, (length >> 8) as u8, length as u8];
    jpeg.extend(payload);
    jpeg.extend([0xff, 0xd9]);
    fs::write(&path, jpeg).unwrap();
    let mut session = ScanSession::new(path.to_str().unwrap()).unwrap();
    while session.run_next_offline() {}
    assert!(
        session
            .observations()
            .iter()
            .any(|o| o.label == "EXIF Make" && o.value.contains("Canon"))
    );
}

#[test]
fn ffprobe_json_exposes_container_codec_dimensions_and_rate() {
    let json = br#"{"format":{"format_long_name":"QuickTime / MOV","duration":"2.500000","tags":{"encoder":"Lavf61","creation_time":"2026-01-02T03:04:05Z"}},"streams":[{"codec_type":"video","codec_name":"h264","codec_long_name":"H.264","width":1920,"height":1080,"avg_frame_rate":"30/1"},{"codec_type":"audio","codec_name":"aac"}]}"#;
    let observations = nulltrace::media::parse_ffprobe_json(json).unwrap();
    assert!(
        observations
            .iter()
            .any(|(k, v)| k == "Container" && v.contains("QuickTime"))
    );
    assert!(
        observations
            .iter()
            .any(|(k, v)| k == "Video dimensions" && v == "1920×1080")
    );
    assert!(
        observations
            .iter()
            .any(|(k, v)| k == "Average frame rate" && v == "30/1")
    );
    assert!(observations.iter().any(|(_, v)| v.contains("H.264")));
    assert!(
        observations
            .iter()
            .any(|(k, v)| k == "Encoder" && v == "Lavf61")
    );
}
#[test]
fn builtin_mp4_inspects_without_external_helpers_and_rejects_truncated_boxes() {
    fn atom(kind: &[u8; 4], payload: &[u8]) -> Vec<u8> {
        let mut b = ((payload.len() + 8) as u32).to_be_bytes().to_vec();
        b.extend(kind);
        b.extend(payload);
        b
    }
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("clip.mp4");
    let mut b = atom(b"ftyp", b"isom\0\0\0\0isom");
    let mut mvhd = vec![0u8; 20];
    mvhd[12..16].copy_from_slice(&1000u32.to_be_bytes());
    mvhd[16..20].copy_from_slice(&2500u32.to_be_bytes());
    let mut tkhd = vec![0u8; 84];
    tkhd[76..80].copy_from_slice(&(1920u32 << 16).to_be_bytes());
    tkhd[80..84].copy_from_slice(&(1080u32 << 16).to_be_bytes());
    let mut moov = atom(b"mvhd", &mvhd);
    moov.extend(atom(b"trak", &atom(b"tkhd", &tkhd)));
    b.extend(atom(b"moov", &moov));
    b.extend(atom(b"mdat", b"sample"));
    std::fs::write(&p, b).unwrap();
    let o = nulltrace::media::inspect_mp4(&p).unwrap();
    assert!(o.iter().any(|(k, v)| k == "Duration" && v == "2.500s"));
    assert!(
        o.iter()
            .any(|(k, v)| k == "Track dimensions" && v == "1920×1080")
    );
    std::fs::write(&p, b"\0\0\x10\0ftypisom").unwrap();
    assert!(nulltrace::media::inspect_mp4(&p).is_err());
}
