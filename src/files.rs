use crate::{Confidence, Finding, Origin, Severity};
use anyhow::{Result, anyhow};
use std::{
    fs::File,
    io::{Read, Seek, SeekFrom},
    path::Path,
};

pub fn visible(text: &str) -> String {
    text.chars().map(|c| if c.is_control() || matches!(c, '\u{061c}' | '\u{200b}'..='\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2060}'..='\u{2069}' | '\u{feff}') {
        format!("<U+{:04X}>", c as u32)
    } else { c.to_string() }).collect()
}
fn finding(rule: &str, summary: &str, evidence: String, weight: u8) -> Finding {
    Finding::new(
        rule,
        "file-identity",
        Origin::Offline,
        Severity::Medium,
        Confidence::High,
        summary,
        weight,
    )
    .with_evidence(evidence)
}
pub type FileInspection = (Vec<Finding>, Vec<(String, String)>);
pub fn inspect(path: &Path) -> Result<FileInspection> {
    let name = path.file_name().unwrap_or_default().to_string_lossy();
    let mut findings = vec![];
    let mut out = vec![("Visible filename".into(), visible(&name))];
    if name.chars().any(|c| matches!(c, '\u{061c}' | '\u{200e}'..='\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}')) {
        findings.push(finding("FILE-BIDI", "Bidirectional controls can reverse the displayed filename", visible(&name), 40));
    }
    if name
        .chars()
        .any(|c| c.is_control() || matches!(c, '\u{200b}'..='\u{200d}' | '\u{2060}' | '\u{feff}'))
    {
        findings.push(finding(
            "FILE-INVISIBLE",
            "Filename contains invisible or control characters",
            visible(&name),
            25,
        ));
    }
    if name.ends_with([' ', '.']) || name.contains(['\u{ff0e}', '\u{2024}', '\u{fe52}']) {
        findings.push(finding(
            "FILE-NAME-AMBIGUITY",
            "Filename contains an ambiguous extension separator or trailing characters",
            visible(&name),
            20,
        ));
    }
    let lower = name.to_lowercase();
    let parts: Vec<_> = lower.split('.').collect();
    let ext = parts.last().copied().unwrap_or("");
    let ext_skeleton = ext
        .chars()
        .map(|c| match c {
            'е' => 'e',
            'х' => 'x',
            'с' => 'c',
            'р' => 'p',
            'о' => 'o',
            'а' => 'a',
            _ => c,
        })
        .collect::<String>();
    if ext_skeleton != ext
        && matches!(
            ext_skeleton.as_str(),
            "exe" | "scr" | "com" | "bat" | "cmd" | "ps1" | "js" | "vbs" | "sh" | "dll" | "apk"
        )
    {
        findings.push(finding(
            "FILE-EXTENSION-CONFUSABLE",
            "Extension visually imitates an executable extension",
            format!("actual extension={ext}; visual skeleton={ext_skeleton}"),
            35,
        ));
    }
    let executable_ext = matches!(
        ext,
        "exe"
            | "scr"
            | "com"
            | "msi"
            | "bat"
            | "cmd"
            | "ps1"
            | "vbs"
            | "js"
            | "sh"
            | "dll"
            | "elf"
            | "apk"
            | "jar"
    );
    if executable_ext
        && parts.len() > 2
        && parts[..parts.len() - 1].iter().any(|p| {
            matches!(
                *p,
                "png" | "jpg" | "jpeg" | "pdf" | "doc" | "docx" | "txt" | "mp4" | "zip"
            )
        })
    {
        findings.push(finding(
            "FILE-DOUBLE-EXTENSION",
            "Document or media extension precedes an executable extension",
            visible(&name),
            35,
        ));
    }
    let mut f = File::open(path)?;
    let mut head = [0u8; 64];
    let n = f.read(&mut head)?;
    if head[..n].starts_with(b"\x7fELF") {
        if n < 20 {
            return Err(anyhow!("truncated ELF header"));
        }
        let le = head[5] == 1;
        if !matches!(head[4], 1 | 2) || !matches!(head[5], 1 | 2) {
            return Err(anyhow!("invalid ELF class or byte order"));
        }
        let machine = if le {
            u16::from_le_bytes([head[18], head[19]])
        } else {
            u16::from_be_bytes([head[18], head[19]])
        };
        out.push((
            "Executable format".into(),
            if head[4] == 2 { "ELF64" } else { "ELF32" }.into(),
        ));
        out.push((
            "Executable architecture".into(),
            architecture(machine, false).into(),
        ));
        out.push((
            "Byte order".into(),
            if le { "little-endian" } else { "big-endian" }.into(),
        ));
        findings.push(finding(
            "FILE-EXECUTABLE",
            "File contains native executable or shared-library code",
            "ELF signature; executable format alone is not malware evidence".into(),
            10,
        ));
    } else if head[..n].starts_with(b"MZ") {
        findings.push(finding(
            "FILE-EXECUTABLE",
            "File has a DOS/Windows executable signature",
            "MZ signature; executable format alone is not malware evidence".into(),
            10,
        ));
        out.push((
            "Executable format".into(),
            "DOS MZ (PE not yet verified)".into(),
        ));
        if n >= 64 {
            let offset = u32::from_le_bytes(head[60..64].try_into()?) as u64;
            if offset
                .checked_add(24)
                .is_some_and(|end| end <= f.metadata().map(|m| m.len()).unwrap_or(0))
            {
                f.seek(SeekFrom::Start(offset))?;
                let mut pe = [0u8; 24];
                f.read_exact(&mut pe)?;
                if pe[..4] == *b"PE\0\0" {
                    out.push(("Executable format".into(), "Windows PE".into()));
                    out.push((
                        "Executable architecture".into(),
                        architecture(u16::from_le_bytes([pe[4], pe[5]]), true).into(),
                    ));
                    out.push((
                        "PE sections".into(),
                        u16::from_le_bytes([pe[6], pe[7]]).to_string(),
                    ));
                    out.push((
                        "PE timestamp (untrusted)".into(),
                        u32::from_le_bytes(pe[8..12].try_into()?).to_string(),
                    ));
                    out.push((
                        "PE characteristics".into(),
                        format!("0x{:04x}", u16::from_le_bytes([pe[22], pe[23]])),
                    ));
                }
            }
        }
    } else if head[..n].starts_with(b"#!") {
        out.push((
            "Script interpreter".into(),
            visible(
                String::from_utf8_lossy(&head[..n])
                    .lines()
                    .next()
                    .unwrap_or(""),
            ),
        ));
        findings.push(finding(
            "FILE-SCRIPT",
            "File contains an interpreter directive",
            "Shebang present; script alone is not malware evidence".into(),
            10,
        ));
    } else if executable_ext {
        findings.push(finding(
            "FILE-ACTIVE-EXTENSION",
            "Extension denotes executable or active content",
            format!("extension={ext}; content has not been verified as safe"),
            10,
        ));
    }
    Ok((findings, out))
}
fn architecture(machine: u16, pe: bool) -> &'static str {
    match (pe, machine) {
        (false, 183) | (true, 0xaa64) => "AArch64",
        (false, 62) | (true, 0x8664) => "x86-64",
        (false, 3) | (true, 0x14c) => "x86",
        (false, 40) | (true, 0x1c4) => "ARM",
        (false, 243) => "RISC-V",
        _ => "unknown",
    }
}
