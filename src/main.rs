use anyhow::Result;
use clap::Parser;
use nulltrace::{scan::ScanSession, tui};

#[derive(Parser)]
#[command(
    name = "nulltrace",
    version,
    about = "Offline-first forensic operations console"
)]
struct Args {
    #[arg(value_name = "URL_OR_FILE")]
    target: String,
}

fn main() -> Result<()> {
    let args = Args::parse();
    let session = ScanSession::new(&args.target)?;
    let _ = tui::run(session)?;
    Ok(())
}
