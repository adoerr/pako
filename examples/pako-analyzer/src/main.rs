#![warn(clippy::all)]

use anyhow::Result;
use clap::{Parser, Subcommand};

#[derive(Parser, Debug)]
#[command(version, about = "Pako Demo Analyzer")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {}

fn main() -> Result<()> {
    env_logger::try_init()?;

    Ok(())
}
