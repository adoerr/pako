#![warn(clippy::all)]

use anyhow::Result;
use clap::{command, Parser, Subcommand};
use pako_core::plugins::PluginsFactory;

#[derive(Parser, Debug)]
#[command(version, about = "Pako Demo Analyzer")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// List plugin builders
    Builders,
}

fn main() -> Result<()> {
    env_logger::try_init()?;

    let cli = Cli::parse();

    let factory = PluginsFactory::default();

    match cli.command {
        Commands::Builders => {
            println!("Plugin builders:");
            factory.iter_builders(|b| println!("    {b}"));
        }
    }

    Ok(())
}
