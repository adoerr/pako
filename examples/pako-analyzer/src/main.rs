#![warn(clippy::all)]

use anyhow::Result;
use clap::{command, Parser, Subcommand};
use pako_core::{
    plugins::PluginsFactory, Plugin, PLUGIN_FLOW_DEL, PLUGIN_FLOW_NEW, PLUGIN_L2, PLUGIN_L3,
    PLUGIN_L4,
};
use pako_tools::Config;

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
    /// List available plugins
    Plugins,
}

fn main() -> Result<()> {
    env_logger::try_init()?;

    let cli = Cli::parse();

    let factory = PluginsFactory::default();
    let registry = factory.build_plugins(&Config::default())?;

    let plugins = |p: &mut dyn Plugin| {
        println!("  {}", p.name());

        let t = p.plugin_type();
        print!("    layers:");
        if t & PLUGIN_L2 != 0 {
            print!("  L2");
        }
        if t & PLUGIN_L3 != 0 {
            print!("  L3");
        }
        if t & PLUGIN_L4 != 0 {
            print!("  L4");
        }
        println!();

        print!("    events:");
        if t & PLUGIN_FLOW_NEW != 0 {
            print!("  FLOW_NEW");
        }
        if t & PLUGIN_FLOW_DEL != 0 {
            print!("  FLOW_DEL")
        }
        println!()
    };

    match cli.command {
        Commands::Builders => {
            println!("Plugin builders:");
            factory.iter_builders(|b| println!("    {b}"));
        }
        Commands::Plugins => {
            registry.run_plugins(|_| true, plugins);
        }
    }

    Ok(())
}
