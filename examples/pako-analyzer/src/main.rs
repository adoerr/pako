use std::{fs::File, io, path::PathBuf, sync::Arc};

use anyhow::Result;
use clap::{command, Parser, Subcommand};
use log::debug;
use pako_core::{
    plugins::PluginsFactory, Analyzer, Plugin, ThreadedAnalyzer, PLUGIN_FLOW_DEL, PLUGIN_FLOW_NEW,
    PLUGIN_L2, PLUGIN_L3, PLUGIN_L4,
};
use pako_tools::{Config, PcapDataEngine, PcapEngine};

#[derive(Debug, Parser)]
#[command(version, about = "Pako Demo Analyzer")]
struct Cli {
    /// Configuration file
    #[arg(short, long)]
    config: Option<PathBuf>,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// List plugin builders
    Builders,
    /// List available plugins
    Plugins,
    /// Analyze the given Pcap file
    Analyze {
        /// Pcap input file
        file: PathBuf,
    },
}

fn main() -> Result<()> {
    env_logger::try_init()?;

    let cli = Cli::parse();

    let factory = PluginsFactory::default();
    let registry = factory.build_plugins(&Config::default())?;

    let config = if let Some(path) = cli.config {
        load_config(path)?
    } else {
        Config::default()
    };

    // determine number of worker threads
    let num_threads = config.get_usize("num_threads").unwrap_or(1);

    match cli.command {
        Commands::Builders => {
            println!("Plugin builders:");
            factory.iter_builders(|b| println!("    {b}"));
        }
        Commands::Plugins => {
            registry.run_plugins(|_| true, plugin_info);
        }
        Commands::Analyze { file } => {
            let mut input = Box::new(File::open(file)?) as Box<dyn io::Read>;

            let mut engine = if num_threads == 1 {
                let analyzer = Analyzer::new(Arc::new(registry), &config);
                Box::new(PcapDataEngine::new(analyzer, &config)) as Box<dyn PcapEngine>
            } else {
                let analyzer = ThreadedAnalyzer::new(registry, &config);
                Box::new(PcapDataEngine::new(analyzer, &config)) as Box<dyn PcapEngine>
            };

            engine.run(&mut input)?;
        }
    }

    Ok(())
}

/// Show plugin info
fn plugin_info(plugin: &mut dyn Plugin) {
    println!("  {}", plugin.name());

    let t = plugin.plugin_type();
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
}

/// Load configuration file from `filepath`
fn load_config(filepath: PathBuf) -> Result<Config> {
    debug!("loading config {:?}", filepath);
    let mut config = Config::default();
    config.load_config(File::open(filepath)?)?;
    Ok(config)
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use anyhow::Result;

    use crate::load_config;

    #[test]
    fn load_config_works() -> Result<()> {
        let path = PathBuf::from(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../conf/pako-analyzer.conf"
        ));

        let config = load_config(path)?;
        assert_eq!(4, config.get_usize("num_threads").unwrap());

        Ok(())
    }
}
