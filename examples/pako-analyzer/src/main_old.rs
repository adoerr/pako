#![warn(clippy::all)]

use std::{
    fs::{File, OpenOptions},
    io,
    io::{Error, ErrorKind},
    path::{Path, PathBuf},
    process,
    sync::Arc,
};

use anyhow::Result;
use clap::{crate_version, Arg, Command};
use flate2::read::GzDecoder;
use log::{debug, info, warn};
use pako_core::{
    plugins, Analyzer, ThreadedAnalyzer, PLUGIN_FLOW_DEL, PLUGIN_FLOW_NEW, PLUGIN_L2, PLUGIN_L3,
    PLUGIN_L4,
};
use pako_tools::{Config, PcapDataEngine, PcapEngine};
use xz2::read::XzDecoder;

fn load_config(config: &mut Config, filename: &str) -> Result<(), Error> {
    debug!("Loading configuration {}", filename);
    let path = Path::new(&filename);
    let file = File::open(path)?;
    config.load_config(file)
}

fn main() -> Result<()> {
    env_logger::try_init()?;

    let matches = Command::new("Pcap analyzer")
        .version(crate_version!())
        .about("Pcap file analysis tool")
        .arg(
            Arg::new("verbose")
                .help("Be verbose")
                .short('v')
                .long("verbose"),
        )
        .arg(
            Arg::new("jobs")
                .help("Number of concurrent jobs to run (default: 1)")
                .short('j')
                .long("jobs"),
        )
        .arg(
            Arg::new("list-builders")
                .help("List plugin builders and exit")
                .long("list-builders"),
        )
        .arg(
            Arg::new("list-plugins")
                .help("List available plugins and exit")
                .short('l')
                .long("list-plugins"),
        )
        .arg(
            Arg::new("plugins")
                .help("Plugins to load (default: all)")
                .short('p')
                .long("plugins"),
        )
        .arg(
            Arg::new("config")
                .help("Configuration file")
                .short('c')
                .long("config"),
        )
        .arg(
            Arg::new("outdir")
                .help("Plugins output directory")
                .short('o')
                .long("outdir"),
        )
        .arg(
            Arg::new("INPUT")
                .help("Input file name")
                .required(true)
                .index(1),
        )
        .arg(
            Arg::new("skip")
                .help("Skip given number of packets")
                .long("skip")
                .default_value("0"),
        )
        .get_matches();

    // create plugin factory with all available plugins
    let factory = plugins::PluginsFactory::default();
    // check if asked to list plugin builders
    if matches.contains_id("list-builders") {
        println!("pako-analyzer available plugin builders:");
        factory.iter_builders(|name| println!("    {name}"));
        process::exit(0);
    }
    // load config
    let mut config = Config::default();
    if let Some(filename) = matches.get_one::<String>("config") {
        load_config(&mut config, filename)?;
    }
    // override config options from command-line arguments
    if let Some(jobs) = matches.get_one::<String>("jobs") {
        #[allow(clippy::or_fun_call)]
        let j = jobs.parse::<u32>().or(Err(Error::new(
            ErrorKind::Other,
            "Invalid value for 'jobs' argument",
        )))?;
        config.set("num_threads", j);
    }
    if let Some(dir) = matches.get_one::<String>("outdir") {
        config.set("output_dir", dir.to_string());
    }

    let skip = matches.get_one::<String>("skip").unwrap();

    let skip = skip
        .parse::<u32>()
        .map_err(|_| Error::new(ErrorKind::Other, "Invalid value for 'skip' argument"))?;
    config.set("skip_index", skip.to_string());

    // Open log file
    let log_file = config.get("log_file").unwrap_or("pako-analyzer.log");
    let mut path_log = PathBuf::new();
    if let Some(dir) = config.get("output_dir") {
        path_log.push(dir);
    }
    path_log.push(log_file);
    OpenOptions::new()
        .append(true)
        .create(true)
        .open(&path_log)
        .unwrap();

    // Now, really start
    info!("Pcap analyser {}", crate_version!());

    // instantiate all plugins
    let registry = if let Some(plugin_names) = matches.get_one::<String>("plugins") {
        debug!("Restricting plugins to: {}", plugin_names);
        let names: Vec<_> = plugin_names.split(',').collect();
        factory
            .build_filter_plugins(
                |n| {
                    debug!("n: {}", n);
                    names.iter().any(|&x| n.contains(x))
                },
                &config,
            )
            .expect("Could not build factory")
    } else {
        factory
            .build_plugins(&config)
            .expect("Could not build factory")
    };
    // check if asked to list plugins
    if matches.contains_id("list-plugins") {
        println!("pako-analyzer plugin instances:");
        registry.run_plugins(
            |_| true,
            |p| {
                println!("  {}", p.name());
                let t = p.plugin_type();
                print!("    layers: ");
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
                print!("    events: ");
                if t & PLUGIN_FLOW_NEW != 0 {
                    print!("  FLOW_NEW");
                }
                if t & PLUGIN_FLOW_DEL != 0 {
                    print!("  FLOW_DEL");
                }
                println!();
            },
        );
        process::exit(0);
    }
    if registry.num_plugins() == 0 {
        warn!("No plugins loaded");
    }
    debug!("Plugins loaded:");
    registry.run_plugins(
        |_| true,
        |p| {
            debug!("  {}", p.name());
        },
    );
    let input_filename = matches.get_one::<String>("INPUT").unwrap();

    let mut input_reader = if input_filename == "-" {
        Box::new(io::stdin())
    } else {
        let path = Path::new(&input_filename);
        let file = File::open(path)?;
        if input_filename.ends_with(".gz") {
            Box::new(GzDecoder::new(file))
        } else if input_filename.ends_with(".xz") {
            Box::new(XzDecoder::new(file))
        } else if input_filename.ends_with(".lz4") {
            Box::new(lz4::Decoder::new(file)?)
        } else {
            Box::new(file) as Box<dyn io::Read>
        }
    };

    let num_threads = config.get_usize("num_threads").unwrap_or(1);
    let mut engine = if num_threads == 1 {
        let analyzer = Analyzer::new(Arc::new(registry), &config);
        Box::new(PcapDataEngine::new(analyzer, &config)) as Box<dyn PcapEngine>
    } else {
        let analyzer = ThreadedAnalyzer::new(registry, &config);
        Box::new(PcapDataEngine::new(analyzer, &config)) as Box<dyn PcapEngine>
    };
    engine.run(&mut input_reader).expect("run analyzer");

    Ok(())
}
