#![warn(clippy::all)]

#[macro_use]
extern crate log;

use std::{
    fs::File,
    io,
    io::{Error, ErrorKind},
    path::Path,
    sync::Arc,
};

use clap::{crate_version, Arg, Command};
use explugin_example::ExEmptyPluginBuilder;
use flate2::read::GzDecoder;
use libpcap_tools::{Config, PcapDataEngine, PcapEngine};
use pako_core::{plugins::PluginsFactory, *};
use simplelog::{LevelFilter, SimpleLogger};
use xz2::read::XzDecoder;

mod display;
use display::*;

fn load_config(config: &mut Config, filename: &str) -> Result<(), io::Error> {
    debug!("Loading configuration {}", filename);
    let path = Path::new(&filename);
    let file = File::open(path)?;
    config.load_config(file)
}

const ENV_LOG: &str = "PCAP_ANALYZER_LOG";
fn env_get_log_level() -> LevelFilter {
    match std::env::var(ENV_LOG) {
        Ok(key) => match key.as_ref() {
            "off" => LevelFilter::Off,
            "error" => LevelFilter::Error,
            "warn" => LevelFilter::Warn,
            "info" => LevelFilter::Info,
            "debug" => LevelFilter::Debug,
            "trace" => LevelFilter::Trace,
            _ => panic!("Invalid log level '{}'", key),
        },
        _ => LevelFilter::Debug,
    }
}

fn main() -> Result<(), io::Error> {
    let matches = Command::new("Pcap analyzer test tool")
        .version(crate_version!())
        .about("Test tool for pcap-analyzer crate")
        .arg(
            Arg::new("config")
                .help("Configuration file")
                .short('c')
                .long("config"),
        )
        .arg(
            Arg::new("jobs")
                .help("Number of concurrent jobs to run (default: 1)")
                .short('j')
                .long("jobs"),
        )
        .arg(
            Arg::new("plugins")
                .help("Plugins to load (default: all)")
                .short('p')
                .long("plugins"),
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

    let log_level = env_get_log_level();
    let _ = SimpleLogger::init(log_level, simplelog::Config::default());
    info!("test-analyzer tool starting");

    // create plugin factory with all available plugins
    let mut factory = PluginsFactory::default();
    // add external plugins
    factory.add_builder(Box::new(ExEmptyPluginBuilder));
    let mut config = Config::default();
    if let Some(filename) = matches.get_one::<String>("config") {
        load_config(&mut config, filename)?;
    }
    let input_filename = matches.get_one::<String>("INPUT").unwrap();

    let skip = matches.get_one::<String>("skip").unwrap();

    let skip = skip
        .parse::<u32>()
        .map_err(|_| Error::new(ErrorKind::Other, "Invalid value for 'skip' argument"))?;
    config.set("skip_index", skip);

    // override config options from command-line arguments
    if let Some(jobs) = matches.get_one::<String>("jobs") {
        let j = jobs
            .parse::<u32>()
            .map_err(|_| Error::new(ErrorKind::Other, "Invalid value for 'jobs' argument"))?;
        config.set("num_threads", j);
    }

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
    debug!("test-analyzer instantiated plugins:");
    registry.run_plugins(
        |_| true,
        |p| {
            debug!("  {}", p.name());
            let t = p.plugin_type();
            let mut s = "    layers: ".to_owned();
            if t & PLUGIN_L2 != 0 {
                s += "  L2";
            }
            if t & PLUGIN_L3 != 0 {
                s += "  L3";
            }
            if t & PLUGIN_L4 != 0 {
                s += "  L4";
            }
            debug!("{}", s);
            let mut s = "    events: ".to_owned();
            if t & PLUGIN_FLOW_NEW != 0 {
                s += "  FLOW_NEW";
            }
            if t & PLUGIN_FLOW_DEL != 0 {
                s += "  FLOW_DEL";
            }
            debug!("{}", s);
        },
    );

    // let analyzer: Box<dyn PcapAnalyzer> = match config.get_usize("num_threads") {
    //     Some(1) => Box::new(Analyzer::new(registry, &config)),
    //     _ => Box::new(ThreadedAnalyzer::new(registry, &config)),
    // };

    let mut input_reader: Box<dyn io::Read> = if input_filename == "-" {
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
    if num_threads == 1 {
        let analyzer = Analyzer::new(Arc::new(registry), &config);
        let mut engine = PcapDataEngine::new(analyzer, &config);
        engine.run(&mut input_reader).expect("run analyzer");
        show_results(engine.data_analyzer());
    } else {
        let analyzer = ThreadedAnalyzer::new(registry, &config);
        let mut engine = PcapDataEngine::new(analyzer, &config);
        engine.run(&mut input_reader).expect("run analyzer");
        let threaded_data_analyzer = engine.data_analyzer();
        show_results(threaded_data_analyzer.inner_analyzer());
    }

    info!("test-analyzer: done");
    Ok(())
}

fn show_results(analyzer: &Analyzer) {
    analyzer.registry().run_plugins(
        |_| true,
        |p| {
            let res = p.get_results();
            // dbg!(&res);
            if let Some(res) = res {
                match p.name() {
                    "BasicStats" => display_json_basicstats(res),
                    "CommunityID" => display_json_communityid(res),
                    "FlowsInfo" => display_json_flowsinfo(res),
                    "Rusticata" => display_json_rusticata(res),
                    "TlsStats" => display_json_tlsstats(res),
                    _ => display_generic(p, res),
                }
            } else {
                info!("{}: <no value>", p.name());
            }
        },
    )
}
