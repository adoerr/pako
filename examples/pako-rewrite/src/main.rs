#![warn(clippy::all)]
#![allow(clippy::upper_case_acronyms)]

use std::{fs::File, io, path::Path};

use clap::{crate_version, Parser};
use libpcap_tools::Config;
use log::{debug, error};
use pako_rewrite::{
    filters,
    filters::{
        dispatch_filter::DispatchFilterBuilder, filtering_action::FilteringAction,
        filtering_key::FilteringKey,
        fragmentation::fragmentation_filter::FragmentationFilterBuilder,
    },
    rewriter::*,
    RewriteOptions,
};

const FILTER_HELP: &str = "Filters to load (default: none)
Arguments can be specified using : after the filter name.
Examples:
-f Source:192.168.1.1
-f Dispatch:fk%fa%path
-f Dispatch:fk%fa

fk: filtering key=si|di|sdi|sipdp|sdipsdp
with si: src IP
     di: dst IP
     sdi: srd/dst IP
     sipdp: src IP, proto, dst port
     sdipsdp: src/dst IP, proto, src/dst port

fa: filtering action=k|d
with k: keep
     d: drop

path: path to a csv formatted file without header that contains filtering keys
";

fn load_config(config: &mut Config, filename: &str) -> Result<(), io::Error> {
    debug!("Loading configuration {}", filename);
    let path = Path::new(&filename);
    let file = File::open(path).map_err(|e| {
        error!("Could not open config file '{}'", filename);
        e
    })?;
    config.load_config(file)
}

#[derive(Parser)]
#[command(version, about = "Rewrite pcap files", long_about = None)]
struct Cli {
    /// Filters to load (default: none
    #[arg(short, long, long_help = FILTER_HELP)]
    filters: Option<Vec<String>>,

    /// Configuration file
    #[arg(short, long)]
    config: Option<String>,

    /// File output format
    #[arg(short, long, value_enum , default_value_t = FileFormat::Pcap)]
    format: FileFormat,

    /// Input file name
    #[arg(short, long)]
    input: String,

    /// Output file name
    #[arg(short, long)]
    output: String,
}

fn main() -> io::Result<()> {
    let cli = Cli::parse();

    let _ =
        simplelog::SimpleLogger::init(simplelog::LevelFilter::Debug, simplelog::Config::default());
    debug!("Pcap rewrite tool {}", crate_version!());

    let mut config = Config::default();

    if let Some(filename) = cli.config {
        load_config(&mut config, &filename)?;
    }

    let input_filename = cli.input;
    let output_filename = cli.output;
    let output_format = cli.format;

    let mut filters: Vec<Box<dyn filters::filter::Filter>> = Vec::new();

    let filter_names = if let Some(filters) = cli.filters {
        filters
    } else {
        vec![]
    };

    for name in &filter_names {
        eprintln!("adding filter: {}", name);
        let args: Vec<_> = name.splitn(2, ':').collect();
        match args[0] {
            "IP" => {
                eprintln!("adding IP filter");
                let f = filters::common_filters::IPFilter::new(&args[1..]);
                filters.push(Box::new(f));
            }
            "Source" => {
                eprintln!("adding source filter");
                let f = filters::common_filters::SourceFilter::new(&args[1..]);
                filters.push(Box::new(f));
            }
            "Dispatch" => {
                eprintln!("adding dispatch filter");
                let dispatch_data = args[1];
                let args: Vec<_> = dispatch_data.split('%').collect();
                assert_eq!(args.len(), 3);
                let filtering_key = FilteringKey::of_string(args[0])
                    .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
                let filtering_action = FilteringAction::of_string(args[1])
                    .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
                let key_file_path = args[2];

                let f = DispatchFilterBuilder::from_args(
                    filtering_key,
                    filtering_action,
                    key_file_path,
                )?;
                filters.push(f);
            }
            "Fragmentation" => {
                eprintln!("adding fragmentation filter");
                let dispatch_data = args[1];
                let args: Vec<_> = dispatch_data.split('%').collect();
                if args.len() != 2 {
                    return Err(io::Error::new(
                        io::ErrorKind::Other,
                        "More than two arguments provided to fragmentation filter.".to_string(),
                    ));
                };
                let filtering_key = FilteringKey::of_string(args[0])
                    .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
                let filtering_action = FilteringAction::of_string(args[1])
                    .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

                let f = FragmentationFilterBuilder::from_args(filtering_key, filtering_action)?;
                filters.push(f);
            }
            _ => {
                error!("Unexpected filter name");
                std::process::exit(1);
            }
        }
    }

    let options = RewriteOptions {
        output_format,
        config,
    };

    pako_rewrite::pcap_rewrite_file(input_filename, output_filename, filters, &options)
}
