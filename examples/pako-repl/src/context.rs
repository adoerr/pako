use std::fs::File;

use pako_core::{plugins::PluginsFactory, Analyzer};
use pako_tools::{Config, PcapDataEngine};

/// Global CLI execution context
#[derive(Default)]
pub struct Context {
    pub file: Option<File>,
    pub config: Config,
    pub factory: PluginsFactory,
    pub engine: Option<PcapDataEngine<Analyzer>>,
}
