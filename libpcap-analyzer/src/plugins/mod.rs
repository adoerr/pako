use std::collections::HashMap;

use crate::{Plugin,PluginBuilder};

mod basic_stats;
mod tcp_states;
mod rusticata;

pub struct Plugins {
    pub storage: HashMap<String, Box<Plugin>>,
}

pub struct PluginsFactory {
    list: Vec<Box<PluginBuilder>>,
}

pub fn plugins_factory() -> PluginsFactory {
    let mut v: Vec<Box<PluginBuilder>> = Vec::new();

    v.push(Box::new(basic_stats::BasicStatsBuilder));
    v.push(Box::new(tcp_states::TcpStatesBuilder));
    v.push(Box::new(rusticata::RusticataBuilder));

    PluginsFactory{ list:v }
}

pub fn build_plugins(factory: &PluginsFactory) -> Plugins {
    let mut h: HashMap<String, Box<Plugin>> = HashMap::new();

    factory.list.iter().for_each(|b| {
        let plugin = b.build();
        h.insert(plugin.name().to_string(), plugin);
    });

    Plugins { storage: h }
}
