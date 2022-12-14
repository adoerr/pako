use log::info;
use pako_tools::Config;

use crate::{
    build_safeplugin, default_plugin_builder,
    plugin::{Plugin, PluginBuilderError, PLUGIN_NONE},
    plugin_registry::PluginRegistry,
};

/// Example plugin, without configuration
#[derive(Default)]
pub struct Empty;

// Derive the default builder (relies on the default() function from the plugin)
default_plugin_builder!(Empty, EmptyBuilder);

impl Plugin for Empty {
    fn name(&self) -> &'static str {
        "Empty"
    }
    fn plugin_type(&self) -> u16 {
        PLUGIN_NONE
    }
}

/// Example plugin, reading a configuration value
#[derive(Default)]
pub struct EmptyWithConfig {
    name: Option<String>,
}

impl Plugin for EmptyWithConfig {
    fn name(&self) -> &'static str {
        "EmptyWithConfig"
    }
    fn plugin_type(&self) -> u16 {
        PLUGIN_NONE
    }

    fn pre_process(&mut self) {
        info!(
            "Hello, I am plugin EmptyWithConfig, with name {:?}",
            self.name
        );
    }
}

/// Implements the plugin PluginBuilder
///
/// We cannot rely on the default implementation, since we want to overload the `build` function
pub struct EmptyWithConfigBuilder;

impl crate::plugin::PluginBuilder for EmptyWithConfigBuilder {
    fn name(&self) -> &'static str {
        "EmptyWithConfigBuilder"
    }
    fn build(
        &self,
        registry: &mut PluginRegistry,
        config: &Config,
    ) -> Result<(), PluginBuilderError> {
        let name = config.get("plugin.emptywithconfig.name");
        let plugin = EmptyWithConfig {
            name: name.map(|s| s.to_string()),
        };
        let safe_p = build_safeplugin!(plugin);
        registry.add_plugin(safe_p);
        // do not register, there is no callback
        Ok(())
    }
}
