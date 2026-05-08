//! Custom tool loading from TOML configuration.

use crate::resources::ResourceType;
use crate::tools::{ToolBinding, ToolRegistry};
use serde::Deserialize;
use std::path::Path;

#[derive(Debug, Deserialize)]
struct ToolsConfig {
    tool: Vec<CustomToolDef>,
}

#[derive(Debug, Deserialize)]
struct CustomToolDef {
    name: String,
    description: String,
    command: String,
    #[serde(default)]
    args_template: Vec<String>,
    #[serde(default)]
    parameters: std::collections::HashMap<String, ParamDef>,
}

#[derive(Debug, Deserialize)]
struct ParamDef {
    #[serde(rename = "type")]
    param_type: String,
    #[serde(default)]
    description: String,
    #[serde(default)]
    required: bool,
}

/// Load custom tools from a TOML file and register them in the registry.
pub fn load_custom_tools(registry: &mut ToolRegistry, path: &Path) {
    let content = match std::fs::read_to_string(path) {
        Ok(c) => c,
        Err(_) => return, // File doesn't exist — that's fine
    };

    let config: ToolsConfig = match toml::from_str(&content) {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!("Invalid tools.toml: {}", e);
            return;
        }
    };

    for tool in config.tool {
        let mut properties = serde_json::Map::new();
        let mut required = Vec::new();

        for (name, param) in &tool.parameters {
            properties.insert(
                name.clone(),
                serde_json::json!({
                    "type": param.param_type,
                    "description": param.description,
                }),
            );
            if param.required {
                required.push(serde_json::Value::String(name.clone()));
            }
        }

        let schema = serde_json::json!({
            "type": "object",
            "properties": properties,
            "required": required,
        });

        registry.register(ToolBinding {
            name: tool.name.clone(),
            description: tool.description,
            parameters_schema: schema,
            resource_type: ResourceType::Application,
            operation: "launch".into(),
        });

        // Store the command template for resolution
        registry.register_command_template(&tool.name, &tool.command, &tool.args_template);
    }
}
