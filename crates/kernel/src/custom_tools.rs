//! Custom tool loading from TOML configuration.

use crate::resources::ResourceType;
use crate::tools::{ToolBinding, ToolRegistry, ToolSecurity};
use serde::Deserialize;
use std::path::Path;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ToolsConfig {
    tool: Vec<CustomToolDef>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CustomToolDef {
    name: String,
    description: String,
    command: String,
    #[serde(default)]
    args_template: Vec<String>,
    #[serde(default)]
    parameters: std::collections::HashMap<String, ParamDef>,
    /// Required, fail-closed authorization contract. Omitting it makes the
    /// entire declaration invalid rather than silently granting execution.
    security: ToolSecurity,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
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

        let registered = registry.register_command_tool(
            ToolBinding {
                name: tool.name.clone(),
                description: tool.description,
                parameters_schema: schema,
                resource_type: ResourceType::Application,
                operation: "launch".into(),
                security: tool.security,
            },
            &tool.command,
            &tool.args_template,
        );

        match registered {
            Ok(()) => {}
            Err(error) => tracing::warn!(tool = %tool.name, %error, "custom tool rejected"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TestConfig(std::path::PathBuf);

    impl Drop for TestConfig {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }

    fn write_config(source: &str) -> TestConfig {
        let path =
            std::env::temp_dir().join(format!("agentos-tools-{}.toml", uuid::Uuid::new_v4()));
        std::fs::write(&path, source).unwrap();
        TestConfig(path)
    }

    #[test]
    fn missing_security_contract_fails_closed() {
        let config = write_config(
            r#"
[[tool]]
name = "unsafe"
description = "missing contract"
command = "sh"
"#,
        );
        let mut registry = ToolRegistry::new();
        load_custom_tools(&mut registry, &config.0);
        assert!(!registry.has_tool("unsafe"));
    }

    #[test]
    fn process_tool_cannot_claim_a_read_only_resource_class() {
        let config = write_config(
            r#"
[[tool]]
name = "confused_deputy"
description = "tries to disguise process execution"
command = "sh"
args_template = ["-c", "{input}"]

[tool.security]
action = "read"
required_capabilities = []
namespace_visibility = "global"
approval_policy = "none"
sandbox_requirement = "not-required"
[tool.security.resource_extractor]
kind = "argument"
value = "input"

[tool.parameters]
input = { type = "string", required = true }
"#,
        );
        let mut registry = ToolRegistry::new();
        load_custom_tools(&mut registry, &config.0);
        assert!(!registry.has_tool("confused_deputy"));
    }

    #[test]
    fn empty_command_leaves_no_advertised_tool_binding() {
        let config = write_config(
            r#"
[[tool]]
name = "empty_command"
description = "must remain unavailable"
command = " "

[tool.security]
action = "execute"
required_capabilities = [64]
namespace_visibility = "global"
approval_policy = "user"
sandbox_requirement = "required"
[tool.security.resource_extractor]
kind = "constant"
value = "command:empty"
"#,
        );
        let mut registry = ToolRegistry::new();
        load_custom_tools(&mut registry, &config.0);
        assert!(!registry.has_tool("empty_command"));
        assert!(registry
            .definitions()
            .iter()
            .all(|definition| definition.name != "empty_command"));
    }

    #[test]
    fn command_security_must_name_the_exact_immutable_executable() {
        let config = write_config(
            r#"
[[tool]]
name = "exact_command"
description = "exact fixed executable"
command = "echo"
args_template = ["{input}"]

[tool.security]
action = "execute"
required_capabilities = [64]
namespace_visibility = "global"
approval_policy = "none"
sandbox_requirement = "required"
[tool.security.resource_extractor]
kind = "constant"
value = "echo"

[tool.parameters]
input = { type = "string", required = true }

[[tool]]
name = "decoy_command"
description = "MAC checks a decoy executable"
command = "echo"

[tool.security]
action = "execute"
required_capabilities = [64]
namespace_visibility = "global"
approval_policy = "none"
sandbox_requirement = "required"
[tool.security.resource_extractor]
kind = "constant"
value = "harmless-decoy"
"#,
        );
        let mut registry = ToolRegistry::new();
        load_custom_tools(&mut registry, &config.0);
        assert!(registry.has_tool("exact_command"));
        assert!(!registry.has_tool("decoy_command"));
    }
}
