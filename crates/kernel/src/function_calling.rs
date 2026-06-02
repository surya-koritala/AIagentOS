//! Function-calling shim for models without native structured tool-calling.
//!
//! Some models cannot emit the OpenAI-style structured `tool_calls` field; they
//! only return plaintext. This module bridges that gap two ways:
//!
//! 1. [`render_tools_prompt`] renders the available tool schemas into a textual
//!    instruction block the model can follow — telling it to emit a fenced JSON
//!    object like `{"tool":"name","arguments":{...}}` when it wants a tool.
//! 2. [`parse_tool_calls`] reads a plaintext model reply back and recovers any
//!    such JSON objects into structured [`ToolCall`]s.
//!
//! The executor uses `parse_tool_calls` as a *fallback*: only when a response
//! carries no native structured tool calls does it scan the plaintext. Models
//! with native function-calling are unaffected.

use crate::connector::{ToolCall, ToolDefinition};

/// Render the available tools into a textual instruction block.
///
/// The block explains the shim protocol — emit a fenced JSON object naming the
/// tool and its arguments — and lists every tool with its description and JSON
/// parameter schema. Returns an empty string when there are no tools so callers
/// can append it unconditionally without injecting noise.
pub fn render_tools_prompt(tools: &[ToolDefinition]) -> String {
    if tools.is_empty() {
        return String::new();
    }

    let mut out = String::new();
    out.push_str(
        "You can call tools. When you want to use a tool, respond with a fenced JSON code block \
         containing an object of the form:\n\n\
         ```json\n\
         {\"tool\": \"<tool_name>\", \"arguments\": { ... }}\n\
         ```\n\n\
         Emit one such block per tool call. Put nothing else inside the block. When you do not \
         need a tool, reply with plain text instead.\n\n\
         Available tools:\n",
    );

    for tool in tools {
        out.push_str("\n- ");
        out.push_str(&tool.name);
        if !tool.description.is_empty() {
            out.push_str(": ");
            out.push_str(&tool.description);
        }
        out.push('\n');
        if let Ok(schema) = serde_json::to_string(&tool.parameters) {
            out.push_str("  parameters: ");
            out.push_str(&schema);
            out.push('\n');
        }
    }

    out
}

/// Recover zero or more tool calls from a plaintext model reply.
///
/// Scans the text for JSON objects shaped like `{"tool":"name","arguments":{...}}`
/// (also accepting `name`/`function` for the tool key and `args`/`parameters`/
/// `input` for the arguments key). Handles objects inside fenced ```` ```json ````
/// blocks and bare objects embedded in prose. Surrounding prose is ignored, and
/// malformed or non-tool JSON yields no call. Returns an empty vector when none
/// are found.
///
/// Each recovered call gets a synthetic, stable id (`shim_call_<n>`) since
/// plaintext replies carry no provider call id.
pub fn parse_tool_calls(text: &str) -> Vec<ToolCall> {
    let mut calls = Vec::new();
    for value in extract_json_objects(text) {
        if let Some(call) = value_to_tool_call(&value, calls.len()) {
            calls.push(call);
        }
    }
    calls
}

/// Interpret a parsed JSON object as a tool call, if it has the expected shape.
fn value_to_tool_call(value: &serde_json::Value, index: usize) -> Option<ToolCall> {
    let obj = value.as_object()?;

    // Accept the canonical "tool" key plus common synonyms.
    let name = obj
        .get("tool")
        .or_else(|| obj.get("name"))
        .or_else(|| obj.get("function"))
        .and_then(|v| v.as_str())?;
    if name.is_empty() {
        return None;
    }

    // Arguments are optional (a no-arg tool); default to an empty object.
    let arguments = obj
        .get("arguments")
        .or_else(|| obj.get("args"))
        .or_else(|| obj.get("parameters"))
        .or_else(|| obj.get("input"))
        .cloned()
        .unwrap_or_else(|| serde_json::json!({}));

    Some(ToolCall {
        id: format!("shim_call_{}", index),
        name: name.to_string(),
        arguments,
    })
}

/// Extract every top-level JSON object embedded in `text`.
///
/// Walks the string tracking brace depth (and skipping over string literals so
/// braces inside strings don't confuse the scan), slicing out each balanced
/// `{...}` span and attempting to parse it. Non-parseable spans are skipped.
/// This naturally handles fenced code blocks — the surrounding ```` ```json ````
/// markers are not braces, so they're ignored.
fn extract_json_objects(text: &str) -> Vec<serde_json::Value> {
    let mut objects = Vec::new();
    let bytes = text.as_bytes();
    let mut i = 0;

    while i < bytes.len() {
        if bytes[i] == b'{' {
            if let Some(end) = match_balanced_object(bytes, i) {
                let slice = &text[i..=end];
                if let Ok(value) = serde_json::from_str::<serde_json::Value>(slice) {
                    objects.push(value);
                }
                // Continue scanning *after* this object so sibling objects
                // (e.g. multiple tool calls) are each found.
                i = end + 1;
                continue;
            }
        }
        i += 1;
    }

    objects
}

/// Given a `{` at `start`, return the index of the matching `}`, or `None` if
/// the object never closes. String literals (with escapes) are skipped so that
/// braces inside JSON string values don't affect the depth count.
fn match_balanced_object(bytes: &[u8], start: usize) -> Option<usize> {
    let mut depth = 0usize;
    let mut in_string = false;
    let mut escaped = false;
    let mut i = start;

    while i < bytes.len() {
        let b = bytes[i];
        if in_string {
            if escaped {
                escaped = false;
            } else if b == b'\\' {
                escaped = true;
            } else if b == b'"' {
                in_string = false;
            }
        } else {
            match b {
                b'"' => in_string = true,
                b'{' => depth += 1,
                b'}' => {
                    depth -= 1;
                    if depth == 0 {
                        return Some(i);
                    }
                }
                _ => {}
            }
        }
        i += 1;
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tool(name: &str, desc: &str) -> ToolDefinition {
        ToolDefinition {
            name: name.into(),
            description: desc.into(),
            parameters: serde_json::json!({
                "type": "object",
                "properties": { "path": { "type": "string" } }
            }),
        }
    }

    #[test]
    fn render_includes_each_tool_name() {
        let tools = vec![tool("read_file", "Read a file"), tool("http_get", "Fetch")];
        let prompt = render_tools_prompt(&tools);
        assert!(prompt.contains("read_file"));
        assert!(prompt.contains("http_get"));
        assert!(prompt.contains("Read a file"));
        // Documents the shim protocol.
        assert!(prompt.contains("\"tool\""));
        assert!(prompt.contains("\"arguments\""));
    }

    #[test]
    fn render_empty_when_no_tools() {
        assert_eq!(render_tools_prompt(&[]), "");
    }

    #[test]
    fn parse_single_call() {
        let text = r#"I'll read it. {"tool": "read_file", "arguments": {"path": "/tmp/x"}}"#;
        let calls = parse_tool_calls(text);
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].name, "read_file");
        assert_eq!(calls[0].arguments["path"], "/tmp/x");
        assert_eq!(calls[0].id, "shim_call_0");
    }

    #[test]
    fn parse_multiple_calls() {
        let text = r#"
            First: {"tool": "read_file", "arguments": {"path": "/a"}}
            Then: {"tool": "read_file", "arguments": {"path": "/b"}}
        "#;
        let calls = parse_tool_calls(text);
        assert_eq!(calls.len(), 2);
        assert_eq!(calls[0].arguments["path"], "/a");
        assert_eq!(calls[1].arguments["path"], "/b");
        assert_eq!(calls[1].id, "shim_call_1");
    }

    #[test]
    fn parse_fenced_json_block() {
        let text = "Sure, let me do that.\n\n```json\n{\"tool\": \"http_get\", \"arguments\": {\"url\": \"http://x\"}}\n```\n\nDone.";
        let calls = parse_tool_calls(text);
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].name, "http_get");
        assert_eq!(calls[0].arguments["url"], "http://x");
    }

    #[test]
    fn parse_handles_synonym_keys() {
        let text = r#"{"name": "list_dir", "args": {"path": "/"}}"#;
        let calls = parse_tool_calls(text);
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].name, "list_dir");
        assert_eq!(calls[0].arguments["path"], "/");
    }

    #[test]
    fn parse_no_arg_tool_defaults_empty_object() {
        let text = r#"{"tool": "list_tools"}"#;
        let calls = parse_tool_calls(text);
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].name, "list_tools");
        assert!(calls[0].arguments.is_object());
    }

    #[test]
    fn parse_ignores_braces_inside_strings() {
        let text = r#"{"tool": "echo", "arguments": {"text": "a } b { c"}}"#;
        let calls = parse_tool_calls(text);
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].arguments["text"], "a } b { c");
    }

    #[test]
    fn parse_empty_for_prose_only() {
        assert!(parse_tool_calls("I think the answer is 42, no tools needed.").is_empty());
    }

    #[test]
    fn parse_empty_for_malformed_or_non_tool_json() {
        // Malformed (unterminated) — never closes.
        assert!(parse_tool_calls(r#"{"tool": "read_file", "arguments": {"#).is_empty());
        // Valid JSON object, but no tool key.
        assert!(parse_tool_calls(r#"{"result": "done", "score": 5}"#).is_empty());
    }
}
