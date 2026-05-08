//! Agent Shell — interactive command interpreter for AI Agent OS.
//!
//! Like bash/zsh but for managing agents. Supports piping, job control,
//! variables, and scripting.

use std::collections::HashMap;

/// A parsed shell command.
#[derive(Debug, Clone)]
pub struct ShellCommand {
    pub program: String,
    pub args: Vec<String>,
    pub pipe_to: Option<Box<ShellCommand>>,
    pub background: bool,
    pub redirect_out: Option<String>,
    pub redirect_in: Option<String>,
}

/// Shell environment (variables, aliases).
pub struct ShellEnv {
    pub variables: HashMap<String, String>,
    pub aliases: HashMap<String, String>,
    pub history: Vec<String>,
    pub cwd: String,
    pub last_exit_code: i32,
}

impl Default for ShellEnv {
    fn default() -> Self {
        Self::new()
    }
}

impl ShellEnv {
    pub fn new() -> Self {
        let mut variables = HashMap::new();
        variables.insert("PATH".into(), "/tools:/bin".into());
        variables.insert("HOME".into(), "/".into());
        variables.insert("SHELL".into(), "agentsh".into());
        Self {
            variables,
            aliases: HashMap::new(),
            history: Vec::new(),
            cwd: "/".into(),
            last_exit_code: 0,
        }
    }

    pub fn set_var(&mut self, key: &str, value: String) {
        self.variables.insert(key.into(), value);
    }
    pub fn get_var(&self, key: &str) -> Option<&str> {
        self.variables.get(key).map(|s| s.as_str())
    }
    pub fn set_alias(&mut self, name: &str, cmd: String) {
        self.aliases.insert(name.into(), cmd);
    }
}

/// Parse a command line into a ShellCommand.
pub fn parse_command(input: &str) -> Option<ShellCommand> {
    let input = input.trim();
    if input.is_empty() {
        return None;
    }

    // Check for pipe
    if let Some(pipe_pos) = input.find('|') {
        let left = &input[..pipe_pos].trim();
        let right = &input[pipe_pos + 1..].trim();
        let mut cmd = parse_simple(left)?;
        cmd.pipe_to = parse_command(right).map(Box::new);
        return Some(cmd);
    }

    parse_simple(input)
}

fn parse_simple(input: &str) -> Option<ShellCommand> {
    let input = input.trim();
    if input.is_empty() {
        return None;
    }

    let mut background = false;
    let mut redirect_out = None;
    let mut redirect_in = None;

    let mut cleaned = input.to_string();

    // Check background (&)
    if cleaned.ends_with('&') {
        background = true;
        cleaned = cleaned[..cleaned.len() - 1].trim().to_string();
    }

    // Check output redirect (>)
    if let Some(pos) = cleaned.find('>') {
        redirect_out = Some(cleaned[pos + 1..].trim().to_string());
        cleaned = cleaned[..pos].trim().to_string();
    }

    // Check input redirect (<)
    if let Some(pos) = cleaned.find('<') {
        redirect_in = Some(cleaned[pos + 1..].trim().to_string());
        cleaned = cleaned[..pos].trim().to_string();
    }

    let parts: Vec<String> = cleaned.split_whitespace().map(|s| s.to_string()).collect();
    if parts.is_empty() {
        return None;
    }

    Some(ShellCommand {
        program: parts[0].clone(),
        args: parts[1..].to_vec(),
        pipe_to: None,
        background,
        redirect_out,
        redirect_in,
    })
}

/// Built-in shell commands.
pub fn is_builtin(cmd: &str) -> bool {
    matches!(
        cmd,
        "cd" | "export" | "alias" | "history" | "exit" | "help" | "echo" | "set"
    )
}

/// Execute a built-in command.
pub fn exec_builtin(cmd: &ShellCommand, env: &mut ShellEnv) -> String {
    match cmd.program.as_str() {
        "cd" => {
            let dir = cmd.args.first().map(|s| s.as_str()).unwrap_or("/");
            env.cwd = dir.to_string();
            String::new()
        }
        "export" => {
            for arg in &cmd.args {
                if let Some((key, val)) = arg.split_once('=') {
                    env.set_var(key, val.to_string());
                }
            }
            String::new()
        }
        "alias" => {
            for arg in &cmd.args {
                if let Some((name, cmd_str)) = arg.split_once('=') {
                    env.set_alias(name, cmd_str.to_string());
                }
            }
            format!("{} aliases defined", env.aliases.len())
        }
        "history" => env
            .history
            .iter()
            .enumerate()
            .map(|(i, h)| format!("{}: {}", i + 1, h))
            .collect::<Vec<_>>()
            .join("\n"),
        "echo" => cmd.args.join(" "),
        "set" => env
            .variables
            .iter()
            .map(|(k, v)| format!("{}={}", k, v))
            .collect::<Vec<_>>()
            .join("\n"),
        "help" => "Built-in commands: cd, export, alias, history, echo, set, exit, help".into(),
        "exit" => "exit".into(),
        _ => format!("unknown builtin: {}", cmd.program),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_simple_command() {
        let cmd = parse_command("agentctl start researcher").unwrap();
        assert_eq!(cmd.program, "agentctl");
        assert_eq!(cmd.args, vec!["start", "researcher"]);
    }

    #[test]
    fn parse_pipe() {
        let cmd = parse_command("agentps | grep running").unwrap();
        assert_eq!(cmd.program, "agentps");
        assert!(cmd.pipe_to.is_some());
        assert_eq!(cmd.pipe_to.unwrap().program, "grep");
    }

    #[test]
    fn parse_background() {
        let cmd = parse_command("agent run task &").unwrap();
        assert!(cmd.background);
    }

    #[test]
    fn parse_redirect() {
        let cmd = parse_command("agentps > /tmp/output.txt").unwrap();
        assert_eq!(cmd.redirect_out, Some("/tmp/output.txt".into()));
    }

    #[test]
    fn builtin_cd() {
        let mut env = ShellEnv::new();
        let cmd = parse_command("cd /agents").unwrap();
        exec_builtin(&cmd, &mut env);
        assert_eq!(env.cwd, "/agents");
    }

    #[test]
    fn builtin_export() {
        let mut env = ShellEnv::new();
        let cmd = parse_command("export MY_VAR=hello").unwrap();
        exec_builtin(&cmd, &mut env);
        assert_eq!(env.get_var("MY_VAR"), Some("hello"));
    }

    #[test]
    fn builtin_echo() {
        let mut env = ShellEnv::new();
        let cmd = parse_command("echo hello world").unwrap();
        let output = exec_builtin(&cmd, &mut env);
        assert_eq!(output, "hello world");
    }
}
