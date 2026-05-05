//! Codebase indexing — build a repo map for LLM context.
//!
//! Scans a directory, extracts file structure and key symbols,
//! produces a condensed map the LLM can use to understand the codebase.

use std::path::{Path, PathBuf};

/// A condensed map of a code repository.
#[derive(Debug, Clone)]
pub struct RepoMap {
    pub root: PathBuf,
    pub files: Vec<FileEntry>,
    pub total_files: usize,
    pub total_lines: usize,
}

/// An entry in the repo map.
#[derive(Debug, Clone)]
pub struct FileEntry {
    pub path: String,
    pub language: String,
    pub lines: usize,
    pub symbols: Vec<String>, // function/struct/class names
}

impl RepoMap {
    /// Build a repo map from a directory.
    pub fn build(root: &Path) -> Self {
        let mut files = Vec::new();
        let mut total_lines = 0;
        Self::scan_dir(root, root, &mut files, &mut total_lines, 0);
        let total_files = files.len();
        Self { root: root.to_path_buf(), files, total_files, total_lines }
    }

    fn scan_dir(root: &Path, dir: &Path, files: &mut Vec<FileEntry>, total_lines: &mut usize, depth: usize) {
        if depth > 5 { return; } // Max depth
        let entries = match std::fs::read_dir(dir) {
            Ok(e) => e,
            Err(_) => return,
        };

        for entry in entries.filter_map(|e| e.ok()) {
            let path = entry.path();
            let name = entry.file_name().to_string_lossy().to_string();

            // Skip hidden dirs, target, node_modules, etc.
            if name.starts_with('.') || name == "target" || name == "node_modules" || name == "dist" || name == "__pycache__" {
                continue;
            }

            if path.is_dir() {
                Self::scan_dir(root, &path, files, total_lines, depth + 1);
            } else if let Some(lang) = detect_language(&name) {
                if let Ok(content) = std::fs::read_to_string(&path) {
                    let lines = content.lines().count();
                    *total_lines += lines;
                    let symbols = extract_symbols(&content, &lang);
                    let rel_path = path.strip_prefix(root).unwrap_or(&path).to_string_lossy().to_string();
                    files.push(FileEntry { path: rel_path, language: lang, lines, symbols });
                }
            }
        }
    }

    /// Format as a condensed string for the LLM system prompt.
    pub fn to_prompt(&self, max_chars: usize) -> String {
        let mut out = format!("Repository: {} ({} files, {} lines)\n\n", self.root.display(), self.total_files, self.total_lines);

        for file in &self.files {
            let line = if file.symbols.is_empty() {
                format!("{} ({}, {} lines)\n", file.path, file.language, file.lines)
            } else {
                format!("{} ({}, {} lines): {}\n", file.path, file.language, file.lines, file.symbols.join(", "))
            };
            if out.len() + line.len() > max_chars { break; }
            out.push_str(&line);
        }
        out
    }
}

fn detect_language(filename: &str) -> Option<String> {
    let ext = filename.rsplit('.').next()?;
    match ext {
        "rs" => Some("Rust".into()),
        "py" => Some("Python".into()),
        "js" | "mjs" => Some("JavaScript".into()),
        "ts" | "tsx" => Some("TypeScript".into()),
        "go" => Some("Go".into()),
        "java" => Some("Java".into()),
        "c" | "h" => Some("C".into()),
        "cpp" | "cc" | "hpp" => Some("C++".into()),
        "rb" => Some("Ruby".into()),
        "toml" => Some("TOML".into()),
        "yaml" | "yml" => Some("YAML".into()),
        "json" => Some("JSON".into()),
        "md" => Some("Markdown".into()),
        "svelte" => Some("Svelte".into()),
        _ => None,
    }
}

/// Extract top-level symbols (functions, structs, classes) from source code.
fn extract_symbols(content: &str, language: &str) -> Vec<String> {
    let mut symbols = Vec::new();
    for line in content.lines() {
        let trimmed = line.trim();
        let sym = match language {
            "Rust" => {
                if trimmed.starts_with("pub fn ") || trimmed.starts_with("fn ") {
                    trimmed.split('(').next().and_then(|s| s.split_whitespace().last()).map(|s| s.to_string())
                } else if trimmed.starts_with("pub struct ") || trimmed.starts_with("struct ") {
                    trimmed.split_whitespace().nth(if trimmed.starts_with("pub") { 2 } else { 1 }).map(|s| s.trim_end_matches('{').to_string())
                } else if trimmed.starts_with("pub enum ") || trimmed.starts_with("enum ") {
                    trimmed.split_whitespace().nth(if trimmed.starts_with("pub") { 2 } else { 1 }).map(|s| s.trim_end_matches('{').to_string())
                } else { None }
            }
            "Python" => {
                if trimmed.starts_with("def ") || trimmed.starts_with("class ") {
                    trimmed.split('(').next().and_then(|s| s.split_whitespace().last()).map(|s| s.trim_end_matches(':').to_string())
                } else { None }
            }
            "JavaScript" | "TypeScript" => {
                if trimmed.starts_with("function ") || trimmed.starts_with("export function ") {
                    trimmed.split('(').next().and_then(|s| s.split_whitespace().last()).map(|s| s.to_string())
                } else if trimmed.contains("class ") && trimmed.contains('{') {
                    trimmed.split_whitespace().find(|w| w.chars().next().map(|c| c.is_uppercase()).unwrap_or(false)).map(|s| s.trim_end_matches('{').to_string())
                } else { None }
            }
            _ => None,
        };
        if let Some(s) = sym {
            if !s.is_empty() && symbols.len() < 15 {
                symbols.push(s);
            }
        }
    }
    symbols
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_rust_symbols() {
        let code = "pub fn hello() {}\nstruct Foo {}\npub enum Bar { A, B }";
        let syms = extract_symbols(code, "Rust");
        assert!(syms.contains(&"hello".to_string()));
        assert!(syms.contains(&"Foo".to_string()));
        assert!(syms.contains(&"Bar".to_string()));
    }

    #[test]
    fn extract_python_symbols() {
        let code = "def greet(name):\n    pass\nclass MyClass:\n    pass";
        let syms = extract_symbols(code, "Python");
        assert!(syms.contains(&"greet".to_string()));
        assert!(syms.contains(&"MyClass".to_string()));
    }

    #[test]
    fn detect_languages() {
        assert_eq!(detect_language("main.rs"), Some("Rust".into()));
        assert_eq!(detect_language("app.py"), Some("Python".into()));
        assert_eq!(detect_language("index.ts"), Some("TypeScript".into()));
        assert_eq!(detect_language("photo.jpg"), None);
    }

    #[test]
    fn build_repo_map() {
        let map = RepoMap::build(std::path::Path::new("/home/surya/AI Agent OS/crates/kernel/src"));
        assert!(map.total_files > 10);
        assert!(map.total_lines > 1000);
        assert!(map.files.iter().any(|f| f.path.contains("execution")));
    }
}
