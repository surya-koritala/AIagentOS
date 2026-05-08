//! Sysctl — runtime kernel configuration.

use std::collections::HashMap;

pub struct Sysctl {
    params: HashMap<String, String>,
}

impl Sysctl {
    pub fn new() -> Self {
        let mut params = HashMap::new();
        params.insert("kernel.max_agents".into(), "100".into());
        params.insert("kernel.max_tokens_per_min".into(), "100000".into());
        params.insert("kernel.time_slice".into(), "1000".into());
        params.insert("kernel.max_open_tools".into(), "256".into());
        params.insert("net.max_socket_buffer".into(), "1024".into());
        params.insert("security.enforcing".into(), "1".into());
        Self { params }
    }

    pub fn get(&self, key: &str) -> Option<&str> {
        self.params.get(key).map(|s| s.as_str())
    }
    pub fn set(&mut self, key: &str, value: String) -> Result<(), &'static str> {
        if !self.params.contains_key(key) {
            return Err("unknown sysctl key");
        }
        self.params.insert(key.to_string(), value);
        Ok(())
    }
    pub fn list(&self) -> Vec<(&str, &str)> {
        self.params
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect()
    }
    pub fn get_u64(&self, key: &str) -> Option<u64> {
        self.get(key)?.parse().ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn get_default() {
        let s = Sysctl::new();
        assert_eq!(s.get("kernel.max_agents"), Some("100"));
    }

    #[test]
    fn set_value() {
        let mut s = Sysctl::new();
        s.set("kernel.max_agents", "200".into()).unwrap();
        assert_eq!(s.get("kernel.max_agents"), Some("200"));
    }

    #[test]
    fn set_unknown_fails() {
        let mut s = Sysctl::new();
        assert!(s.set("nonexistent.key", "x".into()).is_err());
    }

    #[test]
    fn get_u64() {
        let s = Sysctl::new();
        assert_eq!(s.get_u64("kernel.max_agents"), Some(100));
    }
}
