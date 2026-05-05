//! Docker-based sandboxing — isolated containers per agent.

use std::collections::HashMap;
use serde::{Deserialize, Serialize};
use crate::AgentId;

/// Docker sandbox configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DockerSandboxConfig {
    pub image: String,
    pub memory_limit: String,
    pub cpu_limit: String,
    pub network_mode: NetworkMode,
    pub volumes: Vec<VolumeMount>,
    pub env_vars: HashMap<String, String>,
}

impl Default for DockerSandboxConfig {
    fn default() -> Self {
        Self {
            image: "ubuntu:22.04".into(),
            memory_limit: "512m".into(),
            cpu_limit: "1.0".into(),
            network_mode: NetworkMode::None,
            volumes: Vec::new(),
            env_vars: HashMap::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum NetworkMode { None, Host, Bridge }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VolumeMount {
    pub host_path: String,
    pub container_path: String,
    pub read_only: bool,
}

/// A running Docker sandbox.
pub struct DockerSandbox {
    pub container_id: String,
    pub agent_id: AgentId,
    pub config: DockerSandboxConfig,
}

impl DockerSandbox {
    /// Create and start a new Docker container for an agent.
    pub async fn create(agent_id: AgentId, config: DockerSandboxConfig) -> Result<Self, String> {
        let name = format!("agent-os-{}", &agent_id.to_string()[..8]);

        let mut args = vec![
            "run".into(), "-d".into(),
            "--name".into(), name.clone(),
            "--memory".into(), config.memory_limit.clone(),
            "--cpus".into(), config.cpu_limit.clone(),
        ];

        match config.network_mode {
            NetworkMode::None => { args.push("--network".into()); args.push("none".into()); }
            NetworkMode::Host => { args.push("--network".into()); args.push("host".into()); }
            NetworkMode::Bridge => {}
        }

        for vol in &config.volumes {
            args.push("-v".into());
            let ro = if vol.read_only { ":ro" } else { "" };
            args.push(format!("{}:{}{}", vol.host_path, vol.container_path, ro));
        }

        for (k, v) in &config.env_vars {
            args.push("-e".into());
            args.push(format!("{}={}", k, v));
        }

        args.push(config.image.clone());
        args.push("sleep".into());
        args.push("infinity".into());

        let output = tokio::process::Command::new("docker")
            .args(&args)
            .output().await
            .map_err(|e| format!("Docker not available: {}", e))?;

        if !output.status.success() {
            return Err(format!("Docker create failed: {}", String::from_utf8_lossy(&output.stderr)));
        }

        let container_id = String::from_utf8_lossy(&output.stdout).trim().to_string();
        Ok(Self { container_id, agent_id, config })
    }

    /// Execute a command inside the container.
    pub async fn exec(&self, command: &str) -> Result<String, String> {
        let output = tokio::process::Command::new("docker")
            .args(["exec", &self.container_id, "sh", "-c", command])
            .output().await
            .map_err(|e| e.to_string())?;

        if output.status.success() {
            Ok(String::from_utf8_lossy(&output.stdout).to_string())
        } else {
            Err(String::from_utf8_lossy(&output.stderr).to_string())
        }
    }

    /// Copy a file into the container.
    pub async fn copy_in(&self, host_path: &str, container_path: &str) -> Result<(), String> {
        let output = tokio::process::Command::new("docker")
            .args(["cp", host_path, &format!("{}:{}", self.container_id, container_path)])
            .output().await.map_err(|e| e.to_string())?;
        if output.status.success() { Ok(()) } else { Err(String::from_utf8_lossy(&output.stderr).to_string()) }
    }

    /// Copy a file out of the container.
    pub async fn copy_out(&self, container_path: &str, host_path: &str) -> Result<(), String> {
        let output = tokio::process::Command::new("docker")
            .args(["cp", &format!("{}:{}", self.container_id, container_path), host_path])
            .output().await.map_err(|e| e.to_string())?;
        if output.status.success() { Ok(()) } else { Err(String::from_utf8_lossy(&output.stderr).to_string()) }
    }

    /// Stop and remove the container.
    pub async fn destroy(&self) -> Result<(), String> {
        let _ = tokio::process::Command::new("docker")
            .args(["rm", "-f", &self.container_id])
            .output().await;
        Ok(())
    }
}

impl Drop for DockerSandbox {
    fn drop(&mut self) {
        // Best-effort cleanup
        let id = self.container_id.clone();
        std::thread::spawn(move || {
            let _ = std::process::Command::new("docker").args(["rm", "-f", &id]).output();
        });
    }
}
