//! GitHub integration — issues, PRs, code review via GitHub API.

use serde::{Deserialize, Serialize};

const GITHUB_API: &str = "https://api.github.com";

/// GitHub client.
pub struct GitHubClient {
    client: reqwest::Client,
    token: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Issue {
    pub number: u64,
    pub title: String,
    pub body: Option<String>,
    pub state: String,
    pub html_url: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PullRequest {
    pub number: u64,
    pub title: String,
    pub body: Option<String>,
    pub state: String,
    pub html_url: String,
    pub head: BranchRef,
    pub base: BranchRef,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BranchRef {
    #[serde(rename = "ref")]
    pub ref_name: String,
}

impl GitHubClient {
    pub fn new(token: String) -> Self {
        let client = reqwest::Client::builder()
            .user_agent("AIAgentOS/1.0")
            .build().unwrap();
        Self { client, token }
    }

    pub async fn list_issues(&self, owner: &str, repo: &str) -> Result<Vec<Issue>, String> {
        let url = format!("{}/repos/{}/{}/issues?state=open&per_page=20", GITHUB_API, owner, repo);
        let resp = self.get(&url).await?;
        serde_json::from_value(resp).map_err(|e| e.to_string())
    }

    pub async fn create_issue(&self, owner: &str, repo: &str, title: &str, body: &str) -> Result<Issue, String> {
        let url = format!("{}/repos/{}/{}/issues", GITHUB_API, owner, repo);
        let resp = self.post(&url, serde_json::json!({"title": title, "body": body})).await?;
        serde_json::from_value(resp).map_err(|e| e.to_string())
    }

    pub async fn create_pr(&self, owner: &str, repo: &str, title: &str, body: &str, head: &str, base: &str) -> Result<PullRequest, String> {
        let url = format!("{}/repos/{}/{}/pulls", GITHUB_API, owner, repo);
        let resp = self.post(&url, serde_json::json!({"title": title, "body": body, "head": head, "base": base})).await?;
        serde_json::from_value(resp).map_err(|e| e.to_string())
    }

    pub async fn list_files(&self, owner: &str, repo: &str, path: &str) -> Result<Vec<serde_json::Value>, String> {
        let url = format!("{}/repos/{}/{}/contents/{}", GITHUB_API, owner, repo, path);
        let resp = self.get(&url).await?;
        resp.as_array().cloned().ok_or("Not an array".into())
    }

    pub async fn get_file_content(&self, owner: &str, repo: &str, path: &str) -> Result<String, String> {
        let url = format!("{}/repos/{}/{}/contents/{}", GITHUB_API, owner, repo, path);
        let resp = self.get(&url).await?;
        let content = resp["content"].as_str().ok_or("No content")?;
        let decoded = content.replace('\n', "");
        String::from_utf8(base64_decode(&decoded)).map_err(|e| e.to_string())
    }

    async fn get(&self, url: &str) -> Result<serde_json::Value, String> {
        self.client.get(url)
            .header("Authorization", format!("Bearer {}", self.token))
            .header("Accept", "application/vnd.github+json")
            .send().await.map_err(|e| e.to_string())?
            .json().await.map_err(|e| e.to_string())
    }

    async fn post(&self, url: &str, body: serde_json::Value) -> Result<serde_json::Value, String> {
        self.client.post(url)
            .header("Authorization", format!("Bearer {}", self.token))
            .header("Accept", "application/vnd.github+json")
            .json(&body)
            .send().await.map_err(|e| e.to_string())?
            .json().await.map_err(|e| e.to_string())
    }
}

fn base64_decode(input: &str) -> Vec<u8> {
    // Simple base64 decode (standard alphabet)
    let table: Vec<u8> = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/".to_vec();
    let mut output = Vec::new();
    let mut buf: u32 = 0;
    let mut bits: u32 = 0;
    for &byte in input.as_bytes() {
        if byte == b'=' { break; }
        if let Some(val) = table.iter().position(|&b| b == byte) {
            buf = (buf << 6) | val as u32;
            bits += 6;
            if bits >= 8 { bits -= 8; output.push((buf >> bits) as u8); buf &= (1 << bits) - 1; }
        }
    }
    output
}
