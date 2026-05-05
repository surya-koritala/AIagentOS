//! Web browsing and research — fetch, parse, search, extract.

use reqwest::Client;
use scraper::{Html, Selector};

/// Fetch a URL and extract readable text content.
pub async fn browse_url(url: &str, max_chars: usize) -> Result<BrowseResult, String> {
    let client = Client::builder()
        .user_agent("Mozilla/5.0 (compatible; AIAgentOS/1.0)")
        .timeout(std::time::Duration::from_secs(15))
        .build()
        .map_err(|e| e.to_string())?;

    let resp = client.get(url).send().await.map_err(|e| format!("Fetch failed: {}", e))?;
    let status = resp.status().as_u16();
    if status >= 400 {
        return Err(format!("HTTP {}", status));
    }

    let html = resp.text().await.map_err(|e| format!("Read failed: {}", e))?;
    let document = Html::parse_document(&html);

    // Extract title
    let title = Selector::parse("title").ok()
        .and_then(|sel| document.select(&sel).next())
        .map(|el| el.text().collect::<String>())
        .unwrap_or_default();

    // Remove script and style elements, extract text
    let body_sel = Selector::parse("body").unwrap();
    let script_sel = Selector::parse("script, style, nav, footer, header").unwrap();

    let mut text = String::new();
    if let Some(body) = document.select(&body_sel).next() {
        for node in body.text() {
            let trimmed = node.trim();
            if !trimmed.is_empty() {
                text.push_str(trimmed);
                text.push(' ');
            }
        }
    }

    // Clean up whitespace
    let clean: String = text.split_whitespace().collect::<Vec<_>>().join(" ");
    let truncated: String = clean.chars().take(max_chars).collect();

    // Extract links
    let link_sel = Selector::parse("a[href]").unwrap();
    let links: Vec<(String, String)> = document.select(&link_sel)
        .filter_map(|el| {
            let href = el.value().attr("href")?.to_string();
            let text = el.text().collect::<String>().trim().to_string();
            if text.is_empty() || href.starts_with('#') || href.starts_with("javascript:") { return None; }
            Some((text.chars().take(60).collect(), href))
        })
        .take(20)
        .collect();

    Ok(BrowseResult { title, content: truncated, links, url: url.to_string(), status })
}

/// Search the web using DuckDuckGo HTML.
pub async fn search_web(query: &str, max_results: usize) -> Result<Vec<SearchResult>, String> {
    let client = Client::builder()
        .user_agent("Mozilla/5.0 (compatible; AIAgentOS/1.0)")
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .map_err(|e| e.to_string())?;

    let url = format!("https://html.duckduckgo.com/html/?q={}", urlencoding::encode(query));
    let resp = client.get(&url).send().await.map_err(|e| format!("Search failed: {}", e))?;
    let html = resp.text().await.map_err(|e| e.to_string())?;
    let document = Html::parse_document(&html);

    let result_sel = Selector::parse(".result").unwrap();
    let title_sel = Selector::parse(".result__title a").unwrap();
    let snippet_sel = Selector::parse(".result__snippet").unwrap();

    let results: Vec<SearchResult> = document.select(&result_sel)
        .filter_map(|el| {
            let title_el = el.select(&title_sel).next()?;
            let title = title_el.text().collect::<String>().trim().to_string();
            let href = title_el.value().attr("href")?.to_string();
            let snippet = el.select(&snippet_sel).next()
                .map(|s| s.text().collect::<String>().trim().to_string())
                .unwrap_or_default();
            Some(SearchResult { title, url: href, snippet })
        })
        .take(max_results)
        .collect();

    Ok(results)
}

/// Result from browsing a URL.
#[derive(Debug, Clone)]
pub struct BrowseResult {
    pub title: String,
    pub content: String,
    pub links: Vec<(String, String)>,
    pub url: String,
    pub status: u16,
}

/// A single search result.
#[derive(Debug, Clone)]
pub struct SearchResult {
    pub title: String,
    pub url: String,
    pub snippet: String,
}

impl BrowseResult {
    /// Format as a string for the LLM.
    pub fn to_tool_output(&self) -> String {
        let mut out = format!("Title: {}\nURL: {}\n\nContent:\n{}", self.title, self.url, self.content);
        if !self.links.is_empty() {
            out.push_str("\n\nLinks:\n");
            for (text, href) in self.links.iter().take(10) {
                out.push_str(&format!("- {} ({})\n", text, href));
            }
        }
        out
    }
}
