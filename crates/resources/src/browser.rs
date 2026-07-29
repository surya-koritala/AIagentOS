//! Web browsing and research — fetch, parse, search, extract.

use reqwest::Client;
use scraper::{Html, Selector};

use futures::StreamExt;

const REQUEST_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(15);
const MAX_URL_BYTES: usize = 4 * 1024;
const MAX_QUERY_BYTES: usize = 2 * 1024;
const MAX_HTML_BYTES: usize = 4 * 1024 * 1024;
const MAX_CONTENT_CHARS: usize = 64 * 1024;
const MAX_SEARCH_RESULTS: usize = 50;
const MAX_TITLE_CHARS: usize = 512;
const MAX_LINK_TEXT_CHARS: usize = 120;
const MAX_SNIPPET_CHARS: usize = 2 * 1024;

/// Fetch a URL and extract readable text content.
pub async fn browse_url(url: &str, max_chars: usize) -> Result<BrowseResult, String> {
    validate_url(url)?;
    if max_chars > MAX_CONTENT_CHARS {
        return Err("browser output limit is invalid".into());
    }
    let client = trusted_web_client()?;
    let resp = client
        .get(url)
        .send()
        .await
        .map_err(|_| "browser request failed".to_string())?;
    let status = resp.status().as_u16();
    if !resp.status().is_success() {
        return Err(format!("browser returned HTTP status {status}"));
    }

    let html = bounded_utf8_body(resp, "browser response").await?;
    let document = Html::parse_document(&html);

    // Extract title
    let title = Selector::parse("title")
        .ok()
        .and_then(|sel| document.select(&sel).next())
        .map(|el| el.text().collect::<String>())
        .unwrap_or_default();

    // Remove script and style elements, extract text
    let body_sel = Selector::parse("body").expect("static body selector");

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
    let link_sel = Selector::parse("a[href]").expect("static link selector");
    let links: Vec<(String, String)> = document
        .select(&link_sel)
        .filter_map(|el| {
            let href = project_document_link(el.value().attr("href")?)?;
            let text = el.text().collect::<String>().trim().to_string();
            if text.is_empty() {
                return None;
            }
            Some((text.chars().take(MAX_LINK_TEXT_CHARS).collect(), href))
        })
        .take(20)
        .collect();

    Ok(BrowseResult {
        title: title.chars().take(MAX_TITLE_CHARS).collect(),
        content: truncated,
        links,
        url: redact_url(url),
        status,
    })
}

fn trusted_web_client() -> Result<Client, String> {
    Client::builder()
        .user_agent("Mozilla/5.0 (compatible; AIAgentOS/1.0)")
        .timeout(REQUEST_TIMEOUT)
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|_| "browser client configuration failed".into())
}

async fn bounded_utf8_body(
    response: reqwest::Response,
    label: &'static str,
) -> Result<String, String> {
    if response
        .content_length()
        .is_some_and(|length| length > MAX_HTML_BYTES as u64)
    {
        return Err(format!("{label} exceeds the byte limit"));
    }
    let mut bytes = Vec::new();
    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|_| format!("{label} read failed"))?;
        if bytes.len().saturating_add(chunk.len()) > MAX_HTML_BYTES {
            return Err(format!("{label} exceeds the byte limit"));
        }
        bytes.extend_from_slice(&chunk);
    }
    String::from_utf8(bytes).map_err(|_| format!("{label} is not strict UTF-8"))
}

/// Search the web using DuckDuckGo HTML.
pub async fn search_web(query: &str, max_results: usize) -> Result<Vec<SearchResult>, String> {
    validate_search_parameters(query, max_results)?;
    let client = trusted_web_client()?;

    let url = format!(
        "https://html.duckduckgo.com/html/?q={}",
        urlencoding::encode(query)
    );
    let resp = client
        .get(&url)
        .send()
        .await
        .map_err(|_| "browser search failed".to_string())?;
    if !resp.status().is_success() {
        return Err(format!(
            "browser search returned HTTP status {}",
            resp.status().as_u16()
        ));
    }
    let html = bounded_utf8_body(resp, "browser search response").await?;
    let document = Html::parse_document(&html);

    let result_sel = Selector::parse(".result").unwrap();
    let title_sel = Selector::parse(".result__title a").unwrap();
    let snippet_sel = Selector::parse(".result__snippet").unwrap();

    let results: Vec<SearchResult> = document
        .select(&result_sel)
        .filter_map(|el| {
            let title_el = el.select(&title_sel).next()?;
            let title: String = title_el
                .text()
                .collect::<String>()
                .trim()
                .chars()
                .take(MAX_TITLE_CHARS)
                .collect();
            let href = validate_search_result_url(title_el.value().attr("href")?)?;
            let snippet = el
                .select(&snippet_sel)
                .next()
                .map(|s| {
                    s.text()
                        .collect::<String>()
                        .trim()
                        .chars()
                        .take(MAX_SNIPPET_CHARS)
                        .collect()
                })
                .unwrap_or_default();
            Some(SearchResult {
                title,
                url: href,
                snippet,
            })
        })
        .take(max_results)
        .collect();

    Ok(results)
}

fn validate_search_parameters(query: &str, max_results: usize) -> Result<(), String> {
    if query.is_empty()
        || query.trim() != query
        || query.len() > MAX_QUERY_BYTES
        || query.contains('\0')
        || !(1..=MAX_SEARCH_RESULTS).contains(&max_results)
    {
        return Err("browser search parameters are invalid or too large".into());
    }
    Ok(())
}

/// Result from browsing a URL.
#[derive(Clone)]
pub struct BrowseResult {
    pub title: String,
    pub content: String,
    pub links: Vec<(String, String)>,
    pub url: String,
    pub status: u16,
}

/// A single search result.
#[derive(Clone)]
pub struct SearchResult {
    pub title: String,
    pub url: String,
    pub snippet: String,
}

impl std::fmt::Debug for BrowseResult {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("BrowseResult")
            .field("status", &self.status)
            .field("title_chars", &self.title.chars().count())
            .field("content_chars", &self.content.chars().count())
            .field("link_count", &self.links.len())
            .finish()
    }
}

impl std::fmt::Debug for SearchResult {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SearchResult")
            .field("title_chars", &self.title.chars().count())
            .field("snippet_chars", &self.snippet.chars().count())
            .finish()
    }
}

fn validate_url(value: &str) -> Result<(), String> {
    if value.len() > MAX_URL_BYTES || value.contains('\0') {
        return Err("browser URL is invalid or too large".into());
    }
    let parsed = reqwest::Url::parse(value).map_err(|_| "browser URL is invalid".to_string())?;
    if !matches!(parsed.scheme(), "http" | "https")
        || parsed.host_str().is_none()
        || !parsed.username().is_empty()
        || parsed.password().is_some()
    {
        return Err("browser URL must be HTTP(S) without embedded credentials".into());
    }
    Ok(())
}

fn redact_url(value: &str) -> String {
    let Ok(mut url) = reqwest::Url::parse(value) else {
        return "URL unavailable".into();
    };
    let _ = url.set_username("");
    let _ = url.set_password(None);
    url.set_query(None);
    url.set_fragment(None);
    url.to_string()
}

fn project_document_link(value: &str) -> Option<String> {
    if value.is_empty()
        || value.len() > MAX_URL_BYTES
        || value.contains('\0')
        || value.trim() != value
        || value.starts_with('#')
        || value.starts_with("//")
    {
        return None;
    }
    if let Ok(url) = reqwest::Url::parse(value) {
        if !matches!(url.scheme(), "http" | "https")
            || !url.username().is_empty()
            || url.password().is_some()
        {
            return None;
        }
        return Some(redact_url(value));
    }
    let path = value.split(['?', '#']).next().unwrap_or_default();
    (!path.is_empty()).then(|| path.to_string())
}

fn validate_search_result_url(value: &str) -> Option<String> {
    if value.is_empty()
        || value.len() > MAX_URL_BYTES
        || value.contains('\0')
        || value.trim() != value
    {
        return None;
    }
    let candidate = if value.starts_with("//") {
        format!("https:{value}")
    } else {
        value.to_string()
    };
    let parsed = reqwest::Url::parse(&candidate).ok()?;
    if !matches!(parsed.scheme(), "http" | "https")
        || parsed.host_str().is_none()
        || !parsed.username().is_empty()
        || parsed.password().is_some()
    {
        return None;
    }
    Some(candidate)
}

impl BrowseResult {
    /// Format as a string for the LLM.
    pub fn to_tool_output(&self) -> String {
        let mut out = format!(
            "Title: {}\nURL: {}\n\nContent:\n{}",
            self.title, self.url, self.content
        );
        if !self.links.is_empty() {
            out.push_str("\n\nLinks:\n");
            for (text, href) in self.links.iter().take(10) {
                out.push_str(&format!("- {} ({})\n", text, href));
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[test]
    fn trusted_web_inputs_and_debug_output_do_not_expose_secrets() {
        assert!(validate_url("https://example.invalid/path?token=private").is_ok());
        assert!(validate_url("file:///etc/passwd").is_err());
        assert!(validate_url("https://user:private@example.invalid").is_err());
        assert_eq!(
            redact_url("https://user:private@example.invalid/path?token=private#secret"),
            "https://example.invalid/path"
        );
        assert!(validate_search_parameters("", 1).is_err());
        assert!(validate_search_parameters("query", 0).is_err());
        assert!(validate_search_parameters("query", MAX_SEARCH_RESULTS + 1).is_err());
        assert_eq!(
            project_document_link("https://example.invalid/path?token=private#fragment"),
            Some("https://example.invalid/path".into())
        );
        assert_eq!(
            project_document_link("/relative/path?token=private#fragment"),
            Some("/relative/path".into())
        );
        assert!(project_document_link("JaVaScRiPt:alert(1)").is_none());
        assert!(project_document_link("//example.invalid/private").is_none());
        assert!(validate_search_result_url("https://example.invalid/result?q=value").is_some());
        assert!(validate_search_result_url("https://user:secret@example.invalid").is_none());

        let result = BrowseResult {
            title: "private-title".into(),
            content: "private-content".into(),
            links: vec![("private-link".into(), "https://secret.invalid".into())],
            url: "https://secret.invalid".into(),
            status: 200,
        };
        let debug = format!("{result:?}");
        for secret in [
            "private-title",
            "private-content",
            "private-link",
            "secret.invalid",
        ] {
            assert!(!debug.contains(secret));
        }
    }

    #[tokio::test]
    async fn trusted_web_fetch_is_bounded_strict_and_does_not_follow_redirects() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    break;
                };
                tokio::spawn(async move {
                    let mut request = vec![0_u8; 8 * 1024];
                    let Ok(length) = stream.read(&mut request).await else {
                        return;
                    };
                    let request = String::from_utf8_lossy(&request[..length]);
                    let (status, headers, body) = if request.starts_with("GET /redirect ") {
                        (
                            "302 Found",
                            "Location: /ok\r\nContent-Type: text/plain\r\n",
                            Vec::new(),
                        )
                    } else if request.starts_with("GET /large ") {
                        (
                            "200 OK",
                            "Content-Type: text/html\r\nContent-Length: 4194305\r\n",
                            Vec::new(),
                        )
                    } else if request.starts_with("GET /invalid ") {
                        (
                            "200 OK",
                            "Content-Type: text/html\r\nContent-Length: 2\r\n",
                            vec![0xff, 0xfe],
                        )
                    } else {
                        let body =
                            b"<!doctype html><title>fixture</title><body>bounded result</body>"
                                .to_vec();
                        ("200 OK", "Content-Type: text/html; charset=utf-8\r\n", body)
                    };
                    let content_length = if headers.contains("Content-Length:") {
                        String::new()
                    } else {
                        format!("Content-Length: {}\r\n", body.len())
                    };
                    let head = format!(
                        "HTTP/1.1 {status}\r\n{headers}{content_length}Connection: close\r\n\r\n"
                    );
                    let _ = stream.write_all(head.as_bytes()).await;
                    let _ = stream.write_all(&body).await;
                });
            }
        });

        let result = browse_url(
            &format!("http://{address}/ok?token=must-not-return"),
            MAX_CONTENT_CHARS,
        )
        .await
        .unwrap();
        assert_eq!(result.title, "fixture");
        assert_eq!(result.content, "bounded result");
        assert_eq!(result.url, format!("http://{address}/ok"));

        let redirect = browse_url(&format!("http://{address}/redirect"), 100)
            .await
            .unwrap_err();
        assert_eq!(redirect, "browser returned HTTP status 302");
        assert!(browse_url(&format!("http://{address}/large"), 100)
            .await
            .unwrap_err()
            .contains("byte limit"));
        assert!(browse_url(&format!("http://{address}/invalid"), 100)
            .await
            .unwrap_err()
            .contains("strict UTF-8"));
        assert_eq!(
            browse_url(&format!("http://{address}/ok"), MAX_CONTENT_CHARS + 1)
                .await
                .unwrap_err(),
            "browser output limit is invalid"
        );
        server.abort();
    }
}
