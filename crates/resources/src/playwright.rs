//! Feature-gated trusted-process browser automation.
//!
//! This helper is not a kernel [`ResourceProvider`](kernel::resources::ResourceProvider)
//! and must never be registered for untrusted agents. Each launch owns a fresh
//! private Chromium profile, denies downloads through CDP, verifies HTTPS,
//! applies deterministic deadlines, returns bounded data, and redacts
//! caller/page details from failures. The kernel browser provider remains
//! unavailable until its separate egress and live security qualification is
//! complete.

use std::future::Future;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use chromiumoxide::browser::{Browser, BrowserConfig};
use chromiumoxide::cdp::browser_protocol::browser::{
    SetDownloadBehaviorBehavior, SetDownloadBehaviorParams,
};
use chromiumoxide::page::ScreenshotParams;
use chromiumoxide::Page;
use futures::StreamExt;
use tempfile::TempDir;
use tokio::sync::Mutex;
use tokio::task::JoinHandle;

const LAUNCH_TIMEOUT: Duration = Duration::from_secs(20);
const OPERATION_TIMEOUT: Duration = Duration::from_secs(15);
const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_URL_BYTES: usize = 4 * 1024;
const MAX_SELECTOR_BYTES: usize = 4 * 1024;
const MAX_INPUT_BYTES: usize = 64 * 1024;
const MAX_TEXT_CHARS: usize = 64 * 1024;
const MAX_TITLE_CHARS: usize = 512;
const MAX_SCREENSHOT_BYTES: usize = 8 * 1024 * 1024;

/// Configuration for a trusted-process browser launch.
#[derive(Clone, Default)]
pub struct BrowserAutomationConfig {
    chrome_executable: Option<PathBuf>,
}

impl std::fmt::Debug for BrowserAutomationConfig {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("BrowserAutomationConfig")
            .field(
                "chrome_executable_configured",
                &self.chrome_executable.is_some(),
            )
            .finish()
    }
}

impl BrowserAutomationConfig {
    /// Pin the Chromium executable instead of using platform detection.
    pub fn with_chrome_executable(mut self, executable: impl Into<PathBuf>) -> Self {
        self.chrome_executable = Some(executable.into());
        self
    }
}

/// Browser automation client with one isolated profile and bounded lifetime.
pub struct BrowserAutomation {
    // Field order is intentional: Chromium and its handler are dropped before
    // the profile directory if a caller forgets explicit shutdown.
    browser: Option<Browser>,
    page: Option<Arc<Mutex<Page>>>,
    handler: Option<JoinHandle<()>>,
    profile: Option<TempDir>,
}

impl BrowserAutomation {
    /// Launch a headless browser with the fixed security contract.
    pub async fn launch() -> Result<Self, String> {
        Self::launch_with_config(BrowserAutomationConfig::default()).await
    }

    /// Launch with an optional pinned Chromium executable.
    pub async fn launch_with_config(config: BrowserAutomationConfig) -> Result<Self, String> {
        let profile = create_isolated_profile()?;
        let mut builder = BrowserConfig::builder()
            .new_headless_mode()
            .respect_https_errors()
            .disable_cache()
            .user_data_dir(profile.path())
            .launch_timeout(LAUNCH_TIMEOUT)
            .request_timeout(OPERATION_TIMEOUT)
            .args([
                "--disable-component-update",
                "--disable-domain-reliability",
                "--disable-features=AutofillServerCommunication,OptimizationHints,MediaRouter",
                "--disable-notifications",
                "--disable-search-engine-choice-screen",
                "--no-service-autorun",
            ]);
        if let Some(executable) = config.chrome_executable {
            builder = builder.chrome_executable(executable);
        }
        let browser_config = builder
            .build()
            .map_err(|_| "browser configuration failed".to_string())?;

        let (mut browser, mut handler) = bounded(
            "browser launch",
            Browser::launch(browser_config),
            LAUNCH_TIMEOUT,
        )
        .await?;
        let handler_task = tokio::spawn(async move {
            while let Some(result) = handler.next().await {
                if result.is_err() {
                    break;
                }
            }
        });

        if bounded(
            "download policy",
            browser.execute(SetDownloadBehaviorParams::new(
                SetDownloadBehaviorBehavior::Deny,
            )),
            OPERATION_TIMEOUT,
        )
        .await
        .is_err()
        {
            let _ = tokio::time::timeout(SHUTDOWN_TIMEOUT, browser.close()).await;
            let _ = tokio::time::timeout(SHUTDOWN_TIMEOUT, browser.wait()).await;
            handler_task.abort();
            return Err("browser download policy failed".into());
        }

        Ok(Self {
            browser: Some(browser),
            page: None,
            handler: Some(handler_task),
            profile: Some(profile),
        })
    }

    /// Navigate to a bounded HTTP(S) URL without echoing it into errors.
    pub async fn navigate(&mut self, url: &str) -> Result<String, String> {
        validate_navigation_url(url)?;
        let browser = self.browser.as_ref().ok_or("browser is closed")?;
        let page = bounded(
            "browser navigation",
            browser.new_page(url),
            OPERATION_TIMEOUT,
        )
        .await?;
        bounded(
            "browser navigation",
            page.wait_for_navigation(),
            OPERATION_TIMEOUT,
        )
        .await?;
        let title = bounded("browser title read", page.get_title(), OPERATION_TIMEOUT)
            .await?
            .unwrap_or_default();
        self.page = Some(Arc::new(Mutex::new(page)));
        Ok(format!(
            "Navigation complete (title: {})",
            bounded_public_text(&title, MAX_TITLE_CHARS)
        ))
    }

    /// Get bounded text from the current page.
    pub async fn get_text(&self) -> Result<String, String> {
        let page = self.page.as_ref().ok_or("no page is open")?;
        let text = bounded(
            "browser text read",
            async {
                let page = page.lock().await;
                let evaluated = page
                    .evaluate(
                        "(() => { const text = document.body ? document.body.innerText : ''; \
                         return text.slice(0, 65537); })()",
                    )
                    .await
                    .map_err(|_| ())?;
                evaluated.into_value::<String>().map_err(|_| ())
            },
            OPERATION_TIMEOUT,
        )
        .await?;
        Ok(bounded_public_text(&text, MAX_TEXT_CHARS))
    }

    /// Click an element selected by a bounded CSS selector.
    pub async fn click(&self, selector: &str) -> Result<String, String> {
        validate_selector(selector)?;
        let page = self.page.as_ref().ok_or("no page is open")?;
        bounded(
            "browser click",
            async {
                let page = page.lock().await;
                let element = page.find_element(selector).await?;
                element.click().await?;
                Ok::<_, chromiumoxide::error::CdpError>(())
            },
            OPERATION_TIMEOUT,
        )
        .await?;
        Ok("Element clicked".into())
    }

    /// Enter bounded text without returning or logging the text or selector.
    pub async fn type_text(&self, selector: &str, text: &str) -> Result<String, String> {
        validate_selector(selector)?;
        if text.len() > MAX_INPUT_BYTES || text.contains('\0') {
            return Err("browser input is invalid or too large".into());
        }
        let page = self.page.as_ref().ok_or("no page is open")?;
        bounded(
            "browser text entry",
            async {
                let page = page.lock().await;
                let element = page.find_element(selector).await?;
                element.type_str(text).await?;
                Ok::<_, chromiumoxide::error::CdpError>(())
            },
            OPERATION_TIMEOUT,
        )
        .await?;
        Ok("Text entered".into())
    }

    /// Capture the visible viewport as bounded PNG bytes.
    ///
    /// Returning bytes avoids an ambient caller-controlled filesystem path.
    pub async fn screenshot_png(&self) -> Result<Vec<u8>, String> {
        let page = self.page.as_ref().ok_or("no page is open")?;
        let bytes = bounded(
            "browser screenshot",
            async {
                let page = page.lock().await;
                page.screenshot(ScreenshotParams::builder().full_page(false).build())
                    .await
            },
            OPERATION_TIMEOUT,
        )
        .await?;
        if bytes.len() > MAX_SCREENSHOT_BYTES {
            return Err("browser screenshot exceeds the output limit".into());
        }
        Ok(bytes)
    }

    /// Wait a bounded time for a bounded selector.
    pub async fn wait_for(&self, selector: &str) -> Result<String, String> {
        validate_selector(selector)?;
        let page = self.page.as_ref().ok_or("no page is open")?;
        bounded(
            "browser element wait",
            async {
                let page = page.lock().await;
                page.find_element(selector).await.map(|_| ())
            },
            OPERATION_TIMEOUT,
        )
        .await?;
        Ok("Element found".into())
    }

    /// Return the current URL without credentials, query data, or fragments.
    pub async fn current_url(&self) -> Result<String, String> {
        let page = self.page.as_ref().ok_or("no page is open")?;
        let current = bounded(
            "browser URL read",
            async {
                let page = page.lock().await;
                page.url().await
            },
            OPERATION_TIMEOUT,
        )
        .await?
        .ok_or_else(|| "browser URL is unavailable".to_string())?;
        Ok(redact_url(&current.to_string()))
    }

    /// Close Chromium, reap its process, and remove the isolated profile.
    pub async fn shutdown(mut self) -> Result<(), String> {
        self.page.take();
        let mut outcome = Ok(());
        if let Some(mut browser) = self.browser.take() {
            match tokio::time::timeout(SHUTDOWN_TIMEOUT, browser.close()).await {
                Ok(Ok(_)) => {}
                Ok(Err(_)) => outcome = Err("browser shutdown failed".into()),
                Err(_) => outcome = Err("browser shutdown timed out".into()),
            }
            match tokio::time::timeout(SHUTDOWN_TIMEOUT, browser.wait()).await {
                Ok(Ok(_)) => {}
                Ok(Err(_)) => outcome = Err("browser process cleanup failed".into()),
                Err(_) => outcome = Err("browser process cleanup timed out".into()),
            }
            drop(browser);
        }
        if let Some(handler) = self.handler.take() {
            handler.abort();
            let _ = handler.await;
        }
        if let Some(profile) = self.profile.take() {
            if profile.close().is_err() {
                outcome = Err("browser profile cleanup failed".into());
            }
        }
        outcome
    }
}

impl Drop for BrowserAutomation {
    fn drop(&mut self) {
        if let Some(handler) = self.handler.take() {
            handler.abort();
        }
        self.page.take();
        self.browser.take();
        if let Some(profile) = self.profile.take() {
            let _ = profile.close();
        }
    }
}

async fn bounded<T, E>(
    operation: &'static str,
    future: impl Future<Output = Result<T, E>>,
    timeout: Duration,
) -> Result<T, String> {
    match tokio::time::timeout(timeout, future).await {
        Ok(Ok(value)) => Ok(value),
        Ok(Err(_)) => Err(format!("{operation} failed")),
        Err(_) => Err(format!("{operation} timed out")),
    }
}

fn create_isolated_profile() -> Result<TempDir, String> {
    let profile = tempfile::Builder::new()
        .prefix("agentos-browser-")
        .tempdir()
        .map_err(|_| "browser profile creation failed".to_string())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(profile.path(), std::fs::Permissions::from_mode(0o700))
            .map_err(|_| "browser profile permission hardening failed".to_string())?;
    }
    Ok(profile)
}

fn validate_navigation_url(value: &str) -> Result<(), String> {
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

fn validate_selector(value: &str) -> Result<(), String> {
    if value.is_empty()
        || value.len() > MAX_SELECTOR_BYTES
        || value.contains('\0')
        || value.trim() != value
    {
        return Err("browser selector is invalid or too large".into());
    }
    Ok(())
}

fn bounded_public_text(value: &str, max_chars: usize) -> String {
    value
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .chars()
        .take(max_chars)
        .collect()
}

fn redact_url(value: &str) -> String {
    let Ok(mut url) = reqwest::Url::parse(value) else {
        return "URL unavailable".into();
    };
    if !url.username().is_empty() {
        let _ = url.set_username("");
    }
    let _ = url.set_password(None);
    url.set_query(None);
    url.set_fragment(None);
    url.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[test]
    fn navigation_and_selector_inputs_are_bounded_and_credential_free() {
        assert!(validate_navigation_url("https://example.invalid/path?q=value").is_ok());
        assert!(validate_navigation_url("file:///etc/passwd").is_err());
        assert!(validate_navigation_url("https://user:secret@example.invalid").is_err());
        assert!(validate_navigation_url(&format!(
            "https://example.invalid/{}",
            "a".repeat(MAX_URL_BYTES)
        ))
        .is_err());
        assert!(validate_selector("#submit").is_ok());
        assert!(validate_selector(" #submit").is_err());
        assert!(validate_selector("button\0shadow").is_err());
    }

    #[test]
    fn current_url_projection_removes_credentials_query_and_fragment() {
        assert_eq!(
            redact_url("https://user:secret@example.invalid/path?token=secret#private"),
            "https://example.invalid/path"
        );
        assert_eq!(redact_url("not a url"), "URL unavailable");
    }

    #[test]
    fn isolated_profiles_are_private_unique_and_removed_on_drop() {
        let first = create_isolated_profile().unwrap();
        let second = create_isolated_profile().unwrap();
        assert_ne!(first.path(), second.path());
        let first_path = first.path().to_path_buf();
        assert!(first_path.exists());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&first_path).unwrap().permissions().mode() & 0o077,
                0
            );
        }
        drop(first);
        assert!(!first_path.exists());
    }

    #[tokio::test]
    async fn bounded_errors_do_not_include_underlying_secrets() {
        let error = bounded(
            "browser text entry",
            async { Err::<(), _>("typed-secret-value") },
            Duration::from_millis(10),
        )
        .await
        .unwrap_err();
        assert_eq!(error, "browser text entry failed");
        assert!(!error.contains("typed-secret-value"));

        let timeout = bounded(
            "browser operation",
            async {
                tokio::time::sleep(Duration::from_millis(20)).await;
                Ok::<_, String>(())
            },
            Duration::from_millis(1),
        )
        .await
        .unwrap_err();
        assert_eq!(timeout, "browser operation timed out");
    }

    #[tokio::test]
    #[ignore = "requires AGENTOS_TEST_CHROME and permission to launch a disposable browser"]
    async fn live_browser_denies_downloads_and_removes_its_isolated_profile() {
        let executable = std::env::var_os("AGENTOS_TEST_CHROME")
            .map(PathBuf::from)
            .expect("AGENTOS_TEST_CHROME must point to a disposable Chromium binary");
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let download_requests = Arc::new(AtomicUsize::new(0));
        let server_requests = Arc::clone(&download_requests);
        let server = tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    break;
                };
                let requests = Arc::clone(&server_requests);
                tokio::spawn(async move {
                    let mut buffer = vec![0_u8; 8 * 1024];
                    let Ok(length) = stream.read(&mut buffer).await else {
                        return;
                    };
                    let request = String::from_utf8_lossy(&buffer[..length]);
                    let download = request.starts_with("GET /download ");
                    let (headers, body) = if download {
                        requests.fetch_add(1, Ordering::SeqCst);
                        (
                            "Content-Type: application/octet-stream\r\n\
                             Content-Disposition: attachment; filename=\"forbidden.bin\"\r\n",
                            "download-must-not-land",
                        )
                    } else {
                        (
                            "Content-Type: text/html; charset=utf-8\r\n",
                            "<!doctype html><title>Isolated test</title>\
                             <body>isolated browser\
                             <input id=\"secret\"><a id=\"download\" href=\"/download\" \
                             download>download</a></body>",
                        )
                    };
                    let response = format!(
                        "HTTP/1.1 200 OK\r\n{headers}Content-Length: {}\r\n\
                         Connection: close\r\n\r\n{body}",
                        body.len()
                    );
                    let _ = stream.write_all(response.as_bytes()).await;
                });
            }
        });

        let mut browser = BrowserAutomation::launch_with_config(
            BrowserAutomationConfig::default().with_chrome_executable(executable),
        )
        .await
        .unwrap();
        let profile_path = browser.profile.as_ref().unwrap().path().to_path_buf();
        browser
            .navigate(&format!("http://{address}/?token=private"))
            .await
            .unwrap();
        assert_eq!(
            browser.current_url().await.unwrap(),
            format!("http://{address}/")
        );
        let text = browser.get_text().await.unwrap();
        assert!(text.contains("isolated browser"));
        assert!(text.contains("download"));
        assert_eq!(
            browser
                .type_text("#secret", "typed-secret-value")
                .await
                .unwrap(),
            "Text entered"
        );
        assert!(!browser
            .type_text("#missing", "typed-secret-value")
            .await
            .unwrap_err()
            .contains("typed-secret-value"));
        let png = browser.screenshot_png().await.unwrap();
        assert!(png.starts_with(b"\x89PNG\r\n\x1a\n"));
        browser.click("#download").await.unwrap();
        tokio::time::sleep(Duration::from_millis(500)).await;
        assert!(download_requests.load(Ordering::SeqCst) <= 1);
        assert!(!profile_contains_name(&profile_path, "forbidden.bin"));
        browser.shutdown().await.unwrap();
        assert!(!profile_path.exists());
        server.abort();
    }

    fn profile_contains_name(root: &Path, target: &str) -> bool {
        let Ok(entries) = std::fs::read_dir(root) else {
            return false;
        };
        entries.flatten().any(|entry| {
            let path = entry.path();
            entry.file_name() == target || (path.is_dir() && profile_contains_name(&path, target))
        })
    }
}
