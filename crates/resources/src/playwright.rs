//! Full browser automation via Chrome DevTools Protocol.
//!
//! Uses chromiumoxide to control a headless Chrome/Chromium instance.
//! Supports: navigate, click, type, screenshot, extract text, wait for elements.

use std::sync::Arc;
use tokio::sync::Mutex;

/// Browser automation client.
pub struct BrowserAutomation {
    browser: Option<chromiumoxide::Browser>,
    page: Option<Arc<Mutex<chromiumoxide::Page>>>,
}

impl BrowserAutomation {
    /// Launch a headless browser.
    pub async fn launch() -> Result<Self, String> {
        let (browser, mut handler) = chromiumoxide::Browser::launch(
            chromiumoxide::BrowserConfig::builder()
                .no_sandbox()
                .arg("--headless=new")
                .build()
                .map_err(|e| format!("Browser config error: {}", e))?,
        ).await.map_err(|e| format!("Browser launch failed: {}. Is Chrome/Chromium installed?", e))?;

        // Spawn the handler in the background
        tokio::spawn(async move { while let Some(_) = handler.next().await {} });

        Ok(Self { browser: Some(browser), page: None })
    }

    /// Navigate to a URL.
    pub async fn navigate(&mut self, url: &str) -> Result<String, String> {
        let browser = self.browser.as_ref().ok_or("Browser not launched")?;
        let page = browser.new_page(url).await.map_err(|e| e.to_string())?;
        page.wait_for_navigation().await.map_err(|e| e.to_string())?;
        let title = page.get_title().await.map_err(|e| e.to_string())?.unwrap_or_default();
        self.page = Some(Arc::new(Mutex::new(page)));
        Ok(format!("Navigated to: {} (title: {})", url, title))
    }

    /// Get the page's text content.
    pub async fn get_text(&self) -> Result<String, String> {
        let page = self.page.as_ref().ok_or("No page open")?;
        let page = page.lock().await;
        let content = page.content().await.map_err(|e| e.to_string())?;
        // Strip HTML tags
        let text: String = content.split('<')
            .filter_map(|s| s.split('>').nth(1))
            .collect::<Vec<_>>().join(" ");
        let clean: String = text.split_whitespace().collect::<Vec<_>>().join(" ");
        Ok(clean.chars().take(8000).collect())
    }

    /// Click an element by CSS selector.
    pub async fn click(&self, selector: &str) -> Result<String, String> {
        let page = self.page.as_ref().ok_or("No page open")?;
        let page = page.lock().await;
        page.find_element(selector).await.map_err(|e| e.to_string())?
            .click().await.map_err(|e| e.to_string())?;
        Ok(format!("Clicked: {}", selector))
    }

    /// Type text into an element.
    pub async fn type_text(&self, selector: &str, text: &str) -> Result<String, String> {
        let page = self.page.as_ref().ok_or("No page open")?;
        let page = page.lock().await;
        page.find_element(selector).await.map_err(|e| e.to_string())?
            .type_str(text).await.map_err(|e| e.to_string())?;
        Ok(format!("Typed '{}' into {}", text, selector))
    }

    /// Take a screenshot and save to a file.
    pub async fn screenshot(&self, path: &str) -> Result<String, String> {
        let page = self.page.as_ref().ok_or("No page open")?;
        let page = page.lock().await;
        let bytes = page.screenshot(
            chromiumoxide::page::ScreenshotParams::builder().full_page(true).build()
        ).await.map_err(|e| e.to_string())?;
        std::fs::write(path, &bytes).map_err(|e| e.to_string())?;
        Ok(format!("Screenshot saved to {} ({} bytes)", path, bytes.len()))
    }

    /// Wait for an element to appear.
    pub async fn wait_for(&self, selector: &str) -> Result<String, String> {
        let page = self.page.as_ref().ok_or("No page open")?;
        let page = page.lock().await;
        page.find_element(selector).await.map_err(|e| format!("Element '{}' not found: {}", selector, e))?;
        Ok(format!("Found: {}", selector))
    }

    /// Get the current URL.
    pub async fn current_url(&self) -> Result<String, String> {
        let page = self.page.as_ref().ok_or("No page open")?;
        let page = page.lock().await;
        page.url().await.map_err(|e| e.to_string()).map(|u| u.map(|u| u.to_string()).unwrap_or_default())
    }
}

impl Drop for BrowserAutomation {
    fn drop(&mut self) {
        // Browser cleanup happens automatically via chromiumoxide
    }
}

use futures::StreamExt;
