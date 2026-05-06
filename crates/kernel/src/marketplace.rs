//! Plugin marketplace — discover, rate, and install community plugins.

use std::collections::HashMap;
use serde::{Deserialize, Serialize};

/// A plugin listing in the marketplace.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginListing {
    pub id: String,
    pub name: String,
    pub description: String,
    pub author: String,
    pub version: String,
    pub downloads: u64,
    pub rating: f32, // 0.0 - 5.0
    pub ratings_count: u32,
    pub tags: Vec<String>,
    pub published_at: String,
}

/// A user review.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Review {
    pub user_id: String,
    pub plugin_id: String,
    pub rating: u8, // 1-5
    pub comment: String,
    pub created_at: String,
}

/// The marketplace.
pub struct Marketplace {
    plugins: HashMap<String, PluginListing>,
    reviews: Vec<Review>,
}

impl Marketplace {
    pub fn new() -> Self { Self { plugins: HashMap::new(), reviews: Vec::new() } }

    /// Publish a plugin.
    pub fn publish(&mut self, name: String, description: String, author: String, version: String, tags: Vec<String>) -> String {
        let id = uuid::Uuid::new_v4().to_string();
        self.plugins.insert(id.clone(), PluginListing {
            id: id.clone(), name, description, author, version,
            downloads: 0, rating: 0.0, ratings_count: 0, tags,
            published_at: chrono::Utc::now().to_rfc3339(),
        });
        id
    }

    /// Search plugins by query.
    pub fn search(&self, query: &str) -> Vec<&PluginListing> {
        let q = query.to_lowercase();
        self.plugins.values()
            .filter(|p| p.name.to_lowercase().contains(&q) || p.description.to_lowercase().contains(&q) || p.tags.iter().any(|t| t.to_lowercase().contains(&q)))
            .collect()
    }

    /// Get top-rated plugins.
    pub fn top_rated(&self, limit: usize) -> Vec<&PluginListing> {
        let mut sorted: Vec<_> = self.plugins.values().collect();
        sorted.sort_by(|a, b| b.rating.partial_cmp(&a.rating).unwrap_or(std::cmp::Ordering::Equal));
        sorted.into_iter().take(limit).collect()
    }

    /// Record a download.
    pub fn record_download(&mut self, plugin_id: &str) {
        if let Some(p) = self.plugins.get_mut(plugin_id) { p.downloads += 1; }
    }

    /// Add a review.
    pub fn add_review(&mut self, plugin_id: &str, user_id: String, rating: u8, comment: String) {
        let review = Review { user_id, plugin_id: plugin_id.into(), rating: rating.clamp(1, 5), comment, created_at: chrono::Utc::now().to_rfc3339() };
        self.reviews.push(review);
        // Update average rating
        if let Some(p) = self.plugins.get_mut(plugin_id) {
            let plugin_reviews: Vec<_> = self.reviews.iter().filter(|r| r.plugin_id == plugin_id).collect();
            let sum: u32 = plugin_reviews.iter().map(|r| r.rating as u32).sum();
            p.ratings_count = plugin_reviews.len() as u32;
            p.rating = sum as f32 / p.ratings_count as f32;
        }
    }

    /// Get plugin by ID.
    pub fn get(&self, id: &str) -> Option<&PluginListing> { self.plugins.get(id) }

    /// Count plugins.
    pub fn count(&self) -> usize { self.plugins.len() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn publish_and_search() {
        let mut mp = Marketplace::new();
        mp.publish("code-reviewer".into(), "Reviews code for bugs".into(), "alice".into(), "1.0.0".into(), vec!["code".into()]);
        mp.publish("web-scraper".into(), "Scrapes websites".into(), "bob".into(), "2.0.0".into(), vec!["web".into()]);
        let results = mp.search("code");
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].name, "code-reviewer");
    }

    #[test]
    fn ratings() {
        let mut mp = Marketplace::new();
        let id = mp.publish("test".into(), "test".into(), "x".into(), "1.0".into(), vec![]);
        mp.add_review(&id, "u1".into(), 5, "great".into());
        mp.add_review(&id, "u2".into(), 3, "ok".into());
        let plugin = mp.get(&id).unwrap();
        assert_eq!(plugin.rating, 4.0); // (5+3)/2
        assert_eq!(plugin.ratings_count, 2);
    }

    #[test]
    fn downloads() {
        let mut mp = Marketplace::new();
        let id = mp.publish("pkg".into(), "d".into(), "a".into(), "1.0".into(), vec![]);
        mp.record_download(&id);
        mp.record_download(&id);
        assert_eq!(mp.get(&id).unwrap().downloads, 2);
    }
}
