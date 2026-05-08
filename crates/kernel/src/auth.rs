//! Multi-user authentication — OAuth2, sessions, RBAC.

use chrono::{DateTime, Duration, Utc};
use std::collections::HashMap;

/// User account.
#[derive(Debug, Clone)]
pub struct User {
    pub id: String,
    pub username: String,
    pub email: String,
    pub role: Role,
    pub created_at: DateTime<Utc>,
    pub api_keys: Vec<ApiKey>,
}

/// User roles.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Admin,
    User,
    ReadOnly,
}

/// API key for programmatic access.
#[derive(Debug, Clone)]
pub struct ApiKey {
    pub key: String,
    pub name: String,
    pub created_at: DateTime<Utc>,
    pub last_used: Option<DateTime<Utc>>,
}

/// Session token.
#[derive(Debug, Clone)]
pub struct Session {
    pub token: String,
    pub user_id: String,
    pub expires_at: DateTime<Utc>,
}

/// Authentication system.
pub struct AuthSystem {
    users: HashMap<String, User>,
    sessions: HashMap<String, Session>,
    api_keys: HashMap<String, String>, // key → user_id
}

impl AuthSystem {
    pub fn new() -> Self {
        Self {
            users: HashMap::new(),
            sessions: HashMap::new(),
            api_keys: HashMap::new(),
        }
    }

    /// Register a new user.
    pub fn register(&mut self, username: String, email: String, role: Role) -> String {
        let id = uuid::Uuid::new_v4().to_string();
        self.users.insert(
            id.clone(),
            User {
                id: id.clone(),
                username,
                email,
                role,
                created_at: Utc::now(),
                api_keys: Vec::new(),
            },
        );
        id
    }

    /// Create a session (login).
    pub fn create_session(&mut self, user_id: &str) -> Option<String> {
        if !self.users.contains_key(user_id) {
            return None;
        }
        let token = uuid::Uuid::new_v4().to_string();
        self.sessions.insert(
            token.clone(),
            Session {
                token: token.clone(),
                user_id: user_id.into(),
                expires_at: Utc::now() + Duration::hours(24),
            },
        );
        Some(token)
    }

    /// Validate a session token.
    pub fn validate_session(&self, token: &str) -> Option<&str> {
        let session = self.sessions.get(token)?;
        if Utc::now() > session.expires_at {
            return None;
        }
        Some(&session.user_id)
    }

    /// Generate an API key for a user.
    pub fn create_api_key(&mut self, user_id: &str, name: String) -> Option<String> {
        let key = format!("ak_{}", uuid::Uuid::new_v4().to_string().replace('-', ""));
        self.api_keys.insert(key.clone(), user_id.into());
        if let Some(user) = self.users.get_mut(user_id) {
            user.api_keys.push(ApiKey {
                key: key.clone(),
                name,
                created_at: Utc::now(),
                last_used: None,
            });
        }
        Some(key)
    }

    /// Validate an API key.
    pub fn validate_api_key(&self, key: &str) -> Option<&str> {
        self.api_keys.get(key).map(|s| s.as_str())
    }

    /// Check if user has required role.
    pub fn check_role(&self, user_id: &str, required: Role) -> bool {
        self.users
            .get(user_id)
            .map(|u| match (u.role, required) {
                (Role::Admin, _) => true,
                (Role::User, Role::User | Role::ReadOnly) => true,
                (Role::ReadOnly, Role::ReadOnly) => true,
                _ => false,
            })
            .unwrap_or(false)
    }

    /// Get user by ID.
    pub fn get_user(&self, id: &str) -> Option<&User> {
        self.users.get(id)
    }

    /// List all users.
    pub fn list_users(&self) -> Vec<&User> {
        self.users.values().collect()
    }

    /// Revoke a session.
    pub fn revoke_session(&mut self, token: &str) {
        self.sessions.remove(token);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn register_and_login() {
        let mut auth = AuthSystem::new();
        let uid = auth.register("alice".into(), "alice@test.com".into(), Role::User);
        let token = auth.create_session(&uid).unwrap();
        assert_eq!(auth.validate_session(&token), Some(uid.as_str()));
    }

    #[test]
    fn invalid_session() {
        let auth = AuthSystem::new();
        assert!(auth.validate_session("fake-token").is_none());
    }

    #[test]
    fn api_key_auth() {
        let mut auth = AuthSystem::new();
        let uid = auth.register("bot".into(), "bot@test.com".into(), Role::User);
        let key = auth.create_api_key(&uid, "ci-key".into()).unwrap();
        assert_eq!(auth.validate_api_key(&key), Some(uid.as_str()));
    }

    #[test]
    fn role_check() {
        let mut auth = AuthSystem::new();
        let admin = auth.register("admin".into(), "a@t.com".into(), Role::Admin);
        let user = auth.register("user".into(), "u@t.com".into(), Role::User);
        let reader = auth.register("reader".into(), "r@t.com".into(), Role::ReadOnly);
        assert!(auth.check_role(&admin, Role::Admin));
        assert!(!auth.check_role(&user, Role::Admin));
        assert!(auth.check_role(&user, Role::User));
        assert!(!auth.check_role(&reader, Role::User));
    }

    #[test]
    fn revoke_session() {
        let mut auth = AuthSystem::new();
        let uid = auth.register("x".into(), "x@t.com".into(), Role::User);
        let token = auth.create_session(&uid).unwrap();
        auth.revoke_session(&token);
        assert!(auth.validate_session(&token).is_none());
    }
}
