//! Multi-tenant authentication — tenants, users, sessions, API keys, RBAC.
//!
//! Tenancy is the **top-level isolation unit** and rides on the OS primitives the
//! kernel already enforces. The `AuthSystem` here owns only identity + scoping:
//! it resolves an API key / session token to a `(user_id, tenant_id, role)` and
//! tells the kernel which tenant a connection acts on behalf of. The kernel then
//! maps that tenant onto a **namespace group** (so agents/tools/IPC in different
//! tenants are invisible to each other at the syscall gate) and a **cgroup** (so
//! one tenant can't exhaust another's token budget). State (agents, memory, KV,
//! snapshots) is scoped by `tenant_id` at the SQLite layer so a tenant-A caller
//! can never read tenant-B data.
//!
//! ## Security note
//! API keys and session tokens are stored **hashed** (SHA-256, via `ring`): the
//! plaintext secret is returned to the caller exactly once at creation and only
//! its hash is persisted / kept in memory. Lookups hash the presented secret and
//! match on the hash. A salted KDF would be stronger against offline brute-force
//! of weak secrets, but these secrets are random 122-bit UUIDs, so an unsalted
//! cryptographic hash already defeats plaintext-at-rest disclosure.

use chrono::{DateTime, Duration, Utc};
use std::collections::HashMap;

/// SHA-256 hash of a secret, hex-encoded. This is what we persist / keep in
/// memory — never the plaintext.
pub fn hash_secret(secret: &str) -> String {
    let digest = ring::digest::digest(&ring::digest::SHA256, secret.as_bytes());
    let mut out = String::with_capacity(digest.as_ref().len() * 2);
    for b in digest.as_ref() {
        use std::fmt::Write;
        let _ = write!(out, "{b:02x}");
    }
    out
}

/// A tenant — the top-level isolation boundary. Every user, session, api-key and
/// agent belongs to exactly one tenant; the kernel maps each tenant onto its own
/// namespace group + cgroup so cross-tenant access is denied at the syscall gate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tenant {
    pub id: String,
    pub name: String,
    pub created_at: DateTime<Utc>,
}

/// User account, scoped to a tenant.
#[derive(Debug, Clone)]
pub struct User {
    pub id: String,
    pub tenant_id: String,
    pub username: String,
    pub email: String,
    pub role: Role,
    pub created_at: DateTime<Utc>,
}

/// User roles.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Admin,
    User,
    ReadOnly,
}

impl Role {
    pub fn as_str(self) -> &'static str {
        match self {
            Role::Admin => "admin",
            Role::User => "user",
            Role::ReadOnly => "read_only",
        }
    }

    /// Parse a persisted/public role name. Unknown values fail closed instead
    /// of silently becoming a writable user.
    pub fn parse(s: &str) -> Option<Role> {
        match s {
            "admin" => Some(Role::Admin),
            "read_only" | "operator" => Some(Role::ReadOnly),
            "user" => Some(Role::User),
            _ => None,
        }
    }
}

/// API key record — programmatic access for a user. The secret is stored hashed.
#[derive(Debug, Clone)]
pub struct ApiKey {
    /// SHA-256 hash of the key (the plaintext `ak_…` is only ever returned once).
    pub key_hash: String,
    pub name: String,
    pub user_id: String,
    pub tenant_id: String,
    pub created_at: DateTime<Utc>,
}

/// Session token record — interactive login for a user. Stored hashed.
#[derive(Debug, Clone)]
pub struct Session {
    /// SHA-256 hash of the session token (plaintext returned once at login).
    pub token_hash: String,
    pub user_id: String,
    pub tenant_id: String,
    pub expires_at: DateTime<Utc>,
}

/// The kind of credential that authenticated a tenant-bound connection.
///
/// System/open-server and configured shared-secret callers are represented by
/// the wire server's explicit trusted-system path rather than by a tenant
/// [`Principal`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CredentialKind {
    ApiKey,
    Session,
}

/// Stable, non-plaintext identity for the credential used to authenticate a
/// connection. `id` is the SHA-256 digest already stored by the auth subsystem;
/// it can be compared for revocation without retaining or exposing the secret.
#[derive(Clone, PartialEq, Eq)]
pub struct CredentialIdentity {
    pub kind: CredentialKind,
    pub id: String,
}

impl std::fmt::Debug for CredentialIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let short_id = self.id.get(..12).unwrap_or(&self.id);
        f.debug_struct("CredentialIdentity")
            .field("kind", &self.kind)
            .field("id", &format_args!("{short_id}…"))
            .finish()
    }
}

/// The resolved principal a connection acts as: which user, in which tenant,
/// with which role. Returned by [`AuthSystem::authenticate`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Principal {
    pub user_id: String,
    pub tenant_id: String,
    pub role: Role,
    /// Present for principals resolved from an API key or session. Synthetic
    /// in-process principals used by trusted embedding/tests may omit it; wire
    /// connections always preserve it.
    pub credential: Option<CredentialIdentity>,
}

/// Authentication / tenancy system. Holds identity in memory; the kernel
/// persists + rehydrates it through the single SQLite handle.
#[derive(Default)]
pub struct AuthSystem {
    tenants: HashMap<String, Tenant>,
    users: HashMap<String, User>,
    /// session-token-hash → Session
    sessions: HashMap<String, Session>,
    /// api-key-hash → ApiKey
    api_keys: HashMap<String, ApiKey>,
}

impl AuthSystem {
    pub fn new() -> Self {
        Self::default()
    }

    // ----- tenants -------------------------------------------------------

    /// Create a new tenant, returning its id.
    pub fn create_tenant(&mut self, name: impl Into<String>) -> String {
        let id = uuid::Uuid::new_v4().to_string();
        self.tenants.insert(
            id.clone(),
            Tenant {
                id: id.clone(),
                name: name.into(),
                created_at: Utc::now(),
            },
        );
        id
    }

    /// Insert a tenant with a known id (used by rehydration). Idempotent.
    pub fn insert_tenant(&mut self, tenant: Tenant) {
        self.tenants.insert(tenant.id.clone(), tenant);
    }

    pub fn get_tenant(&self, id: &str) -> Option<&Tenant> {
        self.tenants.get(id)
    }

    pub fn list_tenants(&self) -> Vec<&Tenant> {
        self.tenants.values().collect()
    }

    // ----- users ---------------------------------------------------------

    /// Register a user under a tenant. Returns `None` if the tenant is unknown.
    pub fn register(
        &mut self,
        tenant_id: &str,
        username: impl Into<String>,
        email: impl Into<String>,
        role: Role,
    ) -> Option<String> {
        if !self.tenants.contains_key(tenant_id) {
            return None;
        }
        let id = uuid::Uuid::new_v4().to_string();
        self.users.insert(
            id.clone(),
            User {
                id: id.clone(),
                tenant_id: tenant_id.to_string(),
                username: username.into(),
                email: email.into(),
                role,
                created_at: Utc::now(),
            },
        );
        Some(id)
    }

    /// Insert a fully-formed user (used by rehydration).
    pub fn insert_user(&mut self, user: User) {
        self.users.insert(user.id.clone(), user);
    }

    pub fn get_user(&self, id: &str) -> Option<&User> {
        self.users.get(id)
    }

    /// List users in a tenant (tenant-scoped — never leaks other tenants' users).
    pub fn list_users(&self, tenant_id: &str) -> Vec<&User> {
        self.users
            .values()
            .filter(|u| u.tenant_id == tenant_id)
            .collect()
    }

    // ----- sessions ------------------------------------------------------

    /// Create a session (login) for a user. Returns the **plaintext** token
    /// (stored hashed). `None` if the user is unknown.
    pub fn create_session(&mut self, user_id: &str) -> Option<String> {
        let user = self.users.get(user_id)?;
        let tenant_id = user.tenant_id.clone();
        let token = format!("st_{}", uuid::Uuid::new_v4().simple());
        let token_hash = hash_secret(&token);
        self.sessions.insert(
            token_hash.clone(),
            Session {
                token_hash,
                user_id: user_id.to_string(),
                tenant_id,
                expires_at: Utc::now() + Duration::hours(24),
            },
        );
        Some(token)
    }

    /// Insert a session record (rehydration).
    pub fn insert_session(&mut self, session: Session) {
        self.sessions.insert(session.token_hash.clone(), session);
    }

    /// Revoke a session by its plaintext token.
    pub fn revoke_session(&mut self, token: &str) -> bool {
        self.sessions.remove(&hash_secret(token)).is_some()
    }

    // ----- api keys ------------------------------------------------------

    /// Generate an API key for a user. Returns the **plaintext** key (stored
    /// hashed). `None` if the user is unknown.
    pub fn create_api_key(&mut self, user_id: &str, name: impl Into<String>) -> Option<String> {
        let user = self.users.get(user_id)?;
        let tenant_id = user.tenant_id.clone();
        let key = format!("ak_{}", uuid::Uuid::new_v4().simple());
        let key_hash = hash_secret(&key);
        self.api_keys.insert(
            key_hash.clone(),
            ApiKey {
                key_hash,
                name: name.into(),
                user_id: user_id.to_string(),
                tenant_id,
                created_at: Utc::now(),
            },
        );
        Some(key)
    }

    /// Insert an api-key record (rehydration).
    pub fn insert_api_key(&mut self, key: ApiKey) {
        self.api_keys.insert(key.key_hash.clone(), key);
    }

    /// Revoke an API key by its plaintext value.
    pub fn revoke_api_key(&mut self, key: &str) -> bool {
        self.api_keys.remove(&hash_secret(key)).is_some()
    }

    /// Revoke a user and every credential issued to that user. The tenant and
    /// other users remain active.
    pub fn revoke_user(&mut self, user_id: &str) -> bool {
        let existed = self.users.remove(user_id).is_some();
        self.sessions
            .retain(|_, session| session.user_id != user_id);
        self.api_keys.retain(|_, key| key.user_id != user_id);
        existed
    }

    /// Revoke a tenant identity boundary and all of its users/credentials.
    /// Existing agent data remains durable but becomes unreachable through
    /// tenant credentials until an explicit administrative recovery flow.
    pub fn revoke_tenant(&mut self, tenant_id: &str) -> bool {
        let existed = self.tenants.remove(tenant_id).is_some();
        self.users.retain(|_, user| user.tenant_id != tenant_id);
        self.sessions
            .retain(|_, session| session.tenant_id != tenant_id);
        self.api_keys.retain(|_, key| key.tenant_id != tenant_id);
        existed
    }

    // ----- resolution / RBAC --------------------------------------------

    /// Resolve a presented secret (API key **or** session token) to a
    /// [`Principal`]. Tries API keys first, then unexpired sessions. This is the
    /// single entry point the wire server uses to bind a connection to a
    /// `(user, tenant, role)`.
    pub fn authenticate(&self, secret: &str) -> Option<Principal> {
        let hash = hash_secret(secret);
        if let Some(k) = self.api_keys.get(&hash) {
            let user = self.users.get(&k.user_id)?;
            if user.tenant_id != k.tenant_id || !self.tenants.contains_key(&k.tenant_id) {
                return None;
            }
            return Some(Principal {
                user_id: k.user_id.clone(),
                tenant_id: k.tenant_id.clone(),
                role: user.role,
                credential: Some(CredentialIdentity {
                    kind: CredentialKind::ApiKey,
                    id: hash,
                }),
            });
        }
        if let Some(s) = self.sessions.get(&hash) {
            if Utc::now() > s.expires_at {
                return None;
            }
            let user = self.users.get(&s.user_id)?;
            if user.tenant_id != s.tenant_id || !self.tenants.contains_key(&s.tenant_id) {
                return None;
            }
            return Some(Principal {
                user_id: s.user_id.clone(),
                tenant_id: s.tenant_id.clone(),
                role: user.role,
                credential: Some(CredentialIdentity {
                    kind: CredentialKind::Session,
                    id: hash,
                }),
            });
        }
        None
    }

    /// Check whether `user_id` holds at least the `required` role.
    pub fn check_role(&self, user_id: &str, required: Role) -> bool {
        match self.users.get(user_id) {
            Some(u) => matches!(
                (u.role, required),
                (Role::Admin, _)
                    | (Role::User, Role::User | Role::ReadOnly)
                    | (Role::ReadOnly, Role::ReadOnly)
            ),
            None => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn setup() -> (AuthSystem, String, String) {
        let mut auth = AuthSystem::new();
        let tenant = auth.create_tenant("acme");
        let user = auth
            .register(&tenant, "alice", "alice@acme.test", Role::User)
            .unwrap();
        (auth, tenant, user)
    }

    #[test]
    fn register_requires_tenant() {
        let mut auth = AuthSystem::new();
        assert!(auth
            .register("no-such-tenant", "a", "a@t.com", Role::User)
            .is_none());
    }

    #[test]
    fn session_resolves_to_user_tenant_role() {
        let (mut auth, tenant, user) = setup();
        let token = auth.create_session(&user).unwrap();
        let p = auth.authenticate(&token).unwrap();
        assert_eq!(p.user_id, user);
        assert_eq!(p.tenant_id, tenant);
        assert_eq!(p.role, Role::User);
        assert_eq!(p.credential.unwrap().kind, CredentialKind::Session);
    }

    #[test]
    fn api_key_resolves_to_user_tenant_role() {
        let (mut auth, tenant, user) = setup();
        let key = auth.create_api_key(&user, "ci").unwrap();
        let p = auth.authenticate(&key).unwrap();
        assert_eq!(p.user_id, user);
        assert_eq!(p.tenant_id, tenant);
        assert_eq!(p.credential.unwrap().kind, CredentialKind::ApiKey);
    }

    #[test]
    fn secrets_are_hashed_at_rest() {
        let (mut auth, _t, user) = setup();
        let key = auth.create_api_key(&user, "ci").unwrap();
        // The stored record key must not equal the plaintext.
        let stored: Vec<_> = auth.api_keys.keys().cloned().collect();
        assert_eq!(stored.len(), 1);
        assert_ne!(stored[0], key);
        assert_eq!(stored[0], hash_secret(&key));
    }

    #[test]
    fn unknown_secret_rejected() {
        let (auth, _t, _u) = setup();
        assert!(auth.authenticate("ak_bogus").is_none());
    }

    #[test]
    fn revoked_session_rejected() {
        let (mut auth, _t, user) = setup();
        let token = auth.create_session(&user).unwrap();
        assert!(auth.revoke_session(&token));
        assert!(auth.authenticate(&token).is_none());
    }

    #[test]
    fn revoked_key_user_and_tenant_fail_closed() {
        let (mut auth, tenant, user) = setup();
        let first_key = auth.create_api_key(&user, "first").unwrap();
        assert!(auth.revoke_api_key(&first_key));
        assert!(auth.authenticate(&first_key).is_none());

        let user_key = auth.create_api_key(&user, "user").unwrap();
        let user_session = auth.create_session(&user).unwrap();
        assert!(auth.revoke_user(&user));
        assert!(auth.authenticate(&user_key).is_none());
        assert!(auth.authenticate(&user_session).is_none());

        let second_user = auth
            .register(&tenant, "bob", "bob@acme.test", Role::User)
            .unwrap();
        let tenant_key = auth.create_api_key(&second_user, "tenant").unwrap();
        assert!(auth.revoke_tenant(&tenant));
        assert!(auth.authenticate(&tenant_key).is_none());
    }

    #[test]
    fn inconsistent_identity_records_never_fall_back_to_default_authority() {
        let (mut auth, tenant, user) = setup();
        let key = auth.create_api_key(&user, "ci").unwrap();

        auth.users.remove(&user);
        assert!(auth.authenticate(&key).is_none());

        let orphan_user = User {
            id: user,
            tenant_id: tenant.clone(),
            username: "orphan".into(),
            email: "orphan@acme.test".into(),
            role: Role::Admin,
            created_at: Utc::now(),
        };
        auth.insert_user(orphan_user);
        auth.tenants.remove(&tenant);
        assert!(auth.authenticate(&key).is_none());
    }

    #[test]
    fn role_check_hierarchy() {
        let mut auth = AuthSystem::new();
        let t = auth.create_tenant("t");
        let admin = auth.register(&t, "admin", "a@t.com", Role::Admin).unwrap();
        let usr = auth.register(&t, "user", "u@t.com", Role::User).unwrap();
        let ro = auth.register(&t, "ro", "r@t.com", Role::ReadOnly).unwrap();
        assert!(auth.check_role(&admin, Role::Admin));
        assert!(!auth.check_role(&usr, Role::Admin));
        assert!(auth.check_role(&usr, Role::User));
        assert!(!auth.check_role(&ro, Role::User));
    }

    #[test]
    fn unknown_role_names_fail_closed() {
        assert_eq!(Role::parse("admin"), Some(Role::Admin));
        assert_eq!(Role::parse("operator"), Some(Role::ReadOnly));
        assert_eq!(Role::parse("owner"), None);
        assert_eq!(Role::parse(""), None);
    }

    #[test]
    fn list_users_is_tenant_scoped() {
        let mut auth = AuthSystem::new();
        let a = auth.create_tenant("a");
        let b = auth.create_tenant("b");
        auth.register(&a, "a1", "a1@t.com", Role::User).unwrap();
        auth.register(&a, "a2", "a2@t.com", Role::User).unwrap();
        auth.register(&b, "b1", "b1@t.com", Role::User).unwrap();
        assert_eq!(auth.list_users(&a).len(), 2);
        assert_eq!(auth.list_users(&b).len(), 1);
    }
}
