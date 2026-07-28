//! Platform credential-store boundary for desktop provider secrets.
//!
//! Cloud-provider credentials are keyed only by the fixed application service
//! name and a validated provider identifier. Values are never formatted,
//! logged, serialized into desktop config responses, or persisted in AgentOS
//! configuration by this module.

use std::fmt;

use kernel::config::Config;
use keyring::Entry;
use zeroize::Zeroizing;

pub const SUPPORTED_DESKTOP_PROVIDERS: [&str; 4] = ["azure-openai", "openai", "anthropic", "local"];
pub const CLOUD_DESKTOP_PROVIDERS: [&str; 3] = ["azure-openai", "openai", "anthropic"];

const CREDENTIAL_SERVICE: &str = "com.agentos.desktop.provider";
const MAX_PROVIDER_SECRET_BYTES: usize = 16 * 1024;

/// Stable, non-sensitive credential-store failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CredentialStoreError {
    UnsupportedProvider,
    EmptySecret,
    SecretTooLarge,
    Unavailable,
}

impl fmt::Display for CredentialStoreError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::UnsupportedProvider => "unsupported desktop provider",
            Self::EmptySecret => "provider credential must not be empty",
            Self::SecretTooLarge => "provider credential exceeds the desktop input bound",
            Self::Unavailable => "platform credential store is unavailable",
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for CredentialStoreError {}

pub trait ProviderCredentialStore {
    fn load(&self, provider: &str) -> Result<Option<Zeroizing<String>>, CredentialStoreError>;
    fn store(&self, provider: &str, secret: &str) -> Result<(), CredentialStoreError>;
    fn delete(&self, provider: &str) -> Result<bool, CredentialStoreError>;

    fn contains(&self, provider: &str) -> Result<bool, CredentialStoreError> {
        self.load(provider).map(|secret| secret.is_some())
    }
}

/// macOS Keychain, Windows Credential Manager, or Linux Secret Service.
#[derive(Debug, Clone)]
pub struct NativeProviderCredentialStore {
    service: String,
}

impl Default for NativeProviderCredentialStore {
    fn default() -> Self {
        Self {
            service: CREDENTIAL_SERVICE.to_string(),
        }
    }
}

impl NativeProviderCredentialStore {
    #[cfg(test)]
    fn for_test_service(service: String) -> Self {
        Self { service }
    }

    fn entry(&self, provider: &str) -> Result<Entry, CredentialStoreError> {
        validate_cloud_provider(provider)?;
        Entry::new(&self.service, provider).map_err(|_| CredentialStoreError::Unavailable)
    }
}

impl ProviderCredentialStore for NativeProviderCredentialStore {
    fn load(&self, provider: &str) -> Result<Option<Zeroizing<String>>, CredentialStoreError> {
        let entry = self.entry(provider)?;
        match entry.get_password() {
            Ok(secret) => Ok(Some(Zeroizing::new(secret))),
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(_) => Err(CredentialStoreError::Unavailable),
        }
    }

    fn store(&self, provider: &str, secret: &str) -> Result<(), CredentialStoreError> {
        validate_secret(secret)?;
        self.entry(provider)?
            .set_password(secret)
            .map_err(|_| CredentialStoreError::Unavailable)
    }

    fn delete(&self, provider: &str) -> Result<bool, CredentialStoreError> {
        let entry = self.entry(provider)?;
        match entry.delete_credential() {
            Ok(()) => Ok(true),
            Err(keyring::Error::NoEntry) => Ok(false),
            Err(_) => Err(CredentialStoreError::Unavailable),
        }
    }
}

pub fn validate_cloud_provider(provider: &str) -> Result<(), CredentialStoreError> {
    if CLOUD_DESKTOP_PROVIDERS.contains(&provider) {
        Ok(())
    } else {
        Err(CredentialStoreError::UnsupportedProvider)
    }
}

fn validate_secret(secret: &str) -> Result<(), CredentialStoreError> {
    if secret.trim().is_empty() {
        return Err(CredentialStoreError::EmptySecret);
    }
    if secret.len() > MAX_PROVIDER_SECRET_BYTES {
        return Err(CredentialStoreError::SecretTooLarge);
    }
    Ok(())
}

/// Load platform credentials into an in-memory config used only for provider
/// registration. Call this after kernel construction and never save the
/// hydrated value back to disk.
pub fn hydrate_provider_credentials(config: &mut Config) {
    let store = NativeProviderCredentialStore::default();
    for provider in CLOUD_DESKTOP_PROVIDERS {
        match store.load(provider) {
            Ok(Some(secret)) => config.set_api_key(provider, secret.to_string()),
            Ok(None) => {}
            Err(_) => {
                tracing::warn!(provider, "platform credential store is unavailable");
            }
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::Mutex;

    #[derive(Default)]
    pub(crate) struct MemoryCredentialStore {
        values: Mutex<HashMap<String, String>>,
        unavailable: bool,
    }

    impl MemoryCredentialStore {
        pub(crate) fn unavailable() -> Self {
            Self {
                values: Mutex::new(HashMap::new()),
                unavailable: true,
            }
        }
    }

    impl ProviderCredentialStore for MemoryCredentialStore {
        fn load(&self, provider: &str) -> Result<Option<Zeroizing<String>>, CredentialStoreError> {
            validate_cloud_provider(provider)?;
            if self.unavailable {
                return Err(CredentialStoreError::Unavailable);
            }
            Ok(self
                .values
                .lock()
                .unwrap()
                .get(provider)
                .cloned()
                .map(Zeroizing::new))
        }

        fn store(&self, provider: &str, secret: &str) -> Result<(), CredentialStoreError> {
            validate_cloud_provider(provider)?;
            validate_secret(secret)?;
            if self.unavailable {
                return Err(CredentialStoreError::Unavailable);
            }
            self.values
                .lock()
                .unwrap()
                .insert(provider.to_string(), secret.to_string());
            Ok(())
        }

        fn delete(&self, provider: &str) -> Result<bool, CredentialStoreError> {
            validate_cloud_provider(provider)?;
            if self.unavailable {
                return Err(CredentialStoreError::Unavailable);
            }
            Ok(self.values.lock().unwrap().remove(provider).is_some())
        }
    }

    #[test]
    fn store_rotates_and_delete_removes_one_validated_provider_secret() {
        let store = MemoryCredentialStore::default();
        store.store("openai", "first-secret").unwrap();
        store.store("openai", "rotated-secret").unwrap();
        assert_eq!(
            store
                .load("openai")
                .unwrap()
                .as_ref()
                .map(|secret| secret.as_str()),
            Some("rotated-secret")
        );
        assert!(store.delete("openai").unwrap());
        assert!(!store.delete("openai").unwrap());
        assert!(store.load("openai").unwrap().is_none());
    }

    #[test]
    fn provider_and_secret_bounds_fail_before_store_access() {
        let store = MemoryCredentialStore::unavailable();
        assert_eq!(
            store.store("unknown", "secret").unwrap_err(),
            CredentialStoreError::UnsupportedProvider
        );
        let available = MemoryCredentialStore::default();
        assert_eq!(
            available.store("openai", "  ").unwrap_err(),
            CredentialStoreError::EmptySecret
        );
        let oversized = "x".repeat(MAX_PROVIDER_SECRET_BYTES + 1);
        assert_eq!(
            available.store("openai", &oversized).unwrap_err(),
            CredentialStoreError::SecretTooLarge
        );
    }

    #[test]
    fn public_errors_never_include_provider_secret_or_platform_details() {
        let error = CredentialStoreError::Unavailable;
        let rendered = format!("{error:?} {error}");
        assert_eq!(
            rendered,
            "Unavailable platform credential store is unavailable"
        );
    }

    /// This test mutates the operating system's real credential store and is
    /// therefore opt-in locally. CI runs it on disposable Linux, macOS, and
    /// Windows workers after preparing the native store.
    #[test]
    #[ignore = "requires an unlocked disposable operating-system credential store"]
    fn native_platform_store_round_trip() {
        struct Cleanup {
            store: NativeProviderCredentialStore,
        }

        impl Drop for Cleanup {
            fn drop(&mut self) {
                let _ = self.store.delete("openai");
            }
        }

        let store = NativeProviderCredentialStore::for_test_service(format!(
            "{CREDENTIAL_SERVICE}.qualification.{}",
            std::process::id()
        ));
        let _cleanup = Cleanup {
            store: store.clone(),
        };
        let _ = store.delete("openai");

        store
            .store("openai", "agentos-ci-credential-first")
            .expect("store a disposable credential in the native backend");
        assert_eq!(
            store
                .load("openai")
                .expect("read the disposable credential")
                .as_ref()
                .map(|secret| secret.as_str()),
            Some("agentos-ci-credential-first")
        );

        store
            .store("openai", "agentos-ci-credential-rotated")
            .expect("rotate the disposable native credential");
        assert_eq!(
            store
                .load("openai")
                .expect("read the rotated native credential")
                .as_ref()
                .map(|secret| secret.as_str()),
            Some("agentos-ci-credential-rotated")
        );

        assert!(store
            .delete("openai")
            .expect("delete the disposable native credential"));
        assert!(store
            .load("openai")
            .expect("verify native credential deletion")
            .is_none());
    }
}
