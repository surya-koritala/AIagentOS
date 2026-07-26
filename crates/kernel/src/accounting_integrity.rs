//! Authenticated integrity for the enforcement accounting stored in SQLite.
//!
//! Normal accounting writes remain O(1): SQLite triggers XOR a keyed record
//! digest into a state root and append a keyed, hash-chained mutation event in
//! the same transaction as the protected row. Startup independently scans all
//! protected rows and verifies both the root and the complete event chain.
//!
//! The random integrity secret is stored inside the database. SQLCipher
//! therefore protects it in production and storage-key rotation can leave the
//! accounting history intact. On an intentionally plaintext development store
//! this detects accidental corruption, but it is not a defense against an
//! attacker who can read the secret and rewrite the whole database.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use ring::hmac;
use ring::rand::{SecureRandom, SystemRandom};
use rusqlite::functions::{Context as FunctionContext, FunctionFlags};
use rusqlite::types::ValueRef;
use rusqlite::{params, Connection, OptionalExtension};
use zeroize::Zeroizing;

use crate::ContextError;

const ALGORITHM: &str = "hmac-sha256-local-secret-v1";
pub(crate) const SCHEMA_VERSION: i64 = 3;
const MAC_BYTES: usize = 32;
const ZERO_MAC: [u8; MAC_BYTES] = [0; MAC_BYTES];
const MAC_FUNCTION: &str = "aios_accounting_mac";
const XOR_FUNCTION: &str = "aios_accounting_xor";
const FORMAT_DOMAIN: &[u8] = b"AIOS accounting integrity v1\0";

#[derive(Clone, Copy)]
struct RecordSpec {
    table: &'static str,
    columns: &'static [&'static str],
}

const RECORDS: &[RecordSpec] = &[
    RecordSpec {
        table: "usage_log",
        columns: &[
            "id",
            "agent_id",
            "timestamp",
            "tokens_used",
            "input_tokens",
            "output_tokens",
            "cached_tokens",
            "llm_requests",
            "retries",
            "provider_latency_ms",
            "provider_reported_requests",
            "estimated_requests",
            "provider",
            "model",
            "tool_calls",
            "estimated_cost_usd",
            "cost_micros",
        ],
    },
    RecordSpec {
        table: "quota_epoch_floor",
        columns: &["singleton", "epoch"],
    },
    RecordSpec {
        table: "quota_epochs",
        columns: &["scope_kind", "scope_id", "epoch", "requests", "tokens"],
    },
    RecordSpec {
        table: "quota_receipts",
        columns: &[
            "id",
            "receipt_kind",
            "epoch",
            "state",
            "reserved_requests",
            "reserved_tokens",
            "actual_requests",
            "actual_tokens",
        ],
    },
    RecordSpec {
        table: "quota_receipt_scopes",
        columns: &[
            "receipt_id",
            "scope_order",
            "scope_kind",
            "scope_id",
            "reserved_requests",
            "reserved_tokens",
            "actual_requests",
            "actual_tokens",
        ],
    },
    RecordSpec {
        table: "quota_refunded_receipts",
        columns: &["id", "epoch"],
    },
    RecordSpec {
        table: "quota_migration_fence",
        columns: &["epoch"],
    },
];

fn integrity_error(message: impl Into<String>) -> ContextError {
    ContextError::StorageError(format!(
        "accounting integrity verification failed: {}",
        message.into()
    ))
}

fn encode_value(context: &mut hmac::Context, value: ValueRef<'_>) {
    let (kind, bytes): (u8, &[u8]) = match value {
        ValueRef::Null => (0, &[]),
        ValueRef::Integer(value) => {
            context.update(&[1]);
            context.update(&(8_u64).to_be_bytes());
            context.update(&value.to_be_bytes());
            return;
        }
        ValueRef::Real(value) => {
            context.update(&[2]);
            context.update(&(8_u64).to_be_bytes());
            context.update(&value.to_bits().to_be_bytes());
            return;
        }
        ValueRef::Text(value) => (3, value),
        ValueRef::Blob(value) => (4, value),
    };
    context.update(&[kind]);
    context.update(&(bytes.len() as u64).to_be_bytes());
    context.update(bytes);
}

fn mac_values<'a>(
    key: &hmac::Key,
    values: impl IntoIterator<Item = ValueRef<'a>>,
) -> [u8; MAC_BYTES] {
    let mut context = hmac::Context::with_key(key);
    context.update(FORMAT_DOMAIN);
    for value in values {
        encode_value(&mut context, value);
    }
    let mut result = [0_u8; MAC_BYTES];
    result.copy_from_slice(context.sign().as_ref());
    result
}

struct EventMacInput<'a> {
    sequence: i64,
    table: &'a str,
    operation: &'a str,
    record_key: &'a str,
    old_mac: &'a [u8],
    new_mac: &'a [u8],
    state_root: &'a [u8],
    previous_hash: &'a [u8],
}

fn event_mac(key: &hmac::Key, event: &EventMacInput<'_>) -> [u8; MAC_BYTES] {
    mac_values(
        key,
        [
            ValueRef::Text(b"event"),
            ValueRef::Integer(event.sequence),
            ValueRef::Text(event.table.as_bytes()),
            ValueRef::Text(event.operation.as_bytes()),
            ValueRef::Text(event.record_key.as_bytes()),
            ValueRef::Blob(event.old_mac),
            ValueRef::Blob(event.new_mac),
            ValueRef::Blob(event.state_root),
            ValueRef::Blob(event.previous_hash),
        ],
    )
}

fn xor_into(root: &mut [u8; MAC_BYTES], digest: &[u8]) -> Result<(), ContextError> {
    if digest.len() != MAC_BYTES {
        return Err(integrity_error(format!(
            "digest has {} bytes, expected {MAC_BYTES}",
            digest.len()
        )));
    }
    for (target, value) in root.iter_mut().zip(digest) {
        *target ^= value;
    }
    Ok(())
}

fn read_secret(connection: &Connection) -> Result<Zeroizing<[u8; MAC_BYTES]>, ContextError> {
    let secret = connection
        .query_row(
            "SELECT secret FROM accounting_integrity WHERE singleton = 1",
            [],
            |row| row.get::<_, Vec<u8>>(0),
        )
        .map_err(|error| integrity_error(format!("cannot read integrity secret: {error}")))?;
    secret
        .try_into()
        .map(Zeroizing::new)
        .map_err(|secret: Vec<u8>| {
            integrity_error(format!(
                "integrity secret has {} bytes, expected {MAC_BYTES}",
                secret.len()
            ))
        })
}

fn compute_root(connection: &Connection, key: &hmac::Key) -> Result<[u8; MAC_BYTES], ContextError> {
    let mut root = ZERO_MAC;
    for spec in RECORDS {
        let sql = format!("SELECT {} FROM {}", spec.columns.join(", "), spec.table);
        let mut statement = connection.prepare(&sql).map_err(|error| {
            integrity_error(format!(
                "cannot scan protected table {}: {error}",
                spec.table
            ))
        })?;
        let rows = statement
            .query_map([], |row| {
                let mut context = hmac::Context::with_key(key);
                context.update(FORMAT_DOMAIN);
                encode_value(&mut context, ValueRef::Text(b"record"));
                encode_value(&mut context, ValueRef::Text(spec.table.as_bytes()));
                for index in 0..spec.columns.len() {
                    encode_value(&mut context, row.get_ref(index)?);
                }
                Ok(context.sign().as_ref().to_vec())
            })
            .map_err(|error| {
                integrity_error(format!(
                    "cannot enumerate protected table {}: {error}",
                    spec.table
                ))
            })?;
        for row in rows {
            let digest = row.map_err(|error| {
                integrity_error(format!(
                    "cannot read protected table {}: {error}",
                    spec.table
                ))
            })?;
            xor_into(&mut root, &digest)?;
        }
    }
    Ok(root)
}

fn mac_expression(spec: RecordSpec, prefix: &str) -> String {
    let values = spec
        .columns
        .iter()
        .map(|column| format!("{prefix}.{column}"))
        .collect::<Vec<_>>()
        .join(", ");
    format!("{MAC_FUNCTION}('record', '{}', {values})", spec.table)
}

fn trigger_sql(
    spec: RecordSpec,
    operation: &str,
    record_key: &str,
    old_mac: &str,
    new_mac: &str,
) -> String {
    let when_clause = if operation == "update" {
        format!("WHEN {old_mac} != {new_mac}")
    } else {
        String::new()
    };
    format!(
        "CREATE TRIGGER IF NOT EXISTS accounting_{table}_{operation}
         AFTER {sql_operation} ON {table}
         {when_clause}
         BEGIN
             INSERT INTO accounting_events
                (sequence, table_name, operation, record_key, old_mac, new_mac,
                 state_root, previous_hash, entry_hash)
             SELECT event_count + 1, '{table}', '{operation}', {record_key},
                    {old_mac}, {new_mac},
                    {xor_function}(
                        state_root, {xor_function}({old_mac}, {new_mac})
                    ),
                    head_hash,
                    {mac_function}(
                        'event', event_count + 1, '{table}', '{operation}',
                        {record_key}, {old_mac}, {new_mac},
                        {xor_function}(
                            state_root, {xor_function}({old_mac}, {new_mac})
                        ),
                        head_hash
                    )
             FROM accounting_integrity WHERE singleton = 1;
             UPDATE accounting_integrity
             SET state_root = {xor_function}(
                     state_root, {xor_function}({old_mac}, {new_mac})
                 ),
                 event_count = event_count + 1,
                 head_hash = (
                     SELECT entry_hash FROM accounting_events
                     ORDER BY sequence DESC LIMIT 1
                 )
             WHERE singleton = 1;
             SELECT CASE WHEN changes() != 1
                 THEN RAISE(ABORT, 'accounting integrity state unavailable')
             END;
         END;",
        table = spec.table,
        sql_operation = operation.to_ascii_uppercase(),
        mac_function = MAC_FUNCTION,
        xor_function = XOR_FUNCTION,
    )
}

fn expected_trigger_definitions() -> Vec<(String, &'static str, String)> {
    let mut definitions = Vec::new();
    for spec in RECORDS {
        let new_mac = mac_expression(*spec, "NEW");
        let old_mac = mac_expression(*spec, "OLD");
        for (operation, record_key, before, after) in [
            (
                "insert",
                format!("hex({new_mac})"),
                "zeroblob(32)".to_string(),
                new_mac.clone(),
            ),
            (
                "update",
                format!("hex({old_mac})"),
                old_mac.clone(),
                new_mac.clone(),
            ),
            (
                "delete",
                format!("hex({old_mac})"),
                old_mac.clone(),
                "zeroblob(32)".to_string(),
            ),
        ] {
            definitions.push((
                format!("accounting_{}_{operation}", spec.table),
                spec.table,
                trigger_sql(*spec, operation, &record_key, &before, &after),
            ));
        }
    }
    definitions
}

fn install_triggers(connection: &Connection) -> Result<(), ContextError> {
    let mut sql = String::new();
    for (name, _, definition) in expected_trigger_definitions() {
        sql.push_str(&format!("DROP TRIGGER IF EXISTS {name};"));
        sql.push_str(&definition);
    }
    connection
        .execute_batch(&sql)
        .map_err(|error| integrity_error(format!("cannot install accounting triggers: {error}")))
}

fn normalize_sql(sql: &str) -> String {
    sql.trim_end_matches(';')
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .replacen("CREATE TRIGGER IF NOT EXISTS ", "CREATE TRIGGER ", 1)
}

fn verify_canonical_triggers(connection: &Connection) -> Result<(), ContextError> {
    let expected = expected_trigger_definitions()
        .into_iter()
        .map(|(name, table, sql)| (name, (table, normalize_sql(&sql))))
        .collect::<BTreeMap<_, _>>();
    let mut statement = connection
        .prepare("SELECT name, tbl_name, sql FROM sqlite_schema WHERE type = 'trigger'")
        .map_err(|error| integrity_error(format!("cannot inspect accounting triggers: {error}")))?;
    let rows = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
            ))
        })
        .map_err(|error| {
            integrity_error(format!("cannot enumerate accounting triggers: {error}"))
        })?;
    let mut observed = BTreeSet::new();
    for row in rows {
        let (name, table, sql) = row.map_err(|error| {
            integrity_error(format!("cannot read accounting trigger metadata: {error}"))
        })?;
        let Some((expected_table, expected_sql)) = expected.get(&name) else {
            return Err(integrity_error(format!(
                "unexpected trigger {name:?} is attached to table {table:?}"
            )));
        };
        let observed_sql = normalize_sql(&sql);
        if table != *expected_table || observed_sql != *expected_sql {
            return Err(integrity_error(format!(
                "protected-table trigger {name:?} is not the canonical definition"
            )));
        }
        observed.insert(name);
    }
    for name in expected.keys() {
        if !observed.contains(name) {
            return Err(integrity_error(format!(
                "required protected-table trigger {name:?} is missing"
            )));
        }
    }
    Ok(())
}

/// Verify the current state and exact owned trigger set before any startup
/// migration can mutate it or use the registered HMAC function as an oracle.
pub(crate) fn secure_existing_schema(connection: &Connection) -> Result<(), ContextError> {
    verify(connection)?;
    verify_canonical_triggers(connection)
}

/// Add the version-three integrity state and atomically authenticate any
/// accounting rows inherited from an older schema.
pub(crate) fn install(connection: &Connection) -> Result<(), ContextError> {
    connection
        .execute_batch(
            "CREATE TABLE IF NOT EXISTS accounting_integrity (
                 singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                 algorithm TEXT NOT NULL,
                 secret BLOB NOT NULL
                     CHECK (typeof(secret) = 'blob' AND length(secret) = 32),
                 state_root BLOB NOT NULL
                     CHECK (typeof(state_root) = 'blob' AND length(state_root) = 32),
                 event_count INTEGER NOT NULL CHECK (event_count >= 1),
                 head_hash BLOB NOT NULL
                     CHECK (typeof(head_hash) = 'blob' AND length(head_hash) = 32)
             );
             CREATE TABLE IF NOT EXISTS accounting_events (
                 sequence INTEGER PRIMARY KEY CHECK (sequence >= 1),
                 table_name TEXT NOT NULL,
                 operation TEXT NOT NULL
                     CHECK (operation IN ('genesis', 'insert', 'update', 'delete')),
                 record_key TEXT NOT NULL,
                 old_mac BLOB NOT NULL
                     CHECK (typeof(old_mac) = 'blob' AND length(old_mac) = 32),
                 new_mac BLOB NOT NULL
                     CHECK (typeof(new_mac) = 'blob' AND length(new_mac) = 32),
                 state_root BLOB NOT NULL
                     CHECK (typeof(state_root) = 'blob' AND length(state_root) = 32),
                 previous_hash BLOB NOT NULL
                     CHECK (typeof(previous_hash) = 'blob'
                            AND length(previous_hash) = 32),
                 entry_hash BLOB NOT NULL UNIQUE
                     CHECK (typeof(entry_hash) = 'blob' AND length(entry_hash) = 32)
             );",
        )
        .map_err(|error| {
            integrity_error(format!(
                "cannot create accounting integrity schema: {error}"
            ))
        })?;

    let initialized = connection
        .query_row(
            "SELECT 1 FROM accounting_integrity WHERE singleton = 1",
            [],
            |_| Ok(()),
        )
        .optional()
        .map_err(|error| integrity_error(format!("cannot inspect integrity state: {error}")))?
        .is_some();
    if !initialized {
        let mut secret = Zeroizing::new([0_u8; MAC_BYTES]);
        SystemRandom::new()
            .fill(secret.as_mut())
            .map_err(|_| integrity_error("cannot generate integrity secret"))?;
        let key = hmac::Key::new(hmac::HMAC_SHA256, secret.as_ref());
        let root = compute_root(connection, &key)?;
        let genesis_hash = event_mac(
            &key,
            &EventMacInput {
                sequence: 1,
                table: "*",
                operation: "genesis",
                record_key: "baseline",
                old_mac: &ZERO_MAC,
                new_mac: &root,
                state_root: &root,
                previous_hash: &ZERO_MAC,
            },
        );
        connection
            .execute(
                "INSERT INTO accounting_integrity
                    (singleton, algorithm, secret, state_root, event_count, head_hash)
                 VALUES (1, ?1, ?2, ?3, 1, ?4)",
                params![
                    ALGORITHM,
                    secret.as_slice(),
                    root.as_slice(),
                    genesis_hash.as_slice()
                ],
            )
            .map_err(|error| {
                integrity_error(format!("cannot initialize integrity state: {error}"))
            })?;
        connection
            .execute(
                "INSERT INTO accounting_events
                    (sequence, table_name, operation, record_key, old_mac, new_mac,
                     state_root, previous_hash, entry_hash)
                 VALUES (1, '*', 'genesis', 'baseline', ?1, ?2, ?2, ?1, ?3)",
                params![
                    ZERO_MAC.as_slice(),
                    root.as_slice(),
                    genesis_hash.as_slice()
                ],
            )
            .map_err(|error| {
                integrity_error(format!("cannot initialize integrity event chain: {error}"))
            })?;
    }
    if initialized {
        verify_canonical_triggers(connection)
    } else {
        install_triggers(connection)
    }
}

/// Register connection-local keyed functions used by the persistent triggers.
/// A connection that does not register them cannot mutate protected tables.
pub(crate) fn register_functions(connection: &Connection) -> Result<(), ContextError> {
    let secret = read_secret(connection)?;
    let key = Arc::new(hmac::Key::new(hmac::HMAC_SHA256, secret.as_ref()));
    let mac_key = Arc::clone(&key);
    let flags = FunctionFlags::SQLITE_UTF8
        | FunctionFlags::SQLITE_DETERMINISTIC
        | FunctionFlags::SQLITE_INNOCUOUS;
    connection
        .create_scalar_function(MAC_FUNCTION, -1, flags, move |context| {
            Ok(mac_values(
                &mac_key,
                (0..context.len()).map(|index| context.get_raw(index)),
            )
            .to_vec())
        })
        .map_err(|error| {
            integrity_error(format!("cannot register accounting MAC function: {error}"))
        })?;
    connection
        .create_scalar_function(XOR_FUNCTION, 2, flags, |context: &FunctionContext<'_>| {
            let left = context.get::<Vec<u8>>(0)?;
            let right = context.get::<Vec<u8>>(1)?;
            if left.len() != MAC_BYTES || right.len() != MAC_BYTES {
                return Err(rusqlite::Error::UserFunctionError(Box::new(
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "accounting XOR operands must be 32 bytes",
                    ),
                )));
            }
            Ok(left
                .iter()
                .zip(right)
                .map(|(left, right)| left ^ right)
                .collect::<Vec<_>>())
        })
        .map_err(|error| {
            integrity_error(format!("cannot register accounting XOR function: {error}"))
        })
}

/// Verify the authenticated state root and every event-chain link.
pub(crate) fn verify(connection: &Connection) -> Result<(), ContextError> {
    let (algorithm, secret, stored_root, event_count, stored_head) = connection
        .query_row(
            "SELECT algorithm, secret, state_root, event_count, head_hash
             FROM accounting_integrity WHERE singleton = 1",
            [],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, Vec<u8>>(4)?,
                ))
            },
        )
        .map_err(|error| integrity_error(format!("cannot read integrity state: {error}")))?;
    if algorithm != ALGORITHM {
        return Err(integrity_error(format!(
            "unsupported algorithm {algorithm:?}"
        )));
    }
    let secret: [u8; MAC_BYTES] = secret.try_into().map_err(|secret: Vec<u8>| {
        integrity_error(format!(
            "integrity secret has {} bytes, expected {MAC_BYTES}",
            secret.len()
        ))
    })?;
    let secret = Zeroizing::new(secret);
    if stored_root.len() != MAC_BYTES || stored_head.len() != MAC_BYTES || event_count < 1 {
        return Err(integrity_error(
            "integrity state has invalid lengths or count",
        ));
    }
    let key = hmac::Key::new(hmac::HMAC_SHA256, secret.as_ref());
    let computed_root = compute_root(connection, &key)?;
    if stored_root.as_slice() != computed_root {
        return Err(integrity_error(
            "protected usage or quota rows disagree with the authenticated root",
        ));
    }

    let mut statement = connection
        .prepare(
            "SELECT sequence, table_name, operation, record_key, old_mac, new_mac,
                    state_root, previous_hash, entry_hash
             FROM accounting_events ORDER BY sequence",
        )
        .map_err(|error| integrity_error(format!("cannot prepare event verification: {error}")))?;
    let rows = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, Vec<u8>>(4)?,
                row.get::<_, Vec<u8>>(5)?,
                row.get::<_, Vec<u8>>(6)?,
                row.get::<_, Vec<u8>>(7)?,
                row.get::<_, Vec<u8>>(8)?,
            ))
        })
        .map_err(|error| integrity_error(format!("cannot enumerate event chain: {error}")))?;
    let mut expected_sequence = 1_i64;
    let mut previous_hash = ZERO_MAC.to_vec();
    let mut chain_root = ZERO_MAC;
    for row in rows {
        let (sequence, table, operation, record_key, old_mac, new_mac, event_root, previous, entry) =
            row.map_err(|error| integrity_error(format!("cannot read event chain: {error}")))?;
        if sequence != expected_sequence {
            return Err(integrity_error(format!(
                "event sequence {sequence} is not contiguous at {expected_sequence}"
            )));
        }
        if old_mac.len() != MAC_BYTES
            || new_mac.len() != MAC_BYTES
            || event_root.len() != MAC_BYTES
            || previous.len() != MAC_BYTES
            || entry.len() != MAC_BYTES
        {
            return Err(integrity_error(format!(
                "event {sequence} contains a malformed digest"
            )));
        }
        if previous != previous_hash {
            return Err(integrity_error(format!(
                "event {sequence} does not link to its predecessor"
            )));
        }
        xor_into(&mut chain_root, &old_mac)?;
        xor_into(&mut chain_root, &new_mac)?;
        if event_root.as_slice() != chain_root {
            return Err(integrity_error(format!(
                "event {sequence} does not prove its resulting state root"
            )));
        }
        let expected = event_mac(
            &key,
            &EventMacInput {
                sequence,
                table: &table,
                operation: &operation,
                record_key: &record_key,
                old_mac: &old_mac,
                new_mac: &new_mac,
                state_root: &event_root,
                previous_hash: &previous,
            },
        );
        if entry.as_slice() != expected {
            return Err(integrity_error(format!(
                "event {sequence} authentication failed"
            )));
        }
        previous_hash = entry;
        expected_sequence = expected_sequence
            .checked_add(1)
            .ok_or_else(|| integrity_error("event sequence overflow"))?;
    }
    let observed_count = expected_sequence - 1;
    if observed_count != event_count {
        return Err(integrity_error(format!(
            "event count {event_count} disagrees with {observed_count} stored events"
        )));
    }
    if stored_head != previous_hash {
        return Err(integrity_error(
            "event-chain head does not match its final event",
        ));
    }
    if stored_root.as_slice() != chain_root {
        return Err(integrity_error(
            "event-chain root does not match the authenticated state root",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::context::{SqliteContextManager, UsageRecord};

    struct TestDatabase {
        path: std::path::PathBuf,
    }

    impl TestDatabase {
        fn new(label: &str) -> Self {
            Self {
                path: std::env::temp_dir().join(format!(
                    "aiagentos-accounting-integrity-{label}-{}.db",
                    uuid::Uuid::new_v4()
                )),
            }
        }
    }

    impl Drop for TestDatabase {
        fn drop(&mut self) {
            for suffix in ["", "-wal", "-shm"] {
                let _ = std::fs::remove_file(format!("{}{suffix}", self.path.display()));
            }
        }
    }

    fn sample_usage(cost_micros: u64) -> UsageRecord {
        UsageRecord {
            tokens_used: 12,
            input_tokens: 10,
            output_tokens: 2,
            cached_tokens: 0,
            llm_requests: 1,
            retries: 0,
            provider_latency_ms: 5,
            provider_reported_requests: 1,
            estimated_requests: 0,
            provider: "test".to_string(),
            model: "test-model".to_string(),
            tool_calls: 0,
            estimated_cost_usd: cost_micros as f64 / 1_000_000.0,
            cost_micros,
        }
    }

    #[test]
    fn authenticated_usage_survives_clean_restart() {
        let database = TestDatabase::new("usage-restart");
        {
            let manager = SqliteContextManager::new(&database.path).unwrap();
            manager
                .log_usage(uuid::Uuid::new_v4(), &sample_usage(42))
                .unwrap();
            let connection = manager.conn.lock().unwrap();
            verify(&connection).unwrap();
            let event_count: i64 = connection
                .query_row(
                    "SELECT event_count FROM accounting_integrity WHERE singleton = 1",
                    [],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(event_count, 2);
        }

        let reopened = SqliteContextManager::new(&database.path).unwrap();
        verify(&reopened.conn.lock().unwrap()).unwrap();
    }

    #[test]
    fn mutation_events_retain_only_fixed_width_pseudonymous_record_keys() {
        let manager = SqliteContextManager::in_memory().unwrap();
        let agent = uuid::Uuid::new_v4();
        manager.log_usage(agent, &sample_usage(42)).unwrap();
        let connection = manager.conn.lock().unwrap();
        let record_key: String = connection
            .query_row(
                "SELECT record_key FROM accounting_events WHERE sequence = 2",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(record_key.len(), MAC_BYTES * 2);
        assert!(record_key.bytes().all(|byte| byte.is_ascii_hexdigit()));
        assert!(!record_key.contains(&agent.to_string()));
        assert!(!record_key.contains("test-model"));
    }

    #[test]
    fn no_op_quota_floor_update_does_not_grow_the_event_chain() {
        let manager = SqliteContextManager::in_memory().unwrap();
        assert_eq!(manager.provider_rate_usage(0).unwrap().tokens, 0);
        let event_count: i64 = manager
            .conn
            .lock()
            .unwrap()
            .query_row(
                "SELECT event_count FROM accounting_integrity WHERE singleton = 1",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(event_count, 1);
    }

    #[test]
    fn offline_usage_row_tamper_fails_closed_on_restart() {
        let database = TestDatabase::new("usage-tamper");
        {
            let manager = SqliteContextManager::new(&database.path).unwrap();
            manager
                .log_usage(uuid::Uuid::new_v4(), &sample_usage(42))
                .unwrap();
        }
        {
            let connection = Connection::open(&database.path).unwrap();
            connection
                .execute("DROP TRIGGER accounting_usage_log_update", [])
                .unwrap();
            connection
                .execute("UPDATE usage_log SET cost_micros = cost_micros + 1", [])
                .unwrap();
        }

        let error = SqliteContextManager::new(&database.path)
            .err()
            .expect("tampered accounting must fail startup");
        assert!(error.to_string().contains("authenticated root"), "{error}");
    }

    #[test]
    fn offline_quota_row_tamper_fails_closed_on_restart() {
        let database = TestDatabase::new("quota-tamper");
        {
            let manager = SqliteContextManager::new(&database.path).unwrap();
            manager
                .charge_provider_rate_tokens(uuid::Uuid::new_v4(), 7, 42)
                .unwrap();
        }
        {
            let connection = Connection::open(&database.path).unwrap();
            connection
                .execute("DROP TRIGGER accounting_quota_epochs_update", [])
                .unwrap();
            let altered = 43_u64.to_be_bytes();
            connection
                .execute("UPDATE quota_epochs SET tokens = ?1", [altered.as_slice()])
                .unwrap();
        }

        let error = SqliteContextManager::new(&database.path)
            .err()
            .expect("tampered quota accounting must fail startup");
        assert!(error.to_string().contains("authenticated root"), "{error}");
    }

    #[test]
    fn event_chain_tamper_fails_closed_on_restart() {
        let database = TestDatabase::new("event-tamper");
        {
            let manager = SqliteContextManager::new(&database.path).unwrap();
            manager
                .log_usage(uuid::Uuid::new_v4(), &sample_usage(42))
                .unwrap();
        }
        {
            let connection = Connection::open(&database.path).unwrap();
            connection
                .execute(
                    "UPDATE accounting_events SET record_key = 'forged'
                     WHERE sequence = 1",
                    [],
                )
                .unwrap();
        }

        let error = SqliteContextManager::new(&database.path)
            .err()
            .expect("tampered event chain must fail startup");
        assert!(
            error.to_string().contains("authentication failed"),
            "{error}"
        );
    }

    #[test]
    fn event_tail_truncation_cannot_be_hidden_by_resetting_chain_metadata() {
        let database = TestDatabase::new("event-truncation");
        {
            let manager = SqliteContextManager::new(&database.path).unwrap();
            let agent = uuid::Uuid::new_v4();
            manager.log_usage(agent, &sample_usage(41)).unwrap();
            manager.log_usage(agent, &sample_usage(42)).unwrap();
        }
        {
            let connection = Connection::open(&database.path).unwrap();
            connection
                .execute("DELETE FROM accounting_events WHERE sequence = 3", [])
                .unwrap();
            connection
                .execute(
                    "UPDATE accounting_integrity
                     SET event_count = 2,
                         head_hash = (
                             SELECT entry_hash FROM accounting_events
                             WHERE sequence = 2
                         )
                     WHERE singleton = 1",
                    [],
                )
                .unwrap();
        }

        let error = SqliteContextManager::new(&database.path)
            .err()
            .expect("truncated event chain must fail startup");
        assert!(error.to_string().contains("event-chain root"), "{error}");
    }

    #[test]
    fn replaced_protected_trigger_fails_closed_before_startup_mutation() {
        let database = TestDatabase::new("trigger-tamper");
        {
            let manager = SqliteContextManager::new(&database.path).unwrap();
            manager
                .log_usage(uuid::Uuid::new_v4(), &sample_usage(42))
                .unwrap();
        }
        {
            let connection = Connection::open(&database.path).unwrap();
            connection
                .execute_batch(
                    "DROP TRIGGER accounting_usage_log_insert;
                     CREATE TRIGGER accounting_usage_log_insert
                     AFTER INSERT ON usage_log BEGIN SELECT 1; END;",
                )
                .unwrap();
        }

        let error = SqliteContextManager::new(&database.path)
            .err()
            .expect("replaced accounting trigger must fail startup");
        assert!(
            error.to_string().contains("not the canonical definition"),
            "{error}"
        );
    }

    #[test]
    fn unexpected_trigger_cannot_wait_for_the_registered_mac_oracle() {
        let database = TestDatabase::new("trigger-oracle");
        {
            let manager = SqliteContextManager::new(&database.path).unwrap();
            manager
                .log_usage(uuid::Uuid::new_v4(), &sample_usage(42))
                .unwrap();
        }
        {
            let connection = Connection::open(&database.path).unwrap();
            connection
                .execute_batch(
                    "CREATE TRIGGER accounting_oracle
                     AFTER INSERT ON agents BEGIN
                         SELECT aios_accounting_mac('oracle', NEW.id);
                     END;",
                )
                .unwrap();
        }

        let error = SqliteContextManager::new(&database.path)
            .err()
            .expect("unexpected trigger must fail startup");
        assert!(error.to_string().contains("unexpected trigger"), "{error}");
    }

    #[test]
    fn removed_integrity_schema_cannot_be_reinitialized_as_a_new_baseline() {
        let database = TestDatabase::new("schema-removal");
        {
            let manager = SqliteContextManager::new(&database.path).unwrap();
            manager
                .log_usage(uuid::Uuid::new_v4(), &sample_usage(42))
                .unwrap();
        }
        {
            let connection = Connection::open(&database.path).unwrap();
            connection
                .execute_batch(
                    "DROP TABLE accounting_events;
                     DROP TABLE accounting_integrity;",
                )
                .unwrap();
        }

        let error = SqliteContextManager::new(&database.path)
            .err()
            .expect("removed integrity schema must fail startup");
        assert!(
            error
                .to_string()
                .contains("requires accounting integrity state"),
            "{error}"
        );
    }

    #[test]
    fn rolled_back_accounting_write_leaves_no_root_or_event_change() {
        let manager = SqliteContextManager::in_memory().unwrap();
        let mut connection = manager.conn.lock().unwrap();
        let before: (Vec<u8>, i64) = connection
            .query_row(
                "SELECT state_root, event_count FROM accounting_integrity
                 WHERE singleton = 1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        let transaction = connection.transaction().unwrap();
        let id = uuid::Uuid::new_v4().to_string();
        transaction
            .execute(
                "INSERT INTO usage_log
                    (id, agent_id, timestamp, tokens_used, cost_micros)
                 VALUES (?1, ?2, ?3, 1, 1)",
                params![
                    &id,
                    uuid::Uuid::new_v4().to_string(),
                    "2026-01-01T00:00:00Z"
                ],
            )
            .unwrap();
        assert!(transaction
            .execute(
                "INSERT INTO usage_log
                    (id, agent_id, timestamp, tokens_used, cost_micros)
                 VALUES (?1, ?2, ?3, 1, 1)",
                params![
                    &id,
                    uuid::Uuid::new_v4().to_string(),
                    "2026-01-01T00:00:00Z"
                ],
            )
            .is_err());
        transaction.rollback().unwrap();

        let after: (Vec<u8>, i64) = connection
            .query_row(
                "SELECT state_root, event_count FROM accounting_integrity
                 WHERE singleton = 1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(after, before);
        verify(&connection).unwrap();
    }
}
