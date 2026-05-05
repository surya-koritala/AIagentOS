//! Database integration — query SQL/NoSQL databases.

use serde::{Deserialize, Serialize};

/// Supported database types.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DatabaseType { SQLite, PostgreSQL, MySQL }

/// Database connection config.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatabaseConfig {
    pub name: String,
    pub db_type: DatabaseType,
    pub connection_string: String,
    pub read_only: bool,
}

/// Database query result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueryResult {
    pub columns: Vec<String>,
    pub rows: Vec<Vec<serde_json::Value>>,
    pub rows_affected: u64,
}

/// Execute a query against a SQLite database.
pub fn query_sqlite(path: &str, sql: &str, read_only: bool) -> Result<QueryResult, String> {
    let flags = if read_only {
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY
    } else {
        rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE
    };

    let conn = rusqlite::Connection::open_with_flags(path, flags)
        .map_err(|e| format!("Connection failed: {}", e))?;

    // Check if it's a SELECT query
    let trimmed = sql.trim().to_uppercase();
    if trimmed.starts_with("SELECT") || trimmed.starts_with("PRAGMA") {
        let mut stmt = conn.prepare(sql).map_err(|e| format!("Prepare failed: {}", e))?;
        let columns: Vec<String> = stmt.column_names().iter().map(|s| s.to_string()).collect();
        let col_count = columns.len();

        let rows: Vec<Vec<serde_json::Value>> = stmt.query_map([], |row| {
            let mut values = Vec::new();
            for i in 0..col_count {
                let val: rusqlite::types::Value = row.get_unwrap(i);
                values.push(match val {
                    rusqlite::types::Value::Null => serde_json::Value::Null,
                    rusqlite::types::Value::Integer(n) => serde_json::json!(n),
                    rusqlite::types::Value::Real(f) => serde_json::json!(f),
                    rusqlite::types::Value::Text(s) => serde_json::json!(s),
                    rusqlite::types::Value::Blob(b) => serde_json::json!(format!("<blob {} bytes>", b.len())),
                });
            }
            Ok(values)
        }).map_err(|e| format!("Query failed: {}", e))?
        .filter_map(|r| r.ok())
        .collect();

        Ok(QueryResult { columns, rows, rows_affected: 0 })
    } else {
        if read_only {
            return Err("Database is read-only. Only SELECT queries allowed.".into());
        }
        let affected = conn.execute(sql, []).map_err(|e| format!("Execute failed: {}", e))?;
        Ok(QueryResult { columns: vec![], rows: vec![], rows_affected: affected as u64 })
    }
}

/// Get schema information for a SQLite database.
pub fn get_schema(path: &str) -> Result<String, String> {
    let result = query_sqlite(path, "SELECT sql FROM sqlite_master WHERE type='table' ORDER BY name", true)?;
    let schemas: Vec<String> = result.rows.iter()
        .filter_map(|row| row.first()?.as_str().map(|s| s.to_string()))
        .collect();
    Ok(schemas.join("\n\n"))
}

impl QueryResult {
    /// Format as a readable table string for the LLM.
    pub fn to_table_string(&self) -> String {
        if self.columns.is_empty() {
            return format!("Rows affected: {}", self.rows_affected);
        }
        let mut out = self.columns.join(" | ") + "\n";
        out += &format!("{}\n", "-".repeat(out.len()));
        for row in &self.rows {
            let cells: Vec<String> = row.iter().map(|v| match v {
                serde_json::Value::String(s) => s.clone(),
                serde_json::Value::Null => "NULL".into(),
                other => other.to_string(),
            }).collect();
            out += &cells.join(" | ");
            out += "\n";
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn query_sqlite_select() {
        let path = "/tmp/test_db_agent_os.db";
        let conn = rusqlite::Connection::open(path).unwrap();
        conn.execute("CREATE TABLE IF NOT EXISTS test (id INTEGER, name TEXT)", []).unwrap();
        conn.execute("INSERT INTO test VALUES (1, 'alice')", []).unwrap();
        conn.execute("INSERT INTO test VALUES (2, 'bob')", []).unwrap();
        drop(conn);

        let result = query_sqlite(path, "SELECT * FROM test", true).unwrap();
        assert_eq!(result.columns, vec!["id", "name"]);
        assert_eq!(result.rows.len(), 2);

        std::fs::remove_file(path).ok();
    }

    #[test]
    fn read_only_blocks_writes() {
        let path = "/tmp/test_db_ro.db";
        let conn = rusqlite::Connection::open(path).unwrap();
        conn.execute("CREATE TABLE IF NOT EXISTS t (x INTEGER)", []).unwrap();
        drop(conn);

        let result = query_sqlite(path, "INSERT INTO t VALUES (1)", true);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("read-only"));

        std::fs::remove_file(path).ok();
    }
}
