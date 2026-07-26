-- AIagentOS storage fixture produced from the schema shipped by tag v0.2.0
-- (commit b70685ec2c3cba48c14ac8448a0358490d31e8bc).
-- Released v0.2.0 stores were unowned legacy databases:
-- application_id=0 and user_version=0.
PRAGMA application_id = 0;
PRAGMA user_version = 0;

CREATE TABLE contexts (
    agent_id TEXT PRIMARY KEY,
    context_json TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE TABLE facts (
    id TEXT PRIMARY KEY,
    agent_id TEXT NOT NULL,
    content TEXT NOT NULL,
    category TEXT NOT NULL,
    created_at TEXT NOT NULL,
    last_accessed_at TEXT NOT NULL,
    embedding_json TEXT
);
CREATE INDEX idx_facts_agent ON facts(agent_id);
CREATE INDEX idx_facts_category ON facts(agent_id, category);
CREATE TABLE conversations (
    id TEXT PRIMARY KEY,
    agent_id TEXT NOT NULL,
    messages_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE INDEX idx_conv_agent ON conversations(agent_id);
CREATE INDEX idx_conv_updated ON conversations(updated_at);
CREATE TABLE usage_log (
    id TEXT PRIMARY KEY,
    agent_id TEXT NOT NULL,
    timestamp TEXT NOT NULL,
    tokens_used INTEGER NOT NULL,
    model TEXT,
    estimated_cost_usd REAL
);
CREATE VIRTUAL TABLE conversations_fts
    USING fts5(conversation_id, content);
CREATE TABLE agent_kv (
    agent_id TEXT NOT NULL,
    key TEXT NOT NULL,
    value TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    PRIMARY KEY(agent_id, key)
);
CREATE INDEX idx_agent_kv_agent ON agent_kv(agent_id);
CREATE TABLE context_snapshots (
    agent_id TEXT NOT NULL,
    label TEXT NOT NULL,
    context_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    PRIMARY KEY(agent_id, label)
);
CREATE INDEX idx_snapshots_agent ON context_snapshots(agent_id);
CREATE TABLE agents (
    id TEXT PRIMARY KEY,
    session_id TEXT NOT NULL,
    name TEXT NOT NULL,
    task TEXT NOT NULL,
    llm_provider TEXT NOT NULL,
    permission_profile TEXT NOT NULL,
    priority INTEGER NOT NULL,
    status TEXT NOT NULL,
    sandbox_config_json TEXT,
    created_at TEXT NOT NULL,
    last_activity_at TEXT NOT NULL
);
ALTER TABLE agents
    ADD COLUMN tenant_id TEXT NOT NULL DEFAULT 'default';
CREATE TABLE tenants (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE TABLE users (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    username TEXT NOT NULL,
    email TEXT NOT NULL,
    role TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE INDEX idx_users_tenant ON users(tenant_id);
CREATE TABLE api_keys (
    key_hash TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    user_id TEXT NOT NULL,
    tenant_id TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE TABLE sessions (
    token_hash TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    tenant_id TEXT NOT NULL,
    expires_at TEXT NOT NULL
);

INSERT INTO contexts(agent_id, context_json, updated_at) VALUES (
    '00000000-0000-0000-0000-000000000201',
    '{"conversation_history":[{"role":"user","content":"v0.2-context","timestamp":"2023-02-01T00:00:00Z"}],"working_state":{"release":"v0.2.0"},"active_tasks":[],"intermediate_results":[],"token_count":4}',
    '2023-02-01T00:00:00Z'
);
INSERT INTO facts(
    id, agent_id, content, category, created_at, last_accessed_at, embedding_json
) VALUES (
    '00000000-0000-0000-0000-000000000211',
    '00000000-0000-0000-0000-000000000201',
    'v0.2-memory',
    '"Fact"',
    '2023-02-01T00:00:00Z',
    '2023-02-01T00:00:00Z',
    '[0.2,0.3]'
);
INSERT INTO conversations(
    id, agent_id, messages_json, created_at, updated_at
) VALUES (
    '00000000-0000-0000-0000-000000000221',
    '00000000-0000-0000-0000-000000000201',
    '[{"role":"user","content":"v0.2-conversation","timestamp":"2023-02-01T00:00:00Z"}]',
    '2023-02-01T00:00:00Z',
    '2023-02-01T00:00:00Z'
);
INSERT INTO conversations_fts(conversation_id, content) VALUES (
    '00000000-0000-0000-0000-000000000221',
    'v0.2-conversation'
);
INSERT INTO usage_log(
    id, agent_id, timestamp, tokens_used, model, estimated_cost_usd
) VALUES (
    '00000000-0000-0000-0000-000000000231',
    '00000000-0000-0000-0000-000000000201',
    '2023-02-01T00:00:00Z',
    23,
    'v0.2-model',
    0.25
);
INSERT INTO agent_kv(agent_id, key, value, updated_at) VALUES (
    '00000000-0000-0000-0000-000000000201',
    'release-proof',
    'v0.2-kv',
    '2023-02-01T00:00:00Z'
);
INSERT INTO context_snapshots(agent_id, label, context_json, created_at) VALUES (
    '00000000-0000-0000-0000-000000000201',
    'released',
    '{"release":"v0.2.0"}',
    '2023-02-01T00:00:00Z'
);
INSERT INTO tenants(id, name, created_at) VALUES (
    'tenant-v020',
    'v0.2 tenant',
    '2023-02-01T00:00:00Z'
);
INSERT INTO users(id, tenant_id, username, email, role, created_at) VALUES (
    'user-v020',
    'tenant-v020',
    'v020-user',
    'v020@example.invalid',
    'admin',
    '2023-02-01T00:00:00Z'
);
INSERT INTO api_keys(key_hash, name, user_id, tenant_id, created_at) VALUES (
    'v020-key-hash',
    'released key',
    'user-v020',
    'tenant-v020',
    '2023-02-01T00:00:00Z'
);
INSERT INTO sessions(token_hash, user_id, tenant_id, expires_at) VALUES (
    'v020-session-hash',
    'user-v020',
    'tenant-v020',
    '2033-02-01T00:00:00Z'
);
INSERT INTO agents(
    id, session_id, name, task, llm_provider, permission_profile, priority,
    status, sandbox_config_json, created_at, last_activity_at, tenant_id
) VALUES (
    '00000000-0000-0000-0000-000000000201',
    'v020-session',
    'v0.2 agent',
    'survive upgrade',
    'stub',
    'standard',
    3,
    'Created',
    NULL,
    '2023-02-01T00:00:00Z',
    '2023-02-01T00:00:00Z',
    'tenant-v020'
);
