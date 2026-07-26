-- AIagentOS storage fixture produced from the schema shipped by tag v0.1.0
-- (commit 0b515f358ccff684118ae566b321ca4c299cbc49).
-- Released v0.1.0 stores were unowned legacy databases:
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

INSERT INTO contexts(agent_id, context_json, updated_at) VALUES (
    '00000000-0000-0000-0000-000000000101',
    '{"conversation_history":[{"role":"user","content":"v0.1-context","timestamp":"2023-01-01T00:00:00Z"}],"working_state":{"release":"v0.1.0"},"active_tasks":[],"intermediate_results":[],"token_count":4}',
    '2023-01-01T00:00:00Z'
);
INSERT INTO facts(
    id, agent_id, content, category, created_at, last_accessed_at, embedding_json
) VALUES (
    '00000000-0000-0000-0000-000000000111',
    '00000000-0000-0000-0000-000000000101',
    'v0.1-memory',
    '"Fact"',
    '2023-01-01T00:00:00Z',
    '2023-01-01T00:00:00Z',
    '[0.1,0.2]'
);
INSERT INTO conversations(
    id, agent_id, messages_json, created_at, updated_at
) VALUES (
    '00000000-0000-0000-0000-000000000121',
    '00000000-0000-0000-0000-000000000101',
    '[{"role":"user","content":"v0.1-conversation","timestamp":"2023-01-01T00:00:00Z"}]',
    '2023-01-01T00:00:00Z',
    '2023-01-01T00:00:00Z'
);
INSERT INTO conversations_fts(conversation_id, content) VALUES (
    '00000000-0000-0000-0000-000000000121',
    'v0.1-conversation'
);
INSERT INTO usage_log(
    id, agent_id, timestamp, tokens_used, model, estimated_cost_usd
) VALUES (
    '00000000-0000-0000-0000-000000000131',
    '00000000-0000-0000-0000-000000000101',
    '2023-01-01T00:00:00Z',
    17,
    'v0.1-model',
    0.125
);
