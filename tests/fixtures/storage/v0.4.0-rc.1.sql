-- AIagentOS storage fixture produced from the v0.4.0-rc.1 candidate schema
-- at commit 799578afc022c6e8fa9e24517725ba726f372cef.
-- This owned store was migrated through the production v0.3.0 -> schema 7 path
-- before the candidate tag was created.
PRAGMA application_id = 1095323475;
PRAGMA user_version = 7;

/* WARNING: Script requires that SQLITE_DBCONFIG_DEFENSIVE be disabled */
PRAGMA foreign_keys=OFF;
BEGIN TRANSACTION;
CREATE TABLE contexts (
    agent_id TEXT PRIMARY KEY,
    context_json TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
INSERT INTO contexts VALUES('00000000-0000-0000-0000-000000000401','{"conversation_history":[{"role":"user","content":"v0.4-rc1-context","timestamp":"2026-07-30T00:00:00Z"}],"working_state":{"release":"v0.4.0-rc.1"},"active_tasks":[],"intermediate_results":[],"token_count":4}','2026-07-30T00:00:00Z');
CREATE TABLE facts (
    id TEXT PRIMARY KEY,
    agent_id TEXT NOT NULL,
    content TEXT NOT NULL,
    category TEXT NOT NULL,
    created_at TEXT NOT NULL,
    last_accessed_at TEXT NOT NULL,
    embedding_json TEXT
, embedding_model TEXT NOT NULL DEFAULT 'legacy', embedding_version INTEGER NOT NULL DEFAULT 0, embedding_dim INTEGER NOT NULL DEFAULT 0, content_hash TEXT NOT NULL DEFAULT '');
INSERT INTO facts VALUES('00000000-0000-0000-0000-000000000411','00000000-0000-0000-0000-000000000401','v0.4-rc1-memory','"Fact"','2026-07-30T00:00:00Z','2026-07-30T00:00:00Z','[0.3,0.4]','legacy',0,0,'');
CREATE TABLE conversations (
    id TEXT PRIMARY KEY,
    agent_id TEXT NOT NULL,
    messages_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
INSERT INTO conversations VALUES('00000000-0000-0000-0000-000000000421','00000000-0000-0000-0000-000000000401','[{"role":"user","content":"v0.4-rc1-conversation","timestamp":"2026-07-30T00:00:00Z"}]','2026-07-30T00:00:00Z','2026-07-30T00:00:00Z');
CREATE TABLE usage_log (
    id TEXT PRIMARY KEY,
    agent_id TEXT NOT NULL,
    timestamp TEXT NOT NULL,
    tokens_used INTEGER NOT NULL,
    model TEXT,
    estimated_cost_usd REAL
, provider TEXT, tool_calls INTEGER NOT NULL DEFAULT 0, input_tokens INTEGER NOT NULL DEFAULT 0, output_tokens INTEGER NOT NULL DEFAULT 0, cached_tokens INTEGER NOT NULL DEFAULT 0, llm_requests INTEGER NOT NULL DEFAULT 0, retries INTEGER NOT NULL DEFAULT 0, provider_latency_ms INTEGER NOT NULL DEFAULT 0, provider_reported_requests INTEGER NOT NULL DEFAULT 0, estimated_requests INTEGER NOT NULL DEFAULT 0, cost_micros INTEGER NOT NULL DEFAULT 0);
INSERT INTO usage_log VALUES('00000000-0000-0000-0000-000000000431','00000000-0000-0000-0000-000000000401','2026-07-30T00:00:00Z',41,'v0.4-rc1-model',0.5,NULL,0,0,0,0,0,0,0,0,0,500000);
PRAGMA writable_schema=ON;
INSERT INTO sqlite_schema(type,name,tbl_name,rootpage,sql)VALUES('table','conversations_fts','conversations_fts',0,'CREATE VIRTUAL TABLE conversations_fts
    USING fts5(conversation_id, content)');
CREATE TABLE IF NOT EXISTS 'conversations_fts_data'(id INTEGER PRIMARY KEY, block BLOB);
INSERT INTO conversations_fts_data VALUES(1,x'010504');
INSERT INTO conversations_fts_data VALUES(10,x'000000000101010001010101');
INSERT INTO conversations_fts_data VALUES(137438953473,x'0000004f05303030303001060303030504303030300102020904303432310102060101340106010103010c636f6e766572736174696f6e010601010501037263310106010104010276300106010102040b090908130a');
CREATE TABLE IF NOT EXISTS 'conversations_fts_idx'(segid, term, pgno, PRIMARY KEY(segid, term)) WITHOUT ROWID;
INSERT INTO conversations_fts_idx VALUES(1,x'',2);
CREATE TABLE IF NOT EXISTS 'conversations_fts_content'(id INTEGER PRIMARY KEY, c0, c1);
INSERT INTO conversations_fts_content VALUES(1,'00000000-0000-0000-0000-000000000421','v0.4-rc1-conversation');
CREATE TABLE IF NOT EXISTS 'conversations_fts_docsize'(id INTEGER PRIMARY KEY, sz BLOB);
INSERT INTO conversations_fts_docsize VALUES(1,x'0504');
CREATE TABLE IF NOT EXISTS 'conversations_fts_config'(k PRIMARY KEY, v) WITHOUT ROWID;
INSERT INTO conversations_fts_config VALUES('version',4);
CREATE TABLE agent_kv (
    agent_id TEXT NOT NULL,
    key TEXT NOT NULL,
    value TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    PRIMARY KEY(agent_id, key)
);
INSERT INTO agent_kv VALUES('00000000-0000-0000-0000-000000000401','release-proof','v0.4-rc1-kv','2026-07-30T00:00:00Z');
CREATE TABLE context_snapshots (
    agent_id TEXT NOT NULL,
    label TEXT NOT NULL,
    context_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    PRIMARY KEY(agent_id, label)
);
INSERT INTO context_snapshots VALUES('00000000-0000-0000-0000-000000000401','released','{"release":"v0.4.0-rc.1"}','2026-07-30T00:00:00Z');
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
, tenant_id TEXT NOT NULL DEFAULT 'default');
INSERT INTO agents VALUES('00000000-0000-0000-0000-000000000401','00000000-0000-0000-0000-000000000402','v0.4 rc1 agent','survive upgrade','stub','standard',3,'"Running"',NULL,'2026-07-30T00:00:00Z','2026-07-30T00:00:00Z','tenant-v040-rc1');
CREATE TABLE tenants (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    created_at TEXT NOT NULL
);
INSERT INTO tenants VALUES('tenant-v040-rc1','v0.4 rc1 tenant','2026-07-30T00:00:00Z');
CREATE TABLE users (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    username TEXT NOT NULL,
    email TEXT NOT NULL,
    role TEXT NOT NULL,
    created_at TEXT NOT NULL
);
INSERT INTO users VALUES('user-v040-rc1','tenant-v040-rc1','v040-rc1-user','v040-rc1@example.invalid','admin','2026-07-30T00:00:00Z');
CREATE TABLE api_keys (
    key_hash TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    user_id TEXT NOT NULL,
    tenant_id TEXT NOT NULL,
    created_at TEXT NOT NULL
);
INSERT INTO api_keys VALUES('v040-rc1-key-hash','released key','user-v040-rc1','tenant-v040-rc1','2026-07-30T00:00:00Z');
CREATE TABLE sessions (
    token_hash TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    tenant_id TEXT NOT NULL,
    expires_at TEXT NOT NULL
);
INSERT INTO sessions VALUES('v040-rc1-session-hash','user-v040-rc1','tenant-v040-rc1','2036-07-30T00:00:00Z');
CREATE TABLE context_spills (
                agent_id TEXT NOT NULL,
                key TEXT NOT NULL,
                tenant_id TEXT NOT NULL,
                sha256 TEXT NOT NULL,
                byte_count INTEGER NOT NULL,
                created_at TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                PRIMARY KEY(agent_id, key)
            );
CREATE TABLE context_pressure (
                agent_id TEXT PRIMARY KEY,
                active_tokens INTEGER NOT NULL,
                budget_tokens INTEGER NOT NULL,
                spill_count INTEGER NOT NULL DEFAULT 0,
                evicted_messages INTEGER NOT NULL DEFAULT 0,
                error_count INTEGER NOT NULL DEFAULT 0,
                last_error TEXT,
                updated_at TEXT NOT NULL
            );
CREATE TABLE generation_checkpoints (
                id TEXT PRIMARY KEY,
                agent_id TEXT NOT NULL,
                tenant_id TEXT NOT NULL,
                version INTEGER NOT NULL,
                provider_id TEXT NOT NULL,
                model_id TEXT NOT NULL,
                checkpoint_json TEXT NOT NULL,
                status TEXT NOT NULL,
                created_at TEXT NOT NULL,
                expires_at TEXT NOT NULL
            );
CREATE TABLE loaded_package_instances (
                agent_id TEXT PRIMARY KEY,
                tenant_id TEXT NOT NULL,
                name TEXT NOT NULL,
                provider TEXT NOT NULL,
                profile TEXT NOT NULL,
                loaded_at TEXT NOT NULL
            );
CREATE TABLE package_trust_keys (
                tenant_id TEXT NOT NULL,
                key_id TEXT NOT NULL,
                publisher TEXT NOT NULL,
                public_key BLOB NOT NULL,
                status TEXT NOT NULL CHECK (status IN ('trusted', 'revoked')),
                valid_from TEXT NOT NULL,
                valid_until TEXT,
                superseded_by TEXT,
                created_at TEXT NOT NULL,
                PRIMARY KEY (tenant_id, key_id)
            );
CREATE TABLE package_artifacts (
                tenant_id TEXT NOT NULL,
                name TEXT NOT NULL,
                version TEXT NOT NULL,
                publisher TEXT NOT NULL,
                digest TEXT NOT NULL,
                archive BLOB NOT NULL,
                manifest_json TEXT NOT NULL,
                yanked INTEGER NOT NULL DEFAULT 0 CHECK (yanked IN (0, 1)),
                published_at TEXT NOT NULL,
                PRIMARY KEY (tenant_id, name, version),
                UNIQUE (tenant_id, digest)
            );
CREATE TABLE package_installations (
                tenant_id TEXT NOT NULL,
                name TEXT NOT NULL,
                version TEXT NOT NULL,
                digest TEXT NOT NULL,
                lock_json TEXT NOT NULL,
                manifest_json TEXT NOT NULL,
                installed_at TEXT NOT NULL,
                PRIMARY KEY (tenant_id, name)
            );
CREATE TABLE package_install_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                tenant_id TEXT NOT NULL,
                name TEXT NOT NULL,
                snapshot_json TEXT NOT NULL,
                action TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
CREATE TABLE package_rate_limits (
                tenant_id TEXT NOT NULL,
                actor TEXT NOT NULL,
                window_started_at INTEGER NOT NULL,
                requests INTEGER NOT NULL CHECK (requests >= 0),
                PRIMARY KEY (tenant_id, actor)
            );
CREATE TABLE package_transparency (
                sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                tenant_id TEXT NOT NULL,
                action TEXT NOT NULL,
                name TEXT NOT NULL,
                version TEXT NOT NULL,
                digest TEXT NOT NULL,
                previous_hash TEXT NOT NULL,
                entry_hash TEXT NOT NULL UNIQUE,
                actor TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
CREATE TABLE package_audit (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                tenant_id TEXT NOT NULL,
                actor TEXT NOT NULL,
                action TEXT NOT NULL,
                name TEXT,
                version TEXT,
                outcome TEXT NOT NULL,
                digest TEXT,
                detail TEXT,
                created_at TEXT NOT NULL
            );
CREATE TABLE operator_tunables (
                name TEXT PRIMARY KEY,
                value INTEGER NOT NULL CHECK (value >= 0),
                revision INTEGER NOT NULL CHECK (revision > 0),
                updated_at TEXT NOT NULL,
                updated_by TEXT NOT NULL
            );
INSERT INTO operator_tunables VALUES('kernel.max_agents',0,1,'2026-07-30T05:37:55.902063+00:00','kernel-default');
INSERT INTO operator_tunables VALUES('operator.provider_probe_timeout_ms',5000,1,'2026-07-30T05:37:55.902256+00:00','kernel-default');
INSERT INTO operator_tunables VALUES('operator.snapshot_max_agents',10000,1,'2026-07-30T05:37:55.902452+00:00','kernel-default');
CREATE TABLE operator_tunable_audit (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                revision INTEGER,
                previous_value INTEGER,
                requested_value INTEGER,
                effective_value INTEGER,
                action TEXT NOT NULL,
                outcome TEXT NOT NULL,
                actor TEXT NOT NULL,
                reason TEXT,
                created_at TEXT NOT NULL
            );
INSERT INTO operator_tunable_audit VALUES(1,'kernel.max_agents',1,NULL,0,0,'bootstrap','applied','kernel-default',NULL,'2026-07-30T05:37:55.902063+00:00');
INSERT INTO operator_tunable_audit VALUES(2,'operator.provider_probe_timeout_ms',1,NULL,5000,5000,'bootstrap','applied','kernel-default',NULL,'2026-07-30T05:37:55.902256+00:00');
INSERT INTO operator_tunable_audit VALUES(3,'operator.snapshot_max_agents',1,NULL,10000,10000,'bootstrap','applied','kernel-default',NULL,'2026-07-30T05:37:55.902452+00:00');
CREATE TABLE service_runtime (
                name TEXT PRIMARY KEY,
                definition_revision TEXT NOT NULL,
                status TEXT NOT NULL,
                agent_id TEXT,
                restart_count INTEGER NOT NULL CHECK (restart_count >= 0),
                restart_attempts_total INTEGER NOT NULL CHECK (restart_attempts_total >= 0),
                last_exit_code INTEGER,
                desired_running INTEGER NOT NULL CHECK (desired_running IN (0, 1)),
                ready INTEGER NOT NULL CHECK (ready IN (0, 1)),
                healthy INTEGER NOT NULL CHECK (healthy IN (0, 1)),
                restart_exhausted INTEGER NOT NULL CHECK (restart_exhausted IN (0, 1)),
                last_failure TEXT,
                next_restart_at TEXT,
                restart_window_started_at TEXT,
                last_transition_at TEXT NOT NULL,
                dependency_blocks INTEGER NOT NULL CHECK (dependency_blocks >= 0)
            );
CREATE TABLE service_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                event TEXT NOT NULL,
                status TEXT NOT NULL,
                agent_id TEXT,
                reason TEXT,
                created_at TEXT NOT NULL
            );
CREATE TABLE deletion_receipts (
                id TEXT PRIMARY KEY CHECK (length(id) = 36),
                subject_kind TEXT NOT NULL
                    CHECK (subject_kind IN ('agent', 'user', 'tenant')),
                deleted_at TEXT NOT NULL,
                deleted_rows_json TEXT NOT NULL,
                retained_records_json TEXT NOT NULL
            );
CREATE TABLE quota_epoch_floor (
                singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                epoch BLOB NOT NULL
                    CHECK (typeof(epoch) = 'blob' AND length(epoch) = 8)
            );
INSERT INTO quota_epoch_floor VALUES(1,x'0000000001c60c51');
CREATE TABLE quota_epochs (
                scope_kind TEXT NOT NULL
                    CHECK (length(scope_kind) BETWEEN 1 AND 64),
                scope_id TEXT NOT NULL
                    CHECK (length(scope_id) BETWEEN 1 AND 1024),
                epoch BLOB NOT NULL
                    CHECK (typeof(epoch) = 'blob' AND length(epoch) = 8),
                requests BLOB NOT NULL
                    CHECK (typeof(requests) = 'blob' AND length(requests) = 8),
                tokens BLOB NOT NULL
                    CHECK (typeof(tokens) = 'blob' AND length(tokens) = 8),
                PRIMARY KEY (scope_kind, scope_id, epoch)
            ) WITHOUT ROWID;
CREATE TABLE quota_receipts (
                id TEXT PRIMARY KEY CHECK (length(id) = 36),
                receipt_kind TEXT NOT NULL
                    CHECK (length(receipt_kind) BETWEEN 1 AND 64),
                epoch BLOB NOT NULL
                    CHECK (typeof(epoch) = 'blob' AND length(epoch) = 8),
                state TEXT NOT NULL
                    CHECK (state IN ('reserved', 'in_flight', 'estimated', 'reconciled')),
                reserved_requests BLOB NOT NULL
                    CHECK (typeof(reserved_requests) = 'blob'
                           AND length(reserved_requests) = 8),
                reserved_tokens BLOB NOT NULL
                    CHECK (typeof(reserved_tokens) = 'blob'
                           AND length(reserved_tokens) = 8),
                actual_requests BLOB
                    CHECK (actual_requests IS NULL
                           OR (typeof(actual_requests) = 'blob'
                               AND length(actual_requests) = 8)),
                actual_tokens BLOB
                    CHECK (actual_tokens IS NULL
                           OR (typeof(actual_tokens) = 'blob'
                               AND length(actual_tokens) = 8))
            );
CREATE TABLE quota_receipt_scopes (
                receipt_id TEXT NOT NULL
                    REFERENCES quota_receipts(id) ON DELETE CASCADE,
                scope_order INTEGER NOT NULL DEFAULT 0
                    CHECK (scope_order >= 0),
                scope_kind TEXT NOT NULL
                    CHECK (length(scope_kind) BETWEEN 1 AND 64),
                scope_id TEXT NOT NULL
                    CHECK (length(scope_id) BETWEEN 1 AND 1024),
                reserved_requests BLOB NOT NULL
                    CHECK (typeof(reserved_requests) = 'blob'
                           AND length(reserved_requests) = 8),
                reserved_tokens BLOB NOT NULL
                    CHECK (typeof(reserved_tokens) = 'blob'
                           AND length(reserved_tokens) = 8),
                actual_requests BLOB
                    CHECK (actual_requests IS NULL
                           OR (typeof(actual_requests) = 'blob'
                               AND length(actual_requests) = 8)),
                actual_tokens BLOB
                    CHECK (actual_tokens IS NULL
                           OR (typeof(actual_tokens) = 'blob'
                               AND length(actual_tokens) = 8)),
                PRIMARY KEY (receipt_id, scope_kind, scope_id)
            ) WITHOUT ROWID;
CREATE TABLE quota_refunded_receipts (
                id TEXT PRIMARY KEY CHECK (length(id) = 36),
                epoch BLOB NOT NULL
                    CHECK (typeof(epoch) = 'blob' AND length(epoch) = 8)
            );
CREATE TABLE quota_migration_fence (
                epoch BLOB PRIMARY KEY
                    CHECK (typeof(epoch) = 'blob' AND length(epoch) = 8)
            ) WITHOUT ROWID;
INSERT INTO quota_migration_fence VALUES(x'0000000001c60c51');
CREATE TABLE cluster_node_identity (
                singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                node_id TEXT NOT NULL UNIQUE,
                private_key BLOB NOT NULL,
                public_key BLOB NOT NULL,
                fingerprint TEXT NOT NULL UNIQUE,
                created_at TEXT NOT NULL
            );
INSERT INTO cluster_node_identity VALUES(1,'a8cd0f14-6cce-4b34-a4f0-c3573601732f',x'3051020101300506032b657004220420ac28079113a473160e3c401c70c0be33ac3e393c5ca287a1de6ba422f2a08e24812100a5d736dd5512954b3f680e58fbd36209a77a423df6ed3d3d90de45187070318d',x'a5d736dd5512954b3f680e58fbd36209a77a423df6ed3d3d90de45187070318d','33c49f24754d70835c18278f5890788f9f5423c8c7370b0084a3eacb5d6232d5','2026-07-30T05:37:55.904521+00:00');
CREATE TABLE cluster_node_control (
                singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                availability TEXT NOT NULL,
                generation INTEGER NOT NULL CHECK (generation >= 0),
                profile_json TEXT NOT NULL,
                reason TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
INSERT INTO cluster_node_control VALUES(1,'active',0,'{"models":[],"sandbox_profiles":[],"labels":{}}','initial registration','2026-07-30T05:37:55.904565+00:00');
CREATE TABLE cluster_node_control_audit (
                generation INTEGER PRIMARY KEY,
                previous_availability TEXT NOT NULL,
                current_availability TEXT NOT NULL,
                actor TEXT NOT NULL,
                reason TEXT NOT NULL,
                changed_at TEXT NOT NULL
            );
CREATE TABLE cluster_membership_authority (
                singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                cluster_id TEXT NOT NULL UNIQUE,
                generation INTEGER NOT NULL CHECK (generation >= 0),
                created_at TEXT NOT NULL
            );
INSERT INTO cluster_membership_authority VALUES(1,'7dbef135-cedc-4e41-becd-bef90715d3d3',0,'2026-07-30T05:37:55.904565+00:00');
CREATE TABLE cluster_join_challenges (
                challenge_hash TEXT PRIMARY KEY,
                expires_at TEXT NOT NULL,
                consumed_at TEXT
            );
CREATE TABLE cluster_members (
                node_id TEXT PRIMARY KEY,
                fingerprint TEXT NOT NULL UNIQUE,
                public_key TEXT NOT NULL,
                tls_server_certificate_fingerprint TEXT,
                endpoint TEXT NOT NULL UNIQUE,
                server_version TEXT NOT NULL,
                min_protocol_version INTEGER NOT NULL CHECK (min_protocol_version >= 1),
                protocol_version INTEGER NOT NULL CHECK (protocol_version >= min_protocol_version),
                state TEXT NOT NULL,
                generation INTEGER NOT NULL CHECK (generation >= 1),
                joined_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                reason TEXT NOT NULL
            );
CREATE TABLE cluster_membership_audit (
                membership_generation INTEGER PRIMARY KEY,
                node_id TEXT NOT NULL,
                member_generation INTEGER NOT NULL CHECK (member_generation >= 1),
                previous_state TEXT,
                current_state TEXT NOT NULL,
                previous_tls_server_certificate_fingerprint TEXT,
                current_tls_server_certificate_fingerprint TEXT,
                actor TEXT NOT NULL,
                reason TEXT NOT NULL,
                changed_at TEXT NOT NULL
            );
CREATE TABLE cluster_agent_ownership (
                agent_id TEXT PRIMARY KEY CHECK (length(agent_id) = 36),
                owner_node_id TEXT NOT NULL CHECK (length(owner_node_id) = 36),
                authority_term INTEGER NOT NULL DEFAULT 1 CHECK (authority_term >= 1),
                fencing_token INTEGER NOT NULL CHECK (fencing_token >= 1),
                generation INTEGER NOT NULL CHECK (generation >= 1),
                state TEXT NOT NULL CHECK (state IN ('active', 'released')),
                lease_expires_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                reason TEXT NOT NULL
            );
CREATE TABLE cluster_agent_ownership_audit (
                agent_id TEXT NOT NULL CHECK (length(agent_id) = 36),
                generation INTEGER NOT NULL CHECK (generation >= 1),
                previous_owner_node_id TEXT,
                owner_node_id TEXT NOT NULL CHECK (length(owner_node_id) = 36),
                authority_term INTEGER NOT NULL DEFAULT 1 CHECK (authority_term >= 1),
                fencing_token INTEGER NOT NULL CHECK (fencing_token >= 1),
                operation TEXT NOT NULL CHECK (
                    operation IN ('claim', 'transfer', 'renew', 'release')
                ),
                actor TEXT NOT NULL,
                reason TEXT NOT NULL,
                changed_at TEXT NOT NULL,
                PRIMARY KEY (agent_id, generation)
            ) WITHOUT ROWID;
CREATE TABLE cluster_agent_mutation_fences (
                agent_id TEXT PRIMARY KEY CHECK (length(agent_id) = 36),
                cluster_id TEXT NOT NULL CHECK (length(cluster_id) = 36),
                owner_node_id TEXT NOT NULL CHECK (length(owner_node_id) = 36),
                authority_term INTEGER NOT NULL CHECK (authority_term >= 1),
                authority_generation INTEGER NOT NULL CHECK (authority_generation >= 1),
                fencing_token INTEGER NOT NULL CHECK (fencing_token >= 1),
                proof_expires_at TEXT NOT NULL,
                state TEXT NOT NULL CHECK (state IN ('active', 'retired')),
                installed_at TEXT NOT NULL,
                reason TEXT NOT NULL
            );
CREATE TABLE cluster_agent_mutation_fence_audit (
                agent_id TEXT NOT NULL CHECK (length(agent_id) = 36),
                fencing_token INTEGER NOT NULL CHECK (fencing_token >= 1),
                cluster_id TEXT NOT NULL CHECK (length(cluster_id) = 36),
                owner_node_id TEXT NOT NULL CHECK (length(owner_node_id) = 36),
                authority_term INTEGER NOT NULL CHECK (authority_term >= 1),
                authority_generation INTEGER NOT NULL CHECK (authority_generation >= 1),
                proof_expires_at TEXT NOT NULL,
                state TEXT NOT NULL CHECK (state IN ('active', 'retired')),
                actor TEXT NOT NULL,
                reason TEXT NOT NULL,
                changed_at TEXT NOT NULL,
                PRIMARY KEY (
                    agent_id, fencing_token, state, authority_generation,
                    authority_term, proof_expires_at
                )
            ) WITHOUT ROWID;
CREATE TABLE cluster_raft_meta (
                key TEXT PRIMARY KEY CHECK (
                    key IN ('vote', 'committed', 'last_purged')
                ),
                value BLOB NOT NULL CHECK (typeof(value) = 'blob')
            ) WITHOUT ROWID;
CREATE TABLE cluster_raft_log (
                log_index BLOB PRIMARY KEY
                    CHECK (typeof(log_index) = 'blob' AND length(log_index) = 8),
                entry_json BLOB NOT NULL CHECK (typeof(entry_json) = 'blob')
            ) WITHOUT ROWID;
CREATE TABLE cluster_raft_state (
                singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                last_applied_json BLOB,
                membership_json BLOB NOT NULL
                    CHECK (typeof(membership_json) = 'blob'),
                authority_state_json BLOB NOT NULL
                    CHECK (typeof(authority_state_json) = 'blob'),
                snapshot_sequence BLOB NOT NULL
                    CHECK (
                        typeof(snapshot_sequence) = 'blob'
                        AND length(snapshot_sequence) = 8
                    )
            );
CREATE TABLE cluster_raft_snapshot (
                singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                snapshot_id TEXT NOT NULL UNIQUE
                    CHECK (length(snapshot_id) BETWEEN 1 AND 255),
                meta_json BLOB NOT NULL CHECK (typeof(meta_json) = 'blob'),
                data BLOB NOT NULL CHECK (typeof(data) = 'blob'),
                created_at TEXT NOT NULL
            );
CREATE TABLE accounting_integrity (
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
INSERT INTO accounting_integrity VALUES(1,'hmac-sha256-local-secret-v1',x'0db237e83970a71ebafcd7a8216ace794d2768a1451afc76e21dd21b57e72a47',x'edd3c7558ad5e31e842c9a9b69ebbf5187c26fb87223109ec465b88e32bd41d3',1,x'adec24b1f5d85751881ec2ec981584fabfb33023a57a535aa58d57fdfaf70aa3');
CREATE TABLE accounting_events (
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
             );
INSERT INTO accounting_events VALUES(1,'*','genesis','baseline',x'0000000000000000000000000000000000000000000000000000000000000000',x'edd3c7558ad5e31e842c9a9b69ebbf5187c26fb87223109ec465b88e32bd41d3',x'edd3c7558ad5e31e842c9a9b69ebbf5187c26fb87223109ec465b88e32bd41d3',x'0000000000000000000000000000000000000000000000000000000000000000',x'adec24b1f5d85751881ec2ec981584fabfb33023a57a535aa58d57fdfaf70aa3');
CREATE TABLE storage_meta (
                 singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                 application_id INTEGER NOT NULL,
                 schema_version INTEGER NOT NULL,
                 min_reader_schema_version INTEGER NOT NULL,
                 installation_id TEXT NOT NULL,
                 created_at TEXT NOT NULL,
                 upgraded_at TEXT NOT NULL
             );
INSERT INTO storage_meta VALUES(1,1095323475,7,1,'ecac8997-e50c-43b2-84e8-8f6b75164ce7','2026-07-30T05:37:55.893393+00:00','2026-07-30T05:37:55.893393+00:00');
CREATE TABLE schema_migrations (
                 version INTEGER PRIMARY KEY CHECK (version > 0),
                 name TEXT NOT NULL,
                 applied_at TEXT NOT NULL
             );
INSERT INTO schema_migrations VALUES(1,'adopt-versioned-kernel-schema','2026-07-30T05:37:55.893393+00:00');
INSERT INTO schema_migrations VALUES(2,'add-privacy-safe-deletion-receipts','2026-07-30T05:37:55.893393+00:00');
INSERT INTO schema_migrations VALUES(3,'authenticate-usage-and-quota-accounting','2026-07-30T05:37:55.893393+00:00');
INSERT INTO schema_migrations VALUES(4,'add-cluster-agent-ownership-authority','2026-07-30T05:37:55.893393+00:00');
INSERT INTO schema_migrations VALUES(5,'add-destination-agent-mutation-fences','2026-07-30T05:37:55.893393+00:00');
INSERT INTO schema_migrations VALUES(6,'add-durable-cluster-raft-storage','2026-07-30T05:37:55.893393+00:00');
INSERT INTO schema_migrations VALUES(7,'bind-destination-fences-to-authority-terms-and-expiry','2026-07-30T05:37:55.893393+00:00');
CREATE TABLE IF NOT EXISTS sqlite_sequence(name,seq);
DELETE FROM sqlite_sequence;
INSERT INTO sqlite_sequence VALUES('operator_tunable_audit',3);
CREATE TRIGGER accounting_usage_log_insert
         AFTER INSERT ON usage_log

         BEGIN
             INSERT INTO accounting_events
                (sequence, table_name, operation, record_key, old_mac, new_mac,
                 state_root, previous_hash, entry_hash)
             SELECT event_count + 1, 'usage_log', 'insert', hex(aios_accounting_mac('record', 'usage_log', NEW.id, NEW.agent_id, NEW.timestamp, NEW.tokens_used, NEW.input_tokens, NEW.output_tokens, NEW.cached_tokens, NEW.llm_requests, NEW.retries, NEW.provider_latency_ms, NEW.provider_reported_requests, NEW.estimated_requests, NEW.provider, NEW.model, NEW.tool_calls, NEW.estimated_cost_usd, NEW.cost_micros)),
                    zeroblob(32), aios_accounting_mac('record', 'usage_log', NEW.id, NEW.agent_id, NEW.timestamp, NEW.tokens_used, NEW.input_tokens, NEW.output_tokens, NEW.cached_tokens, NEW.llm_requests, NEW.retries, NEW.provider_latency_ms, NEW.provider_reported_requests, NEW.estimated_requests, NEW.provider, NEW.model, NEW.tool_calls, NEW.estimated_cost_usd, NEW.cost_micros),
                    aios_accounting_xor(
                        state_root, aios_accounting_xor(zeroblob(32), aios_accounting_mac('record', 'usage_log', NEW.id, NEW.agent_id, NEW.timestamp, NEW.tokens_used, NEW.input_tokens, NEW.output_tokens, NEW.cached_tokens, NEW.llm_requests, NEW.retries, NEW.provider_latency_ms, NEW.provider_reported_requests, NEW.estimated_requests, NEW.provider, NEW.model, NEW.tool_calls, NEW.estimated_cost_usd, NEW.cost_micros))
                    ),
                    head_hash,
                    aios_accounting_mac(
                        'event', event_count + 1, 'usage_log', 'insert',
                        hex(aios_accounting_mac('record', 'usage_log', NEW.id, NEW.agent_id, NEW.timestamp, NEW.tokens_used, NEW.input_tokens, NEW.output_tokens, NEW.cached_tokens, NEW.llm_requests, NEW.retries, NEW.provider_latency_ms, NEW.provider_reported_requests, NEW.estimated_requests, NEW.provider, NEW.model, NEW.tool_calls, NEW.estimated_cost_usd, NEW.cost_micros)), zeroblob(32), aios_accounting_mac('record', 'usage_log', NEW.id, NEW.agent_id, NEW.timestamp, NEW.tokens_used, NEW.input_tokens, NEW.output_tokens, NEW.cached_tokens, NEW.llm_requests, NEW.retries, NEW.provider_latency_ms, NEW.provider_reported_requests, NEW.estimated_requests, NEW.provider, NEW.model, NEW.tool_calls, NEW.estimated_cost_usd, NEW.cost_micros),
                        aios_accounting_xor(
                            state_root, aios_accounting_xor(zeroblob(32), aios_accounting_mac('record', 'usage_log', NEW.id, NEW.agent_id, NEW.timestamp, NEW.tokens_used, NEW.input_tokens, NEW.output_tokens, NEW.cached_tokens, NEW.llm_requests, NEW.retries, NEW.provider_latency_ms, NEW.provider_reported_requests, NEW.estimated_requests, NEW.provider, NEW.model, NEW.tool_calls, NEW.estimated_cost_usd, NEW.cost_micros))
                        ),
                        head_hash
                    )
             FROM accounting_integrity WHERE singleton = 1;
             UPDATE accounting_integrity
             SET state_root = aios_accounting_xor(
                     state_root, aios_accounting_xor(zeroblob(32), aios_accounting_mac('record', 'usage_log', NEW.id, NEW.agent_id, NEW.timestamp, NEW.tokens_used, NEW.input_tokens, NEW.output_tokens, NEW.cached_tokens, NEW.llm_requests, NEW.retries, NEW.provider_latency_ms, NEW.provider_reported_requests, NEW.estimated_requests, NEW.provider, NEW.model, NEW.tool_calls, NEW.estimated_cost_usd, NEW.cost_micros))
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
         END;
CREATE TRIGGER accounting_usage_log_update
         AFTER UPDATE ON usage_log
         WHEN aios_accounting_mac('record', 'usage_log', OLD.id, OLD.agent_id, OLD.timestamp, OLD.tokens_used, OLD.input_tokens, OLD.output_tokens, OLD.cached_tokens, OLD.llm_requests, OLD.retries, OLD.provider_latency_ms, OLD.provider_reported_requests, OLD.estimated_requests, OLD.provider, OLD.model, OLD.tool_calls, OLD.estimated_cost_usd, OLD.cost_micros) != aios_accounting_mac('record', 'usage_log', NEW.id, NEW.agent_id, NEW.timestamp, NEW.tokens_used, NEW.input_tokens, NEW.output_tokens, NEW.cached_tokens, NEW.llm_requests, NEW.retries, NEW.provider_latency_ms, NEW.provider_reported_requests, NEW.estimated_requests, NEW.provider, NEW.model, NEW.tool_calls, NEW.estimated_cost_usd, NEW.cost_micros)
         BEGIN
             INSERT INTO accounting_events
                (sequence, table_name, operation, record_key, old_mac, new_mac,
                 state_root, previous_hash, entry_hash)
             SELECT event_count + 1, 'usage_log', 'update', hex(aios_accounting_mac('record', 'usage_log', OLD.id, OLD.agent_id, OLD.timestamp, OLD.tokens_used, OLD.input_tokens, OLD.output_tokens, OLD.cached_tokens, OLD.llm_requests, OLD.retries, OLD.provider_latency_ms, OLD.provider_reported_requests, OLD.estimated_requests, OLD.provider, OLD.model, OLD.tool_calls, OLD.estimated_cost_usd, OLD.cost_micros)),
                    aios_accounting_mac('record', 'usage_log', OLD.id, OLD.agent_id, OLD.timestamp, OLD.tokens_used, OLD.input_tokens, OLD.output_tokens, OLD.cached_tokens, OLD.llm_requests, OLD.retries, OLD.provider_latency_ms, OLD.provider_reported_requests, OLD.estimated_requests, OLD.provider, OLD.model, OLD.tool_calls, OLD.estimated_cost_usd, OLD.cost_micros), aios_accounting_mac('record', 'usage_log', NEW.id, NEW.agent_id, NEW.timestamp, NEW.tokens_used, NEW.input_tokens, NEW.output_tokens, NEW.cached_tokens, NEW.llm_requests, NEW.retries, NEW.provider_latency_ms, NEW.provider_reported_requests, NEW.estimated_requests, NEW.provider, NEW.model, NEW.tool_calls, NEW.estimated_cost_usd, NEW.cost_micros),
                    aios_accounting_xor(
                        state_root, aios_accounting_xor(aios_accounting_mac('record', 'usage_log', OLD.id, OLD.agent_id, OLD.timestamp, OLD.tokens_used, OLD.input_tokens, OLD.output_tokens, OLD.cached_tokens, OLD.llm_requests, OLD.retries, OLD.provider_latency_ms, OLD.provider_reported_requests, OLD.estimated_requests, OLD.provider, OLD.model, OLD.tool_calls, OLD.estimated_cost_usd, OLD.cost_micros), aios_accounting_mac('record', 'usage_log', NEW.id, NEW.agent_id, NEW.timestamp, NEW.tokens_used, NEW.input_tokens, NEW.output_tokens, NEW.cached_tokens, NEW.llm_requests, NEW.retries, NEW.provider_latency_ms, NEW.provider_reported_requests, NEW.estimated_requests, NEW.provider, NEW.model, NEW.tool_calls, NEW.estimated_cost_usd, NEW.cost_micros))
                    ),
                    head_hash,
                    aios_accounting_mac(
                        'event', event_count + 1, 'usage_log', 'update',
                        hex(aios_accounting_mac('record', 'usage_log', OLD.id, OLD.agent_id, OLD.timestamp, OLD.tokens_used, OLD.input_tokens, OLD.output_tokens, OLD.cached_tokens, OLD.llm_requests, OLD.retries, OLD.provider_latency_ms, OLD.provider_reported_requests, OLD.estimated_requests, OLD.provider, OLD.model, OLD.tool_calls, OLD.estimated_cost_usd, OLD.cost_micros)), aios_accounting_mac('record', 'usage_log', OLD.id, OLD.agent_id, OLD.timestamp, OLD.tokens_used, OLD.input_tokens, OLD.output_tokens, OLD.cached_tokens, OLD.llm_requests, OLD.retries, OLD.provider_latency_ms, OLD.provider_reported_requests, OLD.estimated_requests, OLD.provider, OLD.model, OLD.tool_calls, OLD.estimated_cost_usd, OLD.cost_micros), aios_accounting_mac('record', 'usage_log', NEW.id, NEW.agent_id, NEW.timestamp, NEW.tokens_used, NEW.input_tokens, NEW.output_tokens, NEW.cached_tokens, NEW.llm_requests, NEW.retries, NEW.provider_latency_ms, NEW.provider_reported_requests, NEW.estimated_requests, NEW.provider, NEW.model, NEW.tool_calls, NEW.estimated_cost_usd, NEW.cost_micros),
                        aios_accounting_xor(
                            state_root, aios_accounting_xor(aios_accounting_mac('record', 'usage_log', OLD.id, OLD.agent_id, OLD.timestamp, OLD.tokens_used, OLD.input_tokens, OLD.output_tokens, OLD.cached_tokens, OLD.llm_requests, OLD.retries, OLD.provider_latency_ms, OLD.provider_reported_requests, OLD.estimated_requests, OLD.provider, OLD.model, OLD.tool_calls, OLD.estimated_cost_usd, OLD.cost_micros), aios_accounting_mac('record', 'usage_log', NEW.id, NEW.agent_id, NEW.timestamp, NEW.tokens_used, NEW.input_tokens, NEW.output_tokens, NEW.cached_tokens, NEW.llm_requests, NEW.retries, NEW.provider_latency_ms, NEW.provider_reported_requests, NEW.estimated_requests, NEW.provider, NEW.model, NEW.tool_calls, NEW.estimated_cost_usd, NEW.cost_micros))
                        ),
                        head_hash
                    )
             FROM accounting_integrity WHERE singleton = 1;
             UPDATE accounting_integrity
             SET state_root = aios_accounting_xor(
                     state_root, aios_accounting_xor(aios_accounting_mac('record', 'usage_log', OLD.id, OLD.agent_id, OLD.timestamp, OLD.tokens_used, OLD.input_tokens, OLD.output_tokens, OLD.cached_tokens, OLD.llm_requests, OLD.retries, OLD.provider_latency_ms, OLD.provider_reported_requests, OLD.estimated_requests, OLD.provider, OLD.model, OLD.tool_calls, OLD.estimated_cost_usd, OLD.cost_micros), aios_accounting_mac('record', 'usage_log', NEW.id, NEW.agent_id, NEW.timestamp, NEW.tokens_used, NEW.input_tokens, NEW.output_tokens, NEW.cached_tokens, NEW.llm_requests, NEW.retries, NEW.provider_latency_ms, NEW.provider_reported_requests, NEW.estimated_requests, NEW.provider, NEW.model, NEW.tool_calls, NEW.estimated_cost_usd, NEW.cost_micros))
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
         END;
CREATE TRIGGER accounting_usage_log_delete
         AFTER DELETE ON usage_log

         BEGIN
             INSERT INTO accounting_events
                (sequence, table_name, operation, record_key, old_mac, new_mac,
                 state_root, previous_hash, entry_hash)
             SELECT event_count + 1, 'usage_log', 'delete', hex(aios_accounting_mac('record', 'usage_log', OLD.id, OLD.agent_id, OLD.timestamp, OLD.tokens_used, OLD.input_tokens, OLD.output_tokens, OLD.cached_tokens, OLD.llm_requests, OLD.retries, OLD.provider_latency_ms, OLD.provider_reported_requests, OLD.estimated_requests, OLD.provider, OLD.model, OLD.tool_calls, OLD.estimated_cost_usd, OLD.cost_micros)),
                    aios_accounting_mac('record', 'usage_log', OLD.id, OLD.agent_id, OLD.timestamp, OLD.tokens_used, OLD.input_tokens, OLD.output_tokens, OLD.cached_tokens, OLD.llm_requests, OLD.retries, OLD.provider_latency_ms, OLD.provider_reported_requests, OLD.estimated_requests, OLD.provider, OLD.model, OLD.tool_calls, OLD.estimated_cost_usd, OLD.cost_micros), zeroblob(32),
                    aios_accounting_xor(
                        state_root, aios_accounting_xor(aios_accounting_mac('record', 'usage_log', OLD.id, OLD.agent_id, OLD.timestamp, OLD.tokens_used, OLD.input_tokens, OLD.output_tokens, OLD.cached_tokens, OLD.llm_requests, OLD.retries, OLD.provider_latency_ms, OLD.provider_reported_requests, OLD.estimated_requests, OLD.provider, OLD.model, OLD.tool_calls, OLD.estimated_cost_usd, OLD.cost_micros), zeroblob(32))
                    ),
                    head_hash,
                    aios_accounting_mac(
                        'event', event_count + 1, 'usage_log', 'delete',
                        hex(aios_accounting_mac('record', 'usage_log', OLD.id, OLD.agent_id, OLD.timestamp, OLD.tokens_used, OLD.input_tokens, OLD.output_tokens, OLD.cached_tokens, OLD.llm_requests, OLD.retries, OLD.provider_latency_ms, OLD.provider_reported_requests, OLD.estimated_requests, OLD.provider, OLD.model, OLD.tool_calls, OLD.estimated_cost_usd, OLD.cost_micros)), aios_accounting_mac('record', 'usage_log', OLD.id, OLD.agent_id, OLD.timestamp, OLD.tokens_used, OLD.input_tokens, OLD.output_tokens, OLD.cached_tokens, OLD.llm_requests, OLD.retries, OLD.provider_latency_ms, OLD.provider_reported_requests, OLD.estimated_requests, OLD.provider, OLD.model, OLD.tool_calls, OLD.estimated_cost_usd, OLD.cost_micros), zeroblob(32),
                        aios_accounting_xor(
                            state_root, aios_accounting_xor(aios_accounting_mac('record', 'usage_log', OLD.id, OLD.agent_id, OLD.timestamp, OLD.tokens_used, OLD.input_tokens, OLD.output_tokens, OLD.cached_tokens, OLD.llm_requests, OLD.retries, OLD.provider_latency_ms, OLD.provider_reported_requests, OLD.estimated_requests, OLD.provider, OLD.model, OLD.tool_calls, OLD.estimated_cost_usd, OLD.cost_micros), zeroblob(32))
                        ),
                        head_hash
                    )
             FROM accounting_integrity WHERE singleton = 1;
             UPDATE accounting_integrity
             SET state_root = aios_accounting_xor(
                     state_root, aios_accounting_xor(aios_accounting_mac('record', 'usage_log', OLD.id, OLD.agent_id, OLD.timestamp, OLD.tokens_used, OLD.input_tokens, OLD.output_tokens, OLD.cached_tokens, OLD.llm_requests, OLD.retries, OLD.provider_latency_ms, OLD.provider_reported_requests, OLD.estimated_requests, OLD.provider, OLD.model, OLD.tool_calls, OLD.estimated_cost_usd, OLD.cost_micros), zeroblob(32))
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
         END;
CREATE TRIGGER accounting_quota_epoch_floor_insert
         AFTER INSERT ON quota_epoch_floor

         BEGIN
             INSERT INTO accounting_events
                (sequence, table_name, operation, record_key, old_mac, new_mac,
                 state_root, previous_hash, entry_hash)
             SELECT event_count + 1, 'quota_epoch_floor', 'insert', hex(aios_accounting_mac('record', 'quota_epoch_floor', NEW.singleton, NEW.epoch)),
                    zeroblob(32), aios_accounting_mac('record', 'quota_epoch_floor', NEW.singleton, NEW.epoch),
                    aios_accounting_xor(
                        state_root, aios_accounting_xor(zeroblob(32), aios_accounting_mac('record', 'quota_epoch_floor', NEW.singleton, NEW.epoch))
                    ),
                    head_hash,
                    aios_accounting_mac(
                        'event', event_count + 1, 'quota_epoch_floor', 'insert',
                        hex(aios_accounting_mac('record', 'quota_epoch_floor', NEW.singleton, NEW.epoch)), zeroblob(32), aios_accounting_mac('record', 'quota_epoch_floor', NEW.singleton, NEW.epoch),
                        aios_accounting_xor(
                            state_root, aios_accounting_xor(zeroblob(32), aios_accounting_mac('record', 'quota_epoch_floor', NEW.singleton, NEW.epoch))
                        ),
                        head_hash
                    )
             FROM accounting_integrity WHERE singleton = 1;
             UPDATE accounting_integrity
             SET state_root = aios_accounting_xor(
                     state_root, aios_accounting_xor(zeroblob(32), aios_accounting_mac('record', 'quota_epoch_floor', NEW.singleton, NEW.epoch))
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
         END;
CREATE TRIGGER accounting_quota_epoch_floor_update
         AFTER UPDATE ON quota_epoch_floor
         WHEN aios_accounting_mac('record', 'quota_epoch_floor', OLD.singleton, OLD.epoch) != aios_accounting_mac('record', 'quota_epoch_floor', NEW.singleton, NEW.epoch)
         BEGIN
             INSERT INTO accounting_events
                (sequence, table_name, operation, record_key, old_mac, new_mac,
                 state_root, previous_hash, entry_hash)
             SELECT event_count + 1, 'quota_epoch_floor', 'update', hex(aios_accounting_mac('record', 'quota_epoch_floor', OLD.singleton, OLD.epoch)),
                    aios_accounting_mac('record', 'quota_epoch_floor', OLD.singleton, OLD.epoch), aios_accounting_mac('record', 'quota_epoch_floor', NEW.singleton, NEW.epoch),
                    aios_accounting_xor(
                        state_root, aios_accounting_xor(aios_accounting_mac('record', 'quota_epoch_floor', OLD.singleton, OLD.epoch), aios_accounting_mac('record', 'quota_epoch_floor', NEW.singleton, NEW.epoch))
                    ),
                    head_hash,
                    aios_accounting_mac(
                        'event', event_count + 1, 'quota_epoch_floor', 'update',
                        hex(aios_accounting_mac('record', 'quota_epoch_floor', OLD.singleton, OLD.epoch)), aios_accounting_mac('record', 'quota_epoch_floor', OLD.singleton, OLD.epoch), aios_accounting_mac('record', 'quota_epoch_floor', NEW.singleton, NEW.epoch),
                        aios_accounting_xor(
                            state_root, aios_accounting_xor(aios_accounting_mac('record', 'quota_epoch_floor', OLD.singleton, OLD.epoch), aios_accounting_mac('record', 'quota_epoch_floor', NEW.singleton, NEW.epoch))
                        ),
                        head_hash
                    )
             FROM accounting_integrity WHERE singleton = 1;
             UPDATE accounting_integrity
             SET state_root = aios_accounting_xor(
                     state_root, aios_accounting_xor(aios_accounting_mac('record', 'quota_epoch_floor', OLD.singleton, OLD.epoch), aios_accounting_mac('record', 'quota_epoch_floor', NEW.singleton, NEW.epoch))
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
         END;
CREATE TRIGGER accounting_quota_epoch_floor_delete
         AFTER DELETE ON quota_epoch_floor

         BEGIN
             INSERT INTO accounting_events
                (sequence, table_name, operation, record_key, old_mac, new_mac,
                 state_root, previous_hash, entry_hash)
             SELECT event_count + 1, 'quota_epoch_floor', 'delete', hex(aios_accounting_mac('record', 'quota_epoch_floor', OLD.singleton, OLD.epoch)),
                    aios_accounting_mac('record', 'quota_epoch_floor', OLD.singleton, OLD.epoch), zeroblob(32),
                    aios_accounting_xor(
                        state_root, aios_accounting_xor(aios_accounting_mac('record', 'quota_epoch_floor', OLD.singleton, OLD.epoch), zeroblob(32))
                    ),
                    head_hash,
                    aios_accounting_mac(
                        'event', event_count + 1, 'quota_epoch_floor', 'delete',
                        hex(aios_accounting_mac('record', 'quota_epoch_floor', OLD.singleton, OLD.epoch)), aios_accounting_mac('record', 'quota_epoch_floor', OLD.singleton, OLD.epoch), zeroblob(32),
                        aios_accounting_xor(
                            state_root, aios_accounting_xor(aios_accounting_mac('record', 'quota_epoch_floor', OLD.singleton, OLD.epoch), zeroblob(32))
                        ),
                        head_hash
                    )
             FROM accounting_integrity WHERE singleton = 1;
             UPDATE accounting_integrity
             SET state_root = aios_accounting_xor(
                     state_root, aios_accounting_xor(aios_accounting_mac('record', 'quota_epoch_floor', OLD.singleton, OLD.epoch), zeroblob(32))
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
         END;
CREATE TRIGGER accounting_quota_epochs_insert
         AFTER INSERT ON quota_epochs

         BEGIN
             INSERT INTO accounting_events
                (sequence, table_name, operation, record_key, old_mac, new_mac,
                 state_root, previous_hash, entry_hash)
             SELECT event_count + 1, 'quota_epochs', 'insert', hex(aios_accounting_mac('record', 'quota_epochs', NEW.scope_kind, NEW.scope_id, NEW.epoch, NEW.requests, NEW.tokens)),
                    zeroblob(32), aios_accounting_mac('record', 'quota_epochs', NEW.scope_kind, NEW.scope_id, NEW.epoch, NEW.requests, NEW.tokens),
                    aios_accounting_xor(
                        state_root, aios_accounting_xor(zeroblob(32), aios_accounting_mac('record', 'quota_epochs', NEW.scope_kind, NEW.scope_id, NEW.epoch, NEW.requests, NEW.tokens))
                    ),
                    head_hash,
                    aios_accounting_mac(
                        'event', event_count + 1, 'quota_epochs', 'insert',
                        hex(aios_accounting_mac('record', 'quota_epochs', NEW.scope_kind, NEW.scope_id, NEW.epoch, NEW.requests, NEW.tokens)), zeroblob(32), aios_accounting_mac('record', 'quota_epochs', NEW.scope_kind, NEW.scope_id, NEW.epoch, NEW.requests, NEW.tokens),
                        aios_accounting_xor(
                            state_root, aios_accounting_xor(zeroblob(32), aios_accounting_mac('record', 'quota_epochs', NEW.scope_kind, NEW.scope_id, NEW.epoch, NEW.requests, NEW.tokens))
                        ),
                        head_hash
                    )
             FROM accounting_integrity WHERE singleton = 1;
             UPDATE accounting_integrity
             SET state_root = aios_accounting_xor(
                     state_root, aios_accounting_xor(zeroblob(32), aios_accounting_mac('record', 'quota_epochs', NEW.scope_kind, NEW.scope_id, NEW.epoch, NEW.requests, NEW.tokens))
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
         END;
CREATE TRIGGER accounting_quota_epochs_update
         AFTER UPDATE ON quota_epochs
         WHEN aios_accounting_mac('record', 'quota_epochs', OLD.scope_kind, OLD.scope_id, OLD.epoch, OLD.requests, OLD.tokens) != aios_accounting_mac('record', 'quota_epochs', NEW.scope_kind, NEW.scope_id, NEW.epoch, NEW.requests, NEW.tokens)
         BEGIN
             INSERT INTO accounting_events
                (sequence, table_name, operation, record_key, old_mac, new_mac,
                 state_root, previous_hash, entry_hash)
             SELECT event_count + 1, 'quota_epochs', 'update', hex(aios_accounting_mac('record', 'quota_epochs', OLD.scope_kind, OLD.scope_id, OLD.epoch, OLD.requests, OLD.tokens)),
                    aios_accounting_mac('record', 'quota_epochs', OLD.scope_kind, OLD.scope_id, OLD.epoch, OLD.requests, OLD.tokens), aios_accounting_mac('record', 'quota_epochs', NEW.scope_kind, NEW.scope_id, NEW.epoch, NEW.requests, NEW.tokens),
                    aios_accounting_xor(
                        state_root, aios_accounting_xor(aios_accounting_mac('record', 'quota_epochs', OLD.scope_kind, OLD.scope_id, OLD.epoch, OLD.requests, OLD.tokens), aios_accounting_mac('record', 'quota_epochs', NEW.scope_kind, NEW.scope_id, NEW.epoch, NEW.requests, NEW.tokens))
                    ),
                    head_hash,
                    aios_accounting_mac(
                        'event', event_count + 1, 'quota_epochs', 'update',
                        hex(aios_accounting_mac('record', 'quota_epochs', OLD.scope_kind, OLD.scope_id, OLD.epoch, OLD.requests, OLD.tokens)), aios_accounting_mac('record', 'quota_epochs', OLD.scope_kind, OLD.scope_id, OLD.epoch, OLD.requests, OLD.tokens), aios_accounting_mac('record', 'quota_epochs', NEW.scope_kind, NEW.scope_id, NEW.epoch, NEW.requests, NEW.tokens),
                        aios_accounting_xor(
                            state_root, aios_accounting_xor(aios_accounting_mac('record', 'quota_epochs', OLD.scope_kind, OLD.scope_id, OLD.epoch, OLD.requests, OLD.tokens), aios_accounting_mac('record', 'quota_epochs', NEW.scope_kind, NEW.scope_id, NEW.epoch, NEW.requests, NEW.tokens))
                        ),
                        head_hash
                    )
             FROM accounting_integrity WHERE singleton = 1;
             UPDATE accounting_integrity
             SET state_root = aios_accounting_xor(
                     state_root, aios_accounting_xor(aios_accounting_mac('record', 'quota_epochs', OLD.scope_kind, OLD.scope_id, OLD.epoch, OLD.requests, OLD.tokens), aios_accounting_mac('record', 'quota_epochs', NEW.scope_kind, NEW.scope_id, NEW.epoch, NEW.requests, NEW.tokens))
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
         END;
CREATE TRIGGER accounting_quota_epochs_delete
         AFTER DELETE ON quota_epochs

         BEGIN
             INSERT INTO accounting_events
                (sequence, table_name, operation, record_key, old_mac, new_mac,
                 state_root, previous_hash, entry_hash)
             SELECT event_count + 1, 'quota_epochs', 'delete', hex(aios_accounting_mac('record', 'quota_epochs', OLD.scope_kind, OLD.scope_id, OLD.epoch, OLD.requests, OLD.tokens)),
                    aios_accounting_mac('record', 'quota_epochs', OLD.scope_kind, OLD.scope_id, OLD.epoch, OLD.requests, OLD.tokens), zeroblob(32),
                    aios_accounting_xor(
                        state_root, aios_accounting_xor(aios_accounting_mac('record', 'quota_epochs', OLD.scope_kind, OLD.scope_id, OLD.epoch, OLD.requests, OLD.tokens), zeroblob(32))
                    ),
                    head_hash,
                    aios_accounting_mac(
                        'event', event_count + 1, 'quota_epochs', 'delete',
                        hex(aios_accounting_mac('record', 'quota_epochs', OLD.scope_kind, OLD.scope_id, OLD.epoch, OLD.requests, OLD.tokens)), aios_accounting_mac('record', 'quota_epochs', OLD.scope_kind, OLD.scope_id, OLD.epoch, OLD.requests, OLD.tokens), zeroblob(32),
                        aios_accounting_xor(
                            state_root, aios_accounting_xor(aios_accounting_mac('record', 'quota_epochs', OLD.scope_kind, OLD.scope_id, OLD.epoch, OLD.requests, OLD.tokens), zeroblob(32))
                        ),
                        head_hash
                    )
             FROM accounting_integrity WHERE singleton = 1;
             UPDATE accounting_integrity
             SET state_root = aios_accounting_xor(
                     state_root, aios_accounting_xor(aios_accounting_mac('record', 'quota_epochs', OLD.scope_kind, OLD.scope_id, OLD.epoch, OLD.requests, OLD.tokens), zeroblob(32))
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
         END;
CREATE TRIGGER accounting_quota_receipts_insert
         AFTER INSERT ON quota_receipts

         BEGIN
             INSERT INTO accounting_events
                (sequence, table_name, operation, record_key, old_mac, new_mac,
                 state_root, previous_hash, entry_hash)
             SELECT event_count + 1, 'quota_receipts', 'insert', hex(aios_accounting_mac('record', 'quota_receipts', NEW.id, NEW.receipt_kind, NEW.epoch, NEW.state, NEW.reserved_requests, NEW.reserved_tokens, NEW.actual_requests, NEW.actual_tokens)),
                    zeroblob(32), aios_accounting_mac('record', 'quota_receipts', NEW.id, NEW.receipt_kind, NEW.epoch, NEW.state, NEW.reserved_requests, NEW.reserved_tokens, NEW.actual_requests, NEW.actual_tokens),
                    aios_accounting_xor(
                        state_root, aios_accounting_xor(zeroblob(32), aios_accounting_mac('record', 'quota_receipts', NEW.id, NEW.receipt_kind, NEW.epoch, NEW.state, NEW.reserved_requests, NEW.reserved_tokens, NEW.actual_requests, NEW.actual_tokens))
                    ),
                    head_hash,
                    aios_accounting_mac(
                        'event', event_count + 1, 'quota_receipts', 'insert',
                        hex(aios_accounting_mac('record', 'quota_receipts', NEW.id, NEW.receipt_kind, NEW.epoch, NEW.state, NEW.reserved_requests, NEW.reserved_tokens, NEW.actual_requests, NEW.actual_tokens)), zeroblob(32), aios_accounting_mac('record', 'quota_receipts', NEW.id, NEW.receipt_kind, NEW.epoch, NEW.state, NEW.reserved_requests, NEW.reserved_tokens, NEW.actual_requests, NEW.actual_tokens),
                        aios_accounting_xor(
                            state_root, aios_accounting_xor(zeroblob(32), aios_accounting_mac('record', 'quota_receipts', NEW.id, NEW.receipt_kind, NEW.epoch, NEW.state, NEW.reserved_requests, NEW.reserved_tokens, NEW.actual_requests, NEW.actual_tokens))
                        ),
                        head_hash
                    )
             FROM accounting_integrity WHERE singleton = 1;
             UPDATE accounting_integrity
             SET state_root = aios_accounting_xor(
                     state_root, aios_accounting_xor(zeroblob(32), aios_accounting_mac('record', 'quota_receipts', NEW.id, NEW.receipt_kind, NEW.epoch, NEW.state, NEW.reserved_requests, NEW.reserved_tokens, NEW.actual_requests, NEW.actual_tokens))
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
         END;
CREATE TRIGGER accounting_quota_receipts_update
         AFTER UPDATE ON quota_receipts
         WHEN aios_accounting_mac('record', 'quota_receipts', OLD.id, OLD.receipt_kind, OLD.epoch, OLD.state, OLD.reserved_requests, OLD.reserved_tokens, OLD.actual_requests, OLD.actual_tokens) != aios_accounting_mac('record', 'quota_receipts', NEW.id, NEW.receipt_kind, NEW.epoch, NEW.state, NEW.reserved_requests, NEW.reserved_tokens, NEW.actual_requests, NEW.actual_tokens)
         BEGIN
             INSERT INTO accounting_events
                (sequence, table_name, operation, record_key, old_mac, new_mac,
                 state_root, previous_hash, entry_hash)
             SELECT event_count + 1, 'quota_receipts', 'update', hex(aios_accounting_mac('record', 'quota_receipts', OLD.id, OLD.receipt_kind, OLD.epoch, OLD.state, OLD.reserved_requests, OLD.reserved_tokens, OLD.actual_requests, OLD.actual_tokens)),
                    aios_accounting_mac('record', 'quota_receipts', OLD.id, OLD.receipt_kind, OLD.epoch, OLD.state, OLD.reserved_requests, OLD.reserved_tokens, OLD.actual_requests, OLD.actual_tokens), aios_accounting_mac('record', 'quota_receipts', NEW.id, NEW.receipt_kind, NEW.epoch, NEW.state, NEW.reserved_requests, NEW.reserved_tokens, NEW.actual_requests, NEW.actual_tokens),
                    aios_accounting_xor(
                        state_root, aios_accounting_xor(aios_accounting_mac('record', 'quota_receipts', OLD.id, OLD.receipt_kind, OLD.epoch, OLD.state, OLD.reserved_requests, OLD.reserved_tokens, OLD.actual_requests, OLD.actual_tokens), aios_accounting_mac('record', 'quota_receipts', NEW.id, NEW.receipt_kind, NEW.epoch, NEW.state, NEW.reserved_requests, NEW.reserved_tokens, NEW.actual_requests, NEW.actual_tokens))
                    ),
                    head_hash,
                    aios_accounting_mac(
                        'event', event_count + 1, 'quota_receipts', 'update',
                        hex(aios_accounting_mac('record', 'quota_receipts', OLD.id, OLD.receipt_kind, OLD.epoch, OLD.state, OLD.reserved_requests, OLD.reserved_tokens, OLD.actual_requests, OLD.actual_tokens)), aios_accounting_mac('record', 'quota_receipts', OLD.id, OLD.receipt_kind, OLD.epoch, OLD.state, OLD.reserved_requests, OLD.reserved_tokens, OLD.actual_requests, OLD.actual_tokens), aios_accounting_mac('record', 'quota_receipts', NEW.id, NEW.receipt_kind, NEW.epoch, NEW.state, NEW.reserved_requests, NEW.reserved_tokens, NEW.actual_requests, NEW.actual_tokens),
                        aios_accounting_xor(
                            state_root, aios_accounting_xor(aios_accounting_mac('record', 'quota_receipts', OLD.id, OLD.receipt_kind, OLD.epoch, OLD.state, OLD.reserved_requests, OLD.reserved_tokens, OLD.actual_requests, OLD.actual_tokens), aios_accounting_mac('record', 'quota_receipts', NEW.id, NEW.receipt_kind, NEW.epoch, NEW.state, NEW.reserved_requests, NEW.reserved_tokens, NEW.actual_requests, NEW.actual_tokens))
                        ),
                        head_hash
                    )
             FROM accounting_integrity WHERE singleton = 1;
             UPDATE accounting_integrity
             SET state_root = aios_accounting_xor(
                     state_root, aios_accounting_xor(aios_accounting_mac('record', 'quota_receipts', OLD.id, OLD.receipt_kind, OLD.epoch, OLD.state, OLD.reserved_requests, OLD.reserved_tokens, OLD.actual_requests, OLD.actual_tokens), aios_accounting_mac('record', 'quota_receipts', NEW.id, NEW.receipt_kind, NEW.epoch, NEW.state, NEW.reserved_requests, NEW.reserved_tokens, NEW.actual_requests, NEW.actual_tokens))
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
         END;
CREATE TRIGGER accounting_quota_receipts_delete
         AFTER DELETE ON quota_receipts

         BEGIN
             INSERT INTO accounting_events
                (sequence, table_name, operation, record_key, old_mac, new_mac,
                 state_root, previous_hash, entry_hash)
             SELECT event_count + 1, 'quota_receipts', 'delete', hex(aios_accounting_mac('record', 'quota_receipts', OLD.id, OLD.receipt_kind, OLD.epoch, OLD.state, OLD.reserved_requests, OLD.reserved_tokens, OLD.actual_requests, OLD.actual_tokens)),
                    aios_accounting_mac('record', 'quota_receipts', OLD.id, OLD.receipt_kind, OLD.epoch, OLD.state, OLD.reserved_requests, OLD.reserved_tokens, OLD.actual_requests, OLD.actual_tokens), zeroblob(32),
                    aios_accounting_xor(
                        state_root, aios_accounting_xor(aios_accounting_mac('record', 'quota_receipts', OLD.id, OLD.receipt_kind, OLD.epoch, OLD.state, OLD.reserved_requests, OLD.reserved_tokens, OLD.actual_requests, OLD.actual_tokens), zeroblob(32))
                    ),
                    head_hash,
                    aios_accounting_mac(
                        'event', event_count + 1, 'quota_receipts', 'delete',
                        hex(aios_accounting_mac('record', 'quota_receipts', OLD.id, OLD.receipt_kind, OLD.epoch, OLD.state, OLD.reserved_requests, OLD.reserved_tokens, OLD.actual_requests, OLD.actual_tokens)), aios_accounting_mac('record', 'quota_receipts', OLD.id, OLD.receipt_kind, OLD.epoch, OLD.state, OLD.reserved_requests, OLD.reserved_tokens, OLD.actual_requests, OLD.actual_tokens), zeroblob(32),
                        aios_accounting_xor(
                            state_root, aios_accounting_xor(aios_accounting_mac('record', 'quota_receipts', OLD.id, OLD.receipt_kind, OLD.epoch, OLD.state, OLD.reserved_requests, OLD.reserved_tokens, OLD.actual_requests, OLD.actual_tokens), zeroblob(32))
                        ),
                        head_hash
                    )
             FROM accounting_integrity WHERE singleton = 1;
             UPDATE accounting_integrity
             SET state_root = aios_accounting_xor(
                     state_root, aios_accounting_xor(aios_accounting_mac('record', 'quota_receipts', OLD.id, OLD.receipt_kind, OLD.epoch, OLD.state, OLD.reserved_requests, OLD.reserved_tokens, OLD.actual_requests, OLD.actual_tokens), zeroblob(32))
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
         END;
CREATE TRIGGER accounting_quota_receipt_scopes_insert
         AFTER INSERT ON quota_receipt_scopes

         BEGIN
             INSERT INTO accounting_events
                (sequence, table_name, operation, record_key, old_mac, new_mac,
                 state_root, previous_hash, entry_hash)
             SELECT event_count + 1, 'quota_receipt_scopes', 'insert', hex(aios_accounting_mac('record', 'quota_receipt_scopes', NEW.receipt_id, NEW.scope_order, NEW.scope_kind, NEW.scope_id, NEW.reserved_requests, NEW.reserved_tokens, NEW.actual_requests, NEW.actual_tokens)),
                    zeroblob(32), aios_accounting_mac('record', 'quota_receipt_scopes', NEW.receipt_id, NEW.scope_order, NEW.scope_kind, NEW.scope_id, NEW.reserved_requests, NEW.reserved_tokens, NEW.actual_requests, NEW.actual_tokens),
                    aios_accounting_xor(
                        state_root, aios_accounting_xor(zeroblob(32), aios_accounting_mac('record', 'quota_receipt_scopes', NEW.receipt_id, NEW.scope_order, NEW.scope_kind, NEW.scope_id, NEW.reserved_requests, NEW.reserved_tokens, NEW.actual_requests, NEW.actual_tokens))
                    ),
                    head_hash,
                    aios_accounting_mac(
                        'event', event_count + 1, 'quota_receipt_scopes', 'insert',
                        hex(aios_accounting_mac('record', 'quota_receipt_scopes', NEW.receipt_id, NEW.scope_order, NEW.scope_kind, NEW.scope_id, NEW.reserved_requests, NEW.reserved_tokens, NEW.actual_requests, NEW.actual_tokens)), zeroblob(32), aios_accounting_mac('record', 'quota_receipt_scopes', NEW.receipt_id, NEW.scope_order, NEW.scope_kind, NEW.scope_id, NEW.reserved_requests, NEW.reserved_tokens, NEW.actual_requests, NEW.actual_tokens),
                        aios_accounting_xor(
                            state_root, aios_accounting_xor(zeroblob(32), aios_accounting_mac('record', 'quota_receipt_scopes', NEW.receipt_id, NEW.scope_order, NEW.scope_kind, NEW.scope_id, NEW.reserved_requests, NEW.reserved_tokens, NEW.actual_requests, NEW.actual_tokens))
                        ),
                        head_hash
                    )
             FROM accounting_integrity WHERE singleton = 1;
             UPDATE accounting_integrity
             SET state_root = aios_accounting_xor(
                     state_root, aios_accounting_xor(zeroblob(32), aios_accounting_mac('record', 'quota_receipt_scopes', NEW.receipt_id, NEW.scope_order, NEW.scope_kind, NEW.scope_id, NEW.reserved_requests, NEW.reserved_tokens, NEW.actual_requests, NEW.actual_tokens))
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
         END;
CREATE TRIGGER accounting_quota_receipt_scopes_update
         AFTER UPDATE ON quota_receipt_scopes
         WHEN aios_accounting_mac('record', 'quota_receipt_scopes', OLD.receipt_id, OLD.scope_order, OLD.scope_kind, OLD.scope_id, OLD.reserved_requests, OLD.reserved_tokens, OLD.actual_requests, OLD.actual_tokens) != aios_accounting_mac('record', 'quota_receipt_scopes', NEW.receipt_id, NEW.scope_order, NEW.scope_kind, NEW.scope_id, NEW.reserved_requests, NEW.reserved_tokens, NEW.actual_requests, NEW.actual_tokens)
         BEGIN
             INSERT INTO accounting_events
                (sequence, table_name, operation, record_key, old_mac, new_mac,
                 state_root, previous_hash, entry_hash)
             SELECT event_count + 1, 'quota_receipt_scopes', 'update', hex(aios_accounting_mac('record', 'quota_receipt_scopes', OLD.receipt_id, OLD.scope_order, OLD.scope_kind, OLD.scope_id, OLD.reserved_requests, OLD.reserved_tokens, OLD.actual_requests, OLD.actual_tokens)),
                    aios_accounting_mac('record', 'quota_receipt_scopes', OLD.receipt_id, OLD.scope_order, OLD.scope_kind, OLD.scope_id, OLD.reserved_requests, OLD.reserved_tokens, OLD.actual_requests, OLD.actual_tokens), aios_accounting_mac('record', 'quota_receipt_scopes', NEW.receipt_id, NEW.scope_order, NEW.scope_kind, NEW.scope_id, NEW.reserved_requests, NEW.reserved_tokens, NEW.actual_requests, NEW.actual_tokens),
                    aios_accounting_xor(
                        state_root, aios_accounting_xor(aios_accounting_mac('record', 'quota_receipt_scopes', OLD.receipt_id, OLD.scope_order, OLD.scope_kind, OLD.scope_id, OLD.reserved_requests, OLD.reserved_tokens, OLD.actual_requests, OLD.actual_tokens), aios_accounting_mac('record', 'quota_receipt_scopes', NEW.receipt_id, NEW.scope_order, NEW.scope_kind, NEW.scope_id, NEW.reserved_requests, NEW.reserved_tokens, NEW.actual_requests, NEW.actual_tokens))
                    ),
                    head_hash,
                    aios_accounting_mac(
                        'event', event_count + 1, 'quota_receipt_scopes', 'update',
                        hex(aios_accounting_mac('record', 'quota_receipt_scopes', OLD.receipt_id, OLD.scope_order, OLD.scope_kind, OLD.scope_id, OLD.reserved_requests, OLD.reserved_tokens, OLD.actual_requests, OLD.actual_tokens)), aios_accounting_mac('record', 'quota_receipt_scopes', OLD.receipt_id, OLD.scope_order, OLD.scope_kind, OLD.scope_id, OLD.reserved_requests, OLD.reserved_tokens, OLD.actual_requests, OLD.actual_tokens), aios_accounting_mac('record', 'quota_receipt_scopes', NEW.receipt_id, NEW.scope_order, NEW.scope_kind, NEW.scope_id, NEW.reserved_requests, NEW.reserved_tokens, NEW.actual_requests, NEW.actual_tokens),
                        aios_accounting_xor(
                            state_root, aios_accounting_xor(aios_accounting_mac('record', 'quota_receipt_scopes', OLD.receipt_id, OLD.scope_order, OLD.scope_kind, OLD.scope_id, OLD.reserved_requests, OLD.reserved_tokens, OLD.actual_requests, OLD.actual_tokens), aios_accounting_mac('record', 'quota_receipt_scopes', NEW.receipt_id, NEW.scope_order, NEW.scope_kind, NEW.scope_id, NEW.reserved_requests, NEW.reserved_tokens, NEW.actual_requests, NEW.actual_tokens))
                        ),
                        head_hash
                    )
             FROM accounting_integrity WHERE singleton = 1;
             UPDATE accounting_integrity
             SET state_root = aios_accounting_xor(
                     state_root, aios_accounting_xor(aios_accounting_mac('record', 'quota_receipt_scopes', OLD.receipt_id, OLD.scope_order, OLD.scope_kind, OLD.scope_id, OLD.reserved_requests, OLD.reserved_tokens, OLD.actual_requests, OLD.actual_tokens), aios_accounting_mac('record', 'quota_receipt_scopes', NEW.receipt_id, NEW.scope_order, NEW.scope_kind, NEW.scope_id, NEW.reserved_requests, NEW.reserved_tokens, NEW.actual_requests, NEW.actual_tokens))
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
         END;
CREATE TRIGGER accounting_quota_receipt_scopes_delete
         AFTER DELETE ON quota_receipt_scopes

         BEGIN
             INSERT INTO accounting_events
                (sequence, table_name, operation, record_key, old_mac, new_mac,
                 state_root, previous_hash, entry_hash)
             SELECT event_count + 1, 'quota_receipt_scopes', 'delete', hex(aios_accounting_mac('record', 'quota_receipt_scopes', OLD.receipt_id, OLD.scope_order, OLD.scope_kind, OLD.scope_id, OLD.reserved_requests, OLD.reserved_tokens, OLD.actual_requests, OLD.actual_tokens)),
                    aios_accounting_mac('record', 'quota_receipt_scopes', OLD.receipt_id, OLD.scope_order, OLD.scope_kind, OLD.scope_id, OLD.reserved_requests, OLD.reserved_tokens, OLD.actual_requests, OLD.actual_tokens), zeroblob(32),
                    aios_accounting_xor(
                        state_root, aios_accounting_xor(aios_accounting_mac('record', 'quota_receipt_scopes', OLD.receipt_id, OLD.scope_order, OLD.scope_kind, OLD.scope_id, OLD.reserved_requests, OLD.reserved_tokens, OLD.actual_requests, OLD.actual_tokens), zeroblob(32))
                    ),
                    head_hash,
                    aios_accounting_mac(
                        'event', event_count + 1, 'quota_receipt_scopes', 'delete',
                        hex(aios_accounting_mac('record', 'quota_receipt_scopes', OLD.receipt_id, OLD.scope_order, OLD.scope_kind, OLD.scope_id, OLD.reserved_requests, OLD.reserved_tokens, OLD.actual_requests, OLD.actual_tokens)), aios_accounting_mac('record', 'quota_receipt_scopes', OLD.receipt_id, OLD.scope_order, OLD.scope_kind, OLD.scope_id, OLD.reserved_requests, OLD.reserved_tokens, OLD.actual_requests, OLD.actual_tokens), zeroblob(32),
                        aios_accounting_xor(
                            state_root, aios_accounting_xor(aios_accounting_mac('record', 'quota_receipt_scopes', OLD.receipt_id, OLD.scope_order, OLD.scope_kind, OLD.scope_id, OLD.reserved_requests, OLD.reserved_tokens, OLD.actual_requests, OLD.actual_tokens), zeroblob(32))
                        ),
                        head_hash
                    )
             FROM accounting_integrity WHERE singleton = 1;
             UPDATE accounting_integrity
             SET state_root = aios_accounting_xor(
                     state_root, aios_accounting_xor(aios_accounting_mac('record', 'quota_receipt_scopes', OLD.receipt_id, OLD.scope_order, OLD.scope_kind, OLD.scope_id, OLD.reserved_requests, OLD.reserved_tokens, OLD.actual_requests, OLD.actual_tokens), zeroblob(32))
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
         END;
CREATE TRIGGER accounting_quota_refunded_receipts_insert
         AFTER INSERT ON quota_refunded_receipts

         BEGIN
             INSERT INTO accounting_events
                (sequence, table_name, operation, record_key, old_mac, new_mac,
                 state_root, previous_hash, entry_hash)
             SELECT event_count + 1, 'quota_refunded_receipts', 'insert', hex(aios_accounting_mac('record', 'quota_refunded_receipts', NEW.id, NEW.epoch)),
                    zeroblob(32), aios_accounting_mac('record', 'quota_refunded_receipts', NEW.id, NEW.epoch),
                    aios_accounting_xor(
                        state_root, aios_accounting_xor(zeroblob(32), aios_accounting_mac('record', 'quota_refunded_receipts', NEW.id, NEW.epoch))
                    ),
                    head_hash,
                    aios_accounting_mac(
                        'event', event_count + 1, 'quota_refunded_receipts', 'insert',
                        hex(aios_accounting_mac('record', 'quota_refunded_receipts', NEW.id, NEW.epoch)), zeroblob(32), aios_accounting_mac('record', 'quota_refunded_receipts', NEW.id, NEW.epoch),
                        aios_accounting_xor(
                            state_root, aios_accounting_xor(zeroblob(32), aios_accounting_mac('record', 'quota_refunded_receipts', NEW.id, NEW.epoch))
                        ),
                        head_hash
                    )
             FROM accounting_integrity WHERE singleton = 1;
             UPDATE accounting_integrity
             SET state_root = aios_accounting_xor(
                     state_root, aios_accounting_xor(zeroblob(32), aios_accounting_mac('record', 'quota_refunded_receipts', NEW.id, NEW.epoch))
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
         END;
CREATE TRIGGER accounting_quota_refunded_receipts_update
         AFTER UPDATE ON quota_refunded_receipts
         WHEN aios_accounting_mac('record', 'quota_refunded_receipts', OLD.id, OLD.epoch) != aios_accounting_mac('record', 'quota_refunded_receipts', NEW.id, NEW.epoch)
         BEGIN
             INSERT INTO accounting_events
                (sequence, table_name, operation, record_key, old_mac, new_mac,
                 state_root, previous_hash, entry_hash)
             SELECT event_count + 1, 'quota_refunded_receipts', 'update', hex(aios_accounting_mac('record', 'quota_refunded_receipts', OLD.id, OLD.epoch)),
                    aios_accounting_mac('record', 'quota_refunded_receipts', OLD.id, OLD.epoch), aios_accounting_mac('record', 'quota_refunded_receipts', NEW.id, NEW.epoch),
                    aios_accounting_xor(
                        state_root, aios_accounting_xor(aios_accounting_mac('record', 'quota_refunded_receipts', OLD.id, OLD.epoch), aios_accounting_mac('record', 'quota_refunded_receipts', NEW.id, NEW.epoch))
                    ),
                    head_hash,
                    aios_accounting_mac(
                        'event', event_count + 1, 'quota_refunded_receipts', 'update',
                        hex(aios_accounting_mac('record', 'quota_refunded_receipts', OLD.id, OLD.epoch)), aios_accounting_mac('record', 'quota_refunded_receipts', OLD.id, OLD.epoch), aios_accounting_mac('record', 'quota_refunded_receipts', NEW.id, NEW.epoch),
                        aios_accounting_xor(
                            state_root, aios_accounting_xor(aios_accounting_mac('record', 'quota_refunded_receipts', OLD.id, OLD.epoch), aios_accounting_mac('record', 'quota_refunded_receipts', NEW.id, NEW.epoch))
                        ),
                        head_hash
                    )
             FROM accounting_integrity WHERE singleton = 1;
             UPDATE accounting_integrity
             SET state_root = aios_accounting_xor(
                     state_root, aios_accounting_xor(aios_accounting_mac('record', 'quota_refunded_receipts', OLD.id, OLD.epoch), aios_accounting_mac('record', 'quota_refunded_receipts', NEW.id, NEW.epoch))
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
         END;
CREATE TRIGGER accounting_quota_refunded_receipts_delete
         AFTER DELETE ON quota_refunded_receipts

         BEGIN
             INSERT INTO accounting_events
                (sequence, table_name, operation, record_key, old_mac, new_mac,
                 state_root, previous_hash, entry_hash)
             SELECT event_count + 1, 'quota_refunded_receipts', 'delete', hex(aios_accounting_mac('record', 'quota_refunded_receipts', OLD.id, OLD.epoch)),
                    aios_accounting_mac('record', 'quota_refunded_receipts', OLD.id, OLD.epoch), zeroblob(32),
                    aios_accounting_xor(
                        state_root, aios_accounting_xor(aios_accounting_mac('record', 'quota_refunded_receipts', OLD.id, OLD.epoch), zeroblob(32))
                    ),
                    head_hash,
                    aios_accounting_mac(
                        'event', event_count + 1, 'quota_refunded_receipts', 'delete',
                        hex(aios_accounting_mac('record', 'quota_refunded_receipts', OLD.id, OLD.epoch)), aios_accounting_mac('record', 'quota_refunded_receipts', OLD.id, OLD.epoch), zeroblob(32),
                        aios_accounting_xor(
                            state_root, aios_accounting_xor(aios_accounting_mac('record', 'quota_refunded_receipts', OLD.id, OLD.epoch), zeroblob(32))
                        ),
                        head_hash
                    )
             FROM accounting_integrity WHERE singleton = 1;
             UPDATE accounting_integrity
             SET state_root = aios_accounting_xor(
                     state_root, aios_accounting_xor(aios_accounting_mac('record', 'quota_refunded_receipts', OLD.id, OLD.epoch), zeroblob(32))
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
         END;
CREATE TRIGGER accounting_quota_migration_fence_insert
         AFTER INSERT ON quota_migration_fence

         BEGIN
             INSERT INTO accounting_events
                (sequence, table_name, operation, record_key, old_mac, new_mac,
                 state_root, previous_hash, entry_hash)
             SELECT event_count + 1, 'quota_migration_fence', 'insert', hex(aios_accounting_mac('record', 'quota_migration_fence', NEW.epoch)),
                    zeroblob(32), aios_accounting_mac('record', 'quota_migration_fence', NEW.epoch),
                    aios_accounting_xor(
                        state_root, aios_accounting_xor(zeroblob(32), aios_accounting_mac('record', 'quota_migration_fence', NEW.epoch))
                    ),
                    head_hash,
                    aios_accounting_mac(
                        'event', event_count + 1, 'quota_migration_fence', 'insert',
                        hex(aios_accounting_mac('record', 'quota_migration_fence', NEW.epoch)), zeroblob(32), aios_accounting_mac('record', 'quota_migration_fence', NEW.epoch),
                        aios_accounting_xor(
                            state_root, aios_accounting_xor(zeroblob(32), aios_accounting_mac('record', 'quota_migration_fence', NEW.epoch))
                        ),
                        head_hash
                    )
             FROM accounting_integrity WHERE singleton = 1;
             UPDATE accounting_integrity
             SET state_root = aios_accounting_xor(
                     state_root, aios_accounting_xor(zeroblob(32), aios_accounting_mac('record', 'quota_migration_fence', NEW.epoch))
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
         END;
CREATE TRIGGER accounting_quota_migration_fence_update
         AFTER UPDATE ON quota_migration_fence
         WHEN aios_accounting_mac('record', 'quota_migration_fence', OLD.epoch) != aios_accounting_mac('record', 'quota_migration_fence', NEW.epoch)
         BEGIN
             INSERT INTO accounting_events
                (sequence, table_name, operation, record_key, old_mac, new_mac,
                 state_root, previous_hash, entry_hash)
             SELECT event_count + 1, 'quota_migration_fence', 'update', hex(aios_accounting_mac('record', 'quota_migration_fence', OLD.epoch)),
                    aios_accounting_mac('record', 'quota_migration_fence', OLD.epoch), aios_accounting_mac('record', 'quota_migration_fence', NEW.epoch),
                    aios_accounting_xor(
                        state_root, aios_accounting_xor(aios_accounting_mac('record', 'quota_migration_fence', OLD.epoch), aios_accounting_mac('record', 'quota_migration_fence', NEW.epoch))
                    ),
                    head_hash,
                    aios_accounting_mac(
                        'event', event_count + 1, 'quota_migration_fence', 'update',
                        hex(aios_accounting_mac('record', 'quota_migration_fence', OLD.epoch)), aios_accounting_mac('record', 'quota_migration_fence', OLD.epoch), aios_accounting_mac('record', 'quota_migration_fence', NEW.epoch),
                        aios_accounting_xor(
                            state_root, aios_accounting_xor(aios_accounting_mac('record', 'quota_migration_fence', OLD.epoch), aios_accounting_mac('record', 'quota_migration_fence', NEW.epoch))
                        ),
                        head_hash
                    )
             FROM accounting_integrity WHERE singleton = 1;
             UPDATE accounting_integrity
             SET state_root = aios_accounting_xor(
                     state_root, aios_accounting_xor(aios_accounting_mac('record', 'quota_migration_fence', OLD.epoch), aios_accounting_mac('record', 'quota_migration_fence', NEW.epoch))
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
         END;
CREATE TRIGGER accounting_quota_migration_fence_delete
         AFTER DELETE ON quota_migration_fence

         BEGIN
             INSERT INTO accounting_events
                (sequence, table_name, operation, record_key, old_mac, new_mac,
                 state_root, previous_hash, entry_hash)
             SELECT event_count + 1, 'quota_migration_fence', 'delete', hex(aios_accounting_mac('record', 'quota_migration_fence', OLD.epoch)),
                    aios_accounting_mac('record', 'quota_migration_fence', OLD.epoch), zeroblob(32),
                    aios_accounting_xor(
                        state_root, aios_accounting_xor(aios_accounting_mac('record', 'quota_migration_fence', OLD.epoch), zeroblob(32))
                    ),
                    head_hash,
                    aios_accounting_mac(
                        'event', event_count + 1, 'quota_migration_fence', 'delete',
                        hex(aios_accounting_mac('record', 'quota_migration_fence', OLD.epoch)), aios_accounting_mac('record', 'quota_migration_fence', OLD.epoch), zeroblob(32),
                        aios_accounting_xor(
                            state_root, aios_accounting_xor(aios_accounting_mac('record', 'quota_migration_fence', OLD.epoch), zeroblob(32))
                        ),
                        head_hash
                    )
             FROM accounting_integrity WHERE singleton = 1;
             UPDATE accounting_integrity
             SET state_root = aios_accounting_xor(
                     state_root, aios_accounting_xor(aios_accounting_mac('record', 'quota_migration_fence', OLD.epoch), zeroblob(32))
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
         END;
CREATE INDEX idx_facts_agent ON facts(agent_id);
CREATE INDEX idx_facts_category ON facts(agent_id, category);
CREATE INDEX idx_conv_agent ON conversations(agent_id);
CREATE INDEX idx_conv_updated ON conversations(updated_at);
CREATE INDEX idx_agent_kv_agent ON agent_kv(agent_id);
CREATE INDEX idx_snapshots_agent ON context_snapshots(agent_id);
CREATE INDEX idx_users_tenant ON users(tenant_id);
CREATE INDEX idx_context_spills_tenant
                ON context_spills(tenant_id, expires_at);
CREATE INDEX idx_generation_checkpoints_agent
                ON generation_checkpoints(agent_id, created_at DESC);
CREATE INDEX idx_generation_checkpoints_tenant
                ON generation_checkpoints(tenant_id, status, expires_at);
CREATE INDEX idx_loaded_packages_tenant
                ON loaded_package_instances(tenant_id, loaded_at DESC);
CREATE INDEX idx_package_trust_publisher
                ON package_trust_keys(tenant_id, publisher, status);
CREATE INDEX idx_package_artifact_search
                ON package_artifacts(tenant_id, name, yanked, version);
CREATE INDEX idx_package_install_history
                ON package_install_history(tenant_id, name, id DESC);
CREATE INDEX idx_package_transparency_tenant
                ON package_transparency(tenant_id, sequence);
CREATE INDEX idx_package_audit_tenant
                ON package_audit(tenant_id, id DESC);
CREATE INDEX idx_operator_tunable_audit_name
                ON operator_tunable_audit(name, id DESC);
CREATE INDEX idx_service_history_name
                ON service_history(name, id DESC);
CREATE INDEX idx_quota_epochs_prune
                ON quota_epochs(epoch);
CREATE INDEX idx_quota_receipts_epoch_state
                ON quota_receipts(epoch, state);
CREATE INDEX idx_quota_receipt_scopes_scope
                ON quota_receipt_scopes(scope_kind, scope_id, receipt_id);
CREATE INDEX idx_quota_refunded_receipts_epoch
                ON quota_refunded_receipts(epoch);
CREATE INDEX idx_cluster_agent_ownership_owner
                ON cluster_agent_ownership(owner_node_id, state, lease_expires_at);
CREATE UNIQUE INDEX idx_quota_receipt_scope_order
                 ON quota_receipt_scopes(receipt_id, scope_order);
PRAGMA writable_schema=OFF;
COMMIT;
