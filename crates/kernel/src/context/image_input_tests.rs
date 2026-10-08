//! Hosted fixtures for lossless multipart history and storage reader fencing.

use super::*;
use crate::connector::{ContentPart, ImageInput, ImageMediaType, MessageContent, StandardMessage};

const PNG: &str =
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAIAAACQd1PeAAAADElEQVR4nGP4z8AAAAMBAQDJ/pLvAAAAAElFTkSuQmCC";

fn image_message() -> StandardMessage {
    StandardMessage::user_content(
        MessageContent::parts(vec![
            ContentPart::Text {
                text: "image before λ".into(),
            },
            ContentPart::Image {
                image: ImageInput::new(ImageMediaType::Png, PNG.into()).unwrap(),
            },
            ContentPart::Text {
                text: "image after 🦀".into(),
            },
        ])
        .unwrap(),
    )
}

fn agent(manager: &SqliteContextManager, tenant: &str) -> AgentId {
    let id = uuid::Uuid::new_v4();
    let now = Utc::now();
    manager
        .save_agent(&PersistedAgent {
            id,
            session_id: uuid::Uuid::new_v4(),
            tenant_id: tenant.into(),
            name: "image history".into(),
            task: "durable fixture".into(),
            llm_provider: "fixture".into(),
            permission_profile: "standard".into(),
            priority: 3,
            status: "\"Running\"".into(),
            sandbox_config_json: None,
            created_at: now,
            last_activity_at: now,
        })
        .unwrap();
    id
}

fn checkpoint(
    agent_id: AgentId,
    messages: Vec<StandardMessage>,
) -> crate::execution::GenerationCheckpoint {
    crate::execution::GenerationCheckpoint {
        agent_id,
        conversation_id: "image-parent".into(),
        user_message: messages.last().unwrap().content.text_projection(),
        messages,
        partial_content: "partial output".into(),
        tool_calls_made: 0,
        tokens_used: 3,
        usage: Default::default(),
    }
}

#[test]
fn image_input_schema13_restart_snapshots_spills_checkpoints_and_erasure_retain_exact_parts() {
    let root =
        std::env::temp_dir().join(format!("aiagentos-image-history-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&root).unwrap();
    let path = root.join("kernel.sqlite");
    let (parent, child, foreign, checkpoint_id, expected, spill) = {
        let manager = SqliteContextManager::new(&path).unwrap();
        let parent = agent(&manager, "tenant-image");
        let child = agent(&manager, "tenant-image");
        let foreign = agent(&manager, "tenant-foreign");
        let image = image_message();
        let spill = serde_json::to_string(&[image.clone()]).unwrap();
        let digest = memory_content_hash(&spill);
        let key = "context_spill:image:fixture";
        manager
            .store_context_spill(parent, key, &spill, &digest)
            .unwrap();
        let expected = vec![StandardMessage::user("legacy text remains usable"),image,
            StandardMessage::system(format!("[Durable context spill: key={key}; sha256-prefix={}; messages=1; roles=user. Page in with StorageGet before relying on omitted detail.]",&digest[..16]))];
        manager
            .save_conversation("image-parent", parent, &expected)
            .unwrap();
        let checkpoint_id = manager
            .save_generation_checkpoint(
                "tenant-image",
                "fixture",
                "vision-fixture",
                &checkpoint(parent, expected.clone()),
                std::time::Duration::from_secs(60),
            )
            .unwrap();
        manager
            .fork_conversation(parent, "image-parent", child, "image-child")
            .unwrap();
        assert_eq!(manager.load_conversation("image-child").unwrap(), expected);
        let conn = manager.locked_conn();
        let metadata = crate::schema::read_storage_metadata(&conn).unwrap();
        assert_eq!(metadata.schema_version, 13);
        assert_eq!(metadata.min_reader_schema_version, 13);
        assert!(matches!(
            crate::schema::preflight_for_reader(&conn, 12),
            Err(ContextError::DatabaseTooNew {
                found: 13,
                supported: 12
            })
        ));
        for table in ["conversations_fts", "execution_snapshot_fts"] {
            let projections: Vec<String> = conn
                .prepare(&format!("SELECT content FROM {table}"))
                .unwrap()
                .query_map([], |row| row.get(0))
                .unwrap()
                .map(Result::unwrap)
                .collect();
            assert!(projections
                .iter()
                .all(|projection| !projection.contains(PNG)));
            assert!(projections
                .iter()
                .any(|projection| projection.contains("image before λ")));
        }
        assert!(!format!(
            "{:?}",
            manager
                .list_generation_checkpoints("tenant-image", Some(parent))
                .unwrap()
        )
        .contains(PNG));
        drop(conn);
        (parent, child, foreign, checkpoint_id, expected, spill)
    };
    {
        let manager = SqliteContextManager::new(&path).unwrap();
        assert_eq!(manager.load_conversation("image-parent").unwrap(), expected);
        assert_eq!(manager.load_conversation("image-child").unwrap(), expected);
        let restored = manager
            .claim_generation_checkpoint(checkpoint_id, parent, "tenant-image")
            .unwrap();
        assert_eq!(restored.checkpoint.messages, expected);
        assert!(!restored.checkpoint.user_message.contains(PNG));
        manager
            .release_generation_checkpoint(checkpoint_id)
            .unwrap();
        assert_eq!(
            manager
                .kv_get(child, "context_spill:image:fixture")
                .unwrap(),
            Some(spill.clone())
        );
        assert_eq!(
            manager
                .kv_get(foreign, "context_spill:image:fixture")
                .unwrap(),
            None
        );
        manager.delete_agent(parent).unwrap();
        assert_eq!(manager.load_conversation("image-child").unwrap(), expected);
        assert_eq!(
            manager
                .kv_get(child, "context_spill:image:fixture")
                .unwrap(),
            Some(spill)
        );
        manager.delete_agent(child).unwrap();
        let conn = manager.locked_conn();
        for table in [
            "execution_context_snapshots",
            "execution_snapshot_fts",
            "execution_spill_blobs",
            "generation_checkpoints",
        ] {
            let count: i64 = conn
                .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
                    row.get(0)
                })
                .unwrap();
            assert_eq!(count, 0, "{table}");
        }
    }
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn image_input_every_durable_writer_refuses_schema_and_min_reader_downgrades() {
    let manager = SqliteContextManager::in_memory().unwrap();
    let parent = agent(&manager, "tenant-image");
    let child = agent(&manager, "tenant-image");
    let history = vec![StandardMessage::user("legacy"), image_message()];
    manager
        .save_conversation("image-parent", parent, &history)
        .unwrap();
    let spill = serde_json::to_string(&history).unwrap();
    for boundary in ["schema", "minimum reader"] {
        {
            let conn = manager.locked_conn();
            if boundary == "schema" {
                conn.pragma_update(None, "user_version", 12).unwrap();
            } else {
                conn.execute("UPDATE storage_meta SET min_reader_schema_version=12", [])
                    .unwrap();
            }
        }
        assert!(manager
            .save_conversation("refused", parent, &history)
            .is_err());
        assert!(manager
            .store_context_spill(
                parent,
                "context_spill:refused",
                &spill,
                &memory_content_hash(&spill)
            )
            .is_err());
        assert!(manager
            .save_generation_checkpoint(
                "tenant-image",
                "fixture",
                "vision-fixture",
                &checkpoint(parent, history.clone()),
                std::time::Duration::from_secs(60)
            )
            .is_err());
        assert!(manager
            .fork_conversation(parent, "image-parent", child, "refused-child")
            .is_err());
        let conn = manager.locked_conn();
        assert_eq!(
            conn.query_row("SELECT COUNT(*) FROM conversations", [], |row| row
                .get::<_, i64>(0))
                .unwrap(),
            1
        );
        assert_eq!(
            conn.query_row("SELECT COUNT(*) FROM generation_checkpoints", [], |row| row
                .get::<_, i64>(0))
                .unwrap(),
            0
        );
        conn.pragma_update(None, "user_version", 13).unwrap();
        conn.execute("UPDATE storage_meta SET min_reader_schema_version=13", [])
            .unwrap();
    }
}

#[test]
fn image_input_migration_from_schema12_retains_old_string_history_before_new_parts() {
    let root = std::env::temp_dir().join(format!(
        "aiagentos-image-migration-{}",
        uuid::Uuid::new_v4()
    ));
    std::fs::create_dir_all(&root).unwrap();
    let path = root.join("kernel.sqlite");
    let owner = {
        let manager = SqliteContextManager::new(&path).unwrap();
        let owner = agent(&manager, "tenant-image");
        manager
            .save_conversation("legacy", owner, &[StandardMessage::user("old history λ")])
            .unwrap();
        let conn = manager.locked_conn();
        conn.pragma_update(None, "user_version", 12).unwrap();
        conn.execute(
            "UPDATE storage_meta SET schema_version=12,min_reader_schema_version=12",
            [],
        )
        .unwrap();
        conn.execute("DELETE FROM schema_migrations WHERE version=13", [])
            .unwrap();
        owner
    };
    {
        let manager = SqliteContextManager::new(&path).unwrap();
        assert_eq!(
            manager.load_conversation("legacy").unwrap(),
            [StandardMessage::user("old history λ")]
        );
        let mut mixed = manager.load_conversation("legacy").unwrap();
        mixed.push(image_message());
        manager.save_conversation("legacy", owner, &mixed).unwrap();
        assert_eq!(manager.load_conversation("legacy").unwrap(), mixed);
        crate::schema::verify(&manager.locked_conn()).unwrap();
    }
    std::fs::remove_dir_all(root).unwrap();
}
