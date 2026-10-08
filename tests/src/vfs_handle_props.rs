//! Generated handle transitions use the real JSON server and SDK. The model
//! predicts authority/liveness/value independently of the descriptor table.

use std::sync::Arc;

use agent_sdk::{KernelClient, MountKind, WireErrorCode, WorkspaceRight};
use kernel::syscall_server::SyscallServer;
use kernel::AgentKernelImpl;
use proptest::prelude::*;

#[derive(Clone)]
struct Reference {
    id: String,
    owner: String,
    rights: u8,
    live: bool,
}

fn rights(mask: u8) -> Vec<WorkspaceRight> {
    [
        (1, WorkspaceRight::Read),
        (2, WorkspaceRight::Write),
        (4, WorkspaceRight::Stat),
    ]
    .into_iter()
    .filter_map(|(bit, right)| (mask & bit != 0).then_some(right))
    .collect()
}

async fn verify_sequence(sequence: Vec<(u8, usize, u8)>) {
    let kernel = Arc::new(AgentKernelImpl::new().unwrap());
    let server = SyscallServer::bind(kernel.clone(), "127.0.0.1:0")
        .await
        .unwrap();
    let address = server.local_addr().unwrap();
    let server_task = tokio::spawn(server.serve());
    let mut client = KernelClient::connect(address).await.unwrap();
    let mut actors = [
        client
            .create_agent("owner one", "public handle property", None, None, None)
            .await
            .unwrap(),
        client
            .create_agent("owner two", "public handle property", None, None, None)
            .await
            .unwrap(),
    ];
    let controller = client
        .create_agent(
            "mount controller",
            "public handle property",
            None,
            None,
            None,
        )
        .await
        .unwrap();
    let mut references = Vec::<Reference>::new();
    let mut values = std::collections::HashMap::<String, Option<String>>::new();
    for owner in &actors {
        values.insert(owner.clone(), None);
    }

    // The same actual allocator must hit/reclaim its unchanged public limit.
    for _ in 0..kernel::vfs::MAX_HANDLES_PER_AGENT {
        let handle = client
            .vfs_open_kv(&actors[0], "/kv", "model-key", rights(7))
            .await
            .unwrap();
        references.push(Reference {
            id: handle.id,
            owner: actors[0].clone(),
            rights: 7,
            live: true,
        });
    }
    assert_eq!(
        client
            .vfs_open_kv(&actors[0], "/kv", "model-key", rights(1))
            .await
            .unwrap_err()
            .wire_code(),
        Some(WireErrorCode::QuotaExceeded)
    );
    client
        .vfs_close(&actors[0], &references[0].id)
        .await
        .unwrap();
    references[0].live = false;
    let reclaimed = client
        .vfs_open_kv(&actors[0], "/kv", "model-key", rights(1))
        .await
        .unwrap();
    references.push(Reference {
        id: reclaimed.id,
        owner: actors[0].clone(),
        rights: 1,
        live: true,
    });
    for reference in &mut references {
        if reference.live {
            client
                .vfs_close(&reference.owner, &reference.id)
                .await
                .unwrap();
            reference.live = false;
        }
    }
    for owner in &actors {
        let handle = client
            .vfs_open_kv(owner, "/kv", "model-key", rights(7))
            .await
            .unwrap();
        references.push(Reference {
            id: handle.id,
            owner: owner.clone(),
            rights: 7,
            live: true,
        });
    }

    for (step, (operation, selector, requested)) in sequence.into_iter().enumerate() {
        let owner_slot = (selector / 2) % actors.len();
        let owner = actors[owner_slot].clone();
        let requested = requested.clamp(1, 7);
        let live = references
            .iter()
            .enumerate()
            .filter_map(|(index, reference)| reference.live.then_some(index))
            .collect::<Vec<_>>();
        let selected_index = if selector % 2 == 0 && !live.is_empty() {
            live[selector % live.len()]
        } else {
            selector % references.len()
        };
        let selected = references[selected_index].clone();
        let owned_live = selected.live && selected.owner == owner;
        match operation {
            0 => {
                let handle = client
                    .vfs_open_kv(&owner, "/kv", "model-key", rights(requested))
                    .await
                    .unwrap();
                references.push(Reference {
                    id: handle.id,
                    owner,
                    rights: requested,
                    live: true,
                });
            }
            1 => {
                let duplicate = client
                    .vfs_dup_data(&owner, &selected.id, rights(requested))
                    .await;
                if !owned_live {
                    assert_eq!(
                        duplicate.unwrap_err().wire_code(),
                        Some(WireErrorCode::NotFound)
                    );
                } else if requested & !selected.rights != 0 {
                    assert_eq!(
                        duplicate.unwrap_err().wire_code(),
                        Some(WireErrorCode::PermissionDenied)
                    );
                } else {
                    let duplicate = duplicate.unwrap();
                    assert!(duplicate
                        .rights
                        .iter()
                        .all(|right| rights(selected.rights).contains(right)));
                    references.push(Reference {
                        id: duplicate.id,
                        owner,
                        rights: requested,
                        live: true,
                    });
                }
            }
            2 => {
                let closed = client.vfs_close(&owner, &selected.id).await;
                if owned_live {
                    closed.unwrap();
                    references[selected_index].live = false;
                } else {
                    assert_eq!(
                        closed.unwrap_err().wire_code(),
                        Some(WireErrorCode::NotFound)
                    );
                }
            }
            3 | 4 | 5 => {
                let required = if operation == 3 {
                    1
                } else if operation == 4 {
                    2
                } else {
                    4
                };
                let result = match operation {
                    3 => {
                        client
                            .vfs_read_data(&owner, &selected.id, serde_json::json!({}))
                            .await
                    }
                    4 => {
                        client
                            .vfs_write_data(
                                &owner,
                                &selected.id,
                                serde_json::json!({"value":step.to_string()}),
                            )
                            .await
                    }
                    _ => client.vfs_stat_data(&owner, &selected.id).await,
                };
                if !owned_live {
                    assert_eq!(
                        result.unwrap_err().wire_code(),
                        Some(WireErrorCode::NotFound)
                    );
                } else if selected.rights & required == 0 {
                    assert_eq!(
                        result.unwrap_err().wire_code(),
                        Some(WireErrorCode::PermissionDenied)
                    );
                } else {
                    let data = result.unwrap();
                    if operation == 3 {
                        assert_eq!(
                            data["value"],
                            serde_json::to_value(&values[&owner]).unwrap()
                        );
                    }
                    if operation == 4 {
                        values.insert(owner, Some(step.to_string()));
                    }
                }
            }
            6 => {
                let view = client.vfs_namespace_mounts(&controller).await.unwrap();
                let mount = view
                    .mounts
                    .iter()
                    .find(|entry| entry.path == "/kv")
                    .unwrap();
                let removed = client
                    .vfs_unmount(
                        &controller,
                        &view.table_id,
                        view.generation,
                        "/kv",
                        &mount.id,
                    )
                    .await
                    .unwrap();
                for reference in &mut references {
                    reference.live = false;
                }
                client
                    .vfs_mount(
                        &controller,
                        &removed.table_id,
                        removed.generation,
                        "/kv",
                        MountKind::Kv,
                    )
                    .await
                    .unwrap();
            }
            _ => {
                client.stop_agent(&owner).await.unwrap();
                for reference in &mut references {
                    if reference.owner == owner {
                        reference.live = false;
                    }
                }
                let replacement = client
                    .create_agent(
                        "replacement owner",
                        "public handle property",
                        None,
                        None,
                        None,
                    )
                    .await
                    .unwrap();
                actors[owner_slot] = replacement.clone();
                values.insert(replacement, None);
            }
        }
        for owner in &actors {
            let expected = references
                .iter()
                .filter(|reference| reference.live && &reference.owner == owner)
                .count();
            assert_eq!(
                client.vfs_mounts(owner).await.unwrap().open_handles,
                expected
            );
            assert!(expected <= kernel::vfs::MAX_HANDLES_PER_AGENT);
        }
    }
    for reference in &mut references {
        if reference.live {
            client
                .vfs_close(&reference.owner, &reference.id)
                .await
                .unwrap();
            reference.live = false;
        }
    }
    for actor in &actors {
        assert_eq!(client.vfs_mounts(actor).await.unwrap().open_handles, 0);
    }
    client.close().await.unwrap();
    server_task.abort();
    let _ = server_task.await;
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(16))]
    #[test]
    fn generated_public_handle_lifecycle_never_broadens_rights_or_resurrects(
        sequence in prop::collection::vec((0u8..8, 0usize..512, 1u8..8), 8..40)
    ) {
        let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        runtime.block_on(verify_sequence(sequence));
    }
}
