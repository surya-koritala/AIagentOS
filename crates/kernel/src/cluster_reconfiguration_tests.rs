async fn wait_live_leader(
    runtimes: &[Option<ClusterRaftRuntime>],
    phase: &str,
) -> ClusterRaftNodeId {
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        let mut votes = BTreeMap::new();
        for runtime in runtimes.iter().flatten() {
            if let Some(leader) = runtime.metrics().borrow().current_leader {
                *votes.entry(leader).or_insert(0usize) += 1;
            }
        }
        if let Some((leader, _)) = votes.into_iter().find(|(_, count)| *count >= 2) {
            return leader;
        }
        if Instant::now() >= deadline {
            let actual = runtimes
                .iter()
                .flatten()
                .map(|runtime| runtime.metrics().borrow().clone())
                .collect::<Vec<_>>();
            panic!("{phase}: no leader; actual bounded node metrics: {actual:?}");
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

struct LiveFixture {
    root: TempDir,
    ca: CertifiedIssuer<'static, KeyPair>,
    peers: Vec<TestPeer>,
    contexts: Vec<Arc<SqliteContextManager>>,
    configs: Vec<ClusterRaftRuntimeConfig>,
    runtimes: Vec<Option<ClusterRaftRuntime>>,
}

impl LiveFixture {
    async fn start(name: &str) -> Self {
        let ca = test_ca();
        let peers = (1..=4).map(|id| test_peer(&ca, id)).collect::<Vec<_>>();
        let bound = listeners(4).await;
        let members = member_map(&peers, &bound);
        let mut configs = peers
            .iter()
            .zip(&bound)
            .map(|(peer, listener)| runtime_config(peer, listener, &members, name))
            .collect::<Vec<_>>();
        for config in &mut configs {
            set_voter_plan(config, 0, BTreeSet::from([1, 2, 3]));
        }
        let root = TempDir::new().unwrap();
        let contexts = (1..=4).map(|id| context(&root, id)).collect::<Vec<_>>();
        let mut runtimes = Vec::new();
        for ((config, listener), context) in configs.iter().cloned().zip(bound).zip(&contexts) {
            runtimes.push(Some(
                ClusterRaftRuntime::start_on_listener(context.clone(), config, listener)
                    .await
                    .unwrap(),
            ));
        }
        let (one, two, three, four) = tokio::join!(
            runtimes[0]
                .as_ref()
                .unwrap()
                .ensure_configured_membership(true),
            runtimes[1]
                .as_ref()
                .unwrap()
                .ensure_configured_membership(true),
            runtimes[2]
                .as_ref()
                .unwrap()
                .ensure_configured_membership(true),
            runtimes[3]
                .as_ref()
                .unwrap()
                .ensure_configured_membership(false),
        );
        one.unwrap();
        two.unwrap();
        three.unwrap();
        four.unwrap();
        let leader = wait_live_leader(&runtimes, "initial live fixture").await;
        runtimes[(leader - 1) as usize]
            .as_ref()
            .unwrap()
            .ensure_authority_initialized()
            .await
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(15);
        loop {
            if contexts
                .iter()
                .all(|context| read_initialized_authority_view(context).is_ok())
            {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "authority did not replicate to every learner"
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        Self {
            root,
            ca,
            peers,
            contexts,
            configs,
            runtimes,
        }
    }

    async fn submit(
        &self,
        source: usize,
        inner: AuthorityCommand,
    ) -> io::Result<AuthorityResponse> {
        let command = crate::cluster_principal::fixture_signed(
            inner,
            crate::cluster_principal::FIXTURE_CLUSTER_ID,
        );
        self.runtimes[source]
            .as_ref()
            .unwrap()
            .authority_handle()
            .commit(
                command.clone(),
                test_authority_delegation(&self.peers[source], &command),
            )
            .await
    }

    async fn current(
        &self,
        source: usize,
    ) -> crate::cluster_reconfiguration::ClusterReconfigurationTarget {
        self.runtimes[source]
            .as_ref()
            .unwrap()
            .authority_handle()
            .reconfiguration_status()
            .await
            .unwrap()
            .current
    }

    fn voter_command(
        &self,
        source: usize,
        prior: crate::cluster_reconfiguration::ClusterReconfigurationTarget,
        target: BTreeSet<u64>,
        expected: u64,
        next: u64,
        operation_id: String,
    ) -> AuthorityCommand {
        AuthorityCommand::ProposeClusterVoterChange {
            operation_id,
            prior,
            target_voter_ids: target,
            expected_generation: expected,
            target_generation: next,
            actor: authority_system_actor(&self.peers[source].application_node_id),
            reason: "controlled live voter proposal".into(),
            proposed_at: chrono::Utc::now(),
        }
    }

    fn trust_command(
        &self,
        source: usize,
        prior: crate::cluster_reconfiguration::ClusterReconfigurationTarget,
        catalog: BTreeMap<u64, ClusterRaftNode>,
        generation: u64,
        expiry: Option<chrono::DateTime<chrono::Utc>>,
    ) -> AuthorityCommand {
        AuthorityCommand::ProposeClusterTrustChange {
            operation_id: Uuid::new_v4().to_string(),
            expected_generation: prior.trust_generation,
            target_generation: generation,
            prior,
            target_catalog: catalog,
            overlap_not_after: expiry,
            actor: authority_system_actor(&self.peers[source].application_node_id),
            reason: "controlled live complete trust catalog".into(),
            proposed_at: chrono::Utc::now(),
        }
    }

    async fn settle(
        &self,
        plan: &crate::cluster_reconfiguration::ClusterReconfigurationPlan,
        count: usize,
    ) {
        let deadline = Instant::now() + Duration::from_secs(25);
        loop {
            let matched = self
                .contexts
                .iter()
                .filter(|context| {
                    let (membership, local) =
                        crate::cluster_consensus::read_cluster_reconfiguration(context).unwrap();
                    let durable =
                        crate::cluster_consensus::read_cluster_raft_membership(context).unwrap();
                    local.as_ref() == Some(plan)
                        && plan.target.is_settled(&membership)
                        && plan.target.is_settled(&durable)
                })
                .count();
            if matched >= count {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "prepared target did not settle on {count} nodes; got {matched}"
            );
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    }

    async fn restart_all(&mut self, configs: Vec<ClusterRaftRuntimeConfig>) {
        for runtime in &mut self.runtimes {
            runtime.take().unwrap().shutdown().await.unwrap();
        }
        self.configs = configs;
        for index in 0..self.configs.len() {
            let config = self.configs[index].clone();
            let listener =
                rebind_test_listener(config.listen_addr, "live fixture configured restart").await;
            self.runtimes[index] = Some(
                ClusterRaftRuntime::start_on_listener(
                    self.contexts[index].clone(),
                    config,
                    listener,
                )
                .await
                .unwrap(),
            );
        }
        let (one, two, three, four) = tokio::join!(
            self.runtimes[0]
                .as_ref()
                .unwrap()
                .ensure_configured_membership(false),
            self.runtimes[1]
                .as_ref()
                .unwrap()
                .ensure_configured_membership(false),
            self.runtimes[2]
                .as_ref()
                .unwrap()
                .ensure_configured_membership(false),
            self.runtimes[3]
                .as_ref()
                .unwrap()
                .ensure_configured_membership(false),
        );
        one.unwrap();
        two.unwrap();
        three.unwrap();
        four.unwrap();
        wait_live_leader(&self.runtimes, "configured live fixture restart").await;
    }

    async fn close(self) {
        for runtime in self.runtimes.into_iter().flatten() {
            runtime.shutdown().await.unwrap();
        }
        let stores = self.contexts.iter().map(Arc::downgrade).collect::<Vec<_>>();
        drop(self.contexts);
        tokio::time::timeout(Duration::from_secs(5), async {
            while stores.iter().any(|store| store.upgrade().is_some()) {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        }).await.expect("shutdown releases every durable Raft context owner before native deletion");
        self.root
            .close()
            .expect("release all real native database handles");
    }
}

fn prepared(
    response: AuthorityResponse,
) -> crate::cluster_reconfiguration::ClusterReconfigurationPlan {
    match response {
        AuthorityResponse::ReconfigurationPrepared {
            plan,
            replayed: false,
            ..
        } => *plan,
        other => panic!("expected a newly prepared exact target, got {other:?}"),
    }
}

async fn projection_reads_do_not_reconstruct_history_under_a_writer_lock(
    context: Arc<SqliteContextManager>,
) {
    let expected = crate::cluster_consensus::read_cluster_reconfiguration(&context).unwrap();
    let holder_context = context.clone();
    let (held_tx, held_rx) = tokio::sync::oneshot::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel();
    let holder = tokio::task::spawn_blocking(move || {
        let guard = holder_context.locked_conn();
        held_tx.send(()).unwrap();
        release_rx
            .recv_timeout(Duration::from_secs(3))
            .expect("fixture writer is bounded");
        drop(guard);
    });
    tokio::time::timeout(Duration::from_secs(1), held_rx)
        .await
        .unwrap()
        .unwrap();
    let mut reader = tokio::task::spawn_blocking(move || {
        crate::cluster_consensus::read_cluster_reconfiguration(&context)
    });
    let delivered = tokio::time::timeout(Duration::from_millis(500), &mut reader).await;
    release_tx.send(()).unwrap();
    tokio::time::timeout(Duration::from_secs(3), holder)
        .await
        .unwrap()
        .unwrap();
    match delivered {
        Ok(delivered) => assert_eq!(delivered.unwrap().unwrap(), expected),
        Err(_) => {
            tokio::time::timeout(Duration::from_secs(3), reader)
                .await
                .unwrap()
                .unwrap()
                .unwrap();
            panic!("a warmed peer-admission projection must not reacquire SQLite or reconstruct signed history");
        }
    }
}

async fn validated_snapshot_refreshes_a_warmed_projection(
    fixture: &LiveFixture,
    plan: &crate::cluster_reconfiguration::ClusterReconfigurationPlan,
) {
    use openraft::storage::RaftStateMachine;
    use openraft::RaftSnapshotBuilder;
    let (_, mut source) =
        crate::cluster_consensus::open_cluster_raft_storage(fixture.contexts[0].clone()).unwrap();
    let mut builder = source.get_snapshot_builder().await;
    let snapshot = builder.build_snapshot().await.unwrap();
    let target = Arc::new(SqliteContextManager::in_memory().unwrap());
    let initial = crate::cluster_consensus::read_cluster_reconfiguration(&target).unwrap();
    assert!(initial.1.is_none());
    let (_, mut destination) = crate::cluster_consensus::open_cluster_raft_storage_pinned(
        target.clone(),
        &fixture.configs[0].authority_genesis,
    )
    .unwrap();
    destination
        .install_snapshot(&snapshot.meta, snapshot.snapshot)
        .await
        .unwrap();
    let (published, retained) =
        crate::cluster_consensus::read_cluster_reconfiguration(&target).unwrap();
    assert_eq!(retained.as_ref(), Some(plan));
    assert!(plan.target.is_settled(&published));
    assert_eq!(
        published,
        crate::cluster_consensus::read_cluster_raft_membership(&target).unwrap()
    );
    projection_reads_do_not_reconstruct_history_under_a_writer_lock(target.clone()).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn live_voter_change_completes_without_restart_and_is_generation_fenced() {
    tokio::time::timeout(Duration::from_secs(120), async {
        let mut fixture = LiveFixture::start("live-voter-change").await;
        projection_reads_do_not_reconstruct_history_under_a_writer_lock(fixture.contexts[0].clone()).await;
        let prior = fixture.current(0).await;
        // An actual unavailable learner prevents catch-up. The old voting
        // quorum stays usable while the exact target remains prepared.
        fixture.runtimes[3].take().unwrap().shutdown().await.unwrap();
        let operation_id = Uuid::new_v4().to_string();
        let inner = fixture.voter_command(0, prior.clone(), BTreeSet::from([1, 2, 4]), 0, 1, operation_id.clone());
        let plan = prepared(fixture.submit(0, inner.clone()).await.unwrap());
        let conflicting = fixture.voter_command(1, prior.clone(), BTreeSet::from([1, 3, 4]), 0, 1, Uuid::new_v4().to_string());
        assert!(matches!(fixture.submit(1, conflicting).await.unwrap(), AuthorityResponse::Rejected { .. }));
        assert!(!plan.target.is_settled(&crate::cluster_consensus::read_cluster_raft_membership(&fixture.contexts[0]).unwrap()));
        let mut incoming = fixture.configs[3].clone();
        set_voter_plan(&mut incoming, 1, plan.target.voter_ids.clone());
        let listener = rebind_test_listener(incoming.listen_addr, "resume incoming learner").await;
        fixture.runtimes[3] = Some(ClusterRaftRuntime::start_on_listener(fixture.contexts[3].clone(), incoming, listener).await.unwrap());
        fixture.settle(&plan, 4).await;
        validated_snapshot_refreshes_a_warmed_projection(&fixture, &plan).await;
        for runtime in fixture.runtimes.iter().flatten() {
            let metrics = runtime.metrics();
            assert_eq!(metrics.borrow().membership_config.membership().get_joint_config(), &vec![BTreeSet::from([1, 2, 4])]);
            assert!(metrics.borrow().membership_config.nodes().any(|(id, _)| *id == 3), "removed voter must remain a replicated learner");
        }
        assert!(matches!(fixture.submit(0, inner.clone()).await.unwrap(), AuthorityResponse::ReconfigurationPrepared { replayed: true, .. }));
        let current = fixture.current(0).await;
        for (expected, target, message) in [(9, 2, "expected generation"), (1, 1, "reuses"), (1, 3, "skips")] {
            let command = fixture.voter_command(0, current.clone(), BTreeSet::from([1, 2, 3]), expected, target, Uuid::new_v4().to_string());
            let response = fixture.submit(0, command).await.unwrap();
            assert!(matches!(&response, AuthorityResponse::Rejected { message: actual, .. } if actual.contains(message)), "{response:?}");
        }
        let stale_configs = fixture.configs.clone();
        let mut updated = fixture.configs.clone();
        for config in &mut updated { set_voter_plan(config, 1, plan.target.voter_ids.clone()); }
        fixture.restart_all(updated).await;
        assert!(fixture.runtimes[0].as_ref().unwrap().authority_handle().reconfiguration_status().await.unwrap().settled);
        assert!(matches!(fixture.submit(0, inner.clone()).await.unwrap(), AuthorityResponse::ReconfigurationPrepared { replayed: true, .. }));
        let mut operator_next = fixture.configs.clone();
        for config in &mut operator_next { set_voter_plan(config, 2, BTreeSet::from([1, 2, 3])); }
        fixture.restart_all(operator_next).await;
        let advanced = fixture.runtimes[0].as_ref().unwrap().authority_handle().reconfiguration_status().await.unwrap();
        assert!(advanced.settled);
        assert_eq!(advanced.current.voter_generation, 2);
        assert!(advanced.target.is_none(), "superseded history is not a pending target");
        assert!(matches!(fixture.submit(0, inner).await.unwrap(), AuthorityResponse::ReconfigurationPrepared { replayed: true, .. }));
        assert_eq!(fixture.current(0).await.voter_generation, 2, "historical replay never restores generation one");
        fixture.runtimes[0].take().unwrap().shutdown().await.unwrap();
        let listener = rebind_test_listener(stale_configs[0].listen_addr, "stale configuration denial").await;
        let error = ClusterRaftRuntime::start_on_listener(fixture.contexts[0].clone(), stale_configs[0].clone(), listener).await.unwrap_err();
        assert!(error.to_string().contains("stale"));
        let listener = rebind_test_listener(fixture.configs[0].listen_addr, "restore updated configuration").await;
        fixture.runtimes[0] = Some(ClusterRaftRuntime::start_on_listener(fixture.contexts[0].clone(), fixture.configs[0].clone(), listener).await.unwrap());
        fixture.close().await;
    }).await.expect("live voter/catch-up/restart proof is bounded");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn live_trust_change_replaces_the_catalog_and_preserves_voters() {
    tokio::time::timeout(Duration::from_secs(120), async {
        let mut fixture = LiveFixture::start("live-trust-change").await;
        // Provisioned version-one roots are a prerequisite of this first
        // supported live API; generation-zero bootstrap is unchanged.
        let roots = certificate_fingerprints_from_pem(fixture.ca.pem().as_bytes()).unwrap();
        let mut versioned = fixture.configs.clone();
        for config in &mut versioned {
            set_transport_trust_plan(config, 1, roots.clone(), None);
        }
        fixture.restart_all(versioned).await;
        let prior = fixture.current(0).await;
        let next_peers = (1..=4)
            .map(|id| test_peer(&fixture.ca, id))
            .collect::<Vec<_>>();
        let mut factory = fixture.runtimes[0]
            .as_ref()
            .unwrap()
            .authority_handle()
            .network
            .clone();
        let cached_four = factory.new_client(4, prior.catalog.get(&4).unwrap()).await;
        let mut fresh_leaf_factory = factory.clone();
        fresh_leaf_factory.source = 4;
        fresh_leaf_factory.client_config = next_peers[3].tls.client_config.clone();
        fresh_leaf_factory.live_catalog = None;
        let fresh_leaf_client = fresh_leaf_factory
            .new_client(1, prior.catalog.get(&1).unwrap())
            .await;
        let vote_probe = || {
            RpcRequest::Vote(VoteRequest {
                vote: Vote::new(0, 4),
                last_log_id: None,
            })
        };
        assert!(
            fresh_leaf_client
                .call(vote_probe(), RPCOption::new(Duration::from_secs(3)))
                .await
                .is_err(),
            "a same-CA leaf is denied before its authorized catalog generation"
        );
        let mut overlap = prior.catalog.clone();
        let expiry = chrono::Utc::now() + chrono::Duration::hours(1);
        for (id, node) in &mut overlap {
            node.transport_trust_generation = 2;
            node.transport_trust_overlap_not_after = Some(expiry);
            node.tls_client_certificate_sha256_overlap = vec![next_peers[(*id - 1) as usize]
                .tls
                .client_certificate_sha256()
                .into()];
        }
        let digest = configured_transport_catalog_sha256(&overlap);
        for node in overlap.values_mut() {
            node.transport_catalog_sha256.clone_from(&digest);
        }
        let command = fixture.trust_command(0, prior.clone(), overlap, 2, Some(expiry));
        let unsigned = command.clone();
        assert!(
            fixture.runtimes[0]
                .as_ref()
                .unwrap()
                .authority_handle()
                .commit(
                    unsigned.clone(),
                    test_authority_delegation(&fixture.peers[0], &unsigned)
                )
                .await
                .is_err(),
            "node keys alone must not authorize a transport change"
        );
        let plan = prepared(fixture.submit(0, command).await.unwrap());
        fixture.settle(&plan, 4).await;
        assert!(
            matches!(
                fresh_leaf_client
                    .call(vote_probe(), RPCOption::new(Duration::from_secs(3)))
                    .await,
                Ok(RpcResponse::Vote(Ok(_)))
            ),
            "the running listener must admit the exact newly authorized overlap leaf"
        );
        assert_eq!(plan.target.voter_ids, prior.voter_ids);
        assert_eq!(plan.target.voter_generation, prior.voter_generation);
        for context in &fixture.contexts {
            let (membership, _) =
                crate::cluster_consensus::read_cluster_reconfiguration(context).unwrap();
            assert_eq!(
                membership
                    .nodes()
                    .map(|(id, node)| (*id, node.clone()))
                    .collect::<BTreeMap<_, _>>(),
                plan.target.catalog
            );
        }
        let voter = fixture.voter_command(
            0,
            plan.target.clone(),
            BTreeSet::from([1, 2]),
            0,
            1,
            Uuid::new_v4().to_string(),
        );
        let voter_plan = prepared(fixture.submit(0, voter).await.unwrap());
        fixture.settle(&voter_plan, 4).await;
        let mut retained_config = fixture.configs[0].clone();
        retained_config.members = voter_plan.target.catalog.clone();
        retained_config.voter_ids = voter_plan.target.voter_ids.clone();
        retained_config.voter_set_generation = voter_plan.target.voter_generation;
        retained_config.voter_set_sha256 = voter_plan.target.voter_set_sha256.clone();
        retained_config.transport_trust_generation = voter_plan.target.trust_generation;
        retained_config.transport_catalog_sha256 = voter_plan.target.catalog_sha256.clone();
        retained_config.transport_trust_overlap_not_after = voter_plan.target.overlap_not_after;
        let mut opaque = retained_config.clone();
        opaque.tls = ClusterRaftTls::from_configs(
            opaque.tls.server_config.as_ref().clone(),
            opaque.tls.client_config.as_ref().clone(),
            opaque.tls.server_certificate_sha256.clone(),
            opaque.tls.client_certificate_sha256.clone(),
        )
        .unwrap();
        fixture.runtimes[0]
            .take()
            .unwrap()
            .shutdown()
            .await
            .unwrap();
        let listener =
            rebind_test_listener(opaque.listen_addr, "opaque root evidence denial").await;
        let denied =
            ClusterRaftRuntime::start_on_listener(fixture.contexts[0].clone(), opaque, listener)
                .await
                .unwrap_err();
        assert_eq!(
            denied.kind(),
            io::ErrorKind::Unsupported,
            "a voter-kind latest plan must not mask versioned root provenance"
        );
        let listener = rebind_test_listener(
            retained_config.listen_addr,
            "restore material-backed live root evidence",
        )
        .await;
        fixture.runtimes[0] = Some(
            ClusterRaftRuntime::start_on_listener(
                fixture.contexts[0].clone(),
                retained_config,
                listener,
            )
            .await
            .unwrap(),
        );
        wait_live_leader(&fixture.runtimes, "restored material-backed root evidence").await;
        let stale_trust = fixture.configs[0].clone();
        let mut exact = fixture.configs.clone();
        for config in &mut exact {
            config.members = voter_plan.target.catalog.clone();
            config.transport_catalog_sha256 = voter_plan.target.catalog_sha256.clone();
            config.transport_trust_generation = voter_plan.target.trust_generation;
            config.transport_trust_overlap_not_after = voter_plan.target.overlap_not_after;
            set_voter_plan(
                config,
                voter_plan.target.voter_generation,
                voter_plan.target.voter_ids.clone(),
            );
        }
        fixture.restart_all(exact).await;
        let actual = fixture.runtimes[0]
            .as_ref()
            .unwrap()
            .authority_handle()
            .reconfiguration_status()
            .await
            .unwrap();
        assert!(actual.settled && actual.quorum_verified);
        assert_eq!(actual.current, voter_plan.target);
        fixture.runtimes[0]
            .take()
            .unwrap()
            .shutdown()
            .await
            .unwrap();
        let listener = rebind_test_listener(
            stale_trust.listen_addr,
            "stale live trust configuration rejection",
        )
        .await;
        let error = ClusterRaftRuntime::start_on_listener(
            fixture.contexts[0].clone(),
            stale_trust,
            listener,
        )
        .await
        .unwrap_err();
        assert!(error.to_string().contains("stale"));
        let listener = rebind_test_listener(
            fixture.configs[0].listen_addr,
            "restore exact live trust configuration",
        )
        .await;
        fixture.runtimes[0] = Some(
            ClusterRaftRuntime::start_on_listener(
                fixture.contexts[0].clone(),
                fixture.configs[0].clone(),
                listener,
            )
            .await
            .unwrap(),
        );
        wait_live_leader(&fixture.runtimes, "restored exact live trust configuration").await;
        // A cached actual OpenRaft client must consult the current catalog.
        // Removing this non-voter makes that pre-existing client fail closed.
        let mut removed = voter_plan.target.catalog.clone();
        removed.remove(&4);
        for node in removed.values_mut() {
            node.transport_trust_generation = 3;
        }
        let digest = configured_transport_catalog_sha256(&removed);
        for node in removed.values_mut() {
            node.transport_catalog_sha256.clone_from(&digest);
        }
        let remove = fixture.trust_command(0, voter_plan.target.clone(), removed, 3, Some(expiry));
        let removed_plan = prepared(fixture.submit(0, remove).await.unwrap());
        fixture.settle(&removed_plan, 3).await;
        assert!(
            fresh_leaf_client
                .call(vote_probe(), RPCOption::new(Duration::from_secs(3)))
                .await
                .is_err(),
            "removed trust source cannot use a previously admitted leaf"
        );
        assert!(cached_four
            .call(
                RpcRequest::Vote(VoteRequest {
                    vote: Vote::new(0, 1),
                    last_log_id: None
                }),
                RPCOption::new(Duration::from_secs(3))
            )
            .await
            .is_err());
        drop(cached_four);
        drop(fresh_leaf_client);
        drop(fresh_leaf_factory);
        drop(factory);
        fixture.close().await;
    })
    .await
    .expect("live complete-catalog proof is bounded");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn simultaneous_live_voter_and_trust_proposals_commit_only_one_generation() {
    tokio::time::timeout(Duration::from_secs(120), async {
        let mut fixture = LiveFixture::start("simultaneous-live-proposals").await;
        let roots = certificate_fingerprints_from_pem(fixture.ca.pem().as_bytes()).unwrap();
        let mut versioned = fixture.configs.clone();
        for config in &mut versioned {
            set_transport_trust_plan(config, 1, roots.clone(), None);
        }
        fixture.restart_all(versioned).await;
        let prior = fixture.current(0).await;
        let voter = fixture.voter_command(
            0,
            prior.clone(),
            BTreeSet::from([1, 2]),
            0,
            1,
            Uuid::new_v4().to_string(),
        );
        let mut catalog = prior.catalog.clone();
        for node in catalog.values_mut() {
            node.transport_trust_generation = 2;
        }
        let digest = configured_transport_catalog_sha256(&catalog);
        for node in catalog.values_mut() {
            node.transport_catalog_sha256.clone_from(&digest);
        }
        let trust = fixture.trust_command(1, prior.clone(), catalog, 2, None);
        let (voter, trust) = tokio::join!(fixture.submit(0, voter), fixture.submit(1, trust));
        let voter = voter.unwrap();
        let trust = trust.unwrap();
        let plan = match (voter, trust) {
            (
                accepted @ AuthorityResponse::ReconfigurationPrepared { .. },
                AuthorityResponse::Rejected { .. },
            )
            | (
                AuthorityResponse::Rejected { .. },
                accepted @ AuthorityResponse::ReconfigurationPrepared { .. },
            ) => prepared(accepted),
            other => panic!("exact prior CAS must admit only one concurrent proposal: {other:?}"),
        };
        fixture.settle(&plan, 4).await;
        let current = fixture.current(0).await;
        assert_eq!(current, plan.target);
        assert!(
            (current.voter_generation == 1 && current.trust_generation == 1)
                || (current.voter_generation == 0 && current.trust_generation == 2)
        );
        fixture.close().await;
    })
    .await
    .expect("concurrent live generation proof is bounded");
}
