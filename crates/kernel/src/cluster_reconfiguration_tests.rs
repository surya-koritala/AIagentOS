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
        let mut configs = peers.iter().zip(&bound).map(|(peer, listener)| runtime_config(peer, listener, &members, name)).collect::<Vec<_>>();
        for config in &mut configs { set_voter_plan(config, 0, BTreeSet::from([1, 2, 3])); }
        let root = TempDir::new().unwrap();
        let contexts = (1..=4).map(|id| context(&root, id)).collect::<Vec<_>>();
        let mut runtimes = Vec::new();
        for ((config, listener), context) in configs.iter().cloned().zip(bound).zip(&contexts) {
            runtimes.push(Some(ClusterRaftRuntime::start_on_listener(context.clone(), config, listener).await.unwrap()));
        }
        let (one, two, three, four) = tokio::join!(
            runtimes[0].as_ref().unwrap().ensure_configured_membership(true),
            runtimes[1].as_ref().unwrap().ensure_configured_membership(true),
            runtimes[2].as_ref().unwrap().ensure_configured_membership(true),
            runtimes[3].as_ref().unwrap().ensure_configured_membership(false),
        );
        one.unwrap(); two.unwrap(); three.unwrap(); four.unwrap();
        let leader = wait_for_leader(&runtimes, None).await;
        runtimes[(leader - 1) as usize].as_ref().unwrap().ensure_authority_initialized().await.unwrap();
        let deadline = Instant::now() + Duration::from_secs(15);
        loop {
            if contexts.iter().all(|context| read_initialized_authority_view(context).is_ok()) { break; }
            assert!(Instant::now() < deadline, "authority did not replicate to every learner");
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        Self { root, ca, peers, contexts, configs, runtimes }
    }

    async fn submit(&self, source: usize, inner: AuthorityCommand) -> io::Result<AuthorityResponse> {
        let command = crate::cluster_principal::fixture_signed(inner, crate::cluster_principal::FIXTURE_CLUSTER_ID);
        self.runtimes[source].as_ref().unwrap().authority_handle().commit(command.clone(), test_authority_delegation(&self.peers[source], &command)).await
    }

    async fn current(&self, source: usize) -> crate::cluster_reconfiguration::ClusterReconfigurationTarget {
        self.runtimes[source].as_ref().unwrap().authority_handle().reconfiguration_status().await.unwrap().current
    }

    fn voter_command(&self, source: usize, prior: crate::cluster_reconfiguration::ClusterReconfigurationTarget, target: BTreeSet<u64>, expected: u64, next: u64, operation_id: String) -> AuthorityCommand {
        AuthorityCommand::ProposeClusterVoterChange {
            operation_id, prior, target_voter_ids: target, expected_generation: expected, target_generation: next,
            actor: authority_system_actor(&self.peers[source].application_node_id), reason: "controlled live voter proposal".into(), proposed_at: chrono::Utc::now(),
        }
    }

    fn trust_command(&self, source: usize, prior: crate::cluster_reconfiguration::ClusterReconfigurationTarget, catalog: BTreeMap<u64, ClusterRaftNode>, generation: u64, expiry: Option<chrono::DateTime<chrono::Utc>>) -> AuthorityCommand {
        AuthorityCommand::ProposeClusterTrustChange {
            operation_id: Uuid::new_v4().to_string(), expected_generation: prior.trust_generation, target_generation: generation,
            prior, target_catalog: catalog, overlap_not_after: expiry,
            actor: authority_system_actor(&self.peers[source].application_node_id), reason: "controlled live complete trust catalog".into(), proposed_at: chrono::Utc::now(),
        }
    }

    async fn settle(&self, plan: &crate::cluster_reconfiguration::ClusterReconfigurationPlan, count: usize) {
        let deadline = Instant::now() + Duration::from_secs(25);
        loop {
            let matched = self.contexts.iter().filter(|context| {
                let (membership, local) = crate::cluster_consensus::read_cluster_reconfiguration(context).unwrap();
                local.as_ref() == Some(plan) && plan.target.is_settled(&membership)
            }).count();
            if matched >= count { break; }
            assert!(Instant::now() < deadline, "prepared target did not settle on {count} nodes; got {matched}");
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    }

    async fn restart_all(&mut self, configs: Vec<ClusterRaftRuntimeConfig>) {
        for runtime in &mut self.runtimes { runtime.take().unwrap().shutdown().await.unwrap(); }
        self.configs = configs;
        for index in 0..self.configs.len() {
            let config = self.configs[index].clone();
            let listener = rebind_test_listener(config.listen_addr, "live fixture configured restart").await;
            self.runtimes[index] = Some(ClusterRaftRuntime::start_on_listener(self.contexts[index].clone(), config, listener).await.unwrap());
        }
        let (one, two, three, four) = tokio::join!(
            self.runtimes[0].as_ref().unwrap().ensure_configured_membership(false),
            self.runtimes[1].as_ref().unwrap().ensure_configured_membership(false),
            self.runtimes[2].as_ref().unwrap().ensure_configured_membership(false),
            self.runtimes[3].as_ref().unwrap().ensure_configured_membership(false),
        );
        one.unwrap(); two.unwrap(); three.unwrap(); four.unwrap();
        wait_for_leader(&self.runtimes, None).await;
    }

    async fn close(self) {
        for runtime in self.runtimes.into_iter().flatten() { runtime.shutdown().await.unwrap(); }
        drop(self.contexts);
        self.root.close().expect("release all real native database handles");
    }
}

fn prepared(response: AuthorityResponse) -> crate::cluster_reconfiguration::ClusterReconfigurationPlan {
    match response {
        AuthorityResponse::ReconfigurationPrepared { plan, replayed: false, .. } => *plan,
        other => panic!("expected a newly prepared exact target, got {other:?}"),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn live_voter_change_completes_without_restart_and_is_generation_fenced() {
    tokio::time::timeout(Duration::from_secs(120), async {
        let mut fixture = LiveFixture::start("live-voter-change").await;
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
        assert!(matches!(fixture.submit(0, inner).await.unwrap(), AuthorityResponse::ReconfigurationPrepared { replayed: true, .. }));
        fixture.runtimes[0].take().unwrap().shutdown().await.unwrap();
        let listener = rebind_test_listener(stale_configs[0].listen_addr, "stale configuration denial").await;
        let error = ClusterRaftRuntime::start_on_listener(fixture.contexts[0].clone(), stale_configs[0].clone(), listener).await.unwrap_err();
        assert!(error.to_string().contains("durable live reconfiguration target"));
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
        for config in &mut versioned { set_transport_trust_plan(config, 1, roots.clone(), None); }
        fixture.restart_all(versioned).await;
        let prior = fixture.current(0).await;
        let next_peer = test_peer(&fixture.ca, 4);
        let mut factory = fixture.runtimes[0].as_ref().unwrap().authority_handle().network.clone();
        let cached_four = factory.new_client(4, prior.catalog.get(&4).unwrap()).await;
        let mut overlap = prior.catalog.clone();
        let expiry = chrono::Utc::now() + chrono::Duration::hours(1);
        for node in overlap.values_mut() {
            node.transport_trust_generation = 2;
            node.transport_trust_overlap_not_after = Some(expiry);
        }
        overlap.get_mut(&4).unwrap().tls_client_certificate_sha256_overlap = vec![next_peer.tls.client_certificate_sha256().into()];
        let digest = configured_transport_catalog_sha256(&overlap);
        for node in overlap.values_mut() { node.transport_catalog_sha256.clone_from(&digest); }
        let command = fixture.trust_command(0, prior.clone(), overlap, 2, Some(expiry));
        let unsigned = command.clone();
        assert!(fixture.runtimes[0].as_ref().unwrap().authority_handle().commit(unsigned.clone(), test_authority_delegation(&fixture.peers[0], &unsigned)).await.is_err(), "node keys alone must not authorize a transport change");
        let plan = prepared(fixture.submit(0, command).await.unwrap());
        fixture.settle(&plan, 4).await;
        assert_eq!(plan.target.voter_ids, prior.voter_ids);
        assert_eq!(plan.target.voter_generation, prior.voter_generation);
        for context in &fixture.contexts {
            let (membership, _) = crate::cluster_consensus::read_cluster_reconfiguration(context).unwrap();
            assert_eq!(membership.nodes().map(|(id, node)| (*id, node.clone())).collect::<BTreeMap<_, _>>(), plan.target.catalog);
        }
        // A cached actual OpenRaft client must consult the current catalog.
        // Removing this non-voter makes that pre-existing client fail closed.
        let mut removed = plan.target.catalog.clone();
        removed.remove(&4);
        for node in removed.values_mut() {
            node.transport_trust_generation = 3;
            node.transport_trust_overlap_not_after = None;
            node.tls_client_certificate_sha256_overlap.clear();
        }
        let digest = configured_transport_catalog_sha256(&removed);
        for node in removed.values_mut() { node.transport_catalog_sha256.clone_from(&digest); }
        let remove = fixture.trust_command(0, plan.target.clone(), removed, 3, None);
        let removed_plan = prepared(fixture.submit(0, remove).await.unwrap());
        fixture.settle(&removed_plan, 3).await;
        assert!(cached_four.call(RpcRequest::Vote(VoteRequest { vote: Vote::new(0, 1), last_log_id: None }), RPCOption::new(Duration::from_secs(3))).await.is_err());
        drop(cached_four); drop(factory);
        fixture.close().await;
    }).await.expect("live complete-catalog proof is bounded");
}
