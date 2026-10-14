//! One-shot, family-bound native open-window execution.
use super::*;
use stoffel_vm_runner::open_collection::{
    ApprovedOpenCollection, NativeOpenCollectionParty, OpenCollectionConfig,
};
use stoffel_mpc_coordinator_off_chain::CoordinatorRPCBaseClient;

fn valid_owner_capture(records: &[(usize, usize)], owner_slot: usize) -> bool {
    records == [(owner_slot, 1)]
}

struct AbortOnDrop(tokio::task::JoinHandle<()>);
impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

fn config_path(args: &[String]) -> Result<PathBuf, String> {
    let positions = args
        .iter()
        .enumerate()
        .filter(|(_, a)| *a == "--open-collection-config")
        .map(|(i, _)| i)
        .collect::<Vec<_>>();
    if positions.len() != 1 {
        return Err("exactly one --open-collection-config FILE is required".into());
    }
    args.get(positions[0] + 1)
        .filter(|p| !p.starts_with("--"))
        .map(PathBuf::from)
        .ok_or_else(|| "--open-collection-config requires FILE".into())
}

fn family_commitment(config: &OpenCollectionConfig, entry: &str) -> Result<[u8; 32], String> {
    let slots = config
        .programs
        .iter()
        .map(|(k, p)| (*k, p.owner_output_slot))
        .collect::<BTreeMap<_, _>>();
    let bytes = serde_json::to_vec(&("stoffel-open-family-v1", &config.policy, slots, entry))
        .map_err(|e| e.to_string())?;
    Ok(program_id_from_bytes(&bytes))
}

pub(super) async fn run(args: &[String]) -> Result<(), String> {
    let path = config_path(args)?;
    // No legacy/client/debug mode may silently change the privacy boundary.
    let allowed = [
        "--open-collection-config",
        "--party-id",
        "--bind",
        "--bootstrap",
        "--cert",
        "--key",
        "--party-cert-dir",
        "--off-chain-coord",
        "--coordinator-public-key",
        "--rpc-bind",
        "--browser-rpc-bind",
        "--entry",
        "--open-timeout-secs",
        "--advertise",
    ];
    let mut i = 0;
    while i < args.len() {
        if args[i] == "--leader" {
            if args[..i].contains(&args[i]) {
                return Err("duplicate open-collection discovery leader option".into());
            }
            i += 1;
            continue;
        }
        if !allowed.contains(&args[i].as_str())
            || args.get(i + 1).is_none_or(|v| v.starts_with("--"))
        {
            return Err(format!("invalid open-collection option: {}", args[i]));
        }
        if args[..i].contains(&args[i]) {
            return Err(format!("duplicate option: {}", args[i]));
        }
        i += 2;
    }
    let coordinator_public_key = hex::decode(standing_required_flag(args, "--coordinator-public-key")?)
        .map_err(|_| "invalid --coordinator-public-key HEX")?;
    let parsed_coordinator_key = p256::ecdsa::VerifyingKey::from_sec1_bytes(&coordinator_public_key)
        .map_err(|_| "invalid coordinator P-256 key")?;
    if parsed_coordinator_key.to_encoded_point(false).as_bytes() != coordinator_public_key {
        return Err("coordinator key must be canonical uncompressed SEC1".into());
    }
    let mut config: OpenCollectionConfig =
        serde_json::from_slice(&fs::read(&path).map_err(|e| format!("read open config: {e}"))?)
            .map_err(|e| format!("parse open config: {e}"))?;
    for file in config.programs.values_mut() {
        if file.path.is_relative() {
            file.path = path.parent().unwrap_or(Path::new(".")).join(&file.path);
        }
    }
    let entry = standing_flag_value(args, "--entry").unwrap_or_else(|| "main".into());
    // Commit the complete approved family, policy and output routes, never claim
    // that max-K preprocessing belongs to an as-yet-unselected immutable binary.
    let family_id = family_commitment(&config, &entry)?;
    let execution_id: ExecutionId = config
        .policy
        .execution_id
        .to_string()
        .parse()
        .map_err(|e| format!("execution id: {e}"))?;
    let approved = ApprovedOpenCollection::load(config, 5, 1)?;
    eprintln!(
        "OPEN_COLLECTION_FAMILY_APPROVED execution={} family={} min={} max={}",
        execution_id,
        hex::encode(family_id),
        approved.policy().min_clients,
        approved.policy().max_clients
    );
    let demand = approved.preprocessing_demand();
    let mask_count = approved.mask_count();
    let reservation_clients = approved.policy().reservation_clients() as usize;
    let width = approved.policy().inputs_per_client as usize;
    let party_id: usize = standing_required_flag(args, "--party-id")?
        .parse()
        .map_err(|_| "invalid party id")?;
    let leader = args.iter().any(|arg| arg == "--leader");
    if leader && party_id != 0 {
        return Err("only configured party zero may host discovery".into());
    }
    MpcSessionTopology::try_new(
        stoffel_vm::net::derive_instance_id_for_execution(&execution_id),
        party_id,
        5,
        1,
    )
    .map_err(|e| e.to_string())?;
    let timeout = standing_flag_value(args, "--open-timeout-secs")
        .unwrap_or_else(|| "300".into())
        .parse::<u64>()
        .map_err(|_| "invalid timeout")?;
    if timeout == 0 || timeout > 3600 {
        return Err("open timeout must be 1..=3600 seconds".into());
    }
    let cert = fs::read(standing_required_flag(args, "--cert")?)
        .map_err(|e| format!("read certificate: {e}"))?;
    let key = fs::read(standing_required_flag(args, "--key")?)
        .map_err(|e| format!("read node key: {e}"))?;
    let roster = load_standing_party_public_keys(
        Path::new(&standing_required_flag(args, "--party-cert-dir")?),
        5,
    )?;
    let local_key =
        QuicNetworkManager::public_key_from_certificate_der(&cert).map_err(|e| e.to_string())?;
    if roster.get(party_id).map(|(_, k)| k) != Some(&local_key) {
        return Err("local certificate does not match party roster".into());
    }
    let bind: SocketAddr = standing_required_flag(args, "--bind")?
        .parse()
        .map_err(|_| "invalid bind")?;
    let bootstrap: SocketAddr = standing_required_flag(args, "--bootstrap")?
        .parse()
        .map_err(|_| "invalid bootstrap")?;
    let rpc_bind: SocketAddr = standing_required_flag(args, "--rpc-bind")?
        .parse()
        .map_err(|_| "invalid RPC bind")?;
    let browser_bind = standing_required_flag(args, "--browser-rpc-bind")?;
    if env::var_os("STOFFEL_BROWSER_NODE_RPC_BIND").is_some() {
        return Err("open mode rejects STOFFEL_BROWSER_NODE_RPC_BIND raw-listener autostart; use --browser-rpc-bind".into());
    }
    let coordinator = standing_host_port(args, "--off-chain-coord")?;
    let _ = rustls::crypto::ring::default_provider().install_default();
    // Keep authenticated coordinator control outside the execution timeout so
    // cancellation cannot strand a still-admitting collection.
    let cleanup = tokio::time::timeout(
        Duration::from_secs(10),
        stoffel_mpc_coordinator_shared::self_signed_certs::setup_client_pinned(
            &coordinator.0, coordinator.1, cert.clone(), key.clone(),
            &coordinator_public_key,
        ),
    ).await.map_err(|_| "coordinator control connection timed out".to_owned())?
        .map_err(|e| format!("coordinator control connection: {e}"))?;
    let tasks = ExecutionTaskGroup::child_of(&CancellationToken::new());
    let mut node_resource = None;
    let mut result = tokio::time::timeout(Duration::from_secs(timeout), async {
        // Discovery is a separate authenticated-protocol bootnode listener,
        // not the party's TLS mesh endpoint. Match legacy leader port mapping.
        let mesh_bind = if leader {
            SocketAddr::new(bind.ip(), bind.port().checked_add(1000).ok_or("leader mesh port overflow")?)
        } else { bind };
        let _bootnode = if leader {
            let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
            let guard = AbortOnDrop(tokio::spawn(async move {
                if run_bootnode_with_config_ready(bind, 5, Some(ready_tx)).await.is_err() {
                    eprintln!("OPEN_COLLECTION_DISCOVERY_STOPPED");
                }
            }));
            ready_rx.await.map_err(|_| "discovery exited before listener readiness")?;
            write_local_runner_marker_or_exit("STOFFEL_LOCAL_BOOTNODE_READY_FILE", "open discovery listener readiness");
            Some(guard)
        } else { None };
        let bootstrap = if leader {
            let ip = if bind.ip().is_unspecified() {
                if bind.is_ipv4() { std::net::Ipv4Addr::LOCALHOST.into() } else { std::net::Ipv6Addr::LOCALHOST.into() }
            } else { bind.ip() };
            SocketAddr::new(ip, bind.port())
        } else { bootstrap };
        let mut network = QuicNetworkManager::with_node_id(party_id);
        network
            .set_local_certificate_der(cert.clone(), key.clone())
            .map_err(|e| e.to_string())?;
        network
            .install_expected_server_public_keys(roster.iter().map(|(_, k)| k.clone()))
            .map_err(|e| e.to_string())?;
        network.listen(mesh_bind).await.map_err(|e| e.to_string())?;
        let session = register_and_wait_for_session(
            &mut network,
            SessionRegistrationConfig {
                execution_id,
                bootnode: bootstrap,
                my_party_id: party_id,
                my_listen: standing_flag_value(args, "--advertise")
                    .map(|s| s.parse())
                    .transpose()
                    .map_err(|_| "invalid advertise")?
                    .unwrap_or(mesh_bind),
                program_id: family_id,
                entry: entry.clone(),
                n_parties: 5,
                threshold: 1,
                timeout: Duration::from_secs(timeout),
                expected_party_public_keys: Some(roster),
            },
        )
        .await
        .map_err(|e| e.to_string())?;
        // QUIC assigns protocol positions from the authenticated certificate mesh;
        // the CLI party id is only the configured certificate-file slot.
        let party_id = network.local_party_id();
        let mux = ExecutionTransportMux::new(4096).map_err(|e| e.to_string())?;
        let inbox = mux
            .register_with_client_identities(execution_id, Vec::new())
            .map_err(|e| e.to_string())?;
        let registration = ExecutionInboxRegistrationGuard::new(mux.clone(), execution_id);
        let scanner = ExecutionConnectionScanner::spawn(network.clone(), mux.clone())
            .map_err(|e| e.to_string())?;
        let accept = AbortOnDrop(spawn_connection_accept_loop(network.clone(), party_id));
        let node = OffChainNodeRPCServer::start_for_execution(
            &rpc_bind.ip().to_string(),
            rpc_bind.port(),
            coordinator_execution_id(execution_id),
            cert.clone(),
            key.clone(),
        )
        .await
        .map_err(|e| e.to_string())?;
        let node = node.with_browser_rpc_sealed(&browser_bind, &key)
            .await
            .map_err(|e| e.to_string())?;
        node_resource = Some(node);
        let node = node_resource.as_ref().expect("listener installed");
        let run = async {
            let native = NativeOpenCollectionParty::connect(
                &coordinator.0,
                coordinator.1,
                cert.clone(),
                key.clone(),
                approved,
                &coordinator_public_key,
            )
            .await?;
            let mut bootstrap_vm = VirtualMachine::builder().build();
            let empty_types = BTreeMap::new();
            let engine =
                setup_hb_party_for_curve::<ark_bls12_381::Fr, ark_bls12_381::G1Projective>(
                    &mut bootstrap_vm,
                    PartySetup {
                        net: Arc::new(network),
                        reply_mux: mux,
                        execution_id,
                        execution_inbox: inbox,
                        my_id: party_id,
                        identity: durable_identity_from_cert(&cert),
                        n: 5,
                        t: 1,
                        instance_id: session.instance_id,
                        expected_client_count: None,
                        expected_client_bindings: None,
                        expected_client_reservation_identities: None,
                        client_count_hint: reservation_clients,
                        client_input_count: width,
                        client_input_types: &empty_types,
                        preprocessing_demand: demand,
                        program_hash: family_id,
                        preproc_store: None,
                        preprocessing: PartyPreprocessing::OneShot,
                        execution_tasks: Some(&tasks),
                    },
                )
                .await?;
            let masks = engine
                .node_handle()
                .lock()
                .await
                .preprocessing_material
                .lock()
                .await
                .take_random_shares(mask_count)
                .map_err(|e| e.to_string())?;
            // Release browser admission only after the listener, pinned policy,
            // and maximum-capacity masks exist. Reservations must come later:
            // waiting for them before publishing readiness would deadlock.
            write_local_runner_marker_or_exit("STOFFEL_LOCAL_RPC_READY_FILE", "open listener and preprocessed-mask readiness");
            println!("OPEN_COLLECTION_READY execution={execution_id}");
            let (collected, output) = native
                .collect::<ark_bls12_381::Fr, RobustShare<ark_bls12_381::Fr>>(
                    &node,
                    masks,
                    Duration::from_secs(timeout),
                )
                .await?;
            let mut vm = load_standing_vm(collected.program.bytes(), None)?;
            vm.set_mpc_engine(engine.clone());
            vm.set_client_roster(
                collected
                    .program
                    .manifest
                    .clients
                    .iter()
                    .map(|c| c.client_slot as usize),
            );
            let types = manifest_client_input_types(&collected.program.manifest, None);
            vm.try_replace_client_inputs_with_types(collected.shares.into_iter().map(
                |(slot, shares)| (slot as usize, shares, types.get(&(slot as usize)).cloned()),
            ))
            .map_err(|e| e.to_string())?;
            let owner_slot = collected.program.owner_output_slot as usize;
            engine
                .set_client_output_slot_map([(owner_slot, owner_slot)].into_iter().collect())
                .await;
            engine.enable_client_output_capture().await;
            // Deliberately discard return values: the only deliverable is the
            // precommitted owner's captured shares, HPKE sealed by the adapter.
            let _ = vm
                .execute_async_with_metrics(&entry, engine.as_ref())
                .await
                .map_err(|e| format!("open VM execution: {e}"))?;
            let records = engine.drain_client_output_records().await;
            let shape = records.iter().map(|r| (r.client_id, r.shares.len())).collect::<Vec<_>>();
            if !valid_owner_capture(&shape, owner_slot) {
                return Err("captured output differs from the exact one-owner-output ABI".into());
            }
            let shares = records
                .into_iter()
                .flat_map(|r| r.shares)
                .collect::<Vec<_>>();
            output.send(&shares).await?;
            eprintln!(
                "OPEN_COLLECTION_COMPLETED execution={} program={}",
                execution_id,
                hex::encode(collected.frozen.registration.program_hash)
            );
            Ok::<(), String>(())
        }
        .await;
        node.retire_execution(coordinator_execution_id(execution_id))
            .await;
        drop(accept);
        scanner.shutdown().await;
        drop(registration);
        run
    })
    .await
    .map_err(|_| "open execution deadline expired".to_owned())
    .and_then(|r| r);
    tasks.shutdown().await;
    if let Some(node) = node_resource {
        node.shutdown().await;
    }
    if let Err(original) = &result {
        let id = coordinator_execution_id(execution_id);
        let retired = tokio::time::timeout(Duration::from_secs(5), async {
            let status = cleanup.open_status(id).await.map_err(|_| "status unavailable")?;
            if status.execution_id != id { return Err("coordinator execution mismatch"); }
            if status.termination.is_some() { return Ok(()); }
            // A winning freeze cannot become evidence of a no-compute abort.
            if status.frozen.is_some() { return Err("execution already frozen; encrypted archive recovery required"); }
            let receipt = cleanup.open_stop(id).await.map_err(|_| "retirement unconfirmed")?;
            if receipt.program_hash.is_some() || receipt.encrypted_output_shares != 0 {
                return Err("freeze won retirement race; encrypted archive recovery required");
            }
            Ok(())
        }).await;
        match retired {
            Ok(Ok(())) => {},
            Ok(Err(reason)) => result = Err(format!("{original}; {reason}")),
            Err(_) => result = Err(format!("{original}; coordinator retirement timed out")),
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn captured_output_must_match_exact_owner_abi() {
        assert!(valid_owner_capture(&[(2, 1)], 2));
        for malformed in [vec![], vec![(2, 0)], vec![(2, 2)], vec![(1, 1)], vec![(2, 1), (2, 1)]] {
            assert!(!valid_owner_capture(&malformed, 2));
        }
    }
    #[test]
    fn family_provenance_binds_policy_entry_and_routes_not_local_paths() {
        use stoffel_mpc_coordinator_off_chain::OpenCollectionPolicy;
        use stoffel_vm_runner::open_collection::OpenProgramFile;
        let mut config = OpenCollectionConfig {
            policy: OpenCollectionPolicy {
                execution_id: CoordinatorExecutionId::from_bytes([7; 32]),
                owner: vec![4; 65],
                min_clients: 2,
                max_clients: 2,
                inputs_per_client: 1,
                approved_programs: [(2, [8; 32])].into_iter().collect(),
                min_output_shares: 5,
                deadline_unix_ms: None,
            },
            programs: [(
                2,
                OpenProgramFile {
                    path: "relative.stflb".into(),
                    owner_output_slot: 2,
                },
            )]
            .into_iter()
            .collect(),
        };
        let original = family_commitment(&config, "main").unwrap();
        config.programs.get_mut(&2).unwrap().path = "/another/node/artifact.stflb".into();
        assert_eq!(original, family_commitment(&config, "main").unwrap());
        assert_ne!(
            original,
            family_commitment(&config, "different_entry").unwrap()
        );
        config.programs.get_mut(&2).unwrap().owner_output_slot = 3;
        assert_ne!(original, family_commitment(&config, "main").unwrap());
        config.programs.get_mut(&2).unwrap().owner_output_slot = 2;
        config.policy.approved_programs.insert(2, [9; 32]);
        assert_ne!(original, family_commitment(&config, "main").unwrap());
    }

    #[tokio::test]
    async fn coordinator_pin_is_required_and_validated_before_config_or_network() {
        for pin in [None, Some(""), Some("zz"), Some("04"), Some("0400000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000")] {
            let mut args = vec!["--open-collection-config".into(), "/nonexistent/open-pin-test.json".into()];
            if let Some(pin) = pin { args.extend(["--coordinator-public-key".into(), pin.into()]); }
            let error = run(&args).await.unwrap_err();
            assert!(!error.contains("read open config"), "pin validation must precede config reads");
        }
    }

    #[test]
    fn config_argument_is_required_and_unique() {
        for args in [
            vec![],
            vec!["--open-collection-config"],
            vec!["--open-collection-config", "--key"],
            vec![
                "--open-collection-config",
                "a",
                "--open-collection-config",
                "b",
            ],
        ] {
            assert!(config_path(&args.into_iter().map(String::from).collect::<Vec<_>>()).is_err());
        }
        assert_eq!(
            config_path(&["--open-collection-config".into(), "relative.json".into()]).unwrap(),
            PathBuf::from("relative.json")
        );
    }
}
